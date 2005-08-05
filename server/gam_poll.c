/* Gamin
 * Copyright (C) 2003 James Willcox, Corey Bowers
 * Copyright (C) 2004 Daniel Veillard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "server_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <glib.h>
#include "fam.h"
#include "gam_error.h"
#include "gam_tree.h"
#include "gam_poll.h"
#include "gam_event.h"
#include "gam_server.h"
#include "gam_protocol.h"
#include "gam_event.h"
#include "gam_excludes.h"

/* #define VERBOSE_POLL */

#define DEFAULT_POLL_TIMEOUT 1

#define FLAG_NEW_NODE 1 << 5


/*
 * Special monitoring modes
 */
#define MON_MISSING	1 << 0  /* The resource is missing */
#define MON_NOKERNEL	1 << 1  /* file(system) not monitored by the kernel */
#define MON_BUSY	1 << 2  /* Too busy to be monitored by the kernel */
#define MON_WRONG_TYPE	1 << 3  /* Expecting a directory and got a file */

static GamTree *tree = NULL;
static GList *new_subs = NULL;
static GList *missing_resources = NULL;
static GList *busy_resources = NULL;
static GList *all_resources = NULL;
static GamPollHandler dir_handler = NULL;
static GamPollHandler file_handler = NULL;
static pollHandlerKernel type_khandler = GAMIN_K_NONE;

static int poll_mode = 0;

static time_t current_time = 0; /* a cache for time() informations */

static GaminEventType poll_file(GamNode * node);
static void trigger_file_handler(const char *path, pollHandlerMode mode,
                                 GamNode * node);

static int
gam_errno(void)
{
    return (errno);
}

/**
 * gam_poll_add_missing:
 * @node: a missing node
 *
 * Add a missing node to the list for polling its creation.
 */
static void
gam_poll_add_missing(GamNode * node)
{
    GAM_DEBUG(DEBUG_INFO, "Poll adding missing node %s\n",
              gam_node_get_path(node));
    if (g_list_find(missing_resources, node) == NULL) {
        missing_resources = g_list_prepend(missing_resources, node);
    } else {
        GAM_DEBUG(DEBUG_INFO, "  already registered\n");
    }
}

/**
 * gam_poll_remove_missing:
 * @node: a missing node
 *
 * Remove a missing node from the list.
 */
static void
gam_poll_remove_missing(GamNode * node)
{
    GAM_DEBUG(DEBUG_INFO, "Poll removing missing node %s\n",
              gam_node_get_path(node));
    missing_resources = g_list_remove_all(missing_resources, node);
}

/**
 * gam_poll_add_busy:
 * @node: a busy node
 *
 * Add a busy node to the list for polling its creation.
 */
static void
gam_poll_add_busy(GamNode * node)
{
    GAM_DEBUG(DEBUG_INFO, "Poll adding busy node %s\n",
              gam_node_get_path(node));
    if (g_list_find(busy_resources, node) == NULL) {
        busy_resources = g_list_prepend(busy_resources, node);
    } else {
        GAM_DEBUG(DEBUG_INFO, "  already registered\n");
    }
}

/**
 * gam_poll_remove_busy:
 * @node: a busy node
 *
 * Remove a busy node from the list.
 */
static void
gam_poll_remove_busy(GamNode * node)
{
    GAM_DEBUG(DEBUG_INFO, "Poll removing busy node %s\n",
              gam_node_get_path(node));
    busy_resources = g_list_remove_all(busy_resources, node);
}

/**
 * trigger_dir_handler:
 * @path: path to the directory
 * @mode: type of kernel monitoring action
 *
 * Interface to the kernel monitoring layer for directories
 */
static void
trigger_dir_handler(const char *path, pollHandlerMode mode, GamNode * node)
{
    if (node->mon_type != GFS_MT_KERNEL)
	    return;

    if (type_khandler == GAMIN_K_DNOTIFY || type_khandler == GAMIN_K_INOTIFY) {
        if (gam_node_is_dir(node)) {
	    if (dir_handler != NULL)
		(*dir_handler) (path, mode);
	} else {
	    trigger_file_handler(path, mode, node);
	}
    } else {
	if (dir_handler != NULL)
	    (*dir_handler) (path, mode);
    }
}

/**
 * trigger_file_handler:
 * @path: path to the file
 * @mode: type of kernel monitoring action
 *
 * Interface to the kernel monitoring layer for files
 */
static void
trigger_file_handler(const char *path, pollHandlerMode mode, GamNode * node)
{
    if (node->mon_type != GFS_MT_KERNEL)
	    return;

    if (type_khandler == GAMIN_K_DNOTIFY || type_khandler == GAMIN_K_INOTIFY) {
        if (gam_node_is_dir(node)) {
	    (*file_handler) (path, mode);
	} else {
	    const char *dir;
	    GamNode *parent = gam_node_parent(node);
	    if (parent == NULL) {
                gam_error(DEBUG_INFO,
                          "Failed to find parent for: %s\n", path);
	        return;
	    }
	    dir = parent->path;
	    switch (mode) {
	        case GAMIN_ACTIVATE:
		    GAM_DEBUG(DEBUG_INFO, "File activating kernel monitoring on %s\n",
			      dir);
		    (*dir_handler) (dir, mode);
		    break;
	        case GAMIN_DESACTIVATE:
		    GAM_DEBUG(DEBUG_INFO, "File deactivating kernel monitoring on %s\n",
			      dir);
		    (*dir_handler) (dir, mode);
		    break;
                case GAMIN_FLOWCONTROLSTART:
		    if ((parent->pflags & MON_BUSY) == 0) {
			GAM_DEBUG(DEBUG_INFO, "File directory busy on %s\n",
				  dir);
		        (*dir_handler) (dir, mode);
			gam_poll_add_busy(parent);
			parent->pflags |= MON_BUSY;
		    }
		    break;
		case GAMIN_FLOWCONTROLSTOP:
		    if (parent->pflags & MON_BUSY) {
			GAM_DEBUG(DEBUG_INFO, "File dir no longer busy %s\n",
				  dir);
			(*dir_handler) (dir, mode);
			gam_poll_remove_busy(parent);
			parent->pflags &= !MON_BUSY;
		    }
		    break;
	    }

	}
    } else {
	if (file_handler != NULL)
	    (*file_handler) (path, mode);
    }
}

/**
 * node_add_subscription:
 * @node: the node tree pointer
 * @sub: the pointer to the subscription
 *
 * register a subscription for this node
 *
 * Returns 0 in case of success and -1 in case of failure
 */

static int
node_add_subscription(GamNode * node, GamSubscription * sub)
{
    if ((node == NULL) || (sub == NULL))
        return (-1);

    if ((node->path == NULL) || (node->path[0] != '/'))
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "node_add_subscription(%s)\n", node->path);
    gam_node_add_subscription(node, sub);

    if (gam_exclude_check(node->path) || gam_fs_get_mon_type (node->path) == GFS_MT_POLL) {
        GAM_DEBUG(DEBUG_INFO, "  gam_exclude_check: true\n");
        if (node->lasttime == 0)
            poll_file(node);

        gam_poll_add_missing(node);
        return (0);
    }

    if (gam_node_is_dir(node))
        trigger_dir_handler(node->path, GAMIN_ACTIVATE, node);
    else
        trigger_file_handler(node->path, GAMIN_ACTIVATE, node);

    return (0);
}

/**
 * node_remove_subscription:
 * @node: the node tree pointer
 * @sub: the pointer to the subscription
 *
 * Removes a subscription for this node
 *
 * Returns 0 in case of success and -1 in case of failure
 */

static int
node_remove_subscription(GamNode * node, GamSubscription * sub)
{
    const char *path;

    if ((node == NULL) || (sub == NULL))
        return (-1);

    if ((node->path == NULL) || (node->path[0] != '/'))
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "node_remove_subscription(%s)\n", node->path);

    gam_node_remove_subscription(node, sub);

    path = node->path;
    if (gam_exclude_check(path) || gam_fs_get_mon_type (path) == GFS_MT_POLL) {
        GAM_DEBUG(DEBUG_INFO, "  gam_exclude_check: true\n");
        return (0);
    }
    if (node->pflags == MON_BUSY) {
        GAM_DEBUG(DEBUG_INFO, "  node is busy\n");
    } else if (node->pflags != 0) {
        GAM_DEBUG(DEBUG_INFO, "  node has flag %d\n", node->pflags);
	return (0);
    }

    /* DNotify makes our life miserable here */
    if (gam_node_is_dir(node))
	trigger_dir_handler(path, GAMIN_DESACTIVATE, node);
    else
	trigger_file_handler(path, GAMIN_DESACTIVATE, node);

    return (0);
}

static void
gam_poll_emit_event(GamNode * node, GaminEventType event)
{
    GList *l;
    GamNode *parent;
    GList *subs;
    int is_dir_node = gam_node_is_dir(node);

#ifdef VERBOSE_POLL
    GAM_DEBUG(DEBUG_INFO, "Poll: emit events %d for %s\n",
              event, gam_node_get_path(node));
#endif
    subs = gam_node_get_subscriptions(node);
    if (subs)
        subs = g_list_copy(subs);

    parent = gam_node_parent(node);
    if (parent) {
        GList *parent_subs = gam_node_get_subscriptions(parent);

        for (l = parent_subs; l; l = l->next) {
            if (!g_list_find(subs, l->data))
                subs = g_list_prepend(subs, l->data);
        }
    }

    gam_server_emit_event(gam_node_get_path(node), is_dir_node, event,
                          subs, 0);

    g_list_free(subs);
}

/**
 * gam_poll_delist_node:
 * @node: the node to delist
 *
 * This function is called when kernel monitoring for a node should
 * be turned off.
 */
static void
gam_poll_delist_node(GamNode * node)
{
    GList *subs;
    const char *path;

    path = gam_node_get_path(node);
    GAM_DEBUG(DEBUG_INFO, "gam_poll_delist_node %s\n", path);

    if (gam_exclude_check(path) || gam_fs_get_mon_type (path) != GFS_MT_KERNEL)
        return;
    subs = gam_node_get_subscriptions(node);

    while (subs != NULL) {
        if (gam_node_is_dir(node))
            trigger_dir_handler(path, GAMIN_DESACTIVATE, node);
        else
            trigger_file_handler(path, GAMIN_DESACTIVATE, node);
        subs = subs->next;
    }
}

/**
 * gam_poll_relist_node:
 * @node: the node to delist
 *
 * This function is called when kernel monitoring for a node should
 * be turned on (again).
 */
static void
gam_poll_relist_node(GamNode * node)
{
    GList *subs;
    const char *path;

    path = gam_node_get_path(node);
    GAM_DEBUG(DEBUG_INFO, "gam_poll_relist_node %s\n", path);

    if (gam_exclude_check(path) || gam_fs_get_mon_type(path) != GFS_MT_KERNEL)
        return;

    subs = gam_node_get_subscriptions(node);

    while (subs != NULL) {
        if (gam_node_is_dir(node))
            trigger_dir_handler(path, GAMIN_ACTIVATE, node);
        else
            trigger_file_handler(path, GAMIN_ACTIVATE, node);
        subs = subs->next;
    }
}

/**
 * gam_poll_flowon_node:
 * @node: the node to delist
 *
 * This function is called when kernel monitoring flow control for a
 * node should be started
 */
static void
gam_poll_flowon_node(GamNode * node)
{
    const char *path;

    path = gam_node_get_path(node);

    if (gam_exclude_check(path) || gam_fs_get_mon_type(path) != GFS_MT_KERNEL)
        return;

    GAM_DEBUG(DEBUG_INFO, "gam_poll_flowon_node %s\n", path);

    if (gam_node_is_dir(node))
        trigger_dir_handler(path, GAMIN_FLOWCONTROLSTART, node);
    else
        trigger_file_handler(path, GAMIN_FLOWCONTROLSTART, node);
}

/**
 * gam_poll_flowoff_node:
 * @node: the node to delist
 *
 * This function is called when kernel monitoring flow control for a
 * node should be started
 */
static void
gam_poll_flowoff_node(GamNode * node)
{
    const char *path;

    path = gam_node_get_path(node);

    if (gam_exclude_check(path) || gam_fs_get_mon_type(path) != GFS_MT_KERNEL)
        return;

    GAM_DEBUG(DEBUG_INFO, "gam_poll_flowoff_node %s\n", path);

    if (gam_node_is_dir(node))
        trigger_dir_handler(path, GAMIN_FLOWCONTROLSTOP, node);
    else
        trigger_file_handler(path, GAMIN_FLOWCONTROLSTOP, node);
}

static GaminEventType
poll_file(GamNode * node)
{
    GaminEventType event;
    struct stat sbuf;
    int stat_ret;
    const char *path;

    /* If not enough time has passed since the last time we polled this node, stop here */
    if (node->lasttime && (current_time - node->lasttime) < node->poll_time) 
	    return 0;

    path = gam_node_get_path(node);
#ifdef VERBOSE_POLL
    GAM_DEBUG(DEBUG_INFO, "Poll: poll_file for %s called\n", path);
#endif

    memset(&sbuf, 0, sizeof(struct stat));
    if (node->lasttime == 0) {
        GAM_DEBUG(DEBUG_INFO, "Poll: file is new\n");
        stat_ret = stat(node->path, &sbuf);
        if (stat_ret != 0)
            node->pflags |= MON_MISSING;
        else
            gam_node_set_is_dir(node, (S_ISDIR(sbuf.st_mode) != 0));
        if (gam_exclude_check(path) || gam_fs_get_mon_type (path) != GFS_MT_KERNEL)
            node->pflags |= MON_NOKERNEL;
        memcpy(&(node->sbuf), &(sbuf), sizeof(struct stat));
        node->lasttime = current_time;

        if (stat_ret == 0)
            return 0;
        else
            return GAMIN_EVENT_DELETED;
    }
#ifdef VERBOSE_POLL
    GAM_DEBUG(DEBUG_INFO, " at %d delta %d : %d\n", current_time,
              current_time - node->lasttime, node->checks);
#endif

    event = 0;

    stat_ret = stat(node->path, &sbuf);
    if (stat_ret != 0) {
        if ((gam_errno() == ENOENT) && (!(node->pflags & MON_MISSING))) {
            /* deleted */
            node->pflags = MON_MISSING;

            gam_poll_remove_busy(node);
            if (gam_node_get_subscriptions(node) != NULL) {
                gam_poll_delist_node(node);
                gam_poll_add_missing(node);
            }
            event = GAMIN_EVENT_DELETED;
        }
    } else if (node->pflags & MON_MISSING) {
        /* created */
        node->pflags &= ~MON_MISSING;
        event = GAMIN_EVENT_CREATED;
#ifdef ST_MTIM_NSEC
    } else if ((node->sbuf.st_mtim.tv_sec != sbuf.st_mtim.tv_sec) ||
               (node->sbuf.st_mtim.tv_nsec != sbuf.st_mtim.tv_nsec) ||
               (node->sbuf.st_size != sbuf.st_size) ||
               (node->sbuf.st_ctim.tv_sec != sbuf.st_ctim.tv_sec) ||
               (node->sbuf.st_ctim.tv_nsec != sbuf.st_ctim.tv_nsec)) {
        event = GAMIN_EVENT_CHANGED;
    } else {
#ifdef VERBOSE_POLL
        GAM_DEBUG(DEBUG_INFO, "Poll: poll_file %s unchanged\n", path);
        GAM_DEBUG(DEBUG_INFO, "%d %d : %d %d\n", node->sbuf.st_mtim.tv_sec,
                  node->sbuf.st_mtim.tv_nsec, sbuf.st_mtim.tv_sec,
                  sbuf.st_mtim.tv_nsec);
#endif
#else
    } else if ((node->sbuf.st_mtime != sbuf.st_mtime) ||
               (node->sbuf.st_size != sbuf.st_size) ||
               (node->sbuf.st_ctime != sbuf.st_ctime)) {
        event = GAMIN_EVENT_CHANGED;
#ifdef VERBOSE_POLL
        GAM_DEBUG(DEBUG_INFO, "%d : %d\n", node->sbuf.st_mtime,
                  sbuf.st_mtime);
#endif
#endif
    }

    /*
     * TODO: handle the case where a file/dir is removed and replaced by 
     *       a dir/file
     */
    if (stat_ret == 0)
        gam_node_set_is_dir(node, (S_ISDIR(sbuf.st_mode) != 0));

    memcpy(&(node->sbuf), &(sbuf), sizeof(struct stat));
    node->sbuf.st_mtime = sbuf.st_mtime; // VALGRIND!

    /*
     * if kernel monitoring prohibited, stop here
     */
    if (node->pflags & MON_NOKERNEL)
        return (event);

    /*
     * load control, switch back to poll on very busy resources
     * and back when no update has happened in 5 seconds
     */
    if (current_time == node->lasttime) {
        if (!(node->pflags & MON_BUSY)) {
            if (node->sbuf.st_mtime == current_time)
                node->checks++;
        }
    } else {
        node->lasttime = current_time;
        if (node->pflags & MON_BUSY) {
            if (event == 0)
                node->checks++;
        } else {
            node->checks = 0;
        }
    }

    if ((node->checks >= 4) && (!(node->pflags & MON_BUSY))) {
        if ((gam_node_get_subscriptions(node) != NULL) &&
            (!gam_exclude_check(node->path) && gam_fs_get_mon_type (node->path) == GFS_MT_KERNEL)) {
            GAM_DEBUG(DEBUG_INFO, "switching %s back to polling\n", path);
            node->pflags |= MON_BUSY;
            node->checks = 0;
            gam_poll_add_busy(node);
            gam_poll_flowon_node(node);
            /*
             * DNotify can be nasty here, we will miss events for parent dir
             * if we are not careful about it
             */
            if (!gam_node_is_dir(node)) {
                GamNode *parent = gam_node_parent(node);

                if ((parent != NULL) &&
                    (gam_node_get_subscriptions(parent) != NULL)) {
                    gam_poll_add_busy(parent);
                    /* gam_poll_flowon_node(parent); */
                }
            }
        }
    }

    if ((event == 0) && (node->pflags & MON_BUSY) && (node->checks > 5)) {
        if ((gam_node_get_subscriptions(node) != NULL) &&
            (!gam_exclude_check(node->path) && gam_fs_get_mon_type (node->path) == GFS_MT_KERNEL)) {
            GAM_DEBUG(DEBUG_INFO,
                      "switching %s back to kernel monitoring\n", path);
            node->pflags &= ~MON_BUSY;
            node->checks = 0;
            gam_poll_remove_busy(node);
            gam_poll_flowoff_node(node);
        }
    }

    return (event);
}

static void
gam_poll_scan_directory_internal(GamNode * dir_node)
{
    GDir *dir;
    const char *name, *dpath;
    char *path;
    GamNode *node;
    GaminEventType event = 0, fevent;
    GList *children, *l;
    unsigned int exists = 0;
    int is_dir_node;

    if (dir_node == NULL)
        return;

    dpath = gam_node_get_path(dir_node);

    if (dpath == NULL)
        return;

    if (!gam_node_get_subscriptions(dir_node))
        goto scan_files;

    event = poll_file(dir_node);

    if (event != 0)
        gam_poll_emit_event(dir_node, event);

    dir = g_dir_open(dpath, 0, NULL);

    if (dir == NULL) {
#ifdef VERBOSE_POLL
        GAM_DEBUG(DEBUG_INFO,
                  "Poll: directory %s is not readable or missing\n",
                  dpath);
#endif
        return;
    }

    exists = 1;

#ifdef VERBOSE_POLL
    GAM_DEBUG(DEBUG_INFO, "Poll: scanning directory %s\n", dpath);
#endif
    while ((name = g_dir_read_name(dir)) != NULL) {
        path = g_build_filename(gam_node_get_path(dir_node), name, NULL);

        node = gam_tree_get_at_path(tree, path);

        if (!node) {
            if (!g_file_test(path, G_FILE_TEST_IS_DIR)) {
                node = gam_node_new(path, NULL, FALSE);
                gam_tree_add(tree, dir_node, node);
                gam_node_set_flag(node, FLAG_NEW_NODE);
            } else {
                node = gam_node_new(path, NULL, TRUE);
                gam_tree_add(tree, dir_node, node);
                gam_node_set_flag(node, FLAG_NEW_NODE);
            }
        }

        g_free(path);
    }

    g_dir_close(dir);

  scan_files:


    /* FIXME: 
     * Shouldn't is_dir_node be assigned inside the loop? */
    is_dir_node = gam_node_is_dir(dir_node);
    children = gam_tree_get_children(tree, dir_node);
    for (l = children; l; l = l->next) {

        node = (GamNode *) l->data;

        fevent = poll_file(node);

        if (gam_node_has_flag(node, FLAG_NEW_NODE)) {
            if (is_dir_node && gam_node_get_subscriptions(node)) {
                gam_node_unset_flag(node, FLAG_NEW_NODE);
                gam_poll_scan_directory_internal(node);
            } else {
                gam_node_unset_flag(node, FLAG_NEW_NODE);
                fevent = GAMIN_EVENT_CREATED;
            }
        }

        if (fevent != 0) {
            gam_poll_emit_event(node, fevent);
        } else {
            /* just send the EXIST events if the node exists */
            if (!(node->pflags & MON_MISSING))
                gam_server_emit_event(gam_node_get_path(node),
                                      gam_node_is_dir(node),
                                      GAMIN_EVENT_EXISTS, NULL, 0);
        }
    }

    g_list_free(children);
}

static void
unregister_node (GamNode * node)
{
    if (missing_resources != NULL) {
       	gam_poll_remove_missing(node);
    }
    if (busy_resources != NULL) {
        gam_poll_remove_busy(node);
    }
    if (all_resources != NULL) {
        all_resources = g_list_remove(all_resources, node);
    }
}


static gboolean
remove_directory_subscription(GamNode * node, GamSubscription * sub)
{
    GList *children, *l;
    gboolean remove_dir;

    GAM_DEBUG(DEBUG_INFO, "remove_directory_subscription %s\n",
              gam_node_get_path(node));

    node_remove_subscription(node, sub);

    remove_dir = (gam_node_get_subscriptions(node) == NULL);

    children = gam_tree_get_children(tree, node);
    for (l = children; l; l = l->next) {
        GamNode *child = (GamNode *) l->data;

        if ((!gam_node_get_subscriptions(child)) && (remove_dir) &&
            (!gam_tree_has_children(tree, child))) {
            unregister_node (child);

            gam_tree_remove(tree, child);
        } else {
            remove_dir = FALSE;
        }
    }

    g_list_free(children);

    /*
     * do not remove the directory if the parent has a directory subscription
     */
    remove_dir = ((gam_node_get_subscriptions(node) == NULL) &&
                  (!gam_node_has_dir_subscriptions
                   (gam_node_parent(node))));

    if (remove_dir) {
        GAM_DEBUG(DEBUG_INFO, "  => remove_dir %s\n",
                  gam_node_get_path(node));
    }
    return remove_dir;
}

static gboolean
gam_poll_scan_callback(gpointer data)
{
    int idx;
    static int in_poll_callback = 0;

#ifdef VERBOSE_POLL
    GAM_DEBUG(DEBUG_INFO,
              "gam_poll_scan_callback(): %d, %d missing, %d busy\n",
              in_poll_callback, g_list_length(missing_resources),
              g_list_length(busy_resources));
#endif
    if (in_poll_callback)
        return (TRUE);

    in_poll_callback++;

    current_time = time(NULL);
    for (idx = 0;; idx++) {
        GamNode *node;

        /*
         * do not simply walk the list as it may be modified in the callback
         */
        node = (GamNode *) g_list_nth_data(missing_resources, idx);

        if (node == NULL) {
#ifdef VERBOSE_POLL
            GAM_DEBUG(DEBUG_INFO, "  node %d == NULL\n", idx);
#endif
            break;
        }
#ifdef VERBOSE_POLL
        GAM_DEBUG(DEBUG_INFO, "Checking missing file %s", data->path);
#endif
        if (node->is_dir) {
            gam_poll_scan_directory_internal(node);
        } else {
            GaminEventType event;

            event = poll_file(node);
            gam_poll_emit_event(node, event);
        }

        /*
         * if the resource exists again and is not in a special monitoring
         * mode then switch back to dnotify for monitoring.
         */
        if ((node->pflags == 0) && (!gam_exclude_check(node->path) && gam_fs_get_mon_type (node->path) == GFS_MT_KERNEL)) {
            gam_poll_remove_missing(node);
            if (gam_node_get_subscriptions(node) != NULL) {
                gam_poll_relist_node(node);
            }
        }
    }

    for (idx = 0;; idx++) {
        GamNode *node;

        /*
         * do not simply walk the list as it may be modified in the callback
         */
        node = (GamNode *) g_list_nth_data(busy_resources, idx);

        if (node == NULL) {
#ifdef VERBOSE_POLL
            GAM_DEBUG(DEBUG_INFO, "  node %d == NULL\n", idx);
#endif
            break;
        }
#ifdef VERBOSE_POLL
        GAM_DEBUG(DEBUG_INFO, "Checking busy file %s", node->path);
#endif
        if (node->is_dir) {
            gam_poll_scan_directory_internal(node);
        } else {
            GaminEventType event;

            event = poll_file(node);
            gam_poll_emit_event(node, event);
        }

        /*
         * if the resource exists again and is not in a special monitoring
         * mode then switch back to dnotify for monitoring.
         */
        if ((node->pflags == 0) && (!gam_exclude_check(node->path) && gam_fs_get_mon_type (node->path) == GFS_MT_KERNEL)) {
            gam_poll_remove_busy(node);
            if (gam_node_get_subscriptions(node) != NULL) {
                gam_poll_flowoff_node(node);
            }
        }
    }
    in_poll_callback = 0;
    return (TRUE);
}

static void
prune_tree(GamNode * node)
{
    /* don't prune the root */
    if (gam_node_parent(node) == NULL)
        return;

    if (!gam_tree_has_children(tree, node) &&
        !gam_node_get_subscriptions(node)) {
        GamNode *parent;

        GAM_DEBUG(DEBUG_INFO,
                  "prune_tree: node %s\n", gam_node_get_path(node));

        parent = gam_node_parent(node);
        unregister_node(node);
        gam_tree_remove(tree, node);
        prune_tree(parent);
    }
}


static gboolean
gam_poll_scan_all_callback(gpointer data)
{
    int idx;
    GamNode *node;

    static int in_poll_callback = 0;

    if (in_poll_callback)
        return (TRUE);

    in_poll_callback++;

    if (new_subs != NULL)
	gam_poll_consume_subscriptions ();

    current_time = time(NULL);
    for (idx = 0;; idx++) {

        /*
         * do not simply walk the list as it may be modified in the callback
         */
        node = (GamNode *) g_list_nth_data(all_resources, idx);

        if (node == NULL) {
            break;
        }

        gam_poll_scan_directory_internal(node);
    }

    in_poll_callback = 0;
    return (TRUE);
}

/**
 * Initializes the polling system.  This must be called before
 * any other functions in this module.
 *
 * @param start_scan_thread TRUE if a separate scanning thread should be
 * started, FALSE otherwise.
 * @returns TRUE if initialization succeeded, FALSE otherwise
 */
gboolean
gam_poll_init_full(gboolean start_scan_thread)
{
    /* already started */
    if ((poll_mode == 2) && (start_scan_thread))
        return (TRUE);
    if ((poll_mode == 1) && (!start_scan_thread))
        return (TRUE);
    /* not started as expected */
    if (poll_mode != 0)
        return(FALSE);

    if (!start_scan_thread) {
        g_timeout_add(DEFAULT_POLL_TIMEOUT * 1000, gam_poll_scan_callback, NULL);
        poll_mode = 1;
    } else {
        g_timeout_add(DEFAULT_POLL_TIMEOUT * 1000, gam_poll_scan_all_callback, NULL);
        poll_mode = 2;
    }
    tree = gam_tree_new();

    gam_backend_add_subscription = gam_poll_add_subscription;
    gam_backend_remove_subscription = gam_poll_remove_subscription;
    gam_backend_remove_all_for = gam_poll_remove_all_for;

    GAM_DEBUG(DEBUG_INFO, "Initialized Poll\n");
    return TRUE;
}

/**
 * Initializes the polling system.  This must be called before
 * any other functions in this module.
 *
 * This function simply calls #gam_poll_init_full (TRUE)
 *
 * @returns TRUE if initialization succeeded, FALSE otherwise
 */
gboolean
gam_poll_init(void)
{
    return gam_poll_init_full(TRUE);
}

/**
 * Adds a subscription to be polled.
 *
 * @param sub a #GamSubscription to be polled
 * @returns TRUE if adding the subscription succeeded, FALSE otherwise
 */
gboolean
gam_poll_add_subscription(GamSubscription * sub)
{
    const char *path;
    gboolean is_dir;

    if (g_list_find(new_subs, sub))
        return FALSE;

    path = gam_subscription_get_path(sub);
    is_dir = gam_subscription_is_dir(sub);

    gam_listener_add_subscription(gam_subscription_get_listener(sub), sub);

    new_subs = g_list_prepend(new_subs, sub);

    GAM_DEBUG(DEBUG_INFO, "Poll: added subscription\n");
    return TRUE;
}

/**
 * gam_poll_remove_subscription_real:
 * @sub: a subscription
 *
 * Implements the removal of a subscription, including
 * trimming the tree and deactivating the kernel back-end if needed.
 */
static void
gam_poll_remove_subscription_real(GamSubscription * sub)
{
    GamNode *node;

    node = gam_tree_get_at_path(tree, gam_subscription_get_path(sub));

    if (node != NULL) {
        if (!gam_node_is_dir(node)) {
            GAM_DEBUG(DEBUG_INFO, "Removing node sub: %s\n",
                      gam_subscription_get_path(sub));
            node_remove_subscription(node, sub);

            if (!gam_node_get_subscriptions(node)) {
                GamNode *parent;

                unregister_node (node);
                if (gam_tree_has_children(tree, node)) {
                    fprintf(stderr,
                            "node %s is not dir but has children\n",
                            gam_node_get_path(node));
                } else {
                    parent = gam_node_parent(node);
                    if ((parent != NULL) &&
                        (!gam_node_has_dir_subscriptions(parent))) {
                        gam_tree_remove(tree, node);

                        prune_tree(parent);
                    }
                }
            }
        } else {
            GAM_DEBUG(DEBUG_INFO, "Removing directory sub: %s\n",
                      gam_subscription_get_path(sub));
            if (remove_directory_subscription(node, sub)) {
                GamNode *parent;

                unregister_node (node);
                parent = gam_node_parent(node);
                if (!gam_tree_has_children(tree, node)) {
                    gam_tree_remove(tree, node);
                }

                prune_tree(parent);
            }
        }
    }

    gam_subscription_free(sub);
}

/**
 * Removes a subscription which was being polled.
 *
 * @param sub a #GamSubscription to remove
 * @returns TRUE if removing the subscription succeeded, FALSE otherwise
 */
gboolean
gam_poll_remove_subscription(GamSubscription * sub)
{
    GamNode *node;

    /*
     * make sure the subscription still isn't in the new subscription queue
     */
    if (g_list_find(new_subs, sub)) {
        GAM_DEBUG(DEBUG_INFO, "new subscription is removed\n");
        new_subs = g_list_remove_all(new_subs, sub);
	return TRUE;
    }

    node = gam_tree_get_at_path(tree, gam_subscription_get_path(sub));
    if (node == NULL) {
        /* free directly */
        gam_subscription_free(sub);
        return TRUE;
    }

    gam_subscription_cancel(sub);

    GAM_DEBUG(DEBUG_INFO, "Tree has %d nodes\n", gam_tree_get_size(tree));
    gam_poll_remove_subscription_real(sub);
    GAM_DEBUG(DEBUG_INFO, "Tree has %d nodes\n", gam_tree_get_size(tree));

    GAM_DEBUG(DEBUG_INFO, "Poll: removed subscription\n");
    return TRUE;
}

/**
 * Stop polling all subscriptions for a given #GamListener.
 *
 * @param listener a #GamListener
 * @returns TRUE if removing the subscriptions succeeded, FALSE otherwise
 */
gboolean
gam_poll_remove_all_for(GamListener * listener)
{
    GList *subs, *l = NULL;

    subs = gam_listener_get_subscriptions(listener);

    for (l = subs; l; l = l->next) {
        GamSubscription *sub = l->data;

        g_assert(sub != NULL);

        gam_poll_remove_subscription(sub);
    }

    if (subs) {
        g_list_free(subs);
        return TRUE;
    } else
        return FALSE;
}

/**
 * Scans a directory for changes, and emits events if needed.
 *
 * @param path the path to the directory to be scanned
 */
void
gam_poll_scan_directory(const char *path)
{
    GamNode *node;

    GAM_DEBUG(DEBUG_INFO, "Poll: directory scanning %s\n", path);

    current_time = time(NULL);
    node = gam_tree_get_at_path(tree, path);
    if (node == NULL)
        node = gam_tree_add_at_path(tree, path, TRUE);
    if (node == NULL) {
        gam_error(DEBUG_INFO, "gam_tree_add_at_path(%s) returned NULL\n",
                  path);
        return;
    }

    gam_poll_scan_directory_internal(node);
    GAM_DEBUG(DEBUG_INFO, "Poll: scanning %s done\n", path);
}

/**
 * First dir scanning on a new subscription, generates the Exists EndExists
 * events.
 */
static void
gam_poll_first_scan_dir(GamSubscription * sub, GamNode * dir_node,
                        const char *dpath)
{
    GDir *dir;
    char *path;
    GList *subs;
    int with_exists = 1;
    const char *name;
    GamNode *node;

    GAM_DEBUG(DEBUG_INFO, "Looking for existing files in: %s...\n", dpath);

    if (gam_subscription_has_option(sub, GAM_OPT_NOEXISTS)) {
        with_exists = 0;
        GAM_DEBUG(DEBUG_INFO, "   Exists not wanted\n");
    }

    subs = g_list_prepend(NULL, sub);

    if (!g_file_test(dpath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_DIR)) {
        GAM_DEBUG(DEBUG_INFO, "Monitoring missing dir: %s\n", dpath);

        gam_server_emit_event(dpath, 1, GAMIN_EVENT_DELETED, subs, 1);

        stat(dir_node->path, &(dir_node->sbuf));
        dir_node->lasttime = current_time;

        if (g_file_test(dpath, G_FILE_TEST_EXISTS)) {
            dir_node->pflags = MON_WRONG_TYPE;
            dir_node->is_dir = 0;
        } else {
            dir_node->pflags = MON_MISSING;
            gam_poll_add_missing(dir_node);
        }
        goto done;
    }

    if (dir_node->lasttime == 0)
	poll_file(dir_node);

    if (with_exists)
        gam_server_emit_event(dpath, 1, GAMIN_EVENT_EXISTS, subs, 1);


    dir = g_dir_open(dpath, 0, NULL);

    if (dir == NULL) {
        goto done;
    }

    while ((name = g_dir_read_name(dir)) != NULL) {
        path = g_build_filename(dpath, name, NULL);

        node = gam_tree_get_at_path(tree, path);

        if (!node) {
            GAM_DEBUG(DEBUG_INFO, "Unregistered node %s\n", path);
            if (!g_file_test(path, G_FILE_TEST_IS_DIR)) {
                node = gam_node_new(path, NULL, FALSE);
            } else {
                node = gam_node_new(path, NULL, TRUE);
            }
            stat(node->path, &(node->sbuf));
            gam_node_set_is_dir(node, (S_ISDIR(node->sbuf.st_mode) != 0));
            if (gam_exclude_check(path) || gam_fs_get_mon_type(path) != GFS_MT_KERNEL)
                node->pflags |= MON_NOKERNEL;
            node->lasttime = current_time;
            gam_tree_add(tree, dir_node, node);
        }
        if (with_exists)
            gam_server_emit_event(name, 1, GAMIN_EVENT_EXISTS, subs, 1);

        g_free(path);
    }

    g_dir_close(dir);

  done:
    if (with_exists)
        gam_server_emit_event(dpath, 1, GAMIN_EVENT_ENDEXISTS, subs, 1);

    g_list_free(subs);

    GAM_DEBUG(DEBUG_INFO, "Done scanning %s\n", dpath);
}

/**
 * Commits all pending added/removed subscriptions.  For new subscriptions,
 * this includes scanning directories.
 *
 */
void
gam_poll_consume_subscriptions(void)
{
    GList *subs, *l;

    /* check for new dir subs which need special handling
     * (specifically, sending them the EXIST event)
     */
    current_time = time(NULL);
    if (new_subs != NULL) {
        /* we don't want to block the main loop */
        subs = new_subs;
        new_subs = NULL;

        GAM_DEBUG(DEBUG_INFO,
                  "%d new subscriptions.\n", g_list_length(subs));

        for (l = subs; l; l = l->next) {
            GamSubscription *sub = l->data;
            GamNode *node;
            int node_is_dir;

            const char *path = gam_subscription_get_path(sub);

            node = gam_tree_get_at_path(tree, path);
            if (!node) {
                node = gam_tree_add_at_path(tree, path,
                                            gam_subscription_is_dir(sub));
            }

            if (node_add_subscription(node, sub) < 0) {
                gam_error(DEBUG_INFO,
                          "Failed to add subscription for: %s\n", path);
                return;
            }

            node_is_dir = gam_node_is_dir(node);
            if (node_is_dir) {
                gam_poll_first_scan_dir(sub, node, path);
            } else {
                GaminEventType event;

                event = poll_file(node);
                GAM_DEBUG(DEBUG_INFO,
                          "New file subscription: %s event %d\n", path,
                          event);
                if ((event == 0) || (event == GAMIN_EVENT_EXISTS)
                    || (event == GAMIN_EVENT_CHANGED)
                    || (event == GAMIN_EVENT_CREATED)) {
		    if (gam_subscription_is_dir(sub)) {
		        /* we are watching a file but requested a directory */
			gam_server_emit_one_event(path, node_is_dir,
						  GAMIN_EVENT_DELETED, sub, 0);
		    } else {
			gam_server_emit_one_event(path, node_is_dir,
						  GAMIN_EVENT_EXISTS, sub, 0);
		    }
                } else if (event != 0) {
                    gam_server_emit_one_event(path, node_is_dir,
                                              GAMIN_EVENT_DELETED, sub, 0);
                }
                gam_server_emit_one_event(path, node_is_dir,
                                          GAMIN_EVENT_ENDEXISTS, sub, 0);
            }
            if ((node->pflags & MON_MISSING) ||
		(node->pflags & MON_NOKERNEL)) {
                gam_poll_add_missing(node);
            }

	    if (!node_is_dir) {
                char *parent;
                parent = g_path_get_dirname(path);
                node = gam_tree_get_at_path(tree, parent);
                if (!node) {
                    node = gam_tree_add_at_path(tree, parent,
                                                gam_subscription_is_dir
                                                (sub));
                }
                g_free(parent);
	    }
            if (g_list_find(all_resources, node) == NULL)
                all_resources = g_list_prepend(all_resources, node);
        }

        g_list_free(subs);
    }
}


/**
 * gam_poll_set_kernel_handler:
 * @d_handler: function to be called to register directories kernel monitoring
 * @f_handler: function to be called to register file kernel monitoring
 * @type: the type of handler being used
 *
 * Sets the function to be called when fiels and directories loses or gains
 * subscriptions. It also allows to discriminate the polling code based on
 * the kind of backend being used, unfortunately needed for dnotify.
 */
void
gam_poll_set_kernel_handler(GamPollHandler d_handler,
		GamPollHandler f_handler, pollHandlerKernel type) {
    dir_handler = d_handler;
    file_handler = f_handler;
    type_khandler = type;
}

/** @} */
