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

#include <config.h>
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

#define DEFAULT_POLL_TIMEOUT 3

#define FLAG_NEW_NODE 1 << 5


/*
 * Special monitoring modes
 */
#define MON_MISSING	1 << 0	/* The resource is missing */
#define MON_NOKERNEL	1 << 1  /* file(system) not monitored by the kernel */
#define MON_BUSY	1 << 2  /* Too busy to be monitored by the kernel */
#define MON_WRONG_TYPE	1 << 3  /* Expecting a directory and got a file */

typedef struct {
    struct stat sbuf;		/* The stat() informations in last check */
    char *path;			/* The file path */
    int flags;			/* A combination of MON_xxx flags */
    time_t lasttime;		/* Epoch of last time checking was done */
    int checks;			/* the number of checks in that Epoch */
} GamPollData;

static GamTree *tree = NULL;
static GList *new_subs = NULL;
static GList *missing_resources = NULL;
static GList *all_resources = NULL;
static GamPollHandler dir_handler = NULL;
static GamPollHandler file_handler = NULL;

static int poll_mode = 0;

static time_t current_time = 0;	/* a cache for time() informations */

static int
gam_errno(void) {
    return(errno);
}

static void
trigger_dir_handler(const char *path, gboolean added)
{
    if (dir_handler != NULL)
        (*dir_handler) (path, added);
}

static void
trigger_file_handler(const char *path, gboolean added)
{
    if (file_handler != NULL)
        (*file_handler) (path, added);
}

static int
node_add_subscription(GamNode * node, GamSubscription * sub)
{
    if ((node == NULL) || (sub == NULL))
        return(-1);

    if ((node->path == NULL) || (node->path[0] != '/'))
        return(-1);

    GAM_DEBUG(DEBUG_INFO, "node_add_subscription(%s)\n", node->path);
    gam_node_add_subscription(node, sub);

    if (gam_exclude_check(node->path)) {
	GAM_DEBUG(DEBUG_INFO, "  gam_exclude_check: true\n");
        return(0);
    }

    if (gam_node_is_dir(node))
        trigger_dir_handler(node->path, TRUE);
    else
        trigger_file_handler(node->path, TRUE);

    return(0);
}

static int
node_remove_subscription(GamNode * node, GamSubscription * sub)
{
    const char *path;

    if ((node == NULL) || (sub == NULL))
        return(-1);

    if ((node->path == NULL) || (node->path[0] != '/'))
        return(-1);

    GAM_DEBUG(DEBUG_INFO, "node_remove_subscription(%s)\n", node->path);

    gam_node_remove_subscription(node, sub);

    path = gam_node_get_path(node);
    if (gam_exclude_check(path)) {
	GAM_DEBUG(DEBUG_INFO, "  gam_exclude_check: true\n");
        return(0);
    }

    /* DNotify makes our life miserable here */
    if (gam_subscription_is_dir(sub)) {
	if (gam_node_is_dir(node))
	    trigger_dir_handler(path, FALSE);
	else {
	    char *dir;

	    dir = g_path_get_dirname(path);
	    trigger_file_handler(dir, FALSE);
	    g_free(dir);
	}
    } else {
	if (gam_node_is_dir(node))
	    trigger_dir_handler(path, FALSE);
	else
	    trigger_file_handler(path, FALSE);
    }

    return(0);
}

static GamPollData *
gam_poll_data_new(const char *path)
{
    GamPollData *data;

    if ((path == NULL) || (path[0] != '/'))
        return(NULL);
    data = g_new(GamPollData, 1);
    if (data == NULL)
        return(NULL);
    memset(data, 0, sizeof(GamPollData));
    data->path = g_strdup(path);

    data->flags = 0;
    if (current_time == 0)
        current_time = time(NULL);
    data->lasttime = current_time;
#ifdef ST_MTIM_NSEC
    data->sbuf.st_mtim.tv_sec = current_time;
#endif
    data->sbuf.st_mtime = current_time;
    data->checks = 0;

    return data;
}

static void
gam_poll_emit_event(GamNode * node, GaminEventType event,
                    GList * exist_subs)
{
    GList *l;
    GamNode *parent;
    GamPollData *data;
    GList *subs;
    int is_dir_node = gam_node_is_dir(node);

    GAM_DEBUG(DEBUG_INFO, "Poll: emit events %d for %s\n",
              event, gam_node_get_path(node));
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

    if (exist_subs) {

        data = gam_node_get_data(node);

        for (l = subs; l; l = l->next) {
            GamSubscription *sub = l->data;
            GaminEventType new_event = event;
	    GList *tmp;

            if (g_list_find(exist_subs, sub)) {
                if ((data) && (!(data->flags & MON_MISSING)))
                    new_event = GAMIN_EVENT_EXISTS;
                else
                    continue;
            }

            tmp = g_list_prepend(NULL, sub);
            gam_server_emit_event(gam_node_get_path(node), is_dir_node,
                                  new_event, tmp, 0);
	    g_list_free(tmp);

        }
    } else {
        
        gam_server_emit_event(gam_node_get_path(node), is_dir_node, event,
	                      subs, 0);
    }

    g_list_free(subs);
}

static void
gam_poll_data_destroy(GamPollData * data)
{
    g_free(data->path);
    g_free(data);
}

/**
 * gam_poll_delist_node:
 * @node: the node to delist
 *
 * This function is called when kernel monitoring for a node should
 * be turned off.
 */
static void
gam_poll_delist_node(GamNode * node) {
    GList *subs;

    GAM_DEBUG(DEBUG_INFO, "gam_poll_delist_node %s\n",
              gam_node_get_path(node));
    subs = gam_node_get_subscriptions(node);

    while (subs != NULL) {
	if (gam_node_is_dir(node))
	    trigger_dir_handler(gam_node_get_path(node), FALSE);
	else
	    trigger_file_handler(gam_node_get_path(node), FALSE);
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
gam_poll_relist_node(GamNode * node) {
    GList *subs;

    GAM_DEBUG(DEBUG_INFO, "gam_poll_relist_node %s\n",
              gam_node_get_path(node));
    subs = gam_node_get_subscriptions(node);

    while (subs != NULL) {
	if (gam_node_is_dir(node))
	    trigger_dir_handler(gam_node_get_path(node), TRUE);
	else
	    trigger_file_handler(gam_node_get_path(node), TRUE);
	subs = subs->next;
    }
}


static GaminEventType
poll_file(GamNode * node)
{
    GamPollData *data;
    GaminEventType event;
    struct stat sbuf;
    int stat_ret;
    const char *path;

    path = gam_node_get_path(node);
    GAM_DEBUG(DEBUG_INFO, "Poll: poll_file for %s called\n", path);

    data = gam_node_get_data(node);
    if (data == NULL) {
        char real[PATH_MAX];

        GAM_DEBUG(DEBUG_INFO, "Poll: poll_file : new\n");
        realpath(path, real);
        data = gam_poll_data_new(real);

        gam_node_set_data(node, data,
                          (GDestroyNotify) gam_poll_data_destroy);

        stat_ret = stat(data->path, &sbuf);
	if (stat_ret != 0)
	    data->flags |= MON_MISSING;
	else
	    gam_node_set_is_dir(node, (S_ISDIR(sbuf.st_mode) != 0));
	if (gam_exclude_check(path))
	    data->flags |= MON_NOKERNEL;
        memcpy(&(data->sbuf), &(sbuf), sizeof(sbuf));

        if (stat_ret == 0)
            return 0;
        else
            return GAMIN_EVENT_DELETED;
    }
    GAM_DEBUG(DEBUG_INFO, " at %d delta %d : %d\n", current_time,
              current_time - data->lasttime, data->checks);

    event = 0;

    stat_ret = stat(data->path, &sbuf);
    if (stat_ret != 0) {
        if ((gam_errno() == ENOENT) && (!(data->flags & MON_MISSING))) {
            /* deleted */
            data->flags = MON_MISSING;

	    if (gam_node_get_subscriptions(node) != NULL) {
		gam_poll_delist_node(node);
	        gam_poll_add_missing(node);
	    }
            event = GAMIN_EVENT_DELETED;
        }
    } else if (data->flags & MON_MISSING) {
        /* created */
        data->flags &= ~MON_MISSING;
        event = GAMIN_EVENT_CREATED;
#ifdef ST_MTIM_NSEC
    } else if ((data->sbuf.st_mtim.tv_sec != sbuf.st_mtim.tv_sec) ||
               (data->sbuf.st_mtim.tv_nsec != sbuf.st_mtim.tv_nsec) ||
               (data->sbuf.st_size != sbuf.st_size) ||
               (data->sbuf.st_ctim.tv_sec != sbuf.st_ctim.tv_sec) ||
               (data->sbuf.st_ctim.tv_nsec != sbuf.st_ctim.tv_nsec)) {
        event = GAMIN_EVENT_CHANGED;
    } else {
	GAM_DEBUG(DEBUG_INFO, "Poll: poll_file %s unchanged\n", path);
	GAM_DEBUG(DEBUG_INFO, "%d %d : %d %d\n", data->sbuf.st_mtim.tv_sec,
	          data->sbuf.st_mtim.tv_nsec, sbuf.st_mtim.tv_sec,
		  sbuf.st_mtim.tv_nsec);
#else
    } else if ((data->sbuf.st_mtime != sbuf.st_mtime) ||
               (data->sbuf.st_size != sbuf.st_size) ||
               (data->sbuf.st_ctime != sbuf.st_ctime)) {
        event = GAMIN_EVENT_CHANGED;
	GAM_DEBUG(DEBUG_INFO, "%d : %d\n", data->sbuf.st_mtime,
		  sbuf.st_mtime);
#endif
    }

    /*
     * TODO: handle the case where a file/dir is removed and replaced by 
     *       a dir/file
     */
    if (stat_ret == 0)
	gam_node_set_is_dir(node, (S_ISDIR(sbuf.st_mode) != 0));
    data->sbuf = sbuf;

    /*
     * if kernel monitoring prohibited, stop here
     */
    if (data->flags & MON_NOKERNEL)
        return(event);

    /*
     * load control, switch back to poll on very busy resources
     * and back when no update has happened in 10 seconds
     */
    if (current_time == data->lasttime) {
	if (!(data->flags & MON_BUSY)) {
	    if (data->sbuf.st_mtime == current_time)
		data->checks++;
	}
    } else {
        data->lasttime = current_time;
	if (data->flags & MON_BUSY) {
	    if (event == 0)
		data->checks++;
	} else {
	    data->checks = 0;
	}
    }

    if ((data->checks >= 4) && (!(data->flags & MON_BUSY))) {
	if (gam_node_get_subscriptions(node) != NULL) {
	    GAM_DEBUG(DEBUG_INFO, "switching %s back to polling\n", path);
	    data->flags |= MON_BUSY;
	    data->checks = 0;
	    gam_poll_add_missing(node);
	    gam_poll_delist_node(node);
	}
    }

    if ((event == 0) && (data->flags & MON_BUSY) && (data->checks > 10)) {
	if ((gam_node_get_subscriptions(node) != NULL) &&
	    (!gam_exclude_check(data->path))) {
	    GAM_DEBUG(DEBUG_INFO, "switching %s back to kernel monitoring\n",
	              path);
	    data->flags &= ~MON_BUSY;
	    data->checks = 0;
	    gam_poll_remove_missing(node);
	    gam_poll_relist_node(node);
	}
    }

    return(event);
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
	gam_poll_emit_event(dir_node, event, NULL);

    dir = g_dir_open(dpath, 0, NULL);

    if (dir == NULL) {
	GAM_DEBUG(DEBUG_INFO, "Poll: directory %s missing\n", dpath);
	return;
    }

    exists = 1;

    GAM_DEBUG(DEBUG_INFO, "Poll: scanning directory %s\n", dpath);
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


    is_dir_node = gam_node_is_dir(dir_node);
    children = gam_tree_get_children(tree, dir_node);
    for (l = children; l; l = l->next) {

        node = (GamNode *) l->data;

        fevent = poll_file(node);

        if (gam_node_has_flag(node, FLAG_NEW_NODE)) {
	    if (is_dir_node &&
		gam_node_get_subscriptions(node)) {
		gam_node_unset_flag(node, FLAG_NEW_NODE);
		gam_poll_scan_directory_internal(node);
	    } else {
		gam_node_unset_flag(node, FLAG_NEW_NODE);
		fevent = GAMIN_EVENT_CREATED;
	    }
	}

        if (fevent != 0) {
            gam_poll_emit_event(node, fevent, NULL);
        } else {
	    GamPollData *data;

            /* just send the EXIST events if the node exists */
	    data = gam_node_get_data(node);

	    if ((data) && (!(data->flags & MON_MISSING)))
		gam_server_emit_event(gam_node_get_path(node),
		                      gam_node_is_dir(node),
				      GAMIN_EVENT_EXISTS, NULL, 0);
        }
    }

    g_list_free(children);
}

static gboolean
remove_directory_subscription(GamNode * node, GamSubscription * sub)
{
    GList *children, *l;
    gboolean remove_dir;

    GAM_DEBUG(DEBUG_INFO, "remove_directory_subscription %s\n",
              gam_node_get_path(node));

    node_remove_subscription(node, sub);

    remove_dir = gam_node_get_subscriptions(node) == NULL;

    children = gam_tree_get_children(tree, node);
    for (l = children; l; l = l->next) {
        GamNode *child = (GamNode *) l->data;

	if (!gam_node_get_subscriptions(child) && remove_dir) {
	    if (missing_resources != NULL) {
		    gam_poll_remove_missing (child);
	    }
	    gam_tree_remove(tree, child);
	} else {
	    remove_dir = FALSE;
	}
    }

    g_list_free(children);

    return remove_dir;
}

static gboolean
gam_poll_scan_callback(gpointer data) {
    int idx;
    static int in_poll_callback = 0;

#ifdef VERBOSE_POLL
    GAM_DEBUG(DEBUG_INFO, "gam_poll_scan_callback(): %d, %d items\n",
              in_poll_callback, g_list_length(missing_resources));
#endif
    if (in_poll_callback)
	return(TRUE);

    in_poll_callback++;

    current_time = time(NULL);
    for (idx = 0;;idx++) {
	GamPollData *data;
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
	data = gam_node_get_data(node);
	if (data == NULL) {
#ifdef VERBOSE_POLL
	    GAM_DEBUG(DEBUG_INFO, "  data %d == NULL\n", idx);
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
	    gam_poll_emit_event(node, event, NULL);
	}

	/*
	 * if the resource exists again and is not in a special monitoring
	 * mode then switch back to dnotify for monitoring.
	 */
	if ((data->flags == 0) && (!gam_exclude_check(data->path))) {
	    gam_poll_remove_missing(node);
	    if (gam_node_get_subscriptions(node) != NULL) {
	        gam_poll_relist_node(node);
	    }
	}
    }

    in_poll_callback = 0;
    return(TRUE);
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
		  "prune_tree: node %s\n",
		  gam_node_get_path(node));

        parent = gam_node_parent(node);
        if (missing_resources != NULL) {
		gam_poll_remove_missing(node);
        }
        if (all_resources != NULL) {
                all_resources = g_list_remove (all_resources, node);
        }
        gam_tree_remove(tree, node);
        prune_tree(parent);
    }
}


static gboolean
gam_poll_scan_all_callback(gpointer data) {
    int idx;
    GList *subs, *l;
    GamNode *node;

    static int in_poll_callback = 0;

    if (in_poll_callback)
	return(TRUE);
 
    in_poll_callback++;

    if (new_subs != NULL) {
        /* we don't want to block the main loop */
        subs = new_subs;
        new_subs = NULL;

        GAM_DEBUG(DEBUG_INFO,
                  "%d new subscriptions.\n", g_list_length(subs));

        for (l = subs; l; l = l->next) {
            GamSubscription *sub = l->data;

            const char *path = gam_subscription_get_path(sub);

            node = gam_tree_get_at_path(tree, path);
            if (!node) {
                node = gam_tree_add_at_path(tree, path,
                                            gam_subscription_is_dir(sub));
            }

            if (node_add_subscription(node, sub) < 0) {
                gam_error(DEBUG_INFO,
                          "Failed to add subscription for: %s\n", path);
	    }
    	    if (!gam_node_is_dir(node)) {
		    char *parent;
		    
		    parent = g_path_get_dirname (path);
		    node = gam_tree_get_at_path(tree, parent);
	            if (!node) {
	                node = gam_tree_add_at_path(tree, parent,
                                            gam_subscription_is_dir(sub));
        	    }
		    g_free (parent);
	    }

	      if (g_list_find(all_resources, node) == NULL) {
		all_resources = g_list_prepend (all_resources, node);
	      }
    	}
	g_list_free (subs);
    }

    current_time = time(NULL);
    for (idx = 0;;idx++) {
	
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
    return(TRUE);
}


/**
 * @defgroup Polling Polling Backend
 * @ingroup Backends
 * @brief Polling backend API
 *
 * This is the default backend used in Gamin.  It basically just calls
 * stat() on files/directories every so often to see when things change.  The
 * statting happens in a separate thread, controllable with arguments to
 * #gam_poll_init_full().
 *
 * @{
 */


/**
 * gam_poll_add_missing:
 * @node: a missing node
 *
 * Add a missing node to the list for polling its creation.
 */
void
gam_poll_add_missing(GamNode *node) {
#if 0
    fprintf(stderr, "Adding %s to polling\n", gam_node_get_path(node));
#endif
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
void
gam_poll_remove_missing(GamNode *node) {
#if 0
    fprintf(stderr, "Removing %s from polling\n", gam_node_get_path(node));
#endif
    GAM_DEBUG(DEBUG_INFO, "Poll removing missing node %s\n",
              gam_node_get_path(node));
    missing_resources = g_list_remove_all(missing_resources, node);
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
    if (poll_mode != 0)
        return(FALSE);

    if (!start_scan_thread) {
        g_timeout_add(1000, gam_poll_scan_callback, NULL);
	poll_mode = 1;
    } else {
        g_timeout_add(1000, gam_poll_scan_all_callback, NULL);
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

                if (missing_resources != NULL) {
                    gam_poll_remove_missing(node);
                }
                if (all_resources != NULL) {
                    all_resources = g_list_remove(all_resources, node);
                }
                if (gam_tree_has_children(tree, node)) {
                    fprintf(stderr,
                            "node %s is not dir but has children\n",
                            gam_node_get_path(node));
                } else {
                    parent = gam_node_parent(node);
                    gam_tree_remove(tree, node);

                    prune_tree(parent);
                }
            }
        } else {
            GAM_DEBUG(DEBUG_INFO, "Removing directory sub: %s\n",
                      gam_subscription_get_path(sub));
            if (remove_directory_subscription(node, sub)) {
                GamNode *parent;

                if (missing_resources != NULL) {
                    gam_poll_remove_missing(node);
                }
                if (all_resources != NULL) {
                    all_resources = g_list_remove(all_resources, node);
                }
                parent = gam_node_parent(node);
                gam_tree_remove(tree, node);

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
        GAM_DEBUG(DEBUG_INFO, "new subscriptions is removed\n");
        new_subs = g_list_remove_all(new_subs, sub);
    }

    node = gam_tree_get_at_path(tree, gam_subscription_get_path(sub));
    if (node == NULL) {
        /* free directly */
        gam_subscription_free(sub);
        return TRUE;
    }

    gam_subscription_cancel(sub);
    gam_listener_remove_subscription(gam_subscription_get_listener(sub),
                                     sub);

    GAM_DEBUG(DEBUG_INFO, "Tree has %d nodes\n",
	      gam_tree_get_size(tree));
    gam_poll_remove_subscription_real(sub);
    GAM_DEBUG(DEBUG_INFO, "Tree has %d nodes\n",
	      gam_tree_get_size(tree));

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
	gam_error(DEBUG_INFO, "gam_tree_add_at_path(%s) returned NULL\n", path);
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
gam_poll_first_scan_dir(GamSubscription *sub, GamNode *dir_node,
                        GamPollData *data, const char *dpath)
{
    GDir *dir;
    char *path;
    GList * subs;
    int with_exists = 1;
    const char *name;
    GamNode *node;

    GAM_DEBUG(DEBUG_INFO, "Looking for existing files in: %s...\n", dpath);

    if (gam_subscription_has_option(sub, GAM_OPT_NOEXISTS)) {
        with_exists = 0;
	GAM_DEBUG(DEBUG_INFO, "   Exists not wanted\n");
    }

    subs = g_list_prepend(NULL, sub);

    dir = g_dir_open(dpath, 0, NULL);

    if (dir == NULL) {
	GAM_DEBUG(DEBUG_INFO, "Monitoring missing dir: %s\n", dpath);
	gam_server_emit_event(dpath, 1, GAMIN_EVENT_DELETED, subs, 1);
	node = gam_node_new(dpath, NULL, TRUE);
	if (node == NULL) {
	    gam_error(DEBUG_INFO, "Failed to allocate node for: %s\n", dpath);
	    goto done;
	}
	data = gam_poll_data_new(dpath);
	if (data == NULL) {
	    gam_error(DEBUG_INFO, "Failed to allocate data for: %s\n", dpath);
	    goto done;
	}
	gam_node_add_subscription(node, sub);
	gam_node_set_data(node, data,
			  (GDestroyNotify) gam_poll_data_destroy);
	if (g_file_test(dpath, G_FILE_TEST_EXISTS)) {
	    data->flags = MON_WRONG_TYPE;
	    node->is_dir = 0;
	} else {
	    data->flags = MON_MISSING;
	    gam_poll_add_missing(node);
	}
	goto done;
    } 

    if (with_exists)
	gam_server_emit_event(dpath, 1, GAMIN_EVENT_EXISTS, subs, 1);
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
	    data = gam_poll_data_new(path);
	    if (data != NULL) {
		gam_node_set_data(node, data,
				  (GDestroyNotify) gam_poll_data_destroy);

		stat(data->path, &(data->sbuf));
		gam_node_set_is_dir(node, (S_ISDIR(data->sbuf.st_mode) != 0));
		if (gam_exclude_check(path))
		    data->flags |= MON_NOKERNEL;
	    }
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
            GamPollData *data;
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
                gam_poll_first_scan_dir(sub, node, data, path);
            } else {
                GaminEventType event;

                event = poll_file(node);
                GAM_DEBUG(DEBUG_INFO,
                          "New file subscription: %s event %d\n", path,
                          event);
                if ((event == 0) || (event == GAMIN_EVENT_EXISTS)
                    || (event == GAMIN_EVENT_CHANGED)
                    || (event == GAMIN_EVENT_CREATED)) {
                    gam_server_emit_one_event(path, node_is_dir,
                                              GAMIN_EVENT_EXISTS, sub, 0);
                } else if (event != 0) {
                    gam_server_emit_one_event(path, node_is_dir,
                                              GAMIN_EVENT_DELETED, sub, 0);
                }
                gam_server_emit_one_event(path, node_is_dir,
                                          GAMIN_EVENT_ENDEXISTS, sub, 0);
            }
            data = gam_node_get_data(node);
            if ((data) && ((data->flags & MON_MISSING) ||
                           (data->flags & MON_NOKERNEL))) {
                gam_poll_add_missing(node);
            }
        }

        g_list_free(subs);
    }
}


/**
 * Sets the function to be called when a directory node loses or gains
 * subscriptions.  This is useful for implementing other sorts of backends
 * that want to use portions of this backend.
 *
 * @param handler a #GamPollHandler
 */
void
gam_poll_set_directory_handler(GamPollHandler handler)
{
    dir_handler = handler;
}

/**
 * Sets the function to be called when a file node loses or gains
 * subscriptions.  This is useful for implementing other sorts of backends
 * that want to use portions of this backend.
 *
 * @param handler a #GamPollHandler
 */
void
gam_poll_set_file_handler(GamPollHandler handler)
{
    file_handler = handler;
}

/** @} */
