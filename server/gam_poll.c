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
#include <glib.h>
#include "gam_error.h"
#include "gam_tree.h"
#include "gam_poll.h"
#include "gam_event.h"
#include "gam_server.h"
#include "gam_event.h"

#define DEFAULT_POLL_TIMEOUT 3

#define FLAG_NEW_NODE 1 << 5


/*
 * Special monitoring modes
 */
#define MON_MISSING	1 << 0	/* The resource is missing */
#define MON_NOKERNEL	1 << 1  /* file(system) not monitored by the kernel */
#define MON_BUSY	1 << 2  /* Too busy to be monitored by the kernel */

typedef struct {
    struct stat sbuf;		/* The stat() informations in last check */
    char *path;			/* The file path */
    int flags;			/* A combination of MON_xxx flags */
    time_t lasttime;		/* Epoch of last time checking was done */
    int checks;			/* the number of checks in that Epoch */
} GamPollData;

static GamTree *tree = NULL;

static GList *new_subs = NULL;

G_LOCK_DEFINE_STATIC(new_subs);

static GList *removed_subs = NULL;

G_LOCK_DEFINE_STATIC(removed_subs);

static GList *missing_resources = NULL;

static GamPollHandler dir_handler = NULL;
static GamPollHandler file_handler = NULL;

static int poll_mode = 0;

static time_t current_time;	/* a cache for time() informations */

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

static void
node_add_subscription(GamNode * node, GamSubscription * sub)
{
    gam_node_add_subscription(node, sub);

    if (gam_node_is_dir(node))
        trigger_dir_handler(gam_node_get_path(node), TRUE);
    else
        trigger_file_handler(gam_node_get_path(node), TRUE);

}

static void
node_remove_subscription(GamNode * node, GamSubscription * sub)
{
    gam_node_remove_subscription(node, sub);

    if (gam_node_is_dir(node))
        trigger_dir_handler(gam_node_get_path(node), FALSE);
    else
        trigger_file_handler(gam_node_get_path(node), FALSE);
}

static GamPollData *
gam_poll_data_new(const char *path)
{
    GamPollData *data;

    data = g_new0(GamPollData, 1);
    data->path = g_strdup(path);

    data->flags = 0;
    data->lasttime = current_time;
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

    /* we only emit CREATED, DELETED and EXISTS for directories */
    if (gam_node_is_dir(node) &&
        !(event == GAMIN_EVENT_CREATED ||
          event == GAMIN_EVENT_DELETED || event == GAMIN_EVENT_EXISTS))
        return;

    gam_debug(DEBUG_INFO, "Poll: emit events for %s\n",
              gam_node_get_path(node));
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

            if (g_list_find(exist_subs, sub)) {
                if ((data) && (!(data->flags & MON_MISSING)))
                    new_event = GAMIN_EVENT_EXISTS;
                else
                    continue;
            }

            gam_server_emit_event(gam_node_get_path(node),
                                  new_event, g_list_append(NULL, sub));
        }
    } else {
        gam_server_emit_event(gam_node_get_path(node), event, subs);
    }

    g_list_free(subs);
}

static void
gam_poll_data_destroy(GamPollData * data)
{
    g_free(data->path);
    g_free(data);
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
    gam_debug(DEBUG_INFO, "Poll: poll_file for %s called\n", path);

    data = gam_node_get_data(node);
    if (data == NULL) {
        char real[PATH_MAX];

        gam_debug(DEBUG_INFO, "Poll: poll_file : new\n");
        realpath(gam_node_get_path(node), real);
        data = gam_poll_data_new(real);

        gam_node_set_data(node, data,
                          (GDestroyNotify) gam_poll_data_destroy);

        stat_ret = stat(data->path, &sbuf);
	if (stat_ret != 0)
	    data->flags |= MON_MISSING;
        data->sbuf = sbuf;

        if (stat_ret == 0)
            return 0;
        else
            return GAMIN_EVENT_DELETED;
    }
    gam_debug(DEBUG_INFO, " at %d delta %d : %d\n", current_time,
              current_time - data->lasttime, data->checks);

    event = 0;

    if (stat(data->path, &sbuf) != 0) {
        if ((errno == ENOENT) && (!(data->flags & MON_MISSING))) {
            /* deleted */
            data->flags = MON_MISSING;
            event = GAMIN_EVENT_DELETED;
	    if (gam_node_get_subscriptions(node) != NULL) {
	        gam_poll_add_missing(node);
	    }
        }
    } else if (data->flags & MON_MISSING) {
        /* created */
        data->flags &= ~MON_MISSING;
        event = GAMIN_EVENT_CREATED;
#ifdef linux
    } else if ((data->sbuf.st_mtim.tv_sec != sbuf.st_mtim.tv_sec) ||
               (data->sbuf.st_mtim.tv_nsec != sbuf.st_mtim.tv_nsec) ||
               (data->sbuf.st_size != sbuf.st_size) ||
               (data->sbuf.st_ctim.tv_sec != sbuf.st_ctim.tv_sec) ||
               (data->sbuf.st_ctim.tv_nsec != sbuf.st_ctim.tv_nsec)) {
        event = GAMIN_EVENT_CHANGED;
#else
    } else if ((data->sbuf.st_mtime != sbuf.st_mtime) ||
               (data->sbuf.st_size != sbuf.st_size) ||
               (data->sbuf.st_ctime != sbuf.st_ctime)) {
        event = GAMIN_EVENT_CHANGED;
#endif
    } else {
	gam_debug(DEBUG_INFO, "Poll: poll_file %s unchanged\n", path);
	gam_debug(DEBUG_INFO, "%d %d : %d %d\n", data->sbuf.st_mtim.tv_sec,
	          data->sbuf.st_mtim.tv_nsec, sbuf.st_mtim.tv_sec,
		  sbuf.st_mtim.tv_nsec);
    }

    data->sbuf = sbuf;

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
#if 1
	    fprintf(stderr, "switching %s back to polling\n", path);
#endif
	    data->flags |= MON_BUSY;
	    data->checks = 0;
	    gam_poll_add_missing(node);
	    if (gam_node_is_dir(node))
		trigger_dir_handler(gam_node_get_path(node), FALSE);
	    else
		trigger_file_handler(gam_node_get_path(node), FALSE);
	}
    }

    if ((event == 0) && (data->flags & MON_BUSY) && (data->checks > 10)) {
#if 1
	fprintf(stderr, "switching %s back to kernel monitoring\n", path);
#endif
	data->flags &= ~MON_BUSY;
	data->checks = 0;
	gam_poll_remove_missing(node);
	if (gam_node_is_dir(node))
	    trigger_dir_handler(gam_node_get_path(node), TRUE);
	else
	    trigger_file_handler(gam_node_get_path(node), TRUE);
    }

    return event;
}

static GList *
list_intersection(GList * a, GList * b)
{
    GList *ret, *l;

    ret = NULL;
    for (l = a; l; l = l->next) {
        if (g_list_find(b, l->data))
            ret = g_list_prepend(ret, l->data);
    }

    return ret;
}

static void
gam_poll_scan_directory_internal(GamNode * dir_node, GList * exist_subs,
                                 gboolean scan_for_new)
{
    GDir *dir;
    const char *name, *dpath;
    char *path;
    GamNode *node;
    GaminEventType event = 0, fevent;
    GList *dir_exist_subs = NULL;
    GList *children, *l;
    unsigned int exists = 0;

    g_return_if_fail(dir_node != NULL);

    dpath = gam_node_get_path(dir_node);

    g_return_if_fail(dpath != NULL);

    if (!scan_for_new)
        goto scan_files;

    if (!gam_node_get_subscriptions(dir_node))
        goto scan_files;

    event = poll_file(dir_node);
    dir_exist_subs =
        list_intersection(exist_subs,
                          gam_node_get_subscriptions(dir_node));

    if (event == 0 && !dir_exist_subs)
        goto scan_files;

    gam_poll_emit_event(dir_node, event, dir_exist_subs);

    dir = g_dir_open(dpath, 0, NULL);

    if (dir == NULL)
        goto scan_files;

    exists = 1;

    gam_debug(DEBUG_INFO, "Poll: scanning directory %s\n", dpath);
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


    if (scan_for_new) {
        if (exists)
            gam_server_emit_event(dpath, GAMIN_EVENT_EXISTS, exist_subs);
        else {
            gam_server_emit_event(dpath, GAMIN_EVENT_DELETED, exist_subs);
	}
    }
    children = gam_tree_get_children(tree, dir_node);
    for (l = children; l; l = l->next) {
        node = (GamNode *) l->data;

        fevent = poll_file(node);

        if (gam_node_is_dir(node) &&
            gam_node_has_flag(node, FLAG_NEW_NODE) &&
            gam_node_get_subscriptions(node)) {
            gam_node_unset_flag(node, FLAG_NEW_NODE);
            gam_poll_scan_directory_internal(node, exist_subs,
                                             scan_for_new);
        } else if (gam_node_has_flag(node, FLAG_NEW_NODE)) {
            gam_node_unset_flag(node, FLAG_NEW_NODE);
            fevent = GAMIN_EVENT_CREATED;
        }

        if (fevent != 0) {
            gam_poll_emit_event(node, fevent, exist_subs);
        } else {
	    GamPollData *data;

            /* just send the EXIST events if the node exists */
	    data = gam_node_get_data(node);

	    if ((data) && (!(data->flags & MON_MISSING)))
		gam_server_emit_event(gam_node_get_path(node),
				      GAMIN_EVENT_EXISTS, exist_subs);

        }
    }

    if (scan_for_new) {
        gam_server_emit_event(dpath, GAMIN_EVENT_ENDEXISTS, exist_subs);
    }

    g_list_free(children);
    g_list_free(dir_exist_subs);
}

static gboolean
remove_directory_subscription(GamNode * node, GamSubscription * sub)
{
    GList *children, *l;
    gboolean remove_dir;

    node_remove_subscription(node, sub);

    remove_dir = gam_node_get_subscriptions(node) == NULL;

    children = gam_tree_get_children(tree, node);
    for (l = children; l; l = l->next) {
        GamNode *child = (GamNode *) l->data;

        if (gam_node_is_dir(child)) {
            if (remove_directory_subscription(child, sub) && remove_dir) {
                gam_tree_remove(tree, child);
            } else {
                remove_dir = FALSE;
            }
        } else {
            node_remove_subscription(child, sub);

            if (!gam_node_get_subscriptions(child) && remove_dir) {
                gam_tree_remove(tree, child);
            } else {
                remove_dir = FALSE;
            }
        }
    }

    g_list_free(children);

    return remove_dir;
}

static gboolean
gam_poll_scan_callback(gpointer data) {
    int idx;

    static int in_poll_callback = 0;

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
	    break;
	} 
	data = gam_node_get_data(node);
	if (data == NULL) {
	    break;
	} 

	gam_poll_scan_directory_internal(node, NULL, TRUE);
	/*
	 * if the resource exists again and is not in a special monitoring
	 * mode then switch back to dnotify for monitoring.
	 */
	if (data->flags == 0) {
	    gam_poll_remove_missing(node);
	    if (gam_node_is_dir(node))
		trigger_dir_handler(gam_node_get_path(node), TRUE);
	    else
		trigger_file_handler(gam_node_get_path(node), TRUE);
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

        parent = gam_node_parent(node);
        gam_tree_remove(tree, node);
        prune_tree(parent);
    }
}



/**
 * @defgroup Polling Polling Backend
 * @ingroup Backends
 * @brief Polling backend API
 *
 * This is the default backend used in Marmot.  It basically just calls
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
#if 1
    fprintf(stderr, "Adding %s to polling\n", gam_node_get_path(node));
#endif
    gam_debug(DEBUG_INFO, "Poll adding missing node %s\n",
              gam_node_get_path(node));
    missing_resources = g_list_prepend(missing_resources, node);
}

/**
 * gam_poll_remove_missing:
 * @node: a missing node
 *
 * Remove a missing node from the list.
 */
void
gam_poll_remove_missing(GamNode *node) {
#if 1
    fprintf(stderr, "Removing %s from polling\n", gam_node_get_path(node));
#endif
    gam_debug(DEBUG_INFO, "Poll removing missing node %s\n",
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
	poll_mode = 2;
    }
    tree = gam_tree_new();

    gam_backend_add_subscription = gam_poll_add_subscription;
    gam_backend_remove_subscription = gam_poll_remove_subscription;
    gam_backend_remove_all_for = gam_poll_remove_all_for;

    gam_debug(DEBUG_INFO, "Initialized Poll\n");
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

    path = gam_subscription_get_path(sub);
    is_dir = gam_subscription_is_dir(sub);

/***
    node = gam_tree_get_at_path(tree, path);

    if (!node) {
        node = gam_tree_add_at_path(tree, path, is_dir);
    }
 ***/

    gam_listener_add_subscription(gam_subscription_get_listener(sub), sub);

    G_LOCK(new_subs);
    new_subs = g_list_prepend(new_subs, sub);
    G_UNLOCK(new_subs);

    gam_debug(DEBUG_INFO, "Poll: added subscription\n");
    return TRUE;
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
    G_LOCK(new_subs);
    if (g_list_find(new_subs, sub)) {
        gam_debug(DEBUG_INFO, "new subscriptions is removed\n");
        new_subs = g_list_remove_all(new_subs, sub);
    }
    G_UNLOCK(new_subs);

    node = gam_tree_get_at_path(tree, gam_subscription_get_path(sub));
    if (node == NULL) {
        /* free directly */
        gam_subscription_free(sub);
        return TRUE;
    }

    gam_subscription_cancel(sub);
    gam_listener_remove_subscription(gam_subscription_get_listener(sub),
                                     sub);

    G_LOCK(removed_subs);
    removed_subs = g_list_prepend(removed_subs, sub);
    G_UNLOCK(removed_subs);

    gam_debug(DEBUG_INFO, "Poll: removed subscription\n");
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
 * @param exist_subs a list of type #GamSubscription of new subscriptions
 * which need to be sent the EXIST event.
 */
void
gam_poll_scan_directory(const char *path, GList * exist_subs)
{
    GamNode *node;

    gam_debug(DEBUG_INFO, "Poll: scanning %s: subs %d\n",
              path, exist_subs != NULL);

    current_time = time(NULL);
    node = gam_tree_get_at_path(tree, path);
    if (node == NULL)
        node = gam_tree_add_at_path(tree, path, TRUE);

    gam_poll_scan_directory_internal(node, exist_subs, TRUE);
    gam_debug(DEBUG_INFO, "Poll: scanning %s done\n", path);
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
    G_LOCK(new_subs);
    if (new_subs != NULL) {
        /* we don't want to block the main loop */
        subs = new_subs;
        new_subs = NULL;
        G_UNLOCK(new_subs);

        gam_debug(DEBUG_INFO,
                  "%d new subscriptions.\n", g_list_length(subs));

        for (l = subs; l; l = l->next) {
            GamSubscription *sub = l->data;
            GamNode *node;

	    const char *path = gam_subscription_get_path(sub);

            node = gam_tree_get_at_path(tree, path);
            if (!node) {
                node = gam_tree_add_at_path(tree, path,
                                            gam_subscription_is_dir(sub));
            }

            node_add_subscription(node, sub);

            if (gam_node_is_dir(node)) {
		GamPollData *data;

                gam_debug(DEBUG_INFO,
                          "Looking for existing files in: %s...\n",
                          path);

                gam_poll_scan_directory_internal(node, subs, TRUE);

                gam_debug(DEBUG_INFO, "Done scanning %s\n", path);
		data = gam_node_get_data(node);
		if (data->flags & MON_MISSING)
		    gam_poll_add_missing(node);
            } else {
		GaminEventType event;

                event = poll_file(node);
                gam_debug(DEBUG_INFO,
                          "New file subscription: %s event %d\n", path, event);
		if ((event == 0) || (event == GAMIN_EVENT_EXISTS) ||
		    (event == GAMIN_EVENT_CHANGED) ||
		    (event == GAMIN_EVENT_CREATED)) {
		    gam_server_emit_one_event(path, GAMIN_EVENT_EXISTS, sub);
		} else if (event != 0) {
		    gam_server_emit_one_event(path, GAMIN_EVENT_DELETED, sub);
		    gam_poll_add_missing(node);
		}
		gam_server_emit_one_event(path, GAMIN_EVENT_ENDEXISTS, sub);
	    }
        }

        g_list_free(subs);
    } else {
        G_UNLOCK(new_subs);
    }

    /* check for things that have been removed, and remove them */
    G_LOCK(removed_subs);
    if (removed_subs != NULL) {
        subs = removed_subs;
        removed_subs = NULL;
        G_UNLOCK(removed_subs);

        gam_debug(DEBUG_INFO, "Tree has %d nodes\n",
                  gam_tree_get_size(tree));
        for (l = subs; l; l = l->next) {
            GamSubscription *sub = l->data;
            GamNode *node = gam_tree_get_at_path(tree,
                                                 gam_subscription_get_path
                                                 (sub));

            gam_debug(DEBUG_INFO, "Removing: %s\n",
                      gam_subscription_get_path(sub));
            if (node != NULL) {
		if (!gam_node_is_dir(node)) {
		    node_remove_subscription(node, sub);

		    if (!gam_node_get_subscriptions(node)) {
			GamNode *parent;

			if (missing_resources != NULL) {
			    gam_poll_remove_missing(node);
			}
			parent = gam_node_parent(node);
			gam_tree_remove(tree, node);

			prune_tree(parent);
		    }
		} else {
		    if (remove_directory_subscription(node, sub)) {
			GamNode *parent;

			if (missing_resources != NULL) {
			    gam_poll_remove_missing(node);
			}
			parent = gam_node_parent(node);
			gam_tree_remove(tree, node);

			prune_tree(parent);
		    }
		}
	    }

            gam_subscription_free(sub);
        }
        g_list_free(subs);

        gam_debug(DEBUG_INFO, "Tree has %d nodes\n",
                  gam_tree_get_size(tree));

    } else {
        G_UNLOCK(removed_subs);
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
