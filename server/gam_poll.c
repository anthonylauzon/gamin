/* Gamin
 * Copyright (C) 2003 James Willcox, Corey Bowers
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

typedef struct {
    gboolean exists;
    char *path;
    struct stat sbuf;
} GamPollData;

static GamTree *tree = NULL;

static GList *new_subs = NULL;

G_LOCK_DEFINE_STATIC(new_subs);

static GList *removed_subs = NULL;

G_LOCK_DEFINE_STATIC(removed_subs);

static GList *missing_resources = NULL;
										G_LOCK_DEFINE_STATIC(missing_resources);

static GamPollHandler dir_handler = NULL;
static GamPollHandler file_handler = NULL;

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

    data->exists = TRUE;

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
                if (data && data->exists)
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

    data = gam_node_get_data(node);
    if (data == NULL) {
        char real[PATH_MAX];

        realpath(gam_node_get_path(node), real);
        data = gam_poll_data_new(real);

        gam_node_set_data(node, data,
                          (GDestroyNotify) gam_poll_data_destroy);

        stat_ret = stat(data->path, &sbuf);
        data->exists = (stat_ret == 0);
        data->sbuf = sbuf;

        if (data->exists)
            return 0;
        else
            return GAMIN_EVENT_DELETED;
    }

    event = 0;

    if (stat(data->path, &sbuf) != 0) {
        if (errno == ENOENT && data->exists) {
            /* deleted */
            data->exists = FALSE;
            event = GAMIN_EVENT_DELETED;
        }
    } else if (!data->exists) {
        /* created */
        data->exists = TRUE;
        event = GAMIN_EVENT_CREATED;
    } else if ((data->sbuf.st_mtime != sbuf.st_mtime) ||
               (data->sbuf.st_ctime != sbuf.st_ctime)) {
        event = GAMIN_EVENT_CHANGED;
    }

    data->sbuf = sbuf;

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
    const char *name;
    char *path;
    GamNode *node;
    GaminEventType event = 0, fevent;
    GList *dir_exist_subs = NULL;
    GList *children, *l;
    unsigned int i, exists = 0;

    g_return_if_fail(dir_node != NULL);

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

    dir = g_dir_open(gam_node_get_path(dir_node), 0, NULL);

    if (dir == NULL)
        goto scan_files;

    exists = 1;

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
            gam_server_emit_event(gam_node_get_path(dir_node),
                                  GAMIN_EVENT_EXISTS, exist_subs);
        else
            gam_server_emit_event(gam_node_get_path(dir_node),
                                  GAMIN_EVENT_DELETED, exist_subs);
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

	    if (data && data->exists)
		gam_server_emit_event(gam_node_get_path(node),
				      GAMIN_EVENT_EXISTS, exist_subs);

        }
    }

    if (scan_for_new) {
        gam_server_emit_event(gam_node_get_path(dir_node),
                              GAMIN_EVENT_ENDEXISTS, exist_subs);
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

static gpointer
gam_poll_scan_loop(gpointer data)
{
    GList *dirs, *l;

    gam_debug(DEBUG_INFO, "Poll: entering gam_poll_scan_loop\n");
    for (;;) {
        g_usleep(DEFAULT_POLL_TIMEOUT * G_USEC_PER_SEC);

        gam_connections_check();

        gam_poll_consume_subscriptions();

        dirs = gam_tree_get_directories(tree, NULL);
        for (l = dirs; l; l = l->next) {
            GamNode *node = (GamNode *) l->data;

            gam_poll_scan_directory_internal(node, NULL, TRUE);
        }

        g_list_free(dirs);
    }
}

static void
prune_tree(GamNode * node)
{
    /* don't prune the root */
    if (gam_node_parent(node) == NULL)
        return;

    /*
     * g_message ("Prune: %s has children? %s - subs? %s",
     * gam_node_get_path (node),
     * gam_tree_has_children (tree, node) ? "TRUE" : "FALSE",
     * gam_node_get_subscriptions (node) ? "TRUE" : "FALSE");
     */

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
    G_LOCK(missing_resources);
    missing_resources = g_list_prepend(missing_resources, node);
    G_UNLOCK(missing_resources);

}

/**
 * gam_poll_remove_missing:
 * @node: a missing node
 *
 * Remove a missing node from the list.
 */
void
gam_poll_remove_missing(GamNode *node) {
    G_LOCK(missing_resources);
    missing_resources = g_list_remove_all(missing_resources, node);
    G_UNLOCK(missing_resources);
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
    tree = gam_tree_new();

#ifdef WITH_TREADING
    if (start_scan_thread)
        g_thread_create(gam_poll_scan_loop, NULL, TRUE, NULL);
#endif

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
    /*
     * node = gam_tree_get_at_path (tree, gam_subscription_get_path (sub));
     * if (!node) {
     * node = gam_tree_add_at_path (tree,
     * gam_subscription_get_path (sub),
     * gam_subscription_is_dir (sub));
     * 
     * if (dir_handler &&
     * gam_subscription_is_dir (sub)) {
     * 
     * (*dir_handler) (gam_node_get_path (node), TRUE);
     * 
     * } else if (file_handler &&
     * !gam_subscription_is_dir (sub)) {
     * 
     * (*file_handler) (gam_node_get_path (node), TRUE);
     * }
     * 
     * } else if (gam_subscription_is_dir (sub) &&
     * gam_subscription_is_recursive (sub)) {
     * GList *dirs, *l;
     * 
     * dirs = gam_tree_get_directories (tree, node);
     * 
     * for (l = dirs; l; l = l->next) {
     * GamNode *child = l->data;
     * 
     * gam_node_add_subscription (child, sub);
     * }
     * 
     * g_list_free (dirs);
     * }
     * 
     * gam_node_add_subscription (node, sub);
     */


    /*
     * if (gam_subscription_is_dir (sub)) {
     * G_LOCK (new_subs);
     * new_subs = g_list_prepend (new_subs, sub);
     * G_UNLOCK (new_subs);
     * }
     */

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

/*
GamSubscription *
gam_poll_get_subscription (GamListener *listener,
			  const char *path)
{
	GamNode *node;
	GList *l;

	node = gam_tree_get_at_path (tree, path);
	if (!node)
		return NULL;

	for (l = gam_node_get_subscriptions (node); l; l = l->next) {
		GamSubscription *sub = l->data;

		if (gam_subscription_get_listener (sub) == listener)
			return sub;
	}

	return NULL;
}
*/

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

    gam_debug(DEBUG_INFO, "Poll: scanning %s\n", path);
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

            node = gam_tree_get_at_path(tree,
                                        gam_subscription_get_path(sub));
            if (!node) {
                node = gam_tree_add_at_path(tree,
                                            gam_subscription_get_path(sub),
                                            gam_subscription_is_dir(sub));
            }

            node_add_subscription(node, sub);

            if (gam_node_is_dir(node)) {
                gam_debug(DEBUG_INFO,
                          "Looking for existing files in: %s...\n",
                          gam_node_get_path(node));

                gam_poll_scan_directory_internal(node, subs, TRUE);

                gam_debug(DEBUG_INFO, "Done scanning %s\n",
                          gam_node_get_path(node));
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

			parent = gam_node_parent(node);
			gam_tree_remove(tree, node);

			prune_tree(parent);
		    }
		} else {
		    if (remove_directory_subscription(node, sub)) {
			GamNode *parent;

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
