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
#include <string.h>
#include <glib.h>
#include "gam_event.h"
#include "gam_node.h"

/**
 * @defgroup GamNode GamNode
 * @ingroup Daemon
 * @brief GamNode API.
 *
 * A node represents a single file or directory.
 * 
 * @{
 */

/**
 * Create a new node
 *
 * @param path the path the node will represent
 * @param sub an initial GamSubscription for the node, could be NULL
 * @param is_dir whether the node is a directory or not
 * @returns the new node
 */
GamNode *
gam_node_new(const char *path, GamSubscription * sub, gboolean is_dir)
{
    GamNode *node;

    node = g_new0(GamNode, 1);

    node->path = g_strdup(path);
    if (sub)
        node->subs = g_list_append(NULL, sub);
    else
        node->subs = NULL;

    node->is_dir = is_dir;
    node->data = NULL;
    node->data_destroy = NULL;
    node->flags = 0;
#ifdef WITH_TREADING
    node->lock = g_mutex_new();
#endif

    return node;
}

/**
 * Frees a node
 *
 * @param node the node
 */
void
gam_node_free(GamNode * node)
{
    g_return_if_fail(node != NULL);

    g_assert(g_list_length(node->subs) == 0);

    if (node->data_destroy && node->data)
        (*node->data_destroy) (node->data);

    g_free(node->path);
    g_list_free(node->subs);
#ifdef WITH_TREADING
    g_mutex_free(node->lock);
#endif
    g_free(node);
}

/**
 * Retrieves the parent of a given node
 *
 * @param node the node
 * @returns the parent, or NULL
 */
GamNode *
gam_node_parent(GamNode * node)
{
    GamNode *ret = NULL;

    /* gam_node_lock (node); */

    if (node->node && node->node->parent)
        ret = (GamNode *) node->node->parent->data;

    /* gam_node_unlock (node); */

    return ret;
}

/**
 * Checks whether a node is a directory or not
 *
 * @param node the node
 * @returns TRUE if the node is a directory, FALSE otherwise
 */
gboolean
gam_node_is_dir(GamNode * node)
{
    if (node == NULL) return(FALSE);
    return(node->is_dir);
}

/**
 * Sets whether a node is a directory or not
 *
 * @param node the node
 * @param is_dir whether the node is a directory
 */
void
gam_node_set_is_dir(GamNode * node, gboolean is_dir)
{
    node->is_dir = is_dir;
}

/**
 * Gets the path a given node represents
 *
 * @param node the node
 * @returns The path.  It should not be freed.
 */
G_CONST_RETURN char *
gam_node_get_path(GamNode * node)
{
    return node->path;
}

/**
 * Returns a list of subscriptions attached to the node
 *
 * @param node the node
 * @returns a list of #GamSubscription, or NULL
 */
GList *
gam_node_get_subscriptions(GamNode * node)
{
    return node->subs;
}

/**
 * Adds a subscription to a node
 *
 * @param node the node
 * @param sub the subscription
 */
gboolean
gam_node_add_subscription(GamNode * node, GamSubscription * sub)
{
    /* gam_node_lock (node); */

    if (!g_list_find(node->subs, sub))
        node->subs = g_list_prepend(node->subs, sub);

    /* gam_node_unlock (node); */

    return TRUE;
}

/**
 * Removes a subscription from a node
 *
 * @param node the node
 * @param sub the subscription to remove
 * @returns TRUE if the subscription was removed, FALSE otherwise
 */
gboolean
gam_node_remove_subscription(GamNode * node, GamSubscription * sub)
{
    /* gam_node_lock (node); */
    node->subs = g_list_remove(node->subs, sub);
    /* gam_node_unlock (node); */

    return TRUE;
}

/**
 * Copys subscriptions from one node to another
 *
 * @param src the source node
 * @param dest the destination node
 * @param filter a function which evaluates whether a subscription should be
 * copied or not.
 * @returns the number of subscriptions copied
 */
int
gam_node_copy_subscriptions(GamNode * src,
                            GamNode * dest, GamSubFilterFunc filter)
{
    GList *l;
    GamSubscription *sub;
    int i = 0;


    gam_node_lock(src);
    for (l = gam_node_get_subscriptions(src); l; l = l->next) {
        sub = (GamSubscription *) l->data;
        if (!filter || (filter && (*filter) (sub))) {
            gam_node_add_subscription(dest, sub);
            i++;
        }
    }
    gam_node_unlock(src);

    return i;
}

/**
 * Checks whether a node has a recursive subscription
 *
 * @param node the node
 * @returns TRUE if the node has a recursive subscription, FALSE otherwise
 */
gboolean
gam_node_has_recursive_sub(GamNode * node)
{
#ifdef WITH_RECURSIVE
    GList *l;

    /* gam_node_lock (node); */

    for (l = gam_node_get_subscriptions(node); l; l = l->next) {
        GamSubscription *sub = (GamSubscription *) l->data;

        if (gam_subscription_is_recursive(sub))
            return TRUE;
    }

    /* gam_node_unlock (node); */
#endif
    return FALSE;
}

/**
 * Attaches some arbitrary data to the node
 *
 * @param node the node
 * @param data a pointer to some data
 * @param destroy a function to destroy the data when the node is freed, or NULL
 */
void
gam_node_set_data(GamNode * node, gpointer data, GDestroyNotify destroy)
{
    /* gam_node_lock (node); */

    node->data = data;
    node->data_destroy = destroy;

    /* gam_node_unlock (node); */
}

/**
 * Retrieves the data attached to the node
 *
 * @param node the node
 * @returns the data, or NULL
 */
gpointer
gam_node_get_data(GamNode * node)
{
    return node->data;
}

/**
 * Sets the GNode associated with this node.  Should only be used by MdTree
 *
 * @param node the node
 * @param gnode the GNode
 */
void
gam_node_set_node(GamNode * node, GNode * gnode)
{
    node->node = gnode;
}

/**
 * Gets the GNode associated with this node.  Should only be used by MdTree
 *
 * @param node the node
 * @returns the GNode
 */
GNode *
gam_node_get_node(GamNode * node)
{
    return node->node;
}

/**
 * Sets a flag on the node
 *
 * @param node the node
 * @param flag the flag
 */
void
gam_node_set_flag(GamNode * node, int flag)
{
    node->flags |= flag;
}

/**
 * Removes a flag on the node
 *
 * @param node the node
 * @param flag the flag
 */
void
gam_node_unset_flag(GamNode * node, int flag)
{
    node->flags &= ~flag;
}

/**
 * Checks whether a node has a given flag
 *
 * @param node the node
 * @param flag the flag
 * @returns TRUE if the node has the flag, FALSE otherwise
 */
gboolean
gam_node_has_flag(GamNode * node, int flag)
{
    return node->flags & flag;
}

/** @} */
