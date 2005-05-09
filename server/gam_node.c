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
        node->subs = g_list_prepend(NULL, sub);
    else
        node->subs = NULL;

    node->is_dir = is_dir;
    node->flags = 0;

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

    g_assert(node->subs == NULL);

    g_free(node->path);
    g_list_free(node->subs);
    node->subs = NULL;
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

    if (!node)
        return(NULL);
    if (node->node && node->node->parent)
        ret = (GamNode *) node->node->parent->data;

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
    if (node == NULL)
        return(FALSE);
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
    if (!node)
        return;
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
    if (!node)
        return(NULL);
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
    if (!node)
        return(NULL);
    return node->subs;
}

/**
 * gam_node_has_dir_subscriptions:
 * @node: the node
 *
 * Allow to find if a node has directory subscriptions
 *
 * Returns TRUE if yes and FALSE otherwise
 */
gboolean
gam_node_has_dir_subscriptions(GamNode * node)
{
    GList *s;

    if (!node)
        return(FALSE);
    if (!(node->is_dir))
        return(FALSE);
    for (s = node->subs;s != NULL;s = s->next) {
        if (gam_subscription_is_dir((GamSubscription *) s->data))
	    return(TRUE);
    }
    return(FALSE);
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

    if (!node)
        return(FALSE);
    if (!g_list_find(node->subs, sub))
        node->subs = g_list_prepend(node->subs, sub);

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
    if (!node)
        return(FALSE);
    node->subs = g_list_remove_all(node->subs, sub);

    return TRUE;
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
    if (node == NULL)
        return;
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
    if (node == NULL)
        return(NULL);
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
    if (node == NULL)
        return;
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
    if (node == NULL)
        return;
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
    if (node == NULL)
        return(FALSE);
    return node->flags & flag;
}

/** @} */
