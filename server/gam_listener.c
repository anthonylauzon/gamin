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
#include "gam_listener.h"
#include "gam_subscription.h"
#include "gam_server.h"
#include "gam_error.h"

/* private struct representing a single listener */
struct _GamListener {
    void *service;
    int pid;
    GList *subs;
};

/**
 * @defgroup GamListener GamListener
 * @ingroup Daemon
 * @brief GamListener API.
 *
 * @{
 */

/**
 * Create a new #GamListener.
 *
 * @param service structure used to communicate with the listener
 * @param pid the unique ID for this listener
 * @returns the new #GamListener
 */
GamListener *
gam_listener_new(void *service, int pid)
{
    GamListener *listener;

    g_return_val_if_fail(service != NULL, NULL);
    g_return_val_if_fail(pid != 0, NULL);

    listener = g_new0(GamListener, 1);
    listener->service = service;
    listener->pid = pid;
    listener->subs = NULL;

    GAM_DEBUG(DEBUG_INFO, "Created listener for %d\n", pid);

    return listener;
}

/**
 * Free a subscription pertaining to a listener.
 *
 * @param subscription the subscription
 * @param listener the listener
 */
static void
gam_listener_free_subscription(GamSubscription * sub,
                               GamListener * listener)
{
    g_return_if_fail(listener != NULL);
    g_return_if_fail(sub != NULL);
    gam_remove_subscription(sub);
}

/**
 * Frees a previously created #GamListener
 *
 * @param listener the #GamListener to free
 */
void
gam_listener_free(GamListener * listener)
{
    GList *cur;

    g_return_if_fail(listener != NULL);
    GAM_DEBUG(DEBUG_INFO, "Freeing listener for %d\n", listener->pid);
    while ((cur = g_list_first(listener->subs)) != NULL) {
        GamSubscription * sub = cur->data;
	listener->subs = g_list_remove_all(listener->subs, sub);
	gam_listener_free_subscription(sub, listener);
    }
    g_free(listener);
}

/**
 * Gets the service associated with a #GamListener
 *
 * The result is owned by the #GamListener and should not be freed.
 *
 * @param listener the listener
 */
void *
gam_listener_get_service(GamListener * listener)
{
    return listener->service;
}

/**
 * Gets the unique process ID associated with a #GamListener
 *
 * @param listener the listener
 */
int
gam_listener_get_pid(GamListener * listener)
{
    return listener->pid;
}

/**
 * Gets the subscription represented by the given path
 *
 * @param listener the listener
 * @param path a path to a file or directory
 * @returns a #GamSubscription, or NULL if it wasn't found
 */
GamSubscription *
gam_listener_get_subscription(GamListener * listener, const char *path)
{
    GList *l;

    for (l = listener->subs; l; l = l->next) {
        GamSubscription *sub = l->data;

        if (strcmp(gam_subscription_get_path(sub), path) == 0)
            return sub;
    }

    return NULL;
}

/**
 * Gets the subscription represented by the given reqno
 *
 * @param listener the listener
 * @param reqno a subscription request number
 * @returns a #GamSubscription, or NULL if it wasn't found
 */
GamSubscription *
gam_listener_get_subscription_by_reqno(GamListener * listener, int reqno)
{
    GList *l;

    for (l = listener->subs; l; l = l->next) {
        GamSubscription *sub = l->data;

        if (gam_subscription_get_reqno(sub) == reqno)
            return sub;
    }

    return NULL;
}

/**
 * Tells if a given #GamListener is subscribed to a file/directory
 *
 * @param listener the listener
 * @param path the path to check for
 */
gboolean
gam_listener_is_subscribed(GamListener * listener, const char *path)
{
    return gam_listener_get_subscription(listener, path) != NULL;
}

/**
 * Adds a subscription to the listener.
 *
 * @param listener the listener
 * @param sub the #GamSubscription to add
 */
void
gam_listener_add_subscription(GamListener * listener,
                              GamSubscription * sub)
{
    g_assert(sub != NULL);

    if (g_list_find(listener->subs, sub) != NULL)
        return;

    listener->subs = g_list_prepend(listener->subs, sub);
}

/**
 * Removes a subscription from the listener.
 *
 * @param listener the listener
 * @param sub the #GamSubscription to remove
 * @returns TRUE if the removal was successful, otherwise FALSE
 */
gboolean
gam_listener_remove_subscription(GamListener * listener,
                                 GamSubscription * sub)
{
    listener->subs = g_list_remove_all(listener->subs, sub);

    return TRUE;
}

/**
 * Get all subscriptions a given listener holds
 *
 * @param listener the listener
 * @returns a list of #MdSuscription, or NULL if the listener has no
 * subscriptions
 */
GList *
gam_listener_get_subscriptions(GamListener * listener)
{
    return g_list_copy(listener->subs);
}

/** @} */
