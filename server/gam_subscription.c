/* Marmot
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
#include <sys/types.h>
#include <regex.h>
#include <string.h>
#include <glib.h>
#include "gam_event.h"
#include "gam_listener.h"
#include "gam_subscription.h"
#include "gam_event.h"
#include "gam_error.h"

struct _GamSubscription {
    char *path;
    int events;
    int reqno;
    int pathlen;

    gboolean is_dir;
    gboolean cancelled;
    regex_t reg;

    GamListener *listener;
};


/**
 * @defgroup GamSubscription GamSubscription
 * @ingroup Daemon
 * @brief GamSubscription API.
 *
 * A #GamSubscription represents a single monitoring request (or "subscription").
 *
 * @{
 */

/**
 * Creates a new GamSubscription
 *
 * @param path the path to be monitored
 * @param events the events that are accepted
 * @param is_dir whether the subscription is for a directory or not
 * @returns the new GamSubscription
 */
GamSubscription *
gam_subscription_new(const char *path,
                     int events,
                     int reqno,
                     gboolean is_dir)
{
    GamSubscription *sub;

    sub = g_new0(GamSubscription, 1);
    sub->path = g_strdup(path);
    sub->events = events;
    sub->reqno = reqno;
    sub->pathlen = strlen(path);

    /* everyone accepts this */
    gam_subscription_set_event(sub, GAMIN_EVENT_EXISTS);

    sub->is_dir = is_dir;

    gam_debug(DEBUG_INFO, "Created subscription for %s\n", path);
    return sub;
}

/**
 * Frees a GamSubscription
 *
 * @param sub the GamSubscription
 */
void
gam_subscription_free(GamSubscription * sub)
{
    gam_debug(DEBUG_INFO, "Freeing subscription for %s\n", sub->path);

    g_free(sub->path);
    g_free(sub);
}

/**
 * Tells if a GamSubscription is for a directory or not
 *
 * @param sub the GamSubscription
 * @returns TRUE if the subscription is for a directory, FALSE otherwise
 */
gboolean
gam_subscription_is_dir(GamSubscription * sub)
{
    return sub->is_dir;
}

/**
 * Tells if a GamSubscription is for a directory or not
 *
 * @param sub the GamSubscription
 * @returns TRUE if the subscription is for a directory, FALSE otherwise
 */
int
gam_subscription_pathlen(GamSubscription * sub)
{
    return sub->pathlen;
}

/**
 * Gets the path for a GamSubscription
 *
 * @param sub the GamSubscription
 * @returns The path being monitored.  It should not be freed.
 */
G_CONST_RETURN char *
gam_subscription_get_path(GamSubscription * sub)
{
    return sub->path;
}

/**
 * Gets the request number for a GamSubscription
 *
 * @param sub the GamSubscription
 * @returns The request number
 */
int
gam_subscription_get_reqno(GamSubscription * sub)
{
    return sub->reqno;
}

/**
 * Gets the GamListener which owns this GamSubscription
 *
 * @param sub the GamSubscription
 * @returns the GamListener, or NULL
 */
GamListener *
gam_subscription_get_listener(GamSubscription * sub)
{
    return sub->listener;
}

/**
 * Sets the GamListener which is owned by this GamSubscription
 *
 * @param sub the GamSubscription
 * @param listener the GamListener
 */
void
gam_subscription_set_listener(GamSubscription * sub,
                              GamListener * listener)
{
    sub->listener = listener;
}

/**
 * Set the events this GamSubscription is interested in
 *
 * @param sub the GamSubscription
 * @param event an ORed combination of the events desired
 */
void
gam_subscription_set_event(GamSubscription * sub, int event)
{
    sub->events |= event;
}

/**
 * Removes an event from the set of acceptable events
 *
 * @param sub the GamSubscription
 * @param event the event to remove
 */
void
gam_subscription_unset_event(GamSubscription * sub, int event)
{
    sub->events &= ~event;
}

/**
 *  
 * @param sub the GamSubscription
 * @param event the event to test for
 * @returns Whether or not this subscription accepts a given event
 */
gboolean
gam_subscription_has_event(GamSubscription * sub, int event)
{
    return sub->events & event;
}

/**
 * Mark this GamSubscription as cancelled
 *
 * @param sub the GamSubscription
 */
void
gam_subscription_cancel(GamSubscription * sub)
{
    sub->cancelled = TRUE;
}

/**
 * Checks if the GamSubscription is cancelled or not
 *
 * @param sub the GamSubscription
 * @returns TRUE if the GamSubscription is cancelled, FALSE otherwise
 */
gboolean
gam_subscription_is_cancelled(GamSubscription * sub)
{
    return sub->cancelled == TRUE;
}

/**
 * Checks if a given path/event combination is accepted by this GamSubscription
 *
 * @param sub the GamSubscription
 * @param name file name (just the base name, not the complete path)
 * @param event the event
 * @returns TRUE if the combination is accepted, FALSE otherwise
 */
gboolean
gam_subscription_wants_event(GamSubscription * sub,
                             const char *name, GaminEventType event)
{
    if (sub->cancelled)
        return FALSE;

    if (!gam_subscription_has_event(sub, event)) {
        return FALSE;
    }

    return TRUE;
}

/** @} */
