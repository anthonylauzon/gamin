/* Gamin
 * Copyright (C) 2003 James Willcox, Corey Bowers
 * Copyright (C) 2004 Red Hat, Inc.
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
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include "gam_error.h"
#include "gam_protocol.h"
#include "gam_event.h"
#include "gam_listener.h"
#include "gam_server.h"
#include "gam_channel.h"
#include "gam_subscription.h"
#include "gam_poll.h"
#ifdef linux
#include "gam_dnotify.h"
#endif

/**
 * gam_init_subscriptions:
 *
 * Initialize the subscription checking backend, on Linux we will use
 * the DNotify kernel support, otherwise the polling module.
 *
 * Return TRUE in case of success and FALSE otherwise
 */
gboolean
gam_init_subscriptions(void)
{

#ifdef linux
    return (gam_dnotify_init());
#else
    return (gam_poll_init());
#endif
}

/**
 * gam_add_subscription:
 *
 * Register a subscription to the checking backend, on Linux we will use
 * the DNotify kernel support, otherwise the polling module.
 *
 * Return TRUE in case of success and FALSE otherwise
 */
gboolean
gam_add_subscription(GamSubscription * sub)
{
#ifdef linux
    return (gam_dnotify_add_subscription(sub));
#else
    return (gam_poll_add_subscription(sub));
#endif
}

/**
 * gam_remove_subscription:
 *
 * Remove a subscription from the checking backend.
 *
 * Return TRUE in case of success and FALSE otherwise
 */
gboolean
gam_remove_subscription(GamSubscription * sub)
{
#ifdef linux
    return (gam_dnotify_remove_subscription(sub));
#else
    return (gam_poll_remove_subscription(sub));
#endif
}

/**
 * @defgroup Daemon Daemon
 *
 */

/**
 * @defgroup Backends Backends
 * @ingroup Daemon
 *
 * One of the goals for Gamin is providing a uniform and consistent
 * monitoring solution, which works even across different platforms.  Different
 * platforms have different kernel-level monitoring systems available (or
 * none at all).  A "backend" simply takes advantage of the services available
 * on a given platform and makes them work with the rest of Gamin.
 * 
 *
 */

static int no_timeout = 0;
static GHashTable *listeners = NULL;
static GIOChannel *socket = NULL;

/**
 * gam_server_emit_event:
 * @path: the file/directory path
 * @event: the event type
 * @subs: the list of subscription for this event
 *
 * Checks which subscriptions are interested in this event and
 * make sure the event are sent to the associated clients.
 */
void
gam_server_emit_event(const char *path, GaminEventType event, GList * subs)
{
    GList *l;
    int pathlen, len;
    const char *subpath;

    pathlen = strlen(path);

    for (l = subs; l; l = l->next) {
        GamSubscription *sub = l->data;
        GamListener *listener;
        GamConnDataPtr conn;
        int reqno;

        if (!gam_subscription_wants_event(sub, path, event))
            continue;
        listener = gam_subscription_get_listener(sub);
        if (listener == NULL)
            continue;
        conn = (GamConnDataPtr) gam_listener_get_service(listener);
        if (conn == NULL)
            continue;

        /*
         * When sending directory related entries, for items in the
         * directory the FAM protocol removes the common direcory part.
         */
        subpath = path;
        len = pathlen;
        if (gam_subscription_is_dir(sub)) {
            int dlen = gam_subscription_pathlen(sub);

            if ((pathlen > dlen + 1) && (path[dlen] == '/')) {
                subpath += dlen + 1;
                len -= dlen + 1;
            }
        }

        reqno = gam_subscription_get_reqno(sub);

        if (gam_send_event(conn, reqno, event, subpath, len) < 0) {
            gam_debug(DEBUG_INFO, "Failed to send event to PID %d\n",
                      gam_connection_get_pid(conn));
        }
    }
}

int
gam_server_num_listeners(void)
{
    return g_hash_table_size(listeners);
}



/**
 * gam_server_init:
 * @loop:  the main event loop of the daemon
 * @session: the session name or NULL
 *
 * Initialize the gamin server
 *
 * Returns TRUE in case of success and FALSE in case of error
 */
static gboolean
gam_server_init(GMainLoop * loop, const char *session)
{
    if (socket != NULL) {
        return (FALSE);
    }
    socket = gam_server_create(session);
    if (socket == NULL)
        return (FALSE);
    g_io_add_watch(socket, G_IO_IN, gam_incoming_conn_read, loop);
    g_io_add_watch(socket, G_IO_HUP | G_IO_NVAL | G_IO_ERR, gam_conn_error,
                   NULL);

    /*
     * Register the timeout checking function
     */
    if (no_timeout == 0)
	g_timeout_add(1000, (GSourceFunc) gam_connections_check, NULL);

    return TRUE;
}

int
main(int argc, const char *argv[])
{
    GMainLoop *loop;
    const char *session = NULL;

    if (argc > 1) {
        if (!strcmp(argv[1], "--notimeout")) {
	    no_timeout = 1;
	    if (argc > 2) {
		session = argv[2];
	    }
	} else {
	    session = argv[1];
	}
    }

    g_thread_init(NULL);

    if (!g_thread_supported()) {
        g_error("The glib thread library does not support your system.\n");
        exit(1);
    }
    if (!gam_init_subscriptions()) {
        g_error("Could not initialize the subscription system.\n");
        exit(1);
    }

    loop = g_main_loop_new(NULL, FALSE);
    if (loop == NULL) {
        g_error("Failed to create the main loop.\n");
        exit(1);
    }

    if (!gam_server_init(loop, session)) {
        g_error("Couldn't initialize the server.\n");
        exit(1);
    }

    g_main_loop_run(loop);

    return (0);
}
