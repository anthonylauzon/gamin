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
#include <sys/stat.h>
#include "gam_error.h"
#include "gam_protocol.h"
#include "gam_event.h"
#include "gam_listener.h"
#include "gam_server.h"
#include "gam_channel.h"
#include "gam_subscription.h"
#include "gam_poll.h"
#ifdef ENABLE_INOTIFY
#include "gam_inotify.h"
#endif
#ifdef ENABLE_DNOTIFY
#include "gam_dnotify.h"
#endif
#include "gam_excludes.h"

static int poll_only = 0;
static const char *session;

/**
 * gam_shutdown:
 *
 * Shutdown routine called when the server exits
 */
void
gam_shutdown(void) {
    gam_conn_shutdown(session);
}

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
    gam_exclude_init();

    if (!poll_only) {
#ifdef ENABLE_INOTIFY
	if (gam_inotify_init()) {
	    GAM_DEBUG(DEBUG_INFO, "Using INotify as backend\n");
	    return(TRUE);
	}
#endif
#ifdef ENABLE_DNOTIFY
	if (gam_dnotify_init()) {
	    GAM_DEBUG(DEBUG_INFO, "Using DNotify as backend\n");
	    return(TRUE);
	}
#endif
    }
    if (gam_poll_init()) {
	GAM_DEBUG(DEBUG_INFO, "Using Poll as backend\n");
	return(TRUE);
    }

    GAM_DEBUG(DEBUG_INFO, "Cannot initialize any backend\n");

    return(FALSE);
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
    
    if (sub == NULL)
        return(FALSE);

    return (gam_backend_add_subscription(sub));
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
    return (gam_backend_remove_subscription(sub));
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
 * gam_server_emit_one_event:
 * @path: the file/directory path
 * @event: the event type
 * @sub: the subscription for this event
 * @force: try to force the event though as much as possible
 *
 * Checks which subscriptions are interested in this event and
 * make sure the event are sent to the associated clients.
 */
void
gam_server_emit_one_event(const char *path, int node_is_dir,
                          GaminEventType event, GamSubscription *sub,
			  int force)
{
    int pathlen, len;
    const char *subpath;
    GamListener *listener;
    GamConnDataPtr conn;
    int reqno;


    pathlen = strlen(path);

    if (!gam_subscription_wants_event(sub, path, node_is_dir, event, force))
	return;
    listener = gam_subscription_get_listener(sub);
    if (listener == NULL)
	return;
    conn = (GamConnDataPtr) gam_listener_get_service(listener);
    if (conn == NULL)
	return;

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
	GAM_DEBUG(DEBUG_INFO, "Failed to send event to PID %d\n",
		  gam_connection_get_pid(conn));
    }
}

/**
 * gam_server_emit_event:
 * @path: the file/directory path
 * @is_dir_node: is the target a directory
 * @event: the event type
 * @subs: the list of subscription for this event
 * @force: force the emission of the events
 *
 * Checks which subscriptions are interested in this event and
 * make sure the event are sent to the associated clients.
 */
void
gam_server_emit_event(const char *path, int is_dir_node, GaminEventType event,
                      GList * subs, int force)
{
    GList *l;
    int pathlen, len;
    const char *subpath;

    if ((path == NULL) || (subs == NULL))
        return;
    pathlen = strlen(path);

    for (l = subs; l; l = l->next) {
        GamSubscription *sub = l->data;
        GamListener *listener;
        GamConnDataPtr conn;
        int reqno;

        if (!gam_subscription_wants_event(sub, path, is_dir_node, event, force))
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
            GAM_DEBUG(DEBUG_INFO, "Failed to send event to PID %d\n",
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
    int i;

    if (argc > 1) {
        for (i = 1;i < argc;i++) {
	    if (!strcmp(argv[i], "--notimeout"))
		no_timeout = 1;
            else if (!strcmp(argv[i], "--pollonly"))
	        poll_only = 1;
	    else
		session = argv[i];
	}
    }

    gam_error_init();
    signal(SIGPIPE, SIG_IGN);

    if (!gam_init_subscriptions()) {
	GAM_DEBUG(DEBUG_INFO, "Could not initialize the subscription system.\n");
        exit(0);
    }

    loop = g_main_loop_new(NULL, FALSE);
    if (loop == NULL) {
        g_error("Failed to create the main loop.\n");
        exit(1);
    }

    if (!gam_server_init(loop, session)) {
        GAM_DEBUG(DEBUG_INFO, "Couldn't initialize the server.\n");
        exit(0);
    }

    g_main_loop_run(loop);

    gam_shutdown();

    return (0);
}
