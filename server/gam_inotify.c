/* Marmot
 * Copyright (C) 2004 John McCutchan, James Willcox, Corey Bowers
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
 * TODO:
 * 	Handle removal of subscriptions when we get IGNORE event
 */


#include <config.h>
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include "/usr/src/linux/include/linux/inotify.h"
#include "gam_error.h"
#include "gam_inotify.h"
#include "gam_tree.h"
#include "gam_event.h"
#include "gam_server.h"
#include "gam_event.h"

typedef struct {
    char *path;
    int wd;
    int refcount;
    GList *subs;
} INotifyData;

static GHashTable *path_hash = NULL;
static GHashTable *wd_hash = NULL;

static GList *new_subs = NULL;
G_LOCK_DEFINE_STATIC(new_subs);
static GList *removed_subs = NULL;
G_LOCK_DEFINE_STATIC(removed_subs);

G_LOCK_DEFINE_STATIC(inotify);
static GIOChannel *inotify_read_ioc = NULL;

static gboolean have_consume_idler = FALSE;


int fd = -1; // the device fd

static INotifyData *
gam_inotify_data_new(const char *path, int wd)
{
    INotifyData *data;

    data = g_new0(INotifyData, 1);
    data->path = g_strdup(path);
    data->wd = wd;
    data->refcount = 1;
    data->subs = NULL;

    return data;
}

static void
gam_inotify_data_free(INotifyData * data)
{
    g_free(data->path);
    g_free(data);
}

static void
gam_inotify_add_rm_handler(const char *path, GamSubscription *sub, gboolean added)
{
    INotifyData *data;
    struct inotify_watch_request iwr;
    int wd,r;

    G_LOCK(inotify);

    if (added) {
	GList *subs;

	subs = NULL;
	subs = g_list_append(subs, sub);

        if ((data = g_hash_table_lookup(path_hash, path)) != NULL) {
            data->refcount++;
	    data->subs = g_list_prepend(data->subs, sub);
            G_UNLOCK(inotify);
	    gam_debug(DEBUG_INFO, "inotify updated refcount\n");
	    gam_server_emit_event (path, GAMIN_EVENT_EXISTS, subs);
            gam_server_emit_event (path, GAMIN_EVENT_ENDEXISTS, subs);
            return;
        }

	iwr.dirname = g_strdup(path);
	iwr.mask = 0xffffffff; // all events

        wd = ioctl(fd, INOTIFY_WATCH,&iwr);
        g_free(iwr.dirname);	

        if (wd < 0) {
            G_UNLOCK(inotify);
            return;
        }

        data = gam_inotify_data_new(path, wd);
    	data->subs = g_list_prepend(data->subs, sub);
        g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd), data);
        g_hash_table_insert(path_hash, data->path, data);

        gam_debug(DEBUG_INFO, "activated INotify for %s\n", path);

	gam_server_emit_event (path, GAMIN_EVENT_EXISTS, subs);
	gam_server_emit_event (path, GAMIN_EVENT_ENDEXISTS, subs);
    } else {
        data = g_hash_table_lookup(path_hash, path);

        if (!data) {
            G_UNLOCK(inotify);
            return;
        }

	if (g_list_find (data->subs, sub)) {
		data->subs = g_list_remove_all (data->subs, sub);
	}
        data->refcount--;
	    gam_debug(DEBUG_INFO, "inotify decremeneted refcount\n");

        if (data->refcount == 0) {
            r = ioctl (fd, INOTIFY_IGNORE, &data->wd); 
	    if (r < 0) {
                gam_debug (DEBUG_INFO, "INOTIFY_IGNORE failed for %s\n", data->path);
            }
            gam_debug(DEBUG_INFO, "deactivated INotify for %s\n",
                      data->path);
            g_hash_table_remove(path_hash, data->path);
            g_hash_table_remove(wd_hash, GINT_TO_POINTER(data->wd));
            gam_inotify_data_free(data);
        }
    }

    G_UNLOCK(inotify);
}


static GaminEventType inotify_event_to_gamin_event (int mask) 
{
	switch (mask)
	{
		case IN_ATTRIB:
		case IN_MODIFY:
			return GAMIN_EVENT_CHANGED;
		break;
		case IN_CREATE:
			return GAMIN_EVENT_CREATED;
		break;
		case IN_DELETE:
			return GAMIN_EVENT_DELETED;
		break;
		case IN_RENAME:
		case IN_MOVE:
			return GAMIN_EVENT_MOVED;
		break;
		default:
			return GAMIN_EVENT_UNKNOWN;
	}
}
static void gam_inotify_emit_event (INotifyData *data, struct inotify_event *event)
{
	GaminEventType gevent;
	char *event_path;

	if (!data||!event)
		return;

	gevent = inotify_event_to_gamin_event (event->mask);
	// we got some event that GAMIN doesn't understand
	if (gevent == GAMIN_EVENT_UNKNOWN) {
		gam_debug(DEBUG_INFO, "inotify_emit_event got unknown event %x\n", event->mask);
		return;
	}

	if (event->filename[0] != '\0') {
		int pathlen = strlen(data->path);
		gam_debug(DEBUG_INFO, "Got filename with event\n");
		if (data->path[pathlen-1] == '/') {
			event_path = g_strconcat (data->path, event->filename, NULL);
		} else {
			event_path = g_strconcat (data->path, "/", event->filename, NULL);
		}
	} else {
		gam_debug(DEBUG_INFO, "Got not filename with event\n");
		event_path = g_strdup (data->path);
	}

	gam_debug(DEBUG_INFO, "gam_inotify_emit_event() %s\n", event_path);

	gam_server_emit_event (event_path, gevent, data->subs);
}

static gboolean
gam_inotify_read_handler(gpointer user_data)
{
    struct inotify_event event;
    INotifyData *data;

    gam_debug(DEBUG_INFO, "gam_inotify_read_handler()\n");
    G_LOCK(inotify);

    if (g_io_channel_read_chars(inotify_read_ioc, (char *)&event, sizeof(struct inotify_event), NULL, NULL) != G_IO_STATUS_NORMAL) {
	G_UNLOCK(inotify);
        gam_debug(DEBUG_INFO, "gam_inotify_read_handler failed\n");
	return FALSE;
    }

    /* When we get an ignore event, we 
     * remove all the subscriptions for this wd
     */
    if (event.mask == IN_IGNORED) {
	    GList *l;
	    data = g_hash_table_lookup (wd_hash, GINT_TO_POINTER(event.wd));

	    if (!data) {
		    G_UNLOCK(inotify);
		    return TRUE;
		}

	    l = data->subs;
	    data->subs = NULL;
	    for (l = l; l; l = l->next) {
		    GamSubscription *sub = l->data;
		    gam_inotify_remove_subscription (sub);
	    }
	    G_UNLOCK(inotify);
	    return TRUE;
    }

    data = g_hash_table_lookup (wd_hash, GINT_TO_POINTER(event.wd));

    if (!data) {
	gam_debug(DEBUG_INFO, "Could not find WD %d in hash\n", event.wd);
        G_UNLOCK(inotify);
        return TRUE;
    }

    gam_inotify_emit_event (data, &event);

    gam_debug(DEBUG_INFO, "gam_inotify event for %s (%x) %s\n", data->path, event.mask, event.filename);

    gam_debug(DEBUG_INFO, "gam_inotify_read_handler() done\n");

    G_UNLOCK(inotify);

    return TRUE;
}

static gboolean
gam_inotify_consume_subscriptions_real(gpointer data)
{
	GList *subs, *l;
	
	G_LOCK(new_subs);
	if (new_subs) {
		subs = new_subs;
		new_subs = NULL;
		G_UNLOCK(new_subs);

		for (l = subs; l; l = l->next) {
			GamSubscription *sub = l->data;
			gam_debug(DEBUG_INFO, "called gam_inotify_add_handler()\n");
			gam_inotify_add_rm_handler (gam_subscription_get_path (sub), sub, TRUE);
		}

	} else { 
		G_UNLOCK(new_subs);
	}

	G_LOCK(removed_subs);
	if (removed_subs) {
		subs = removed_subs;
		removed_subs = NULL;
		G_UNLOCK(removed_subs);

		for (l = subs; l; l = l->next) {
			GamSubscription *sub = l->data;
			gam_debug(DEBUG_INFO, "called gam_inotify_rm_handler()\n");
			gam_inotify_add_rm_handler (gam_subscription_get_path (sub), sub, FALSE);
		}
	} else {
		G_UNLOCK(removed_subs);
	}

	gam_debug(DEBUG_INFO, "gam_inotify_consume_subscriptions()\n");

	have_consume_idler = FALSE;
	return FALSE;
}

static void
gam_inotify_consume_subscriptions(void)
{
	GSource *source;

	if (have_consume_idler)
		return;

	have_consume_idler = TRUE;

	source = g_idle_source_new ();
	g_source_set_callback (source, gam_inotify_consume_subscriptions_real, NULL, NULL);

	g_source_attach (source, NULL);
}

/**
 * @defgroup INotify INotify Backend
 * @ingroup Backends
 * @brief INotify backend API
 *
 * Since version 2.6.X, Linux kernels have included the Linux Inode
 * Notification system (inotify).  This backend uses inotify to know when
 * files are changed/created/deleted.  
 *
 * @{
 */


/**
 * Initializes the inotify system.  This must be called before
 * any other functions in this module.
 *
 * @returns TRUE if initialization succeeded, FALSE otherwise
 */
gboolean
gam_inotify_init(void)
{
    GSource *source;

    fd = open("/dev/inotify", O_RDONLY);

    if (fd < 0) {
        g_warning("Could not open /dev/inotify\n");
        return FALSE;
    }

    inotify_read_ioc = g_io_channel_unix_new(fd);

    /* For binary data */
    g_io_channel_set_encoding (inotify_read_ioc, NULL, NULL);
    /* Non blocking */
    g_io_channel_set_flags(inotify_read_ioc, G_IO_FLAG_NONBLOCK, NULL);

    source = g_io_create_watch(inotify_read_ioc,
                               G_IO_IN | G_IO_HUP | G_IO_ERR);
    g_source_set_callback(source, gam_inotify_read_handler, NULL, NULL);

    g_source_attach(source, NULL);

    path_hash = g_hash_table_new(g_str_hash, g_str_equal);
    wd_hash = g_hash_table_new(g_direct_hash, g_direct_equal);

    gam_debug(DEBUG_INFO, "inotify initialized\n");

    int i = 0; // INOTIFY_DEBUG_INODE|INOTIFY_DEBUG_ERRORS|INOTIFY_DEBUG_EVENTS;
    ioctl(fd, INOTIFY_SETDEBUG, &i);

    return TRUE;
}

/**
 * Adds a subscription to be monitored.
 *
 * @param sub a #GamSubscription to be polled
 * @returns TRUE if adding the subscription succeeded, FALSE otherwise
 */
gboolean
gam_inotify_add_subscription(GamSubscription * sub)
{
	gam_listener_add_subscription(gam_subscription_get_listener(sub), sub);

	G_LOCK(new_subs);
	new_subs = g_list_prepend(new_subs, sub);
	G_UNLOCK(new_subs);

	gam_debug(DEBUG_INFO, "inotify_add_sub\n");

	gam_inotify_consume_subscriptions();
    return TRUE;
}

/**
 * Removes a subscription which was being monitored.
 *
 * @param sub a #GamSubscription to remove
 * @returns TRUE if removing the subscription succeeded, FALSE otherwise
 */
gboolean
gam_inotify_remove_subscription(GamSubscription * sub)
{
	G_LOCK(new_subs);
	if (g_list_find(new_subs, sub)) {
		gam_debug(DEBUG_INFO, "removed sub found on new_subs\n");
		new_subs = g_list_remove_all (new_subs, sub);
		G_UNLOCK(new_subs);
		return TRUE;
	}
	G_UNLOCK(new_subs);

	gam_subscription_cancel (sub);
	gam_listener_remove_subscription(gam_subscription_get_listener(sub), sub);

	G_LOCK(removed_subs);
	removed_subs = g_list_prepend (removed_subs, sub);
	G_UNLOCK(removed_subs);

	gam_debug(DEBUG_INFO, "inotify_remove_sub\n");
	gam_inotify_consume_subscriptions();

    return TRUE;
}

/**
 * Stop monitoring all subscriptions for a given listener.
 *
 * @param listener a #GamListener
 * @returns TRUE if removing the subscriptions succeeded, FALSE otherwise
 */
gboolean
gam_inotify_remove_all_for(GamListener * listener)
{
	GList *subs, *l = NULL;

	subs = gam_listener_get_subscriptions (listener);

	for (l = subs; l; l = l->next) {
		GamSubscription *sub = l->data;

		g_assert (sub != NULL);

		gam_inotify_remove_subscription (sub);

	}

	if (subs) {
		g_list_free (subs);
		gam_inotify_consume_subscriptions();
		return TRUE;
	} else {
		return FALSE;
	}
}

/** @} */
