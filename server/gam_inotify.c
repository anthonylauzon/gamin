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
 * 	- *properly* Handle removal of subscriptions when we get IGNORE event
 * 	- this backend does not produce the same events as the dnotify/poll backend.
 * 	for example, the dp backend allows for watching non-exist files/folders, 
 * 	and be notified when they are created. there are more places where
 * 	the events are not consistent.
 */


#include <config.h>
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#ifdef HAVE_LINUX_INOTIFY_H
#include <linux/inotify.h>
#else
#include "local_inotify.h"
#endif
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
gam_inotify_add_rm_handler(const char *path, GamSubscription *sub,
                           pollHandlerMode mode)
{
    INotifyData *data;
    struct inotify_watch_request iwr;
    int wd,r;

    G_LOCK(inotify);

    if (mode == GAMIN_ACTIVATE) {
	GList *subs;

	subs = NULL;
	subs = g_list_append(subs, sub);

        if ((data = g_hash_table_lookup(path_hash, path)) != NULL) {
            data->refcount++;
	    data->subs = g_list_prepend(data->subs, sub);
            G_UNLOCK(inotify);
	    GAM_DEBUG(DEBUG_INFO, "inotify updated refcount\n");
	    /*
	     * hum might need some work to check if the path is a dir,
	     * setting 0 and forcing to bypass checks right now.
	     */
	    gam_server_emit_event (path, 0, GAMIN_EVENT_EXISTS, subs, 1);
            gam_server_emit_event (path, 0, GAMIN_EVENT_ENDEXISTS, subs, 1);
            return;
        }

	{
	    int file_fd = open(path, O_RDONLY);

	    if (file_fd < 0) {
		G_UNLOCK(inotify);
		return;
	    }

	    iwr.fd = file_fd;
	    iwr.mask = 0xffffffff; // all events
	    wd = ioctl(fd, INOTIFY_WATCH, &iwr);
	    close (file_fd);
	}

        if (wd < 0) {
            G_UNLOCK(inotify);
            return;
        }

        data = gam_inotify_data_new(path, wd);
    	data->subs = g_list_prepend(data->subs, sub);
        g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd), data);
        g_hash_table_insert(path_hash, data->path, data);

        GAM_DEBUG(DEBUG_INFO, "added inotify watch for %s\n", path);

	gam_server_emit_event (path, 0, GAMIN_EVENT_EXISTS, subs, 1);
	gam_server_emit_event (path, 0, GAMIN_EVENT_ENDEXISTS, subs, 1);
    } else if (mode == GAMIN_DESACTIVATE) {
        data = g_hash_table_lookup(path_hash, path);

        if (!data) {
            G_UNLOCK(inotify);
            return;
        }

	if (g_list_find (data->subs, sub)) {
		data->subs = g_list_remove_all (data->subs, sub);
	}
        data->refcount--;
	    GAM_DEBUG(DEBUG_INFO, "inotify decremeneted refcount for %s\n", path);

        if (data->refcount == 0) {
            r = ioctl (fd, INOTIFY_IGNORE, &data->wd); 
	    if (r < 0) {
                GAM_DEBUG (DEBUG_INFO, "INOTIFY_IGNORE failed for %s (wd = %d)\n", data->path, data->wd);
            }
            GAM_DEBUG(DEBUG_INFO, "removed inotify watch for %s\n", data->path);
            g_hash_table_remove(path_hash, data->path);
            g_hash_table_remove(wd_hash, GINT_TO_POINTER(data->wd));
            gam_inotify_data_free(data);
        }
    } else {
        GAM_DEBUG(DEBUG_INFO, "Inotify: unimplemented mode request %d\n", mode);
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
		case IN_MOVED_TO:
		case IN_CREATE_SUBDIR:
		case IN_CREATE_FILE:
			return GAMIN_EVENT_CREATED;
		break;
		case IN_MOVED_FROM:
		case IN_DELETE_SUBDIR:
		case IN_DELETE_FILE:
			return GAMIN_EVENT_DELETED;
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

	// gamins event vocabulary is very small compared to inotify
	// so we often will receieve events that have no equivelant 
	// in gamin
	if (gevent == GAMIN_EVENT_UNKNOWN) {
		return;
	}

	if (event->name[0] != '\0') {
		int pathlen = strlen(data->path);
		if (data->path[pathlen-1] == '/') {
			event_path = g_strconcat (data->path, event->name, NULL);
		} else {
			event_path = g_strconcat (data->path, "/", event->name, NULL);
		}
	} else {
		event_path = g_strdup (data->path);
	}

	GAM_DEBUG(DEBUG_INFO, "inotify emitting event %s for %s\n", gam_event_to_string(gevent) , event_path);

	gam_server_emit_event (event_path, 0, gevent, data->subs, 1);

	g_free (event_path);
}

static gboolean
gam_inotify_read_handler (gpointer user_data)
{
    char *buffer;
    int buffer_size;
    gsize buffer_i, read_size;

    G_LOCK(inotify);

    if (ioctl(fd, FIONREAD, &buffer_size) < 0) {
	G_UNLOCK(inotify);
	GAM_DEBUG(DEBUG_INFO, "inotify FIONREAD < 0. kaboom!\n");
	return FALSE;
    }

    buffer = g_malloc(buffer_size);

    if (g_io_channel_read_chars(inotify_read_ioc, (char *)buffer, buffer_size, &read_size, NULL) != G_IO_STATUS_NORMAL) {
	G_UNLOCK(inotify);
        GAM_DEBUG(DEBUG_INFO, "inotify failed to read events from inotify fd.\n");
	g_free (buffer);
	return FALSE;
    }

    buffer_i = 0;
    while (buffer_i < read_size) {
	struct inotify_event *event;
	gsize event_size;
	INotifyData *data;

	event = (struct inotify_event *)&buffer[buffer_i];
	event_size = sizeof(struct inotify_event) + event->len;

	data = g_hash_table_lookup (wd_hash, GINT_TO_POINTER(event->wd));
	if (!data) {
	    GAM_DEBUG(DEBUG_INFO, "inotify can't find wd %d\n", event->wd);
	    GAM_DEBUG(DEBUG_INFO, "weird things have happened to inotify.\n");
	} else {
	    /* Do the shit with the event */
	    if (event->mask == IN_IGNORED) {
		GList *l;

		l = data->subs;
		data->subs = NULL;
		for (l = l; l; l = l->next) {
		    GamSubscription *sub = l->data;
		    gam_inotify_remove_subscription (sub);
		}
	    } else {
		    gam_inotify_emit_event (data, event);
	    }
	}

	buffer_i += event_size;
    }

    g_free (buffer);
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
			GAM_DEBUG(DEBUG_INFO, "called gam_inotify_add_handler()\n");
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
			GAM_DEBUG(DEBUG_INFO, "called gam_inotify_rm_handler()\n");
			gam_inotify_add_rm_handler (gam_subscription_get_path (sub), sub, FALSE);
		}
	} else {
		G_UNLOCK(removed_subs);
	}

	GAM_DEBUG(DEBUG_INFO, "gam_inotify_consume_subscriptions()\n");

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
 * @defgroup inotify inotify backend
 * @ingroup Backends
 * @brief inotify backend API
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
        GAM_DEBUG(DEBUG_INFO, "Could not open /dev/inotify\n");
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

    GAM_DEBUG(DEBUG_INFO, "inotify initialized\n");

    gam_backend_add_subscription = gam_inotify_add_subscription;
    gam_backend_remove_subscription = gam_inotify_remove_subscription;
    gam_backend_remove_all_for = gam_inotify_remove_all_for;

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

	GAM_DEBUG(DEBUG_INFO, "inotify_add_sub\n");

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
		GAM_DEBUG(DEBUG_INFO, "removed sub found on new_subs\n");
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

	GAM_DEBUG(DEBUG_INFO, "inotify_remove_sub\n");
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
