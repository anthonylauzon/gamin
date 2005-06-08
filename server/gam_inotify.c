/* gamin inotify backend
 * Copyright (C) 2005 John McCutchan
 *
 * Based off of code,
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


#include "server_config.h"
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <glib.h>
#include "gam_error.h"
#include "gam_poll.h"
#ifdef HAVE_LINUX_INOTIFY_H
#include <linux/inotify.h>
#else
#include "local_inotify.h"
#endif
#include "gam_inotify.h"
#include "gam_tree.h"
#include "gam_event.h"
#include "gam_server.h"
#include "gam_event.h"
#ifdef GAMIN_DEBUG_API
#include "gam_debugging.h"
#endif

#define MIN_POLL_TIME 1.0

typedef struct {
    char *path;
    int wd;
    int refcount;
    GList *subs;
    int busy;
	gboolean deactivated;
} inotify_data_t;

static GHashTable *path_hash = NULL;
static GHashTable *wd_hash = NULL;

G_LOCK_DEFINE_STATIC(inotify);

static GIOChannel *inotify_read_ioc = NULL;

static gboolean have_consume_idler = FALSE;

static int inotify_device_fd = -1;

static guint should_poll_mask = IN_MODIFY|IN_ATTRIB|IN_CLOSE_WRITE|IN_MOVED_FROM|IN_MOVED_TO|IN_DELETE|IN_CREATE|IN_DELETE_SELF|IN_UNMOUNT;

static void print_mask(int mask)
{
    if (mask & IN_ACCESS)
    {
        GAM_DEBUG(DEBUG_INFO, "ACCESS\n");
    }
    if (mask & IN_MODIFY)
    {
        GAM_DEBUG(DEBUG_INFO, "MODIFY\n");
    }
    if (mask & IN_ATTRIB)
    {
        GAM_DEBUG(DEBUG_INFO, "ATTRIB\n");
    }
    if (mask & IN_CLOSE_WRITE)
    {
        GAM_DEBUG(DEBUG_INFO, "CLOSE_WRITE\n");
    }
    if (mask & IN_CLOSE_NOWRITE)
    {
        GAM_DEBUG(DEBUG_INFO, "CLOSE_WRITE\n");
    }
    if (mask & IN_OPEN)
    {
        GAM_DEBUG(DEBUG_INFO, "OPEN\n");
    }
    if (mask & IN_MOVED_FROM)
    {
        GAM_DEBUG(DEBUG_INFO, "MOVE_FROM\n");
    }
    if (mask & IN_MOVED_TO)
    {
        GAM_DEBUG(DEBUG_INFO, "MOVE_TO\n");
    }
    if (mask & IN_DELETE)
    {
        GAM_DEBUG(DEBUG_INFO, "DELETE\n");
    }
    if (mask & IN_CREATE)
    {
        GAM_DEBUG(DEBUG_INFO, "CREATE_SUBDIR\n");
    }
    if (mask & IN_DELETE_SELF)
    {
        GAM_DEBUG(DEBUG_INFO, "DELETE_SELF\n");
    }
    if (mask & IN_UNMOUNT)
    {
        GAM_DEBUG(DEBUG_INFO, "UNMOUNT\n");
    }
    if (mask & IN_Q_OVERFLOW)
    {
        GAM_DEBUG(DEBUG_INFO, "Q_OVERFLOW\n");
    }
    if (mask & IN_IGNORED)
    {
        GAM_DEBUG(DEBUG_INFO, "IGNORED\n");
    }
}

static inotify_data_t *
gam_inotify_data_new(const char *path, int wd)
{
    inotify_data_t *data;

    data = g_new0(inotify_data_t, 1);
    data->path = g_strdup(path);
    data->wd = wd;
    data->busy = 0;
    data->refcount = 1;

    return data;
}

static void
gam_inotify_data_free(inotify_data_t * data)
{
    if (data->refcount != 0)
	GAM_DEBUG(DEBUG_INFO, "gam_inotify_data_free called with reffed data.\n");
    g_free(data->path);
    g_free(data);
}

static void
gam_inotify_directory_handler_internal(const char *path, pollHandlerMode mode)
{
    inotify_data_t *data;
    int path_fd;
    int path_wd;
    struct inotify_watch_request iwr;


    switch (mode) {
        case GAMIN_ACTIVATE:
	    GAM_DEBUG(DEBUG_INFO, "Adding %s to inotify\n", path);
	    break;
        case GAMIN_DESACTIVATE:
	    GAM_DEBUG(DEBUG_INFO, "Removing %s from inotify\n", path);
	    break;
	case GAMIN_FLOWCONTROLSTART:
	    GAM_DEBUG(DEBUG_INFO, "inotify: Start flow control for %s\n", path);
	    break;
	case GAMIN_FLOWCONTROLSTOP:
	    GAM_DEBUG(DEBUG_INFO, "inotify: Stop flow control for %s\n", path);
	    break;
	default:
	    gam_error(DEBUG_INFO, "Unknown inotify operation %d for %s\n",
	              mode, path);
	    return;
    }
    G_LOCK(inotify);

    if (mode == GAMIN_ACTIVATE) {
        if ((data = g_hash_table_lookup(path_hash, path)) != NULL) {
            data->refcount++;
	    GAM_DEBUG(DEBUG_INFO, "  found incremented refcount: %d\n",
	              data->refcount);
            G_UNLOCK(inotify);
#ifdef GAMIN_DEBUG_API
            gam_debug_report(GAMinotifyChange, path, data->refcount);
#endif
            GAM_DEBUG(DEBUG_INFO, "inotify updated refcount\n");
            return;
        }

        path_fd = open(path, O_RDONLY);

        if (path_fd < 0) {
            G_UNLOCK(inotify);
            return;
        }

	iwr.fd = path_fd;
	iwr.mask = should_poll_mask;
	path_wd = ioctl (inotify_device_fd, INOTIFY_WATCH, &iwr);
	close (path_fd);

        data = gam_inotify_data_new(path, path_wd);
        g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd), data);
        g_hash_table_insert(path_hash, data->path, data);

        GAM_DEBUG(DEBUG_INFO, "activated inotify for %s\n", path);
#ifdef GAMIN_DEBUG_API
        gam_debug_report(GAMinotifyCreate, path, 0);
#endif
    } else if (mode == GAMIN_DESACTIVATE) {
	char *dir = (char *) path;

	data = g_hash_table_lookup(path_hash, path);

	if (!data) {
	    dir = g_path_get_dirname(path);
	    data = g_hash_table_lookup(path_hash, dir);

	    if (!data) {
		GAM_DEBUG(DEBUG_INFO, "  not found !!!\n");

		if (dir != NULL)
		    g_free(dir);

		G_UNLOCK(inotify);
		return;
	    }
	    GAM_DEBUG(DEBUG_INFO, "  not found using parent\n");
	}

        data->refcount--;
        GAM_DEBUG(DEBUG_INFO, "inotify decremeneted refcount for %s\n",
                  path);

        if (data->refcount == 0) {
	    int wd = data->wd;

	    GAM_DEBUG(DEBUG_INFO, "removed inotify watch for %s\n", data->path);

	    g_hash_table_remove(path_hash, data->path);
	    g_hash_table_remove(wd_hash, GINT_TO_POINTER(data->wd));
	    gam_inotify_data_free(data);

	    if (ioctl (inotify_device_fd, INOTIFY_IGNORE, &wd) < 0) {
		GAM_DEBUG (DEBUG_INFO, "INOTIFY_IGNORE failed for %s (wd = %d)\n", data->path, data->wd);
	    }
#ifdef GAMIN_DEBUG_API
	    gam_debug_report(GAMinotifyDelete, dir, 0);
#endif
        } else {
	    GAM_DEBUG(DEBUG_INFO, "  found decremented refcount: %d\n",
	              data->refcount);
#ifdef GAMIN_DEBUG_API
            gam_debug_report(GAMinotifyChange, dir, data->refcount);
#endif
	}
	if ((dir != path) && (dir != NULL))
	    g_free(dir);
    } else if ((mode == GAMIN_FLOWCONTROLSTART) ||
               (mode == GAMIN_FLOWCONTROLSTOP)) {
        char *dir = (char *) path;

        data = g_hash_table_lookup(path_hash, path);
        if (!data) {
            dir = g_path_get_dirname(path);
            data = g_hash_table_lookup(path_hash, dir);

            if (!data) {
                GAM_DEBUG(DEBUG_INFO, "  not found !!!\n");

                if (dir != NULL)
                    g_free(dir);
                G_UNLOCK(inotify);
                return;
            }
            GAM_DEBUG(DEBUG_INFO, "  not found using parent\n");
        }
        if (data != NULL) {
	    if (mode == GAMIN_FLOWCONTROLSTART) {
		GAM_DEBUG(DEBUG_INFO, "inotify: GAMIN_FLOWCONTROLSTART for %s\n", data->path);
		if (data->wd >= 0) {
		    if (ioctl (inotify_device_fd, INOTIFY_IGNORE, &data->wd) < 0) {
			GAM_DEBUG (DEBUG_INFO, "INOTIFY_IGNORE failed for %s (wd = %d)\n", data->path, data->wd);
		    }
		    data->deactivated = TRUE;
		    GAM_DEBUG(DEBUG_INFO, "deactivated inotify for %s\n",
			      data->path);
#ifdef GAMIN_DEBUG_API
		    gam_debug_report(GAMinotifyFlowOn, dir, 0);
#endif
		}
		data->busy++;
	    } else {
		GAM_DEBUG(DEBUG_INFO, "inotify: GAMIN_FLOWCONTROLSTOP for %s\n", data->path);
	        if (data->busy > 0) {
		    GAM_DEBUG(DEBUG_INFO, "inotify: data->busy > 0 for %s\n", data->path);
		    data->busy--;
		    if (data->busy == 0) {
			GAM_DEBUG(DEBUG_INFO, "inotify: data->busy == 0 for %s\n", data->path);
			path_fd = open(data->path, O_RDONLY);
			if (path_fd < 0) {
			    G_UNLOCK(inotify);
			    GAM_DEBUG(DEBUG_INFO,
			              "failed to reactivate inotify for %s\n",
				      data->path);

                            if ((dir != path) && (dir != NULL))
                                g_free(dir);
                            return;
			}

			iwr.fd = path_fd;
			iwr.mask = 0xffffffff;
			path_wd = ioctl (inotify_device_fd, INOTIFY_WATCH, &iwr);
			close (path_fd);

			/* Remove the old wd from the hash table */
			g_hash_table_remove(wd_hash, GINT_TO_POINTER(data->wd));

			data->wd = path_wd;
			data->deactivated = FALSE;

			/* Insert the new wd into the hash table */
			g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd),
			                    data);
			GAM_DEBUG(DEBUG_INFO, "reactivated inotify for %s\n",
			          data->path);
#ifdef GAMIN_DEBUG_API
			gam_debug_report(GAMinotifyFlowOff, path, 0);
#endif
		    }
		}
	    }
	}
        if ((dir != path) && (dir != NULL))
            g_free(dir);
    } else {
	GAM_DEBUG(DEBUG_INFO, "Unimplemented operation\n");
    }

    G_UNLOCK(inotify);
}

static void
gam_inotify_directory_handler(const char *path, pollHandlerMode mode)
{
    GAM_DEBUG(DEBUG_INFO, "gam_inotify_directory_handler %s : %d\n",
              path, mode);

    if ((mode == GAMIN_DESACTIVATE) ||
        (g_file_test(path, G_FILE_TEST_IS_DIR))) {
	gam_inotify_directory_handler_internal(path, mode);
    } else {
	char *dir;

	dir = g_path_get_dirname(path);
	GAM_DEBUG(DEBUG_INFO, " not a dir using parent %s\n", dir);
	gam_inotify_directory_handler_internal(dir, mode);
	g_free(dir);
    }
}

static void
gam_inotify_file_handler(const char *path, pollHandlerMode mode)
{
    GAM_DEBUG(DEBUG_INFO, "gam_inotify_file_handler %s : %d\n", path, mode);
    
    if (g_file_test(path, G_FILE_TEST_IS_DIR)) {
	gam_inotify_directory_handler_internal(path, mode);
    } else {
	char *dir;

	dir = g_path_get_dirname(path);
	GAM_DEBUG(DEBUG_INFO, " not a dir using parent %s\n", dir);
	gam_inotify_directory_handler_internal(dir, mode);
	g_free(dir);
    }
}

static gboolean
gam_inotify_read_handler(gpointer user_data)
{
    char *buffer;
    int buffer_size;
    int events;
    gsize buffer_i, read_size;

    G_LOCK(inotify);

#if 0
    gam_inotify_dirty_list_cleaner ();
#endif

    if (ioctl(inotify_device_fd, FIONREAD, &buffer_size) < 0) {
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
    events = 0;
    while (buffer_i < read_size) {
	struct inotify_event *event;
	gsize event_size;
	inotify_data_t *data;

	event = (struct inotify_event *)&buffer[buffer_i];
	event_size = sizeof(struct inotify_event) + event->len;

	data = g_hash_table_lookup (wd_hash, GINT_TO_POINTER(event->wd));
	if (!data) {
	    GAM_DEBUG(DEBUG_INFO, "processing event: inotify can't find wd %d\n", event->wd);
	} else if (data->deactivated) {
	    GAM_DEBUG(DEBUG_INFO, "inotify: ignoring event on temporarily deactivated watch %s\n", data->path);
	} else {
	    if (event->mask == IN_IGNORED) {
		GList *l;

		GAM_DEBUG(DEBUG_INFO, "inotify: IN_IGNORE on wd=%d\n", event->wd);
		GAM_DEBUG(DEBUG_INFO, "inotify: removing all subscriptions for %s\n", data->path);

		l = data->subs;
		data->subs = NULL;
		for (l = l; l; l = l->next) {
		    GamSubscription *sub = l->data;
		    gam_inotify_remove_subscription (sub);
		}
	    } else if (event->mask != IN_Q_OVERFLOW) {
		if (event->mask & should_poll_mask) {
		    GAM_DEBUG(DEBUG_INFO, "inotify requesting poll for %s\n", data->path);
		    GAM_DEBUG(DEBUG_INFO, "poll was requested for event = ");
		    print_mask (event->mask);
		    gam_poll_scan_directory (data->path);
		}
	    } else if (event->mask == IN_Q_OVERFLOW) {
		    GAM_DEBUG(DEBUG_INFO, "inotify queue over flowed\n");
		    GAM_DEBUG(DEBUG_INFO, "FIXME, should request poll for all paths here\n");
	    }
	}

        buffer_i += event_size;
	events++;
    }
    GAM_DEBUG(DEBUG_INFO, "inotify recieved %d events\n", events);

    g_free(buffer);
    G_UNLOCK(inotify);

    return TRUE;
}


static gboolean
gam_inotify_consume_subscriptions_real(gpointer data)
{
    GAM_DEBUG(DEBUG_INFO, "gam_inotify_consume_subscriptions_real()\n");
    gam_poll_consume_subscriptions();
    have_consume_idler = FALSE;
    return FALSE;
}

static void
gam_inotify_consume_subscriptions(void)
{
    GSource *source;

    if (have_consume_idler)
        return;

    GAM_DEBUG(DEBUG_INFO, "gam_inotify_consume_subscriptions()\n");
    have_consume_idler = TRUE;
    source = g_idle_source_new();
    g_source_set_callback(source, gam_inotify_consume_subscriptions_real,
                          NULL, NULL);
    g_source_attach(source, NULL);
}

/**
 * @defgroup inotify inotify Backend
 * @ingroup Backends
 * @brief inotify backend API
 *
 * Since version 2.6.X, Linux kernels have included the Linux Inode
 * Notification system (inotify).  This backend uses inotify to know when
 * files are changed/created/deleted.  Since inotify can't watch files/dirs that
 * don't exist we still have to cache stat() information. For this,
 * we can just use the code in the polling backend.
 *
 * @{
 */


/**
 * Initializes the inotify backend.  This must be called before
 * any other functions in this module.
 *
 * @returns TRUE if initialization succeeded, FALSE otherwise
 */
gboolean
gam_inotify_init(void)
{
    GSource *source;

    inotify_device_fd = open("/dev/inotify", O_RDONLY);

    if (inotify_device_fd < 0) {
		GAM_DEBUG(DEBUG_INFO, "Could not open /dev/inotify\n");
		return FALSE;
    }

    g_return_val_if_fail(gam_poll_init_full(FALSE), FALSE);

	inotify_read_ioc = g_io_channel_unix_new(inotify_device_fd);

    /* For binary data */
    g_io_channel_set_encoding(inotify_read_ioc, NULL, NULL);
    /* Non blocking */
    g_io_channel_set_flags(inotify_read_ioc, G_IO_FLAG_NONBLOCK, NULL);

    source = g_io_create_watch(inotify_read_ioc,
			       G_IO_IN | G_IO_HUP | G_IO_ERR);
    g_source_set_callback(source, gam_inotify_read_handler, NULL, NULL);

    g_source_attach(source, NULL);

    path_hash = g_hash_table_new(g_str_hash, g_str_equal);
    wd_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    gam_poll_set_kernel_handler(gam_inotify_directory_handler,
                                gam_inotify_file_handler,
				GAMIN_K_INOTIFY);

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
    GAM_DEBUG(DEBUG_INFO, "gam_inotify_add_subscription\n");
    if (!gam_poll_add_subscription(sub)) {
        return FALSE;
    }

    gam_inotify_consume_subscriptions();

    GAM_DEBUG(DEBUG_INFO, "gam_inotify_add_subscription: done\n");
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
    GAM_DEBUG(DEBUG_INFO, "gam_inotify_remove_subscription\n");

    if (!gam_poll_remove_subscription(sub)) {
        return FALSE;
    }

    gam_inotify_consume_subscriptions();

    GAM_DEBUG(DEBUG_INFO, "gam_inotify_remove_subscription: done\n");
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
    if (!gam_poll_remove_all_for(listener)) {
        return FALSE;
    }

    gam_inotify_consume_subscriptions();

    return TRUE;
}

/** @} */
