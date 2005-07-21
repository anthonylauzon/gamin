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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <glib.h>
#include "gam_error.h"
#include "gam_poll.h"
#ifdef HAVE_LINUX_INOTIFY_H
#include <linux/inotify.h>
#else
#include "local_inotify.h"
#endif
#include "local_inotify_syscalls.h"
#include "gam_inotify.h"
#include "gam_tree.h"
#include "gam_event.h"
#include "gam_server.h"
#include "gam_event.h"
#ifdef GAMIN_DEBUG_API
#include "gam_debugging.h"
#endif

#include <errno.h>

int gam_inotify_add_watch (const char *path, __u32 mask);
int gam_inotify_rm_watch (const char *path, __u32 wd);
void gam_inotify_read_events (gsize *buffer_size_out, struct inotify_event **buffer_out);

typedef struct {
    char *path;
    int wd;
    int refcount;
    int busy;
    gboolean deactivated;
    gboolean ignored;
    int events;
    int deactivated_events;
    int ignored_events;
} inotify_data_t;

static GHashTable *path_hash = NULL;
static GHashTable *wd_hash = NULL;

G_LOCK_DEFINE_STATIC(inotify);

static GIOChannel *inotify_read_ioc = NULL;

static gboolean have_consume_idler = FALSE;

static int inotify_device_fd = -1;

static guint should_poll_mask = IN_MODIFY|IN_ATTRIB|IN_CLOSE_WRITE|IN_MOVED_FROM|IN_MOVED_TO|IN_DELETE|IN_CREATE|IN_DELETE_SELF|IN_UNMOUNT;

static void 
gam_inotify_data_debug (gpointer key, gpointer value, gpointer user_data)
{
    inotify_data_t *data = (inotify_data_t *)value;

    if (!data)
        return;

    int deactivated = data->deactivated;
    int ignored = data->ignored;

    GAM_DEBUG(DEBUG_INFO, "isub wd %d refs %d busy %d deactivated %d ignored %d events (%d:%d:%d): %s\n", data->wd, data->refcount, data->busy, deactivated, ignored, data->events, data->deactivated_events, data->ignored_events, data->path);
}

void
gam_inotify_debug(void)
{
    if (inotify_device_fd == -1)
    {
        GAM_DEBUG(DEBUG_INFO, "Inotify device not opened\n");
        return;
    }

    if (path_hash == NULL)
        return;

    GAM_DEBUG(DEBUG_INFO, "Inotify device fd = %d\n", inotify_device_fd);
    GAM_DEBUG(DEBUG_INFO, "Dumping inotify subscriptions\n");
    g_hash_table_foreach (path_hash, gam_inotify_data_debug, NULL);
}

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

    g_assert (wd >= 0);

    data = g_new0(inotify_data_t, 1);
    data->path = g_strdup(path);
    data->wd = wd;
    data->refcount = 1;
    data->busy = 0;
    data->deactivated = FALSE;
    data->ignored = FALSE;
    data->events = 0;
    data->deactivated_events = 0;
    data->ignored_events = 0;

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
	int path_wd = -1;

	switch (mode) {
	case GAMIN_ACTIVATE:
	case GAMIN_DESACTIVATE:
	case GAMIN_FLOWCONTROLSTART:
	case GAMIN_FLOWCONTROLSTOP:
		break;
	default:
		gam_error(DEBUG_INFO, "Unknown operation %d for %s\n", mode, path);
		return;
	}

	G_LOCK(inotify);

	if (mode == GAMIN_ACTIVATE) {
		data = g_hash_table_lookup (path_hash, path);

		if (data != NULL) {
			data->refcount++;
			GAM_DEBUG (DEBUG_INFO, "inotify: incremented refcount for %s (ref = %d)\n", path, data->refcount);
#ifdef GAMIN_DEBUG_API
			gam_debug_report(GAMDnotifyChange, path, data->refcount);
#endif
			G_UNLOCK(inotify);
			return;
		}

		/* We aren't already watching this path */
		path_wd = gam_inotify_add_watch (path, should_poll_mask);
		if (path_wd < 0) {
			G_UNLOCK(inotify);
			return;
		}

		data = gam_inotify_data_new (path, path_wd);
		g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd), data);
		g_hash_table_insert(path_hash, data->path, data);
#ifdef GAMIN_DEBUG_API
		gam_debug_report(GAMDnotifyCreate, path, 0);
#endif
		G_UNLOCK(inotify);
		return;
	} else if (mode == GAMIN_DESACTIVATE) {
		data = g_hash_table_lookup(path_hash, path);

		if (!data) {
			GAM_DEBUG (DEBUG_INFO, "inotify: requested DEACTIVATE on unknown path: %s\n", data->path);
			G_UNLOCK (inotify);
			return;
		}

		data->refcount--;
		GAM_DEBUG (DEBUG_INFO, "inotify: decremented refcount for %s (ref = %d)\n", path, data->refcount);

		if (data->refcount == 0) {
		    int wd = data->wd;
		    g_assert (wd >= 0);

		    GAM_DEBUG (DEBUG_INFO, "inotify: refcount == 0 for %s (wd = %d)\n", path, wd);
		    g_hash_table_remove(path_hash, data->path);
		    g_hash_table_remove(wd_hash, GINT_TO_POINTER(data->wd));

		    if (data->ignored) {
			    GAM_DEBUG (DEBUG_INFO, "inotify: removing IGNORED watch for %s (wd = %d)\n", data->path, data->wd);
		    }

		    if (data->deactivated == FALSE) {
			    gam_inotify_rm_watch (data->path, data->wd);
		    } else {
			    GAM_DEBUG (DEBUG_INFO, "inotify: removing deactivated watch for %s\n", data->path);
		    }
#ifdef GAMIN_DEBUG_API
		    gam_debug_report(GAMDnotifyDelete, data->path, 0);
#endif
		    gam_inotify_data_free(data);
		    G_UNLOCK (inotify);
		    return;
		} else {
#ifdef GAMIN_DEBUG_API
		    gam_debug_report(GAMDnotifyChange, data->path, data->refcount);
#endif
		}
	} 
	else if ((mode == GAMIN_FLOWCONTROLSTART) || (mode == GAMIN_FLOWCONTROLSTOP))
	{
		data = g_hash_table_lookup(path_hash, path);

		if (!data) {
			GAM_DEBUG (DEBUG_INFO, "inotify: requested FLOWOP on unknown path: %s\n", data->path);
			G_UNLOCK (inotify);
			return;
		}

		if (mode == GAMIN_FLOWCONTROLSTART) {
			if (!data->deactivated) {
				GAM_DEBUG (DEBUG_INFO, "inotify: enabling flow control for %s\n", data->path);
				if (gam_inotify_rm_watch (data->path, data->wd) < 0)
				{
					G_UNLOCK(inotify);
					return;
				}
				data->deactivated = TRUE;
#ifdef GAMIN_DEBUG_API
				gam_debug_report(GAMDnotifyFlowOn, data->path, 0);
#endif
			}
			data->busy++;
			GAM_DEBUG (DEBUG_INFO, "inotify: incremented busy count for %s (busy = %d)\n", data->path, data->busy);
			G_UNLOCK(inotify);
			return;
		} else {
			if (data->busy > 0) {
				data->busy--;
				GAM_DEBUG (DEBUG_INFO, "inotify: incremented busy count for %s (busy = %d)\n", data->path, data->busy);
				if (data->busy == 0) {
					GAM_DEBUG(DEBUG_INFO, "inotify: disabling flow control for %s\n", data->path);

					path_wd = gam_inotify_add_watch (data->path, should_poll_mask);

					if (path_wd < 0) {
						G_UNLOCK(inotify);
						return;
					}

					g_assert (data->wd >= 0);
					g_assert (path_wd >= 0);

					/* Remove the old wd from the hash table */
					g_hash_table_remove(wd_hash, GINT_TO_POINTER(data->wd));


					/* Insert the new wd into the hash table */
					data->wd = path_wd;
					data->deactivated = FALSE;
					g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd), data);
#ifdef GAMIN_DEBUG_API
					gam_debug_report(GAMDnotifyFlowOff, path, 0);
#endif
					G_UNLOCK(inotify);
					return;
				}
			} else {
				GAM_DEBUG (DEBUG_INFO, "inotify: requested FLOWSTOP for watch with busy count <= 0 for %s (busy = %d)\n", data->path, data->busy);
				G_UNLOCK (inotify);
				return;
			}
		}
	}
}

static void
gam_inotify_directory_handler(const char *path, pollHandlerMode mode)
{
    GAM_DEBUG(DEBUG_INFO, "gam_inotify_directory_handler %s : %d\n",
              path, mode);

    gam_inotify_directory_handler_internal(path, mode);
}

static void
gam_inotify_file_handler(const char *path, pollHandlerMode mode)
{
    GAM_DEBUG(DEBUG_INFO, "gam_inotify_file_handler %s : %d\n", path, mode);
    
    if (g_file_test(path, G_FILE_TEST_IS_DIR)) {
	gam_inotify_directory_handler_internal(path, mode);
    } else {
	GAM_DEBUG(DEBUG_INFO, " not a dir %s, FAILED!!!\n", path);
    }
}

static void 
gam_inotify_q_overflow (gpointer key, gpointer value, gpointer user_data)
{
    inotify_data_t *data = (inotify_data_t *)value;

    gam_poll_scan_directory (data->path);
}

static gboolean
gam_inotify_read_handler(gpointer user_data)
{
	struct inotify_event *buffer;
	gsize buffer_size, buffer_i, events;

        G_LOCK(inotify);

        gam_inotify_read_events (&buffer_size, &buffer);

        buffer_i = 0;
        events = 0;

        while (buffer_i < buffer_size) {
                struct inotify_event *event;
                gsize event_size;
                inotify_data_t *data;

                event = (struct inotify_event *)&buffer[buffer_i];
                event_size = sizeof(struct inotify_event) + event->len;

                data = g_hash_table_lookup (wd_hash, GINT_TO_POINTER(event->wd));

                if (!data) {
                        GAM_DEBUG (DEBUG_INFO, "inotify: got an event for unknown wd %d\n", event->wd);
                } else if (data->deactivated) {
                        GAM_DEBUG (DEBUG_INFO, "inotify: ignoring event on temporarily deactivated watch %s\n", data->path);
                        data->deactivated_events++;
                } else if (data->ignored) {
                        GAM_DEBUG (DEBUG_INFO, "inotify: got event on ignored watch %s\n", data->path);
                        data->ignored_events++;
                } else {
                        if (event->mask & IN_IGNORED) {
                                GAM_DEBUG (DEBUG_INFO, "inotify: IN_IGNORE on wd=%d\n", event->wd);
                                data->ignored = TRUE;
                                data->ignored_events++;
                        } else if (!(event->mask & IN_Q_OVERFLOW)) {
                                if (event->mask & should_poll_mask) {
                                        GAM_DEBUG (DEBUG_INFO, "inotify: requesting poll for %s event = ", data->path);
                                        print_mask (event->mask);
                                        data->events++;
                                        gam_poll_scan_directory (data->path);
                                }
                        } else if (event->mask & IN_Q_OVERFLOW) {
                                GAM_DEBUG (DEBUG_INFO, "inotify: queue over flowed, requesting poll on all watched paths\n");
                                g_hash_table_foreach (path_hash, gam_inotify_q_overflow, NULL);
                        }
                }

                buffer_i += event_size;
                events++;
        }

	GAM_DEBUG(DEBUG_INFO, "inotify recieved %d events\n", events);

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

    g_return_val_if_fail(gam_poll_init_full(FALSE), FALSE);

    inotify_device_fd = inotify_init ();

    if (inotify_device_fd < 0) {
        GAM_DEBUG(DEBUG_INFO, "Could not open /dev/inotify\n");
	GAM_DEBUG(DEBUG_INFO, "fd = %d\n", inotify_device_fd);
        return FALSE;
    }

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


int gam_inotify_add_watch (const char *path, __u32 mask)
{
	int wd = -1;

	g_assert (path&&*path);
	g_assert (inotify_device_fd >= 0);

	wd = inotify_add_watch (inotify_device_fd, path, mask);

	if (wd < 0)
	{
		int e = errno;
		GAM_DEBUG (DEBUG_INFO, "inotify: failed to add watch for %s\n", path);
		GAM_DEBUG (DEBUG_INFO, "inotify: reason = %s\n", strerror (e));
		return wd;
	} 
	else 
	{
		GAM_DEBUG (DEBUG_INFO, "inotify: success adding watch for %s (wd = %d)\n", path, wd);
	}

	g_assert (wd >= 0);

	return wd;
}

int gam_inotify_rm_watch (const char *path, __u32 wd)
{
	g_assert (wd >= 0);

	if (inotify_rm_watch (inotify_device_fd, wd) < 0) 
	{
		int e = errno;
		GAM_DEBUG (DEBUG_INFO, "inotify: failed to rm watch for %s (wd = %d)\n", path, wd);
		GAM_DEBUG (DEBUG_INFO, "inotify: reason = %s\n", strerror (e));
		return -1;
	}
	else
	{
		GAM_DEBUG (DEBUG_INFO, "inotify: success removing watch for %s (wd = %d)\n", path, wd);
	}

	return 0;
}

/* Code below based on beagle inotify glue code. I assume it was written by Robert Love */
#define MAX_PENDING_COUNT 5
#define PENDING_THRESHOLD(qsize) ((qsize) >> 1)
#define PENDING_MARGINAL_COST(p) ((unsigned int)(1 << (p)))
#define MAX_QUEUED_EVENTS 8192
#define AVERAGE_EVENT_SIZE sizeof (struct inotify_event) + 16
#define PENDING_PAUSE_MICROSECONDS 2000

void gam_inotify_read_events (gsize *buffer_size_out, struct inotify_event **buffer_out)
{
        static int prev_pending = 0, pending_count = 0;
        static struct inotify_event *buffer = NULL;
        static gsize buffer_size;


        /* Initialize the buffer on our first read() */
        if (buffer == NULL)
        {
                buffer_size = AVERAGE_EVENT_SIZE;
                buffer_size *= MAX_QUEUED_EVENTS;
                buffer = g_malloc (buffer_size);

                if (!buffer) {
                        *buffer_size_out = 0;
                        *buffer_out = NULL;
                        GAM_DEBUG (DEBUG_INFO, "inotify: could not allocate read buffer\n");
                        return;
                }
        }

        *buffer_size_out = 0;
        *buffer_out = NULL;

        while (pending_count < MAX_PENDING_COUNT) {
                unsigned int pending;

                if (ioctl (inotify_device_fd, FIONREAD, &pending) == -1)
                        break;

                pending /= AVERAGE_EVENT_SIZE;

                /* Don't wait if the number of pending events is too close
                 * to the maximum queue size.
                 */

                if (pending > PENDING_THRESHOLD (MAX_QUEUED_EVENTS))
                        break;

                /* With each successive iteration, the minimum rate for
                 * further sleep doubles. */

                if (pending-prev_pending < PENDING_MARGINAL_COST(pending_count))
                        break;

		prev_pending = pending;
                pending_count++;

                /* We sleep for a bit and try again */
                g_usleep (PENDING_PAUSE_MICROSECONDS);
        }

        if (g_io_channel_read_chars (inotify_read_ioc, (char *)buffer, buffer_size, buffer_size_out, NULL) != G_IO_STATUS_NORMAL) {
                GAM_DEBUG (DEBUG_INFO, "inotify: failed to read from buffer\n");
        }
        *buffer_out = buffer;

        prev_pending = 0;
        pending_count = 0;
}

/** @} */
