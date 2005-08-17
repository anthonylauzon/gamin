/* gamin inotify backend
 * Copyright (C) 2005 John McCutchan
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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <time.h>
#include <glib.h>
#ifdef GAMIN_DEBUG_API
#include "gam_debugging.h"
#endif
#include "gam_error.h"
#include "gam_poll_generic.h"
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
#include "gam_fs.h"

#define GAM_INOTIFY_SANITY
#define GAM_INOTIFY_WD_MISSING -1
#define GAM_INOTIFY_WD_PERM -2
#define GAM_INOTIFY_WD_LINK -3

/* Timings for pairing MOVED_TO / MOVED_FROM events */
/* These numbers are in microseconds */
#define DEFAULT_HOLD_UNTIL_TIME 1000 /* 1 ms */
#define MOVE_HOLD_UNTIL_TIME 5000 /* 5 ms */

/* Timings for main loop */
/* These numbers are in milliseconds */
#define SCAN_MISSING_TIME 1000 /* 1 Hz */
#define SCAN_LINKS_TIME 1000 /* 1 Hz */
#define PROCESS_EVENTS_TIME 33 /* 30 Hz */ 

typedef struct {
	/* The full pathname of this node */
	char *path;
	gboolean dir; /* Is this path a directory */

	/* Inotify */
	int wd;

	/* State */
	gboolean busy;
	gboolean missing;
	gboolean link;
	gboolean permission; /* Exists, but don't have read access */
	gboolean deactivated;
	gboolean ignored;
	int refcount;

	/* Statistics */
	int events;
	int deactivated_events;
	int ignored_events;

	/* Gamin state */
	GList *subs;
} inotify_data_t;

typedef struct _inotify_event_t {
	gint wd;
	gint mask;
	gint cookie;
	char *name;
	gboolean seen;
	gboolean sent;
	GTimeVal hold_until;
	struct _inotify_event_t *pair; 
} inotify_event_t;

typedef struct {
	char *path;
	GTime last_scan_time;
	GTime scan_interval;
	gboolean permission;
} inotify_missing_t;

typedef struct {
	char *path;
	struct stat sbuf;
	GTime last_scan_time;
	GTime scan_interval;
} inotify_links_t;

static GHashTable *	path_hash = NULL;
static GHashTable *	wd_hash = NULL;
static GList *		missing_list = NULL;
static GList *		links_list = NULL;
static GHashTable *	cookie_hash = NULL;
static GQueue *		event_queue = NULL;
static GQueue *		events_to_process = NULL;
static GIOChannel *	inotify_read_ioc = NULL;
static int		inotify_device_fd = -1;

#define GAM_INOTIFY_MASK (IN_MODIFY|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|IN_DELETE|IN_CREATE|IN_DELETE_SELF|IN_UNMOUNT|IN_MOVE_SELF)

static int 	gam_inotify_add_watch 		(const char *path, __u32 mask, int *err);
static int 	gam_inotify_rm_watch 		(const char *path, __u32 wd);
static void 	gam_inotify_read_events 	(gsize *buffer_size_out, gchar **buffer_out);

static gboolean gam_inotify_is_missing		(const char *path);
static gboolean gam_inotify_nolonger_missing 	(const char *path);
static void 	gam_inotify_add_missing 	(const char *path, gboolean perm);
static void 	gam_inotify_rm_missing 		(const char *path);
static gboolean gam_inotify_scan_missing 	(gpointer userdata);

static gboolean	gam_inotify_is_link		(const char *path);
static gboolean gam_inotify_nolonger_link	(const char *path);
static void	gam_inotify_add_link		(const char *path);
static void	gam_inotify_rm_link		(const char *path);
static gboolean	gam_inotify_scan_links		(gpointer userdata);
static void	gam_inotify_poll_link		(inotify_links_t *links);

static void 	gam_inotify_sanity_check	(void);

static gboolean	g_timeval_lt			(GTimeVal *val1, GTimeVal *val2);
static gboolean	g_timeval_eq			(GTimeVal *val1, GTimeVal *val2);

static void 
gam_inotify_data_debug (gpointer key, gpointer value, gpointer user_data)
{
	int busy;
	int deactivated;
	int ignored;
	int missing;
	int permission;
	inotify_data_t *data = (inotify_data_t *)value;

	if (!data)
		return;

	busy = data->busy;
	deactivated = data->deactivated;
	ignored = data->ignored;
	missing = data->missing;
	permission = data->permission;

	GAM_DEBUG(DEBUG_INFO, "isub wd %d refs %d permission %d missing %d busy %d deactivated %d ignored %d events (%d:%d:%d): %s\n", data->wd, data->refcount, permission, missing, busy, deactivated, ignored, data->events, data->deactivated_events, data->ignored_events, data->path);
}

gboolean
gam_inotify_is_running(void)
{
	return inotify_device_fd >= 0;
}

void
gam_inotify_debug(void)
{
	if (inotify_device_fd == -1)
	{
		return;
	}

	if (path_hash == NULL)
		return;

	GAM_DEBUG(DEBUG_INFO, "Inotify device fd = %d\n", inotify_device_fd);
	GAM_DEBUG(DEBUG_INFO, "Dumping inotify subscriptions\n");
	g_hash_table_foreach (path_hash, gam_inotify_data_debug, NULL);
}

static const char *
mask_to_string (int mask)
{
	mask &= ~IN_ISDIR;
	switch (mask)
	{
	case IN_ACCESS:
		return "ACCESS";
	break;
	case IN_MODIFY:
		return "MODIFY";
	break;
	case IN_ATTRIB:
		return "ATTRIB";
	break;
	case IN_CLOSE_WRITE:
		return "CLOSE_WRITE";
	break;
	case IN_CLOSE_NOWRITE:
		return "CLOSE_NOWRITE";
	break;
	case IN_OPEN:
		return "OPEN";
	break;
	case IN_MOVED_FROM:
		return "MOVED_FROM";
	break;
	case IN_MOVED_TO:
		return "MOVED_TO";
	break;
	case IN_DELETE:
		return "DELETE";
	break;
	case IN_CREATE:
		return "CREATE";
	break;
	case IN_DELETE_SELF:
		return "DELETE_SELF";
	break;
	case IN_UNMOUNT:
		return "UNMOUNT";
	break;
	case IN_Q_OVERFLOW:
		return "Q_OVERFLOW";
	break;
	case IN_IGNORED:
		return "IGNORED";
	break;
	default:
		return "UNKNOWN_EVENT";
	break;
	}
}

static GaminEventType
mask_to_gam_event (gint mask)
{
	mask &= ~IN_ISDIR;
	switch (mask)
	{
	case IN_MODIFY:
	case IN_ATTRIB:
		return GAMIN_EVENT_CHANGED;
	break;
	case IN_MOVE_SELF:
	case IN_MOVED_FROM:
	case IN_DELETE:
	case IN_DELETE_SELF:
		return GAMIN_EVENT_DELETED;
	break;
	case IN_CREATE:
	case IN_MOVED_TO:
		return GAMIN_EVENT_CREATED;
	break;
	case IN_Q_OVERFLOW:
	case IN_OPEN:
	case IN_CLOSE_WRITE:
	case IN_CLOSE_NOWRITE:
	case IN_UNMOUNT:
	case IN_ACCESS:
	case IN_IGNORED:
	default:
		return GAMIN_EVENT_UNKNOWN;
	break;
	}
}

/* Called when a directory is being watched as a file */
static GaminEventType
gam_inotify_mask_to_gam_file_event (gint mask)
{
	mask &= ~IN_ISDIR;
	switch (mask)
	{
	case IN_MOVED_FROM:
	case IN_DELETE:
	case IN_CREATE:
	case IN_MOVED_TO:
		return GAMIN_EVENT_CHANGED;
	break;
	case IN_MOVE_SELF:
	case IN_DELETE_SELF:
		return GAMIN_EVENT_DELETED;
	break;
	case IN_ATTRIB:
	case IN_MODIFY:
	case IN_Q_OVERFLOW:
	case IN_OPEN:
	case IN_CLOSE_WRITE:
	case IN_CLOSE_NOWRITE:
	case IN_UNMOUNT:
	case IN_ACCESS:
	case IN_IGNORED:
	default:
		return GAMIN_EVENT_UNKNOWN;
	break;
	}
}

/* Called when a file is watched as a directory */
static GaminEventType
gam_inotify_mask_to_gam_dir_event (gint mask)
{
	mask &= ~IN_ISDIR;
	switch (mask)
	{
	case IN_MOVED_FROM:
	case IN_DELETE:
	case IN_CREATE:
	case IN_MOVED_TO:
	case IN_MOVE_SELF:
	case IN_DELETE_SELF:
	case IN_ATTRIB:
	case IN_MODIFY:
	case IN_Q_OVERFLOW:
	case IN_OPEN:
	case IN_CLOSE_WRITE:
	case IN_CLOSE_NOWRITE:
	case IN_UNMOUNT:
	case IN_ACCESS:
	case IN_IGNORED:
	default:
		return GAMIN_EVENT_UNKNOWN;
	break;
	}
}

static inotify_data_t *
gam_inotify_data_new(const char *path, int wd, gboolean dir)
{
	inotify_data_t *data;

	data = g_new0(inotify_data_t, 1);

	data->path = g_strdup(path);
	data->wd = wd;
	data->busy = FALSE;
	if (wd == GAM_INOTIFY_WD_MISSING)
		data->missing = TRUE;
	else
		data->missing = FALSE;
	if (wd == GAM_INOTIFY_WD_PERM)
		data->permission = TRUE;
	else
		data->permission = FALSE;
	if (wd == GAM_INOTIFY_WD_LINK)
		data->link = TRUE;
	else
		data->link = FALSE;
	data->deactivated = FALSE;
	data->ignored = FALSE;
	data->refcount = 1;
	data->events = 0;
	data->deactivated_events = 0;
	data->ignored_events = 0;
	data->dir = dir;
	
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

static inotify_event_t *
gam_inotify_event_new (struct inotify_event *event)
{
	inotify_event_t *gam_event;
	GTimeVal tv;

	gam_event = g_new0(inotify_event_t, 1);

	gam_event->wd = event->wd;
	gam_event->mask = event->mask;
	gam_event->cookie = event->cookie;

	if (event->len) 
	{
		gam_event->name = g_strdup (event->name);
	} else {
		gam_event->name = g_strdup ("");
	}

	g_get_current_time (&tv);
	g_time_val_add (&tv, DEFAULT_HOLD_UNTIL_TIME);
	gam_event->hold_until = tv;

	return gam_event;
}

static void
gam_inotify_event_free (inotify_event_t *event)
{
	g_free (event->name);
	g_free (event);
}

static void
gam_inotify_event_pair_with (inotify_event_t *event1, inotify_event_t *event2)
{
	g_assert (event1 && event2);
	/* We should only be pairing events that have the same cookie */
	g_assert (event1->cookie == event2->cookie);
	/* We shouldn't pair an event that already is paired */
	g_assert (event1->pair == NULL && event2->pair == NULL);
	event1->pair = event2;
	event2->pair = event1;
	
	GAM_DEBUG(DEBUG_INFO, "inotify: pairing a MOVE together\n");
	if (g_timeval_lt (&event1->hold_until, &event2->hold_until))
		event1->hold_until = event2->hold_until;

	event2->hold_until = event1->hold_until;
}

static void
gam_inotify_event_add_microseconds (inotify_event_t *event, glong ms)
{
	g_assert (event);
	g_time_val_add (&event->hold_until, ms);
}

static gboolean
gam_inotify_event_ready (inotify_event_t *event)
{
	GTimeVal tv;
	g_assert (event);

	g_get_current_time (&tv);

	/* An event is ready if,
	 *
	 * it has no cookie -- there is nothing to be gained by holding it
	 * or, it is already paired -- we don't need to hold it anymore
	 * or, we have held it long enough
	 */
	return event->cookie == 0 || 
	       event->pair != NULL ||
	       g_timeval_lt(&event->hold_until, &tv) || g_timeval_eq(&event->hold_until, &tv);
}

static void
gam_inotify_emit_one_event (inotify_data_t *data, inotify_event_t *event, GamSubscription *sub)
{
	gint force = 1;
	gint is_dir_node = 0;
	GaminEventType gevent;
	gchar *fullpath = NULL;
	gboolean watching_dir_as_file;
	gboolean watching_file_as_dir;

	g_assert (data && event);

	is_dir_node = event->mask & IN_ISDIR;
	watching_dir_as_file = data->dir && !gam_subscription_is_dir (sub);
	watching_file_as_dir = !data->dir && gam_subscription_is_dir (sub);

	if (watching_dir_as_file)
	{
		gevent = gam_inotify_mask_to_gam_file_event (event->mask);
		fullpath = g_strdup (data->path);
	} else if (watching_file_as_dir) {
		gevent = gam_inotify_mask_to_gam_dir_event (event->mask);
		fullpath = g_strdup (data->path);
	} else {
		gevent = mask_to_gam_event (event->mask);
		if (strlen (event->name) == 0)
			fullpath = g_strdup (data->path);
		else
			fullpath = g_strdup_printf ("%s/%s", data->path, event->name);
	}

	if (gevent == GAMIN_EVENT_UNKNOWN) {
		GAM_DEBUG(DEBUG_INFO, "inotify: Not handling event %d\n", event->mask);
		g_free (fullpath);
		return;
	}

	GAM_DEBUG(DEBUG_INFO, "inotify: Emitting %s on %s\n", gam_event_to_string (gevent), fullpath);
	gam_server_emit_one_event (fullpath, is_dir_node, gevent, sub, force);
	g_free(fullpath);
}

static void
gam_inotify_emit_events (inotify_data_t *data, inotify_event_t *event)
{
	GList *l;

	if (!data||!event)
		return;

	for (l = data->subs; l; l = l->next) {
		GamSubscription *sub = l->data;
		gam_inotify_emit_one_event (data, event, sub);
	}
}

static void
gam_inotify_process_event (inotify_event_t *event)
{
	inotify_data_t *data = NULL;

	data = g_hash_table_lookup (wd_hash, GINT_TO_POINTER(event->wd));

	if (!data) 
	{
		GAM_DEBUG (DEBUG_INFO, "inotify: got %s event for unknown wd %d\n", mask_to_string (event->mask), event->wd);
		return;
	}

	if (data->deactivated) 
	{
		GAM_DEBUG (DEBUG_INFO, "inotify: ignoring event on temporarily deactivated watch %s\n", data->path);
		data->deactivated_events++;
		return;
	}

	if (data->ignored) {
		GAM_DEBUG (DEBUG_INFO, "inotify: got event on ignored watch %s\n", data->path);
		data->ignored_events++;
		return;
	} 

	if (event->mask & IN_IGNORED) 
	{
		data->ignored = TRUE;
		data->ignored_events++;
		return;
	}

	if (event->mask & IN_DELETE_SELF || event->mask & IN_MOVE_SELF)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify: resource %s went away. Adding it to missing list\n", data->path);
		/* Remove the wd from the hash table */
		g_hash_table_remove (wd_hash, GINT_TO_POINTER(data->wd));
#ifdef GAMIN_DEBUG_API
		gam_debug_report(GAMDnotifyDelete, data->path, 0);
#endif
		/* Send delete event */
		gam_inotify_emit_events (data, event);
		data->events++;
		/* Set state bits in struct */
		data->wd = GAM_INOTIFY_WD_MISSING;
		data->missing = TRUE;
		data->permission = FALSE;
		data->dir = FALSE;
		/* Add path to missing list */
		gam_inotify_add_missing (data->path, FALSE);
		return;
	}

	if (event->mask & GAM_INOTIFY_MASK)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify: got %s on = %s/%s\n",  mask_to_string (event->mask), data->path, event->name);
		gam_inotify_emit_events (data, event);
		data->events++;
		return;
	}

	if (event->mask & IN_Q_OVERFLOW) 
	{
		/* At this point we have missed some events, and no longer have a consistent
		 * view of the filesystem.
		 */
		// XXX: Kill server and hope for the best?
		// XXX: Or we could send_initial_events , does this work for FAM?
		GAM_DEBUG (DEBUG_INFO, "inotify: DANGER, queue over flowed! Events have been missed.\n");
		return;
	}

	GAM_DEBUG(DEBUG_INFO, "inotify: error event->mask = %d\n", event->mask);
}

static void
gam_inotify_pair_moves (gpointer data, gpointer user_data)
{
	inotify_event_t *event = (inotify_event_t *)data;

	if (event->seen == TRUE || event->sent == TRUE)
		return;

	if (event->cookie != 0)
	{
		if (event->mask & IN_MOVED_FROM) {
			g_hash_table_insert (cookie_hash, GINT_TO_POINTER(event->cookie), event);
			gam_inotify_event_add_microseconds (event, MOVE_HOLD_UNTIL_TIME);
		} else if (event->mask & IN_MOVED_TO) {
			inotify_event_t *match = NULL;
			match = g_hash_table_lookup (cookie_hash, GINT_TO_POINTER(event->cookie));
			if (match) {
				g_hash_table_remove (cookie_hash, GINT_TO_POINTER(event->cookie));
				gam_inotify_event_pair_with (match, event);
			}
		}
	}
	event->seen = TRUE;
}

static void
gam_inotify_process_internal ()
{
	int ecount = 0;
	g_queue_foreach (events_to_process, gam_inotify_pair_moves, NULL);

	while (!g_queue_is_empty (events_to_process)) 
	{
		inotify_event_t *event = g_queue_peek_head (events_to_process);

		if (!gam_inotify_event_ready (event)) {
			GAM_DEBUG(DEBUG_INFO, "inotify: event not ready\n");
			break;
		}

		/* Pop it */
		event = g_queue_pop_head (events_to_process);
		/* This must have been sent as part of a MOVED_TO/MOVED_FROM */
		if (event->sent)
			continue;

		/* Check if this is a MOVED_FROM that is also sitting in the cookie_hash */
		if (event->cookie && event->pair == NULL &&
			g_hash_table_lookup (cookie_hash, GINT_TO_POINTER(event->cookie)))
		{
			g_hash_table_remove (cookie_hash, GINT_TO_POINTER(event->cookie));
			event->sent = TRUE;
		}
		
		g_queue_push_tail (event_queue, event);
		ecount++;
		if (event->pair) {
			// if this event has a pair
			event->pair->sent = TRUE;
			g_queue_push_tail (event_queue, event->pair);
			ecount++;
		}

	}
	if (ecount)
		GAM_DEBUG(DEBUG_INFO, "inotify: moved %d events to event queue\n", ecount);
}

static gboolean
gam_inotify_process_event_queue (gpointer data)
{
	/* Try and move as many events to the event queue */
	gam_inotify_process_internal ();

	/* Send the events on the event queue to gam clients */
	while (!g_queue_is_empty (event_queue))
	{
		inotify_event_t *event = g_queue_pop_head (event_queue);
		g_assert (event);
		gam_inotify_process_event (event);
		gam_inotify_event_free (event);
	}

	return TRUE;
}

static gboolean
gam_inotify_read_handler(gpointer user_data)
{
	gchar *buffer;
	gsize buffer_size, buffer_i, events;

        gam_inotify_read_events (&buffer_size, &buffer);

        buffer_i = 0;
        events = 0;
        while (buffer_i < buffer_size) 
	{
                struct inotify_event *event;
                gsize event_size;
                event = (struct inotify_event *)&buffer[buffer_i];
                event_size = sizeof(struct inotify_event) + event->len;
		g_queue_push_tail (events_to_process, gam_inotify_event_new (event));
                buffer_i += event_size;
                events++;
        }

	GAM_DEBUG(DEBUG_INFO, "inotify recieved %d events\n", events);
        return TRUE;
}

static void
gam_inotify_send_initial_events (inotify_data_t *data, GamSubscription *sub)
{
	GaminEventType gevent;
	gboolean is_dir = FALSE;
	gboolean was_missing = data->missing;
	gboolean was_permission = data->permission;
	gboolean exists = FALSE;
#if 0
	gboolean watching_dir_as_file = data->dir && !gam_subscription_is_dir (sub);
#endif
	gboolean watching_file_as_dir = FALSE;
	
	struct stat sb;
	memset(&sb, 0, sizeof (struct stat));
	
	exists = lstat (data->path, &sb) >= 0;
	is_dir = (exists && (sb.st_mode & S_IFDIR) != 0) ? TRUE : FALSE;

	if (was_missing) {
		GAM_DEBUG (DEBUG_INFO, "inotify: Sending initial events for %s -- WAS_MISSING\n", data->path);
	} else if (was_permission) {
		GAM_DEBUG (DEBUG_INFO, "inotify: Sending initial events for %s -- WAS_PERMISSION\n", data->path);
	} else {
		GAM_DEBUG (DEBUG_INFO, "inotify: Sending initial events for %s\n", data->path);
	}

	if (data->wd >= 0)
		watching_file_as_dir = !data->dir && gam_subscription_is_dir (sub);
	else
		watching_file_as_dir = FALSE;

	if (!watching_file_as_dir && exists) 
	{
		gevent = was_permission ? GAMIN_EVENT_EXISTS : was_missing ? GAMIN_EVENT_CREATED : GAMIN_EVENT_EXISTS;

		gam_server_emit_one_event (data->path, is_dir ? 1 : 0, gevent, sub, 1);

		if (is_dir) 
		{
			GDir *dir;
			GError *err = NULL;
			dir = g_dir_open (data->path, 0, &err);
			if (dir)
			{
				const char *filename;

				while ((filename = g_dir_read_name (dir)))
				{
					gchar *fullname = g_strdup_printf ("%s/%s", data->path, filename);
					gboolean file_is_dir = FALSE;
					struct stat fsb;
					memset(&fsb, 0, sizeof (struct stat));
					lstat(fullname, &fsb);
					file_is_dir = (fsb.st_mode & S_IFDIR) != 0 ? TRUE : FALSE;
					gam_server_emit_one_event (fullname, file_is_dir ? 1 : 0, gevent, sub, 1);
					g_free (fullname);
				}

				g_dir_close (dir);
			} else {
				GAM_DEBUG (DEBUG_INFO, "unable to open directory %s: %s\n", data->path, err->message);
				g_error_free (err);
			}

		}

		if (!was_missing) 
		{
			gam_server_emit_one_event (data->path, is_dir ? 1 : 0, GAMIN_EVENT_ENDEXISTS, sub, 1);
		}

	} else {
		gam_server_emit_one_event (data->path, is_dir ? 1 : 0, GAMIN_EVENT_DELETED, sub, 1);
		gam_server_emit_one_event (data->path, is_dir ? 1 : 0, GAMIN_EVENT_ENDEXISTS, sub, 1);
	}
}

static void
gam_inotify_send_initial_events_all (inotify_data_t *data)
{
	GList *l;

	if (!data)
		return;

	for (l = data->subs; l; l = l->next) {
		GamSubscription *sub = l->data;
		gam_inotify_send_initial_events (data, sub);
	}

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
	const char *path = gam_subscription_get_path (sub);
	inotify_data_t *data = g_hash_table_lookup (path_hash, path);
	int wd, err;


	if (data) 
	{
		data->subs = g_list_prepend (data->subs, sub);
		data->refcount++;
		gam_inotify_send_initial_events (data, sub);
#ifdef GAMIN_DEBUG_API
		gam_debug_report(GAMDnotifyChange, path, data->refcount);
#endif
		gam_listener_add_subscription(gam_subscription_get_listener(sub), sub);
		return TRUE;
	}

	wd = gam_inotify_add_watch (path, GAM_INOTIFY_MASK, &err);
	if (wd < 0) {
		GAM_DEBUG (DEBUG_INFO, "inotify: could not add watch for %s\n", path);
		if (err == EACCES) {
			GAM_DEBUG (DEBUG_INFO, "inotify: adding %s to missing list PERM\n", path);
		} else {
			GAM_DEBUG (DEBUG_INFO, "inotify: adding %s to missing list MISSING\n", path);
		}
		data = gam_inotify_data_new (path, err == EACCES ? GAM_INOTIFY_WD_PERM : GAM_INOTIFY_WD_MISSING, FALSE);
		gam_inotify_add_missing (path, err == EACCES ? TRUE : FALSE);
	} else if (gam_inotify_is_link (path)) {
		/* The file turned out to be a link, cancel the watch, and add it to the links list */
		gam_inotify_rm_watch (path, wd);
		GAM_DEBUG (DEBUG_INFO, "inotify: could not add watch for %s\n", path);
		GAM_DEBUG (DEBUG_INFO, "inotify: adding %s to links list\n", path);
		data = gam_inotify_data_new (path, GAM_INOTIFY_WD_LINK, FALSE);
		gam_inotify_add_link (path);
	} else {
		struct stat sbuf;
		memset(&sbuf, 0, sizeof (struct stat));
		lstat (path, &sbuf);
		/* Just in case,
		 * Clear this path off the missing list */
		gam_inotify_rm_missing (path);
		data = gam_inotify_data_new (path, wd, sbuf.st_mode & S_IFDIR);
		g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd), data);
	}

#ifdef GAMIN_DEBUG_API
	gam_debug_report(GAMDnotifyCreate, path, 0);
#endif
	gam_listener_add_subscription(gam_subscription_get_listener(sub), sub);

	g_hash_table_insert(path_hash, data->path, data);
	data->subs = g_list_prepend (data->subs, sub);
	gam_inotify_send_initial_events (data, sub);
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
	const char *path = gam_subscription_get_path (sub);
	inotify_data_t *data = g_hash_table_lookup (path_hash, path);

	g_assert (g_list_find (data->subs, sub));

	data->subs = g_list_remove_all (data->subs, sub);
	data->refcount--;
	/* No one is watching this path anymore */
	if (!data->subs && data->refcount == 0)
	{
		if (data->link)
		{
			g_assert (data->wd == GAM_INOTIFY_WD_LINK);
			g_assert (data->missing == FALSE && data->permission == FALSE);
			g_hash_table_remove (path_hash, data->path);
			gam_inotify_rm_link (data->path);
		} else if (data->missing) {
			g_assert (data->wd == GAM_INOTIFY_WD_MISSING);
			g_assert (data->link == FALSE && data->permission == FALSE);
			g_hash_table_remove (path_hash, data->path);
			gam_inotify_rm_missing (data->path);
		} else if (data->permission) {
			g_assert (data->wd == GAM_INOTIFY_WD_PERM);
			g_assert (data->link == FALSE && data->missing == FALSE);
			g_hash_table_remove (path_hash, data->path);
			gam_inotify_rm_missing (data->path);
		} else {
			g_hash_table_remove (wd_hash, GINT_TO_POINTER(data->wd));
			g_hash_table_remove (path_hash, data->path);
			gam_inotify_rm_watch (data->path, data->wd);
		}
#ifdef GAMIN_DEBUG_API
		gam_debug_report(GAMDnotifyDelete, path, 0);
#endif
		gam_inotify_data_free (data);
	} else {
#ifdef GAMIN_DEBUG_API
		gam_debug_report(GAMDnotifyChange, path, data->refcount);
#endif
	}

	gam_subscription_cancel (sub);

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
	GList *subs;
	GList *l;
	gboolean success = TRUE;

	subs = gam_listener_get_subscriptions(listener);

	for (l = subs; l != NULL; l = l->next)
		if (!gam_inotify_remove_subscription(l->data))
			success = FALSE;

	g_list_free(subs);

	return success;
}

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

    inotify_device_fd = inotify_init ();

    if (inotify_device_fd < 0) {
        GAM_DEBUG(DEBUG_INFO, "Could not initialize inotify\n");
        return FALSE;
    }

    inotify_read_ioc = g_io_channel_unix_new(inotify_device_fd);

    g_io_channel_set_encoding(inotify_read_ioc, NULL, NULL);
    g_io_channel_set_flags(inotify_read_ioc, G_IO_FLAG_NONBLOCK, NULL);

    source = g_io_create_watch(inotify_read_ioc,
			       G_IO_IN | G_IO_HUP | G_IO_ERR);
    g_source_set_callback(source, gam_inotify_read_handler, NULL, NULL);
    g_source_attach(source, NULL);
    g_timeout_add (SCAN_MISSING_TIME, gam_inotify_scan_missing, NULL);
    g_timeout_add (SCAN_LINKS_TIME, gam_inotify_scan_links, NULL);
    g_timeout_add (PROCESS_EVENTS_TIME, gam_inotify_process_event_queue, NULL);

    path_hash = g_hash_table_new(g_str_hash, g_str_equal);
    wd_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    cookie_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    event_queue = g_queue_new ();
    events_to_process = g_queue_new ();

	gam_poll_generic_init ();
	gam_server_install_kernel_hooks (GAMIN_K_INOTIFY2,
					 gam_inotify_add_subscription,
					 gam_inotify_remove_subscription,
					 gam_inotify_remove_all_for, NULL, NULL);

	GAM_DEBUG(DEBUG_INFO, "inotify backend initialized\n");

    return TRUE;
}

int gam_inotify_add_watch (const char *path, __u32 mask, int *err)
{
	int wd = -1;

	g_assert (path != NULL);
	g_assert (inotify_device_fd >= 0);

	wd = inotify_add_watch (inotify_device_fd, path, mask);

	if (wd < 0)
	{
		int e = errno;
		GAM_DEBUG (DEBUG_INFO, "inotify: failed to add watch for %s\n", path);
		GAM_DEBUG (DEBUG_INFO, "inotify: reason %d = %s\n", e, strerror (e));
		if (err)
			*err = e;
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
#define PENDING_PAUSE_MICROSECONDS 8000

void gam_inotify_read_events (gsize *buffer_size_out, gchar **buffer_out)
{
        static int prev_pending = 0, pending_count = 0;
        static gchar *buffer = NULL;
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

	memset(buffer, 0, buffer_size);

        if (g_io_channel_read_chars (inotify_read_ioc, (char *)buffer, buffer_size, buffer_size_out, NULL) != G_IO_STATUS_NORMAL) {
                GAM_DEBUG (DEBUG_INFO, "inotify: failed to read from buffer\n");
        }
        *buffer_out = buffer;

        prev_pending = 0;
        pending_count = 0;
}

gboolean gam_inotify_is_missing (const char *path)
{
	struct stat sbuf;

	/* If the file doesn't exist, it is missing. */
	if (lstat (path, &sbuf) < 0)
		return TRUE;

	/* If we can't read the file, it is missing. */
	if (access (path, R_OK) < 0)
		return TRUE;

	return FALSE;
}

static gint missing_list_compare (gconstpointer a, gconstpointer b)
{
	const inotify_missing_t *missing = NULL;
	
	g_assert (a);
	g_assert (b);
	missing = a;
	g_assert (missing->path);

	return strcmp (missing->path, b);
}

static void gam_inotify_add_missing (const char *path, gboolean perm)
{
	inotify_missing_t *missing = NULL;

	g_assert (path);

	missing = g_new0 (inotify_missing_t, 1);

	g_assert (missing);

	missing->path = g_strdup (path);
	missing->scan_interval = gam_fs_get_poll_timeout (path);
	missing->last_scan_time = time (NULL);
	missing->permission = perm;

	GAM_DEBUG (DEBUG_INFO, "inotify-missing: add - %s\n", path);

	missing_list = g_list_prepend (missing_list, missing);
}

static void gam_inotify_rm_missing (const char *path)
{
	GList *node = NULL;
	inotify_missing_t *missing = NULL;

	g_assert (path && *path);

	node = g_list_find_custom (missing_list, path, missing_list_compare);

	if (!node)
		return;

	GAM_DEBUG (DEBUG_INFO, "inotify-missing: rm - %s\n", path);
	missing = node->data;
	g_free (missing->path);
	g_free (missing);

	missing_list = g_list_remove_link (missing_list, node);
}

static gboolean gam_inotify_nolonger_missing (const char *path)
{
	int wd = -1, err;
	inotify_data_t *data = NULL;
	struct stat sbuf;
	memset(&sbuf, 0, sizeof (struct stat));

	data = g_hash_table_lookup (path_hash, path);
	if (!data) {
		GAM_DEBUG (DEBUG_INFO, "inotify: Could not find missing %s in hash table.\n", path);
		return FALSE;
	}

	g_assert ((data->missing == TRUE || data->permission == TRUE) && data->link == FALSE);

	wd = gam_inotify_add_watch (path, GAM_INOTIFY_MASK,&err);
	if (wd < 0) {
		/* Check if we don't have access to the new file */
		if (err == EACCES)
		{
			data->wd = GAM_INOTIFY_WD_PERM;
			data->permission = TRUE;
			data->missing = FALSE;
		} else {
			data->wd = GAM_INOTIFY_WD_MISSING;
			data->permission = FALSE;
			data->missing = TRUE;
		}
		return FALSE;
	} else if (gam_inotify_is_link (path)) {
		GAM_DEBUG(DEBUG_INFO, "inotify: Missing resource %s exists now BUT IT IS A LINK\n", path);
		/* XXX: See NOTE1 */
		if (g_hash_table_lookup (wd_hash, GINT_TO_POINTER(wd)) == NULL)
			gam_inotify_rm_watch (path, wd);
		data->missing = FALSE;
		data->permission = FALSE;
		data->link = TRUE;
		data->wd = GAM_INOTIFY_WD_LINK;
		gam_inotify_add_link (path);
		gam_inotify_send_initial_events_all (data);
		return TRUE;
	}


	GAM_DEBUG(DEBUG_INFO, "inotify: Missing resource %s exists now\n", path);

	lstat (path, &sbuf);
	data->dir = (sbuf.st_mode & S_IFDIR);
	data->wd = wd;
	g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd), data);
	gam_inotify_send_initial_events_all (data);
	data->missing = FALSE;
	data->permission = FALSE;

	return TRUE;
}

/* This function is called once per second in the main loop*/
static gboolean gam_inotify_scan_missing (gpointer userdata)
{
	guint i;

	gam_inotify_sanity_check ();
	/* We have to walk the list like this because entries might be removed while we walk the list */
	for (i = 0; ; i++)
	{
		inotify_missing_t *missing = g_list_nth_data (missing_list, i);

		if (!missing)
			break;

		/* Not enough time has passed since the last scan */
		if (time(NULL) - missing->last_scan_time < missing->scan_interval)
			continue;
		
		missing->last_scan_time = time(NULL);
		if (!gam_inotify_is_missing (missing->path))
		{
			if (gam_inotify_nolonger_missing (missing->path))
			{
#ifdef GAMIN_DEBUG_API
				gam_debug_report(GAMDnotifyCreate, missing->path, 0);
#endif
				gam_inotify_rm_missing (missing->path);
			}
		}
	}

	gam_inotify_sanity_check ();
	return TRUE;
}


static gboolean	
gam_inotify_is_link (const char *path)
{
	struct stat sbuf;

	if (lstat(path, &sbuf) < 0)
		return FALSE;

	return S_ISLNK(sbuf.st_mode) != 0;
}

static gboolean 
gam_inotify_nolonger_link (const char *path)
{
	int wd = -1, err;
	inotify_data_t *data = NULL;
	struct stat sbuf;
	memset(&sbuf, 0, sizeof (struct stat));

	GAM_DEBUG(DEBUG_INFO, "inotify: link resource %s no longer a link\n", path);
	data = g_hash_table_lookup (path_hash, path);
	if (!data) {
		GAM_DEBUG (DEBUG_INFO, "inotify: Could not find link %s in hash table.\n", path);
		return FALSE;
	}

	g_assert (data->link == TRUE && data->missing == FALSE && data->permission == FALSE);

	wd = gam_inotify_add_watch (path, GAM_INOTIFY_MASK, &err);
	if (wd < 0) {
		/* The file must not exist anymore, so we add it to the missing list */
		data->link = FALSE;
		/* Check if we don't have access to the new file */
		if (err == EACCES)
		{
			data->wd = GAM_INOTIFY_WD_PERM;
			data->permission = TRUE;
			data->missing = FALSE;
		} else {
			data->wd = GAM_INOTIFY_WD_MISSING;
			data->permission = FALSE;
			data->missing = TRUE;
		}

		gam_server_emit_event (path, data->dir, GAMIN_EVENT_DELETED, data->subs, 1);
		gam_inotify_add_missing (path, data->permission);
		return TRUE;
	} else if (gam_inotify_is_link (path)) {
		GAM_DEBUG(DEBUG_INFO, "inotify: Link resource %s re-appeared as a link...\n", path);
		/* NOTE1: This is tricky, because inotify works on the inode level and
		 * we are dealing with a link, we can be watching the same inode 
		 * from two different paths (the wd's will be the same). So,
		 * if the wd isn't in the hash table, we can remvoe the watch, 
		 * otherwise we just leave the watch. This should probably be
		 * handled by ref counting
		 */
		if (g_hash_table_lookup (wd_hash, GINT_TO_POINTER(wd)) == NULL)
			gam_inotify_rm_watch (path, wd);
		data->missing = FALSE;
		data->permission = FALSE;
		data->link = TRUE;
		data->wd = GAM_INOTIFY_WD_LINK;
		gam_inotify_send_initial_events_all (data);
		return FALSE;
	}

	lstat (path, &sbuf);
	data->dir = (sbuf.st_mode & S_IFDIR);
	data->wd = wd;
	g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd), data);
	gam_inotify_send_initial_events_all (data);
	data->missing = FALSE;
	data->permission = FALSE;
	return TRUE;
}

static gint links_list_compare (gconstpointer a, gconstpointer b)
{
	const inotify_links_t *links = NULL;
	
	g_assert (a);
	g_assert (b);
	links = a;
	g_assert (links->path);

	return strcmp (links->path, b);
}

static void
gam_inotify_add_link (const char *path)
{
	inotify_links_t *links = NULL;
	struct stat sbuf;

	g_assert (path);

	links = g_new0 (inotify_links_t, 1);

	g_assert (links);

	GAM_DEBUG (DEBUG_INFO, "inotify-link: add - %s\n", path);
	links->path = g_strdup (path);
	links->scan_interval = gam_fs_get_poll_timeout (path);
	links->last_scan_time = 0;
	lstat(path, &sbuf);
	links->sbuf = sbuf;
	links_list = g_list_prepend (links_list, links);
}

static void
gam_inotify_rm_link (const char *path)
{
	GList *node = NULL;
	inotify_links_t *links = NULL;

	g_assert (path && *path);

	node = g_list_find_custom (links_list, path, links_list_compare);

	if (!node)
		return;

	GAM_DEBUG (DEBUG_INFO, "inotify-link: rm - %s\n", path);
	links = node->data;
	g_free (links->path);
	g_free (links);

	links_list = g_list_remove_link (links_list, node);

}

static gboolean 
gam_inotify_scan_links (gpointer userdata)
{
	guint i;

	gam_inotify_sanity_check ();
	/* We have to walk the list like this because entries might be removed while we walk the list */
	for (i = 0; ; i++)
	{
		inotify_links_t *links = g_list_nth_data (links_list, i);

		if (!links)
			break;

		/* Not enough time has passed since the last scan */
		if (time(NULL) - links->last_scan_time < links->scan_interval)
			continue;
		
		links->last_scan_time = time(NULL);
		if (!gam_inotify_is_link (links->path))
		{
			if (gam_inotify_nolonger_link (links->path))
			{
				gam_inotify_rm_link (links->path);
			}
		} else {
			gam_inotify_poll_link (links);
		}

	}

	gam_inotify_sanity_check ();
	return TRUE;
}

static gboolean
gam_inotify_stat_changed (struct stat sbuf1, struct stat sbuf2)
{
#ifdef ST_MTIM_NSEC
	return ((sbuf1.st_mtim.tv_sec != sbuf2.st_mtim.tv_sec) ||
		(sbuf1.st_mtim.tv_nsec != sbuf2.st_mtim.tv_nsec) ||
		(sbuf1.st_size != sbuf2.st_size) ||
		(sbuf1.st_ctim.tv_sec != sbuf2.st_ctim.tv_sec) ||
		(sbuf1.st_ctim.tv_nsec != sbuf2.st_ctim.tv_nsec));
#else
	return ((sbuf1.st_mtime != sbuf2.st_mtime) ||
		(sbuf1.st_size != sbuf2.st_size) ||
		(sbuf1.st_ctime != sbuf2.st_ctime));
#endif
}

static void
gam_inotify_poll_link (inotify_links_t *links)
{
	struct stat sbuf;
	g_assert (links);

	/* Next time around, we will detect the deletion, and send the event */
	if (lstat (links->path, &sbuf) < 0)
		return;

	if (gam_inotify_stat_changed (sbuf, links->sbuf))
	{
		inotify_data_t *data = g_hash_table_lookup (path_hash, links->path);
		g_assert (data);
		gam_server_emit_event (data->path, data->dir, GAMIN_EVENT_CHANGED, data->subs, 1);
	}

	links->sbuf = sbuf;
}

static void
gam_inotify_wd_check (gpointer key, gpointer value, gpointer user_data)
{
	gint wd = GPOINTER_TO_INT(key);
	inotify_data_t *data = (inotify_data_t *)value;
	if (wd < 0)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: FAILURE wd hash for %s key < 0\n", data->path);
	}
	if (data->wd < 0)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: FAILURE wd hash for %s value < 0\n", data->path);
	}
	if (data->wd != wd) 
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: FAILURE wd hash value & key don't match\n");
	}
}

static void
gam_inotify_wd_hash_sanity_check (void)
{
	g_hash_table_foreach (wd_hash, gam_inotify_wd_check, NULL);
}

static void
gam_inotify_missing_check (gpointer data, gpointer user_data)
{
	inotify_missing_t *missing = data;
	inotify_data_t *idata = NULL;

	if (!missing)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: Missing check called with NULL argument\n");
		return;
	}

	if (!missing->path)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: Missing entry missing path name\n");
		return;
	}

	idata = g_hash_table_lookup (path_hash, missing->path);

	if (!idata) 
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: Could not find %s in path hash table\n", missing->path);
		return;
	}

	if (idata->wd != GAM_INOTIFY_WD_MISSING && idata->wd != GAM_INOTIFY_WD_PERM) 
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: data->wd != GAM_INOTIFY_WD_(MISSING/PERM) for path in missing list\n");
		return;
	}

	if (idata->missing != TRUE && idata->permission != TRUE)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: data->missing/permission != TRUE for path in missing list\n");
		return;
	}

	if (idata->missing == TRUE && idata->wd != GAM_INOTIFY_WD_MISSING)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: data->missing == TRUE && idata->wd != GAM_INOTIFY_WD_MISSING\n");
		return;
	}

	if (idata->permission == TRUE && idata->wd != GAM_INOTIFY_WD_PERM)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: data->permission == TRUE && idata->wd != GAM_INOTIFY_WD_PERM\n");
		return;
	}

	if (idata->wd == GAM_INOTIFY_WD_MISSING && idata->missing != TRUE)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: data->missing == FALSE && idata->wd == GAM_INOTIFY_WD_MISSING\n");
		return;
	}

	if (idata->wd == GAM_INOTIFY_WD_PERM && idata->permission != TRUE)
	{
		GAM_DEBUG (DEBUG_INFO, "inotify-sanity: data->permission != TRUE && idata->wd == GAM_INOTIFY_WD_PERM\n");
		return;
	}
}

static void
gam_inotify_missing_list_sanity_check (void)
{
	g_list_foreach (missing_list, gam_inotify_missing_check, NULL);
}


static void
gam_inotify_sanity_check (void)
{
#ifdef GAM_INOTIFY_SANITY
	gam_inotify_wd_hash_sanity_check ();
	gam_inotify_missing_list_sanity_check ();
#endif
}

static gboolean
g_timeval_lt(GTimeVal *val1, GTimeVal *val2)
{
	if (val1->tv_sec < val2->tv_sec)
		return TRUE;

	if (val1->tv_sec > val2->tv_sec)
		return FALSE;

	/* val1->tv_sec == val2->tv_sec */
	if (val1->tv_usec < val2->tv_usec)
		return TRUE;

	return FALSE;
}

static gboolean
g_timeval_eq(GTimeVal *val1, GTimeVal *val2)
{
	return (val1->tv_sec == val2->tv_sec) && (val1->tv_usec == val2->tv_usec);
}

