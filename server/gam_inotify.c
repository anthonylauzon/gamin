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
 */


#include <config.h>
#ifdef USE_INOTIFY
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include "/usr/src/linux/include/linux/inotify.h"
#include "gam_error.h"
#include "gam_poll.h"
#include "gam_inotify.h"
#include "gam_tree.h"
#include "gam_event.h"
#include "gam_server.h"
#include "gam_event.h"

/* just pulling a value out of nowhere here...may need tweaking */
#define MAX_QUEUE_SIZE 500

typedef struct {
    char *path;
    int wd;
    int refcount;
} INotifyData;

static GHashTable *path_hash = NULL;
static GHashTable *wd_hash = NULL;

G_LOCK_DEFINE_STATIC(inotify);

static GQueue *changes = NULL;

#ifdef WITH_TREADING
static GMainContext *loop_context;
#endif
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

    return data;
}

static void
gam_inotify_data_free(INotifyData * data)
{
    g_free(data->path);
    g_free(data);
}

static void
gam_inotify_directory_handler(const char *path, gboolean added)
{
    INotifyData *data;
    struct inotify_watch_request iwr;
    int wd,r;

    G_LOCK(inotify);

    if (added) {

        if ((data = g_hash_table_lookup(path_hash, path)) != NULL) {
            data->refcount++;
            G_UNLOCK(inotify);
            return;
        }

	iwr.dirname = g_strdup(path);
	iwr.mask = IN_MODIFY|IN_CREATE|IN_DELETE|IN_RENAME|IN_ATTRIB|IN_UNMOUNT|IN_IGNORED;

        wd = ioctl(fd, INOTIFY_WATCH,&iwr);
        g_free(iwr.dirname);	

        if (wd < 0) {
            G_UNLOCK(inotify);
            return;
        }


        data = gam_inotify_data_new(path, wd);
        g_hash_table_insert(wd_hash, GINT_TO_POINTER(data->wd), data);
        g_hash_table_insert(path_hash, data->path, data);

        gam_debug(DEBUG_INFO, "activated INotify for %s\n", path);
    } else {
        data = g_hash_table_lookup(path_hash, path);

        if (!data) {
            G_UNLOCK(inotify);
            return;
        }

        data->refcount--;

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

static void
gam_inotify_file_handler(const char *path, gboolean added)
{
    char *dir;

    dir = g_path_get_dirname(path);
    gam_inotify_directory_handler(dir, added);
    g_free(dir);
}

#ifdef WITH_TREADING
static gpointer
gam_inotify_scan_loop(gpointer data)
{
    g_main_loop_run(g_main_loop_new(loop_context, TRUE));
    return (NULL);
}
#endif

static gboolean
gam_inotify_read_handler(gpointer user_data)
{
    struct inotify_event event;
    INotifyData *data;

    gam_debug(DEBUG_INFO, "gam_inotify_read_handler()\n");
    G_LOCK(inotify);

    if (g_io_channel_read_chars(inotify_read_ioc, (char *)&event, sizeof(struct inotify_event), NULL, NULL) != G_IO_STATUS_NORMAL) {
        gam_debug(DEBUG_INFO, "gam_inotify_read_handler failed\n");
	return FALSE;
    }


    data = g_hash_table_lookup (wd_hash, GINT_TO_POINTER(event.wd));

    if (!data) {
	gam_debug(DEBUG_INFO, "Could not find WD %d in hash\n", event.wd);
        G_UNLOCK(inotify);
        return TRUE;
    }

    /* TODO: Handle IGNORED events (they come after UMOUNT events!) */
    /*
    if (event.mask & IN_IGNORED) {
	    gam_debug(DEBUG_INFO, "Removing wd %d from hash after IN_IGNORED\n", event.wd);
            g_hash_table_remove(path_hash, data->path);
            g_hash_table_remove(wd_hash, GINT_TO_POINTER(data->wd));
            gam_inotify_data_free(data);
	    G_UNLOCK(inotify);
	    return TRUE;
    }
    */

    gam_debug(DEBUG_INFO, "gam_inotify event for %s (%x)\n", data->path, event.mask);
    gam_poll_scan_directory(data->path, NULL);

    gam_debug(DEBUG_INFO, "gam_inotify_read_handler() done\n");

    G_UNLOCK(inotify);

    return TRUE;
}

static gboolean
gam_inotify_consume_subscriptions_real(gpointer data)
{
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

    have_consume_idler = TRUE;
    source = g_idle_source_new();
    g_source_set_callback(source, gam_inotify_consume_subscriptions_real,
                          NULL, NULL);
#ifdef WITH_TREADING
    g_source_attach(source, loop_context);
#else
    g_source_attach(source, NULL);
#endif
}

/**
 * @defgroup INotify INotify Backend
 * @ingroup Backends
 * @brief INotify backend API
 *
 * Since version 2.X, Linux kernels have included the Linux Inode
 * Notification system (inotify).  This backend uses inotify to know when
 * files are changed/created/deleted.  Since inotify doesn't tell us
 * exactly what event happened to which file (just that some even happened
 * in some directory), we still have to cache stat() information.  For this,
 * we can just use the code in the polling backend.
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

    g_return_val_if_fail(gam_poll_init_full(FALSE), FALSE);

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

#ifdef WITH_TREADING
    loop_context = g_main_context_new();
#endif

    source = g_io_create_watch(inotify_read_ioc,
                               G_IO_IN | G_IO_HUP | G_IO_ERR);
    g_source_set_callback(source, gam_inotify_read_handler, NULL, NULL);

#ifdef WITH_TREADING
    g_source_attach(source, loop_context);
#else
    g_source_attach(source, NULL);
#endif

    changes = g_queue_new();

#ifdef WITH_TREADING
    g_thread_create(gam_inotify_scan_loop, NULL, TRUE, NULL);
#endif

    path_hash = g_hash_table_new(g_str_hash, g_str_equal);
    wd_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    gam_poll_set_directory_handler(gam_inotify_directory_handler);
    gam_poll_set_file_handler(gam_inotify_file_handler);

    gam_debug(DEBUG_INFO, "inotify initialized\n");

    int i = INOTIFY_DEBUG_INODE|INOTIFY_DEBUG_ERRORS|INOTIFY_DEBUG_EVENTS;
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
    if (!gam_poll_add_subscription(sub)) {
        return FALSE;
    }

    if (gam_subscription_is_dir(sub)) {
        gam_inotify_consume_subscriptions();
    }

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
    if (!gam_poll_remove_subscription(sub)) {
        return FALSE;
    }

    if (gam_subscription_is_dir(sub)) {
        gam_inotify_consume_subscriptions();
    }

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

#endif /* USE_INOTIFY */
