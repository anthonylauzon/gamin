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
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include "gam_error.h"
#include "gam_poll.h"
#include "gam_dnotify.h"
#include "gam_tree.h"
#include "gam_event.h"
#include "gam_server.h"
#include "gam_event.h"

/* just pulling a value out of nowhere here...may need tweaking */
#define MAX_QUEUE_SIZE 500

typedef struct {
    char *path;
    int fd;
    int refcount;
} DNotifyData;

static GHashTable *path_hash = NULL;
static GHashTable *fd_hash = NULL;

G_LOCK_DEFINE_STATIC(dnotify);

/* TODO: GQueue is not signal-safe, need to use something else */
static GQueue *changes = NULL;

static GIOChannel *pipe_read_ioc = NULL;
static GIOChannel *pipe_write_ioc = NULL;

static gboolean have_consume_idler = FALSE;

static DNotifyData *
gam_dnotify_data_new(const char *path, int fd)
{
    DNotifyData *data;

    data = g_new0(DNotifyData, 1);
    data->path = g_strdup(path);
    data->fd = fd;
    data->refcount = 1;

    return data;
}

static void
gam_dnotify_data_free(DNotifyData * data)
{
    g_free(data->path);
    g_free(data);
}

static void
gam_dnotify_directory_handler(const char *path, gboolean added)
{
    DNotifyData *data;
    int fd;

#if 0
    if (added)
        fprintf(stderr, "Adding %s to dnotify\n", path);
    else
        fprintf(stderr, "Removing %s from dnotify\n", path);
#endif

    G_LOCK(dnotify);

    if (added) {

        if ((data = g_hash_table_lookup(path_hash, path)) != NULL) {
            data->refcount++;
            G_UNLOCK(dnotify);
            return;
        }

        fd = open(path, O_RDONLY);

        if (fd < 0) {
            G_UNLOCK(dnotify);
            return;
        }

        data = gam_dnotify_data_new(path, fd);
        g_hash_table_insert(fd_hash, GINT_TO_POINTER(data->fd), data);
        g_hash_table_insert(path_hash, data->path, data);

        fcntl(fd, F_SETSIG, SIGRTMIN);
        fcntl(fd, F_NOTIFY,
              DN_MODIFY | DN_CREATE | DN_DELETE | DN_RENAME | DN_ATTRIB |
              DN_MULTISHOT);
        gam_debug(DEBUG_INFO, "activated DNotify for %s\n", path);
    } else {
        data = g_hash_table_lookup(path_hash, path);

        if (!data) {
            G_UNLOCK(dnotify);
            return;
        }

        data->refcount--;

        if (data->refcount == 0) {
            close(data->fd);
            gam_debug(DEBUG_INFO, "deactivated DNotify for %s\n",
                      data->path);
            g_hash_table_remove(path_hash, data->path);
            g_hash_table_remove(fd_hash, GINT_TO_POINTER(data->fd));
            gam_dnotify_data_free(data);
        }
    }

    G_UNLOCK(dnotify);
}

static void
gam_dnotify_file_handler(const char *path, gboolean added)
{
    gam_debug(DEBUG_INFO, "gam_dnotify_file_handler %s : %d\n", path, added);
    
    if (g_file_test(path, G_FILE_TEST_IS_DIR)) {
	gam_dnotify_directory_handler(path, added);
    } else {
	char *dir;

	dir = g_path_get_dirname(path);
	gam_dnotify_directory_handler(dir, added);
	g_free(dir);
    }
}

static void
dnotify_signal_handler(int sig, siginfo_t * si, void *sig_data)
{
    if (changes->length > MAX_QUEUE_SIZE) {
        gam_debug(DEBUG_INFO, "Queue Full\n");
        return;
    }

    g_queue_push_head(changes, GINT_TO_POINTER(si->si_fd));

    g_io_channel_write_chars(pipe_write_ioc, "bogus", 5, NULL, NULL);
    g_io_channel_flush(pipe_write_ioc, NULL);

    gam_debug(DEBUG_INFO, "signal handler done\n");
}

static void
overflow_signal_handler(int sig, siginfo_t * si, void *sig_data)
{
    gam_debug(DEBUG_INFO, "**** signal queue overflow ***\n");
}

static gboolean
gam_dnotify_pipe_handler(gpointer user_data)
{
    char buf[5000];
    DNotifyData *data;
    gpointer fd;
    int i;

    gam_debug(DEBUG_INFO, "gam_dnotify_pipe_handler()\n");
    g_io_channel_read_chars(pipe_read_ioc, buf, sizeof(buf), NULL, NULL);

    i = 0;
    while ((fd = g_queue_pop_tail(changes)) != NULL) {

        G_LOCK(dnotify);
        data = g_hash_table_lookup(fd_hash, fd);
        G_UNLOCK(dnotify);

        if (data == NULL)
            continue;

        gam_debug(DEBUG_INFO, "handling signal\n");

        gam_poll_scan_directory(data->path, NULL);
        i++;
    }

    gam_debug(DEBUG_INFO, "gam_dnotify_pipe_handler() done\n");
    return TRUE;
}

static gboolean
gam_dnotify_consume_subscriptions_real(gpointer data)
{
    gam_debug(DEBUG_INFO, "gam_dnotify_consume_subscriptions_real()\n");
    gam_poll_consume_subscriptions();
    have_consume_idler = FALSE;
    return FALSE;
}

static void
gam_dnotify_consume_subscriptions(void)
{
    GSource *source;

    if (have_consume_idler)
        return;

    gam_debug(DEBUG_INFO, "gam_dnotify_consume_subscriptions()\n");
    have_consume_idler = TRUE;
    source = g_idle_source_new();
    g_source_set_callback(source, gam_dnotify_consume_subscriptions_real,
                          NULL, NULL);
    g_source_attach(source, NULL);
}

/**
 * @defgroup DNotify DNotify Backend
 * @ingroup Backends
 * @brief DNotify backend API
 *
 * Since version 2.4, Linux kernels have included the Linux Directory
 * Notification system (dnotify).  This backend uses dnotify to know when
 * files are changed/created/deleted.  Since dnotify doesn't tell us
 * exactly what event happened to which file (just that some even happened
 * in some directory), we still have to cache stat() information.  For this,
 * we can just use the code in the polling backend.
 *
 * @{
 */


/**
 * Initializes the polling system.  This must be called before
 * any other functions in this module.
 *
 * @returns TRUE if initialization succeeded, FALSE otherwise
 */
gboolean
gam_dnotify_init(void)
{
    struct sigaction act;
    int fds[2];
    GSource *source;

    g_return_val_if_fail(gam_poll_init_full(FALSE), FALSE);

    if (pipe(fds) < 0) {
        g_warning("Could not create pipe.\n");
        return FALSE;
    }

    pipe_read_ioc = g_io_channel_unix_new(fds[0]);
    pipe_write_ioc = g_io_channel_unix_new(fds[1]);

    g_io_channel_set_flags(pipe_read_ioc, G_IO_FLAG_NONBLOCK, NULL);
    g_io_channel_set_flags(pipe_write_ioc, G_IO_FLAG_NONBLOCK, NULL);


    source = g_io_create_watch(pipe_read_ioc,
                               G_IO_IN | G_IO_HUP | G_IO_ERR);
    g_source_set_callback(source, gam_dnotify_pipe_handler, NULL, NULL);

    g_source_attach(source, NULL);

    /* setup some signal stuff */
    act.sa_sigaction = dnotify_signal_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGRTMIN, &act, NULL);

    /* catch SIGIO as well (happens when the realtime queue fills up) */
    act.sa_sigaction = overflow_signal_handler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGIO, &act, NULL);

    changes = g_queue_new();

    path_hash = g_hash_table_new(g_str_hash, g_str_equal);
    fd_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
    gam_poll_set_directory_handler(gam_dnotify_directory_handler);
    gam_poll_set_file_handler(gam_dnotify_file_handler);

    gam_debug(DEBUG_INFO, "dnotify initialized\n");

    gam_backend_add_subscription = gam_dnotify_add_subscription;
    gam_backend_remove_subscription = gam_dnotify_remove_subscription;
    gam_backend_remove_all_for = gam_dnotify_remove_all_for;

    return TRUE;
}

/**
 * Adds a subscription to be monitored.
 *
 * @param sub a #GamSubscription to be polled
 * @returns TRUE if adding the subscription succeeded, FALSE otherwise
 */
gboolean
gam_dnotify_add_subscription(GamSubscription * sub)
{
    gam_debug(DEBUG_INFO, "gam_dnotify_add_subscription\n");

    if (!gam_poll_add_subscription(sub)) {
        return FALSE;
    }

    gam_dnotify_consume_subscriptions();

    gam_debug(DEBUG_INFO, "gam_dnotify_add_subscription: done\n");
    return TRUE;
}

/**
 * Removes a subscription which was being monitored.
 *
 * @param sub a #GamSubscription to remove
 * @returns TRUE if removing the subscription succeeded, FALSE otherwise
 */
gboolean
gam_dnotify_remove_subscription(GamSubscription * sub)
{
    gam_debug(DEBUG_INFO, "gam_dnotify_remove_subscription\n");

    if (!gam_poll_remove_subscription(sub)) {
        return FALSE;
    }

    gam_dnotify_consume_subscriptions();

    gam_debug(DEBUG_INFO, "gam_dnotify_remove_subscription: done\n");
    return TRUE;
}

/**
 * Stop monitoring all subscriptions for a given listener.
 *
 * @param listener a #GamListener
 * @returns TRUE if removing the subscriptions succeeded, FALSE otherwise
 */
gboolean
gam_dnotify_remove_all_for(GamListener * listener)
{
    if (!gam_poll_remove_all_for(listener)) {
        return FALSE;
    }

    gam_dnotify_consume_subscriptions();

    return TRUE;
}

/** @} */
