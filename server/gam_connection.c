#include <string.h>             /* for memmove */
#include <stdlib.h>             /* for exit() */
#include <time.h>
#include "gam_connection.h"
#include "gam_subscription.h"
#include "gam_listener.h"
#include "gam_server.h"
#include "gam_event.h"
#include "gam_protocol.h"
#include "gam_channel.h"
#include "gam_error.h"
#ifdef GAMIN_DEBUG_API
#include "gam_debugging.h"
#endif
#include "fam.h"

/************************************************************************
 *									*
 *			Connection data handling			*
 *									*
 ************************************************************************/

GList *gamConnList = NULL;

struct GamConnData {
    GamConnState state;         /* the state for the connection */
    int fd;                     /* the file descriptor */
    int pid;                    /* the PID of the remote process */
    GMainLoop *loop;            /* the Glib loop used */
    GIOChannel *source;         /* the Glib I/O Channel used */
    int req_read;               /* how many bytes were read for the request */
    GAMPacket request;          /* the next request being read */
    GamListener *listener;      /* the listener associated to the connection */
};

/**
 * gam_connections_init:
 *
 * Initialize the connections data layer
 *
 * Returns 0 in case of success and -1 in case of failure
 */
int
gam_connections_init(void)
{
    return (0);
}

/**
 * gam_connection_exists:
 * @conn: the connection
 *
 * Routine to chech whether a connection still exists
 *
 * Returns 1 if still registered and 0 if not
 */
int
gam_connection_exists(GamConnDataPtr conn)
{
    GList *item;

    if (conn == NULL)
        return (0);
    item = g_list_find(gamConnList, (gconstpointer) conn);
    return (item != NULL);
}

/**
 * gam_connection_close:
 * @conn: the connection
 *
 * Routine to close a connection and discard the associated data
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
gam_connection_close(GamConnDataPtr conn)
{
    GList *item;

    if (conn == NULL)
        return (-1);
    item = g_list_find(gamConnList, (gconstpointer) conn);
    if (item == NULL) {
        GAM_DEBUG(DEBUG_INFO, "Connection already closed \n");
        return (-1);
    }

    if (conn->listener != NULL) {
        gam_listener_free(conn->listener);
    }
    if (conn->source == NULL) {
        GAM_DEBUG(DEBUG_INFO, "connection has no source: close failed\n");
        return (-1);
    }
#ifdef GAMIN_DEBUG_API
    gam_debug_release(conn);
#endif
    GAM_DEBUG(DEBUG_INFO, "Closing connection %d\n", conn->fd);
    g_io_channel_unref(conn->source);
    gamConnList = g_list_remove_all(gamConnList, conn);
    g_free(conn);
    return (0);
}

/**
 * gam_close_a_connection:
 * @conn: the connection
 * @result: the result
 *
 * Internal routine to close a connection
 */
static void
gam_close_a_connection(GamConnDataPtr conn, int *result)
{
    int ret;

    ret = gam_connection_close(conn);
    if (ret < 0)
        *result = ret;
}

/**
 * gam_connections_close:
 *
 * Close all the connections registered
 *
 * Returns 0 in case of success and -1 in case of failure
 */
int
gam_connections_close(void)
{
    int ret = 0;
    int tmp = 0;
    GList *cur;

    while ((cur = g_list_first(gamConnList)) != NULL) {
        gam_close_a_connection((GamConnDataPtr) cur->data, &tmp);
        if (tmp < 0) ret = -1;
    }
    return (ret);
}

/**
 * gam_connection_new:
 * @fd: the file descriptor for the incoming socket.
 * @loop: the Glib loop
 * @source: the  Glib I/O Channel 
 *
 * Create a new connection data structure.
 *
 * Returns the newly allocated structure or NULL in case of error.
 */
GamConnDataPtr
gam_connection_new(GMainLoop * loop, GIOChannel * source)
{
    GamConnDataPtr ret;

    if ((loop == NULL) || (source == NULL))
        return (NULL);
    ret = g_malloc0(sizeof(GamConnData));
    if (ret == NULL)
        return (NULL);

    ret->state = GAM_STATE_AUTH;
    ret->fd = g_io_channel_unix_get_fd(source);
    ret->loop = loop;
    ret->source = source;
    ret->req_read = 0;
    gamConnList = g_list_prepend(gamConnList, ret);
    GAM_DEBUG(DEBUG_INFO, "Created connection %d\n", ret->fd);
    return (ret);
}

/**
 * gam_connection_get_fd:
 * @conn: a connection data structure.
 *
 * accessor for the file descriptor associated to the connection
 *
 * Returns the file descriptor or -1 in case of error.
 */
int
gam_connection_get_fd(GamConnDataPtr conn)
{
    if (conn == NULL)
        return (-1);
    return (conn->fd);
}

/**
 * gam_connection_get_pid:
 * @conn: a connection data structure.
 *
 * accessor for the pid associated to the connection
 *
 * Returns the process identifier or -1 in case of error.
 */
int
gam_connection_get_pid(GamConnDataPtr conn)
{
    if (conn == NULL)
        return (-1);
    return (conn->pid);
}

/**
 * gam_connection_set_pid:
 * @conn: a connection data structure.
 * @pid: the client process id
 *
 * Set the client process id, this also indicate that authentication was done.
 *
 * Returns 0 in case of success or -1 in case of error.
 */
int
gam_connection_set_pid(GamConnDataPtr conn, int pid)
{
    if (conn == NULL)
        return (-1);
    if (conn->state != GAM_STATE_AUTH) {
        GAM_DEBUG(DEBUG_INFO, "Not waiting for authentication\n");
        conn->state = GAM_STATE_ERROR;
        return (-1);
    }
    conn->state = GAM_STATE_OKAY;
    conn->pid = pid;
    conn->listener = gam_listener_new(conn, pid);
    if (conn->listener == NULL) {
        GAM_DEBUG(DEBUG_INFO, "Failed to create listener\n");
        conn->state = GAM_STATE_ERROR;
        return (-1);
    }
    return (0);
}

/**
 * gam_connection_get_state:
 * @conn: a connection data structure.
 *
 * accessor for the connection state
 *
 * Returns the connection state or GAM_STATE_ERROR in case of error
 */
GamConnState
gam_connection_get_state(GamConnDataPtr conn)
{
    if (conn == NULL)
        return (GAM_STATE_ERROR);
    return (conn->state);
}

/**
 * gam_connection_get_data:
 * @conn: connection data structure.
 * @data: address to store data
 * @size: amount of storage available
 *
 * Get the address and length of the data store for the connection
 *
 * Returns 0 in case of success and -1 in case of failure
 */
int
gam_connection_get_data(GamConnDataPtr conn, char **data, int *size)
{
    if ((conn == NULL) || (data == NULL) || (size == NULL))
        return (-1);
    *data = (char *) &conn->request;
    *size = sizeof(GAMPacket);
    *data += conn->req_read;
    *size -= conn->req_read;
    return (0);
}

/**
 * gam_connection_request:
 * @conn: connection data structure.
 * @req: the request
 *
 * Received a complete request, process it.
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
gam_connection_request(GamConnDataPtr conn, GAMPacketPtr req)
{
    GamSubscription *sub;
    int events;
    gboolean is_dir = TRUE;
    char byte_save;
    int type;
    int options;

    if ((conn == NULL) || (req == NULL))
        return (-1);
    if ((conn->fd < 0) || (conn->listener == NULL))
        return (-1);
    type = req->type & 0xF;
    options = req->type & 0xFFF0;
    GAM_DEBUG(DEBUG_INFO, "Request: from %d, seq %d, type %d options %d\n",
              conn->pid, req->seq, type, options);
    if (req->pathlen >= MAXPATHLEN)
        return (-1);

    /*
     * zero-terminate the string in the buffer, but keep the byte as
     * it may be the first one of the next request.
     */
    byte_save = req->path[req->pathlen];
    req->path[req->pathlen] = 0;

    switch (type) {
        case GAM_REQ_FILE:
        case GAM_REQ_DIR:
            events = GAMIN_EVENT_CHANGED | GAMIN_EVENT_CREATED |
                GAMIN_EVENT_DELETED | GAMIN_EVENT_MOVED |
                GAMIN_EVENT_EXISTS;
            if (type == GAM_REQ_DIR) {
                is_dir = TRUE;
		events |= GAMIN_EVENT_ENDEXISTS;
            } else {
                is_dir = FALSE;
            }
            sub = gam_subscription_new(&req->path[0], events, req->seq,
	                               is_dir, options);

            gam_subscription_set_listener(sub, conn->listener);
            gam_add_subscription(sub);
            break;
        case GAM_REQ_CANCEL:
            sub =
                gam_listener_get_subscription_by_reqno(conn->listener,
                                            	       req->seq);
            if (sub == NULL) {
                GAM_DEBUG(DEBUG_INFO,
                          "Cancel: subscription for (%d) not found\n",
                          req->seq);
		goto error;
            }
            GAM_DEBUG(DEBUG_INFO, "Cancelling subscription for (%d)\n",
                      req->seq);
            gam_remove_subscription(sub);
            gam_listener_remove_subscription(conn->listener, sub);
            break;
        case GAM_REQ_DEBUG:
#ifdef GAMIN_DEBUG_API
	    gam_debug_add(conn, &req->path[0], options);
#else
            GAM_DEBUG(DEBUG_INFO, "Unhandled debug request for %s\n",
                      &req->path[0]);
#endif
            break;
        default:
            GAM_DEBUG(DEBUG_INFO, "Unknown request type %d for %s\n",
                      type, &req->path[0]);
            goto error;
    }

    req->path[req->pathlen] = byte_save;
    return (0);
error:
    req->path[req->pathlen] = byte_save;
    return (-1);
}

/**
 * gam_connection_data:
 * @conn: connection data structure.
 * @len: the request len
 *
 * Received some incoming data, check if there is complete incoming
 * request(s) and process it (them), otherwise make some sanity check
 * and keep the incomplete request in the structure, waiting for more.
 *
 * Returns 0 in case of success and -1 in case of error
 */
int
gam_connection_data(GamConnDataPtr conn, int len)
{
    GAMPacketPtr req;

    if ((conn == NULL) || (len < 0) || (conn->req_read < 0)) {
        GAM_DEBUG(DEBUG_INFO, "invalid connection data\n");
        return (-1);
    }
    if ((len + conn->req_read) > (int) sizeof(GAMPacket)) {
        GAM_DEBUG(DEBUG_INFO,
                  "detected a data overflow or invalid size\n");
        return (-1);
    }
    conn->req_read += len;
    req = &conn->request;

    /*
     * loop processing all complete requests available in conn->request
     */
    while (1) {
        if (conn->req_read < (int) GAM_PACKET_HEADER_LEN) {
            /*
             * we don't have enough data to check the current request
             * keep it as a pending incomplete request and wait for more.
             */
            break;
        }
        /* check the packet total length */
        if (req->len > sizeof(GAMPacket)) {
            GAM_DEBUG(DEBUG_INFO, "invalid length %d\n", req->len);
            return (-1);
        }
        /* check the version */
        if (req->version != GAM_PROTO_VERSION) {
            GAM_DEBUG(DEBUG_INFO, "unsupported version %d\n",
                      req->version);
            return (-1);
        }
	if (GAM_REQ_CANCEL != req->type) {
    	    /* double check pathlen and total length */
    	    if ((req->pathlen <= 0) || (req->pathlen > MAXPATHLEN)) {
        	GAM_DEBUG(DEBUG_INFO, "invalid path length %d\n\n",
                	  req->pathlen);
        	return (-1);
    	    }
	}
        if (req->pathlen + GAM_PACKET_HEADER_LEN != req->len) {
            GAM_DEBUG(DEBUG_INFO, "invalid packet sizes: %d %d\n",
                      req->len, req->pathlen);
            return (-1);
        }
        /* Check the type of the request: TODO !!! */

        /*
         * We can now decide if the request is complete, if not
         * keep it as a pending incomplete request and wait for more.
         */
        if (conn->req_read < req->len) {
            /*
             * we don't have enough data to process the current request
             * keep it as a pending incomplete request and wait for more.
             */
            break;
        }

        if (gam_connection_request(conn, req) < 0) {
            GAM_DEBUG(DEBUG_INFO, "gam_connection_request() failed\n");
            return (-1);
        }

        /*
         * process any remaining request piggy-back'ed on the same packet
         */
        conn->req_read -= req->len;
        if (conn->req_read == 0)
            break;
        memmove(req, &(req->path[req->pathlen]), conn->req_read);
    }

    return (0);
}


/**
 * gam_send_event:
 * @conn: the connection data
 * @event: the event type
 * @path: the file/directory path
 *
 * Emit an event to the connection
 *
 * Returns 0 in case of success and -1 in case of failure
 */
int
gam_send_event(GamConnDataPtr conn, int reqno, int event,
               const char *path, int len)
{
    GAMPacket req;
    size_t tlen;
    int ret;
    int type;

    if ((conn == NULL) || (conn->fd < 0) || (path == NULL))
        return (-1);

    if (len <= 0) {
        GAM_DEBUG(DEBUG_INFO, "Empty file path\n");
        return (-1);
    }

    if (len >= MAXPATHLEN) {
        GAM_DEBUG(DEBUG_INFO, "File path too long %s\n", path);
        return (-1);
    }

    /*
     * Convert between Gamin/Marmot internal values and FAM ones.
     */
    switch (event) {
        case GAMIN_EVENT_CHANGED:
            type = FAMChanged;
            break;
        case GAMIN_EVENT_CREATED:
            type = FAMCreated;
            break;
        case GAMIN_EVENT_DELETED:
            type = FAMDeleted;
            break;
        case GAMIN_EVENT_MOVED:
            type = FAMMoved;
            break;
        case GAMIN_EVENT_EXISTS:
            type = FAMExists;
            break;
        case GAMIN_EVENT_ENDEXISTS:
            type = FAMEndExist;
            break;
#ifdef GAMIN_DEBUG_API
	case 50:
	    type = 50 + reqno;
	    break;
#endif
        default:
            GAM_DEBUG(DEBUG_INFO, "Unknown event type %d\n", event);
            return (-1);
    }

    GAM_DEBUG(DEBUG_INFO, "Event to %d : %d, %d, %s %s\n", conn->pid,
              reqno, type, path, gam_event_to_string(event));
    /*
     * prepare the packet
     */
    tlen = GAM_PACKET_HEADER_LEN + len;
    /* We use only local socket so no need for network byte order conversion */
    req.len = (unsigned short) tlen;
    req.version = GAM_PROTO_VERSION;
    req.seq = reqno;
    req.type = (unsigned short) type;
    req.pathlen = len;
    memcpy(&req.path[0], path, len);
    ret =
        gam_client_conn_write(conn->source, conn->fd, (gpointer) & req,
                              tlen);
    if (!ret) {
        GAM_DEBUG(DEBUG_INFO, "Failed to send event to %d\n", conn->pid);
        return (-1);
    }
    return (0);

}

/************************************************************************
 *									*
 *			Automatic exit handling				*
 *									*
 ************************************************************************/

#define MAX_IDLE_TIMEOUT 30

/**
 * gam_connections_check:
 *
 * This function is called periodically and will make the server exit
 * once there have been no connections for a while.
 */
gboolean
gam_connections_check(void)
{
    static time_t timeout = 0;

    if (g_list_first(gamConnList) != NULL) {
        if (timeout != 0) {
            GAM_DEBUG(DEBUG_INFO, "New active connection\n");
        }
        timeout = 0;
        return (TRUE);
    }
    if (timeout == 0) {
        GAM_DEBUG(DEBUG_INFO, "No more active connections\n");
        timeout = time(NULL);
    } else if (time(NULL) - timeout > MAX_IDLE_TIMEOUT) {
        GAM_DEBUG(DEBUG_INFO, "Exitting on timeout\n");
	gam_shutdown();
        exit(0);
    }
    return (TRUE);
}

/**
 * gam_connections_debug:
 *
 * Calling this function generate debugging informations about the set
 * of existing connections.
 */
void
gam_connections_debug(void) {
#ifdef GAM_DEBUG_ENABLED
    GamConnDataPtr conn;
    GList *cur;

    if (!gam_debug_active) return;
    if (gamConnList == NULL) {
	GAM_DEBUG(DEBUG_INFO, "No active connection\n");
	return;
    }
    cur = gamConnList;
    while (cur != NULL) {
        conn = (GamConnDataPtr) cur->data;
	if (conn == NULL) {
	    GAM_DEBUG(DEBUG_INFO, "Error: connection with no data\n");
	} else {
	    const char *state = "unknown";

	    switch (conn->state) {
	        case GAM_STATE_ERROR:
		    state = "error";
		    break;
	        case GAM_STATE_AUTH:
		    state = "need auth";
		    break;
	        case GAM_STATE_OKAY:
		    state = "okay";
		    break;
	        case GAM_STATE_CLOSED:
		    state = "closed";
		    break;
	    }
	    GAM_DEBUG(DEBUG_INFO, 
	              "Connection fd %d to pid %d: state %s, %d read\n",
		      conn->fd, conn->pid, state, conn->req_read);
	    gam_listener_debug(conn->listener);
	}
        cur = g_list_next(cur);
    }
#endif
}
