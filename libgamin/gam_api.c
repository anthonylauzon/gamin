/**
 * gam_api.c: implementation of the library side of the gamin FAM implementation
 */

#include "config.h"
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "fam.h"
#include "gam_protocol.h"
#include "gam_data.h"
#include "gam_fork.h"
#include "gam_error.h"

#define TEST_DEBUG

#define MAX_RETRIES 25

#ifdef TEST_DEBUG
static char *
gamin_dump_event(FAMEvent *event) {
    static char res[200];
    const char *type;

    if (event == NULL)
        return("NULL event !");
    switch (event->code) {
        case FAMChanged: type = "Changed"; break;
        case FAMDeleted: type = "Deleted"; break;
        case FAMStartExecuting: type = "StartExecuting"; break;
        case FAMStopExecuting: type = "StopExecuting"; break;
        case FAMCreated: type = "Created"; break;
        case FAMMoved: type = "Moved"; break;
        case FAMAcknowledge: type = "Acknowledge"; break;
        case FAMExists: type = "Exists"; break;
        case FAMEndExist: type = "EndExist"; break;
	default: type = "Unknown"; break;
    }
    snprintf(res, 199, "%s : %s", type, &event->filename[0]);
    return(res);
}
#endif

/************************************************************************
 *									*
 *			Path for the socket connection			*
 *									*
 ************************************************************************/

/**
 * gamin_get_user_name:
 *
 * Get the user name for the current process.
 *
 * Returns a new string or NULL in case of error.
 */
static char *
gamin_get_user_name(void)
{
    struct passwd *pw;

    pw = getpwuid(getuid());
    if (pw != NULL)
        return (strdup(pw->pw_name));
    return (NULL);
}

/**
 * gamin_get_socket_path:
 *
 * Get the file path to the socket to connect the FAM server.
 * The fam server interface is available though a socket whose
 * id is available though an environment variable GAM_CLIENT_ID
 *
 * Returns a new string or NULL in case of error.
 */
static char *
gamin_get_socket_path(void)
{
    const char *fam_client_id;
    char *user;
    char *ret;
    char path[MAXPATHLEN + 1];

    fam_client_id = getenv("GAM_CLIENT_ID");
    if (fam_client_id == NULL) {
        GAM_DEBUG(DEBUG_INFO, "Error getting GAM_CLIENT_ID\n");
        fam_client_id = "";
    }
    user = gamin_get_user_name();

    if (user == NULL) {
        gam_error(DEBUG_INFO, "Error getting user informations");
        return (NULL);
    }
#ifdef HAVE_ABSTRACT_SOCKETS
    snprintf(path, MAXPATHLEN, "/tmp/fam-%s-%s", user, fam_client_id);
#else
    snprintf(path, MAXPATHLEN, "/tmp/fam-%s/fam-%s", user, fam_client_id);
#endif
    path[MAXPATHLEN] = 0;
    ret = strdup(path);
    free(user);
    return (ret);
}

#ifndef HAVE_ABSTRACT_SOCKETS
/**
 * gamin_get_socket_dir:
 *
 * Get the directory path to the socket to connect the FAM server.
 *
 * Returns a new string or NULL in case of error.
 */
static char *
gamin_get_socket_dir(void)
{
    char *user;
    char *ret;
    char path[MAXPATHLEN + 1];

    user = gamin_get_user_name();

    if (user == NULL) {
        gam_error(DEBUG_INFO, "Error getting user informations");
        return (NULL);
    }
    snprintf(path, MAXPATHLEN, "/tmp/fam-%s", user);
    path[MAXPATHLEN] = 0;
    ret = strdup(path);
    free(user);
    return (ret);
}



/************************************************************************
 *									*
 *		Security for OSes without abstract sockets		*
 *									*
 ************************************************************************/
/**
 * gamin_check_secure_dir:
 *
 * Tries to ensure that the directory used to hold the socket used
 * for communicating with is a safe directory to avoid possible attacks.
 *
 * Returns 1 if safe, 0 if missing, -1 if not safe
 */
static int
gamin_check_secure_dir(void)
{
    char *dir;
    struct stat st;
    int ret;

    dir = gamin_get_socket_dir();
    if (dir == NULL) {
	gam_error(DEBUG_INFO, "Failed to get path to socket directory\n");
        return(0);
    }
    ret = stat(dir, &st);
    if (ret < 0) {
	free(dir);
	return(0);
    }
    if (st.st_uid != getuid()) {
	gam_error(DEBUG_INFO,
		  "Socket directory %s has different owner\n",
		  dir);
	goto unsafe;
    }
    if (!S_ISDIR (st.st_mode)) {
	gam_error(DEBUG_INFO, "Socket path %s is not a directory\n",
		  dir);
	goto unsafe;
    }
    if (st.st_mode & (S_IRWXG|S_IRWXO)) {
	gam_error(DEBUG_INFO,
		  "Socket directory %s has wrong permissions\n",
		  dir);
	goto unsafe;
    }
    if (((st.st_mode & (S_IRWXU)) != S_IRWXU)) {
	gam_error(DEBUG_INFO,
		  "Socket directory %s has wrong permissions\n",
		  dir);
	goto unsafe;
    }

    /*
     * all checks on existing dir seems okay
     */
    gam_debug(DEBUG_INFO, "Reusing socket directory %s\n", dir);
    free(dir);
    return(1);

unsafe:
    /*
     * The path to the directory is considered unsafe
     * try to remove the given path to rebuild the directory.
     */
    ret = rmdir(dir);
    if (ret < 0) {
	ret = unlink(dir);
	if (ret < 0) {
	    gam_error(DEBUG_INFO, "Failed to remove unsafe path %s\n",
	              dir);
	    free(dir);
	    return(-1);
	}
    }
    gam_debug(DEBUG_INFO, "Removed %s\n", dir);
    free(dir);
    return(0);
}

/**
 * gamin_check_secure_path:
 * @path: path to the (possibly abstract) socket
 *
 * Tries to create or ensure that the socket used for communicating with
 * the clients are in a safe directory to avoid possible attacks.
 *
 * Returns 1 if safe, 0 if missing, -1 if not safe
 */
static int
gamin_check_secure_path(const char *path)
{
    struct stat st;
    int ret;

    ret = gamin_check_secure_dir();
    if (ret <= 0)
        return(ret);

    /*
     * Check the existing socket if any
     */
    ret = stat(path, &st);
    if (ret < 0)
	return(0);
    
    if (st.st_uid != getuid()) {
	gam_error(DEBUG_INFO,
		  "Socket %s has different owner\n",
		  path);
	goto cleanup;
    }
#ifdef S_ISSOCK
    if (!S_ISSOCK (st.st_mode)) {
	gam_error(DEBUG_INFO, "Socket path %s is not a socket\n",
		  path);
	goto cleanup;
    }
#endif
    if (st.st_mode & (S_IRWXG|S_IRWXO)) {
	gam_error(DEBUG_INFO,
		  "Socket %s has wrong permissions\n",
		  path);
	goto cleanup;
    }
    /*
     * Looks good though binding may fail due to an existing server
     */
    return(1);

cleanup:
    /*
     * the existing file at the socket location seems strange, try to remove it
     */
    ret = unlink(path);
    if (ret < 0) {
	gam_error(DEBUG_INFO, "Failed to remove %s\n", path);
	return(-1);
    }
    return(0);
}
#endif /* ! HAVE_ABSTRACT_SOCKETS */

/************************************************************************
 *									*
 *			Connection socket shutdown			*
 *									*
 ************************************************************************/

/**
 * gamin_connect_unix_socket:
 * @path: path to the (possibly abstract) socket

 * Returns the socket file descriptor or -1 in case of error.
 */
static int
gamin_connect_unix_socket(const char *path)
{
    int fd;
    struct sockaddr_un addr;
    int retries = 0;

  retry_start:
    fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        gam_error(DEBUG_INFO, "Failed to create unix socket\n");
        return (-1);
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
#ifdef HAVE_ABSTRACT_SOCKETS
    addr.sun_path[0] = '\0';
    strncpy(&addr.sun_path[1], path, (sizeof(addr) - 4) - 2);
#else
    /*
     * if the socket is exposed at the filesystem level we need to take
     * some extra protection checks. Also make sure the socket is created
     * with restricted mode
     */
    if (gamin_check_secure_path(path) < 0) {
	return (-1);
    }
    strncpy(&addr.sun_path[0], path, (sizeof(addr) - 4) - 1);
#endif

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        if (retries == 0) {
            const char *fam_client_id = getenv("GAM_CLIENT_ID");

            if (fam_client_id == NULL)
                fam_client_id = "";
            /*
             * need to close it here to avoid inheriting it
             * otherwise autoshudown won't fail since the server
             * itself is still connected to the socket.
             */
            close(fd);
            gamin_fork_server(fam_client_id);
            retries++;
            goto retry_start;
        }
        if (retries < MAX_RETRIES) {
            usleep(50000);
            retries++;
            close(fd);
            goto retry_start;
        }

        gam_error(DEBUG_INFO, "Failed to connect to socket %s\n", path);
        close(fd);
        return (-1);
    }
    GAM_DEBUG(DEBUG_INFO, "Connected to socket %s : %d\n", path, fd);

    return (fd);
}

/**
 * gamin_write_credential_byte:
 * @fd: the file descriptor for the socket
 *
 * The authentication on the server receiving side need to receive some
 * data from the client to be able to assert the client credential. So
 * this routine simply output a 0 byte to allow the kernel to pass that
 * information.
 *
 * Returns -1 in case of error, 0 otherwise
 */
static int
gamin_write_credential_byte(int fd)
{
    char data[2] = { 0, 0 };
    int written;

retry:
    written = write(fd, &data[0], 1);
    if (written < 0) {
        if (errno == EINTR)
            goto retry;
        gam_error(DEBUG_INFO,
                  "Failed to write credential bytes to socket %d\n", fd);
        return (-1);
    }
    if (written != 1) {
        gam_error(DEBUG_INFO, "Wrote %d credential bytes to socket %d\n",
                  written, fd);
        return (-1);
    }
    GAM_DEBUG(DEBUG_INFO, "Wrote credential bytes to socket %d\n", fd);
    return (0);
}

/**
 * gamin_data_available:
 * @fd: the file descriptor for the socket
 *
 * Check if there is some incoming data to be read from the file descriptor
 *
 * Returns -1 in case of error, 0 if no data, 1 if data can be read
 */
static int
gamin_data_available(int fd)
{
    fd_set read_set;
    struct timeval tv;
    int avail;

    if (fd < 0)
        return (-1);

  retry:
    FD_ZERO(&read_set);
    FD_SET(fd, &read_set);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    avail = select(fd + 1, &read_set, NULL, NULL, &tv);
    if (avail < 0) {
        if (errno == EINTR)
            goto retry;
        gam_error(DEBUG_INFO,
                  "Failed to check data availability on socket %d\n", fd);
        return (-1);
    }
    if (avail == 0)
        return (0);
    return (1);
}

/**
 * gamin_write_byte:
 * @fd: the file descriptor for the socket
 * @data: pointer to the data
 * @len: length of the data in bytes
 *
 * Write some data to the server socket.
 *
 * Returns -1 in case of error, 0 otherwise
 */
static int
gamin_write_byte(int fd, const char *data, size_t len)
{
    int written;

  retry:
    written = write(fd, &data[0], len);
    if (written < 0) {
        if (errno == EINTR)
            goto retry;
        gam_error(DEBUG_INFO, "Failed to write bytes to socket %d\n", fd);
        return (-1);
    }
    if (written != (int) len) {
        gam_error(DEBUG_INFO, "Wrote only %d bytes to socket %d\n",
                  written, fd);
        return (-1);
    }
    GAM_DEBUG(DEBUG_INFO, "Wrote %d bytes to socket %d\n", written, fd);
    return (0);
}

/**
 * gamin_send_request:
 * @type: the GAMReqType for the request
 * @fd: the file descriptor for the socket
 * @filename,: the filename for the file or directory
 * @fr: the fam request
 * @userData: user data associated to this request
 * @has_reqnum: indicate if fr already has a request number
 */
static int
gamin_send_request(GAMReqType type, int fd, const char *filename,
                   FAMRequest * fr, void *userData, GAMDataPtr data,
		   int has_reqnum)
{
    int reqnum;
    size_t len, tlen;
    GAMPacket req;
    int ret;

    if (filename == NULL) {
        len = 0;
        reqnum = fr->reqnum;
    } else if (has_reqnum == 0) {
        len = strlen(filename);
        if (len > MAXPATHLEN)
            return (-1);
        reqnum = gamin_data_get_reqnum(data, filename, (int) type, userData);
        if (reqnum < 0)
            return (-1);
	fr->reqnum = reqnum;
    } else {
        len = strlen(filename);
        if (len > MAXPATHLEN)
            return (-1);
        reqnum = gamin_data_get_request(data, filename, (int) type, userData,
	                                fr->reqnum);
        if (reqnum < 0)
            return (-1);
    }
    tlen = sizeof(GAMPacket) - MAXPATHLEN + len;
    /* We use only local socket so no need for network byte order conversion */
    req.len = (unsigned short) tlen;
    req.version = GAM_PROTO_VERSION;
    req.seq = reqnum;
    req.type = (unsigned short) type;
    req.pathlen = len;
    if (len > 0)
        memcpy(&req.path[0], filename, len);
    ret = gamin_write_byte(fd, (const char *) &req, tlen);

    GAM_DEBUG(DEBUG_INFO, "gamin_send_request %d for socket %d\n", reqnum,
              fd);
    return (ret);
}

/**
 * gamin_check_cred:
 *
 * The first read on the connection gathers credentials from the server
 * and checks them. Parts directly borrowed from DBus code.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
static int
gamin_check_cred(GAMDataPtr conn, int fd)
{
    struct msghdr msg;
    struct iovec iov;
    char buf;
    pid_t c_pid;
    uid_t c_uid, s_uid;
    gid_t c_gid;

#ifdef HAVE_CMSGCRED
    char cmsgmem[CMSG_SPACE(sizeof(struct cmsgcred))];
    struct cmsghdr *cmsg = (struct cmsghdr *) cmsgmem;
#endif

    s_uid = getuid();

#if defined(LOCAL_CREDS) && defined(HAVE_CMSGCRED)
    /* Set the socket to receive credentials on the next message */
    {
        int on = 1;

        if (setsockopt(fd, 0, LOCAL_CREDS, &on, sizeof(on)) < 0) {
            gam_error(DEBUG_INFO, "Unable to set LOCAL_CREDS socket option\n");
            return(-1);
        }
    }
#endif

    iov.iov_base = &buf;
    iov.iov_len = 1;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

#ifdef HAVE_CMSGCRED
    memset(cmsgmem, 0, sizeof(cmsgmem));
    msg.msg_control = cmsgmem;
    msg.msg_controllen = sizeof(cmsgmem);
#endif

retry:
    if (recvmsg(fd, &msg, 0) < 0) {
        if (errno == EINTR)
            goto retry;

        gam_debug(DEBUG_INFO, "Failed to read credentials byte on %d\n", fd);
        goto failed;
    }

    if (buf != '\0') {
        gam_debug(DEBUG_INFO, "Credentials byte was not nul on %d\n", fd);
        goto failed;
    }
#ifdef HAVE_CMSGCRED
    if (cmsg->cmsg_len < sizeof(cmsgmem) || cmsg->cmsg_type != SCM_CREDS) {
        gam_debug(DEBUG_INFO,
                  "Message from recvmsg() was not SCM_CREDS\n");
        goto failed;
    }
#endif

    gam_debug(DEBUG_INFO, "read credentials byte\n");

    {
#ifdef SO_PEERCRED
        struct ucred cr;
        int cr_len = sizeof(cr);

        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) ==
            0 && cr_len == sizeof(cr)) {
            c_pid = cr.pid;
            c_uid = cr.uid;
            c_gid = cr.gid;
        } else {
            gam_debug(DEBUG_INFO,
                      "Failed to getsockopt() credentials on %d, returned len %d/%d\n",
                      fd, cr_len, (int) sizeof(cr));
            goto failed;
        }
#elif defined(HAVE_CMSGCRED)
        struct cmsgcred *cred;

        cred = (struct cmsgcred *) CMSG_DATA(cmsg);

        c_pid = cred->cmcred_pid;
        c_uid = cred->cmcred_euid;
        c_gid = cred->cmcred_groups[0];
#else /* !SO_PEERCRED && !HAVE_CMSGCRED */
        gam_debug(DEBUG_INFO,
                  "Socket credentials not supported on this OS\n");
        goto failed;
#endif
    }

    if (s_uid != c_uid) {
        gam_debug(DEBUG_INFO,
                  "Credentials check failed: s_uid %d, c_uid %d\n",
                  (int) s_uid, (int) c_uid);
        goto failed;
    }
    gam_debug(DEBUG_INFO,
              "Credentials: s_uid %d, c_uid %d, c_gid %d, c_pid %d\n",
              (int) s_uid, (int) c_uid, (int) c_gid, (int) c_pid);
    gamin_data_done_auth(conn);

    return(0);

failed:
    close(fd);
    return (-1);
}

/**
 * gamin_read_data:
 * @conn: the connection
 * @fd: the file descriptor for the socket
 *
 * Read the available data on the file descriptor. This is a potentially
 * blocking operation.
 *
 * Return 0 in case of success, -1 in case of error.
 */
static int
gamin_read_data(GAMDataPtr conn, int fd)
{
    int ret;
    char *data;
    int size;

    ret = gamin_data_need_auth(conn);
    if (ret == 1) {
        gam_debug(DEBUG_INFO, "Client need auth %d\n", fd);
        if (gamin_check_cred(conn, fd) < 0) {
	    return (-1);
	}
	ret = gamin_data_available(fd);
	if (ret < 0)
	    return(-1);
	if (ret == 0)
	    return(0);
    } else if (ret != 0) {
	return (-1);
    }
    ret = gamin_data_get_data(conn, &data, &size);
    if (ret < 0) {
        return (-1);
    }
retry:
    ret = read(fd, (char *) data, size);
    if (ret < 0) {
        if (errno == EINTR)
            goto retry;
        gam_error(DEBUG_INFO, "failed to read() from server connection\n");
        return (-1);
    }
    if (ret == 0) {
        gam_error(DEBUG_INFO, "end from FAM server connection\n");
        return (-1);
    }
    gam_debug(DEBUG_INFO, "read %d bytes from server\n", ret);

    if (gamin_data_conn_data(conn, ret) < 0) {
        gam_error(DEBUG_INFO, "Failed to process %d bytes from server\n",
                  ret);
        return (-1);
    }
    return (0);
}

/**
 * gamin_resend_request:
 * @fd: the file descriptor for the socket
 * @type: the GAMReqType for the request
 * @filename,: the filename for the file or directory
 * @reqnum: the request number.
 *
 * Reemit a request, used on a reconnection.
 *
 * Returns 0 in case of success and -1 in case of error
 */
static int
gamin_resend_request(int fd, GAMReqType type, const char *filename,
                     int reqnum)
{
    size_t len, tlen;
    GAMPacket req;
    int ret;

    if ((filename == NULL) || (fd < 0))
        return(-1);

    len = strlen(filename);
    tlen = sizeof(GAMPacket) - MAXPATHLEN + len;
    /* We use only local socket so no need for network byte order conversion */
    req.len = (unsigned short) tlen;
    req.version = GAM_PROTO_VERSION;
    req.seq = reqnum;
    req.type = (unsigned short) type;
    req.pathlen = len;
    if (len > 0)
        memcpy(&req.path[0], filename, len);
    ret = gamin_write_byte(fd, (const char *) &req, tlen);

    GAM_DEBUG(DEBUG_INFO, "gamin_resend_request %d for socket %d\n", reqnum,
              fd);
    return (ret);
}

/**
 * gamin_try_reconnect:
 * @conn: the connection
 * @fd: the file descriptor for the socket
 *
 * The last read or write resulted in a failure, connection to the server
 * has been broken, close the socket and try to reconnect and register
 * the monitors again. Reusing the same fd is needed since applications
 * are unlikely to recheck it.
 *
 * Return 0 in case of success, -1 in case of error.
 */
static int
gamin_try_reconnect(GAMDataPtr conn, int fd)
{
    int newfd, i, ret, nb_req;
    GAMReqDataPtr *reqs;
    char *socket_name;


    if ((conn == NULL) || (fd < 0))
        return(-1);
    GAM_DEBUG(DEBUG_INFO, "Trying to reconnect to server on %d\n", fd);

    /*
     * the connection is no more in an usable state
     */
    /*conn->fd = -1; */

    socket_name = gamin_get_socket_path();
    if (socket_name == NULL)
        return (-1);

    /*
     * try to reopen a connection to the server
     */
    close(fd);
    newfd = gamin_connect_unix_socket(socket_name);

    free(socket_name);
    if (newfd < 0) {
        return (-1);
    }

    if (newfd != fd) {
	/*
	 * reuse the same descriptor
	 */
	ret = dup2(newfd, fd);
	if (ret < 0) {
	    gam_error(DEBUG_INFO,
	              "Failed to reuse descriptor %d on reconnect\n",
		      fd);
	    close(newfd);
	    return (-1);
	}
    }

    /*
     * seems we managed to rebuild a connection to the server.
     * start the authentication again and resubscribe all existing
     * monitoring commands.
     */
    ret = gamin_write_credential_byte(fd);
    if (ret != 0) {
        close(fd);
        return (-1);
    }

    nb_req = gamin_data_reset(conn, &reqs);
    if (reqs != NULL) {
	for (i = 0; i < nb_req;i++) {
	    gamin_resend_request(fd, reqs[i]->type, reqs[i]->filename,
	                         reqs[i]->reqno);
	}
    }
    return(0);
}

/************************************************************************
 *									*
 *			Public interfaces				*
 *									*
 ************************************************************************/

/**
 * FAMOpen:
 * @fc:  pointer to an uninitialized connection structure
 *
 * This function tries to open a connection to the FAM server.
 *
 * Returns -1 in case of error, 0 otherwise
 */
int
FAMOpen(FAMConnection * fc)
{
    char *socket_name;
    int fd, ret;

    GAM_DEBUG(DEBUG_INFO, "FAMOpen()\n");

    if (fc == NULL)
        return (-1);

    socket_name = gamin_get_socket_path();
    if (socket_name == NULL)
        return (-1);

    fd = gamin_connect_unix_socket(socket_name);

    free(socket_name);
    if (fd < 0) {
        return (-1);
    }
    ret = gamin_write_credential_byte(fd);
    if (ret != 0) {
        close(fd);
        return (-1);
    }
    fc->fd = fd;
    fc->client = (void *) gamin_data_new();
    if (fc->client == NULL) {
        close(fd);
        return (-1);
    }
    return (0);
}

/**
 * FAMOpen2:
 * @fc:  pointer to an uninitialized connection structure
 * @appName:  the application name
 *
 * This function tries to open a connection to the FAM server.
 * The fam server interface is available though a socket whose
 * id is available though an environment variable GAM_CLIENT_ID
 *
 * Returns -1 in case of error, 0 otherwise
 */
int
FAMOpen2(FAMConnection * fc, const char *appName)
{
    int ret;

    GAM_DEBUG(DEBUG_INFO, "FAMOpen2()\n");

    ret = FAMOpen(fc);
    /*
    if (ret == 0)
        fc->client = (void *) appName;
     */
    return (ret);
}

/**
 * FAMClose:
 * @fc:  pointer to a connection structure.
 *
 * This function closes the connection to the FAM server.
 *
 * Returns -1 in case of error, 0 otherwise
 */
int
FAMClose(FAMConnection * fc)
{
    int ret;

    if (fc == NULL)
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "FAMClose()\n");

    ret = close(fc->fd);
    fc->fd = -1;
    gamin_data_free(fc->client);
    return (ret);
}

/**
 * FAMMonitorDirectory:
 * @fc: pointer to a connection structure.
 * @filename: the directory filename, it must not be relative.
 * @fr: pointer to the request structure.
 * @userData: user data associated to this request
 *
 * Register a monitoring request for a given directory.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
FAMMonitorDirectory(FAMConnection * fc, const char *filename,
                    FAMRequest * fr, void *userData)
{
    if ((fc == NULL) || (filename == NULL) || (fr == NULL))
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "FAMMonitorDirectory(%s)\n", filename);

    if ((filename[0] != '/') || (strlen(filename) >= MAXPATHLEN))
        return (-1);
    if ((fc->fd < 0) || (fc->client == NULL))
        return (-1);
    return (gamin_send_request(GAM_REQ_DIR, fc->fd, filename,
                               fr, userData, fc->client, 0));
}

/**
 * FAMMonitorDirectory2:
 * @fc: pointer to a connection structure.
 * @filename: the directory filename, it must not be relative.
 * @fr: pointer to the request structure.
 *
 * Register a monitoring request for a given directory.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
FAMMonitorDirectory2(FAMConnection * fc, const char *filename,
                     FAMRequest * fr)
{
    if ((fc == NULL) || (filename == NULL) || (fr == NULL))
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "FAMMonitorDirectory2(%s, %d)\n",
              filename, fr->reqnum);

    if ((filename[0] != '/') || (strlen(filename) >= MAXPATHLEN))
        return (-1);
    if ((fc->fd < 0) || (fc->client == NULL))
        return (-1);

    return (gamin_send_request(GAM_REQ_DIR, fc->fd, filename,
                               fr, NULL, fc->client, 1));
}

/**
 * FAMMonitorFile:
 * @fc: pointer to a connection structure.
 * @filename: the file filename, it must not be relative.
 * @fr: pointer to the request structure.
 * @userData: user data associated to this request
 *
 * Register a monitoring request for a given file.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
FAMMonitorFile(FAMConnection * fc, const char *filename,
               FAMRequest * fr, void *userData)
{
    if ((fc == NULL) || (filename == NULL) || (fr == NULL))
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "FAMMonitorFile(%s)\n", filename);

    if ((filename[0] != '/') || (strlen(filename) >= MAXPATHLEN))
        return (-1);
    if ((fc->fd < 0) || (fc->client == NULL))
        return (-1);
    return (gamin_send_request(GAM_REQ_FILE, fc->fd, filename,
                               fr, userData, fc->client, 0));
}

/**
 * FAMMonitorFile2:
 * @fc: pointer to a connection structure.
 * @filename: the file filename, it must not be relative.
 * @fr: pointer to the request structure.
 *
 * Register a monitoring request for a given file.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
FAMMonitorFile2(FAMConnection * fc, const char *filename, FAMRequest * fr)
{
    if ((fc == NULL) || (filename == NULL) || (fr == NULL))
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "FAMMonitorFile2(%s, %d)\n", filename, fr->reqnum);

    if ((filename[0] != '/') || (strlen(filename) >= MAXPATHLEN))
        return (-1);
    if ((fc->fd < 0) || (fc->client == NULL))
        return (-1);
    return (gamin_send_request(GAM_REQ_FILE, fc->fd, filename,
                               fr, NULL, fc->client, 1));
}

/**
 * FAMMonitorCollection:
 * @fc: pointer to a connection structure.
 * @filename: the file filename, it must not be relative.
 * @fr: pointer to the request structure.
 * @userData: user data associated to this request
 * @depth:  supposedly a limit in the recursion depth
 * @mask:  unknown !
 *
 * Register a extended monitoring request for a given directory.
 * NOT SUPPORTED
 *
 * Returns -1
 */
int
FAMMonitorCollection(FAMConnection * fc, const char *filename,
                     FAMRequest * fr, void *userData, int depth,
                     const char *mask)
{
    if (filename == NULL)
        filename = "NULL";
    if (mask == NULL)
        mask = "NULL";
    gam_error(DEBUG_INFO,
              "Unsupported call filename %s, depth %d, mask %s\n",
              filename, depth, mask);
    return (-1);
}


/**
 * FAMNextEvent:
 * @fc: pointer to a connection structure.
 * @fe: pointer to an event structure.
 *
 * Read the next event, possibly blocking on input.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
FAMNextEvent(FAMConnection * fc, FAMEvent * fe)
{
    int ret;
    int fd;
    GAMDataPtr conn;

    if ((fc == NULL) || (fe == NULL))
        return (-1);
    conn = fc->client;
    if (conn == NULL)
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "FAMNextEvent(fd = %d)\n", fc->fd);

    fd = fc->fd;
    if (fd < 0) {
        return (-1);
    }

    if (!gamin_data_event_ready(conn)) {
        if (gamin_read_data(conn, fc->fd) < 0) {
	    gamin_try_reconnect(conn, fc->fd);
	    return (-1);
	}
    }
    ret = gamin_data_read_event(conn, fe);
    if (ret < 0)
        return (ret);
    fe->fc = fc;
#ifdef TEST_DEBUG
    GAM_DEBUG(DEBUG_INFO, "FAMNextEvent : %s\n", gamin_dump_event(fe));
#endif
    return (1);
}

/**
 * FAMPending:
 * @fc: pointer to a connection structure.
 *
 * Check for event waiting for processing.
 *
 * Returns the number of events waiting for processing or -1 in case of error.
 */
int
FAMPending(FAMConnection * fc)
{
    int ret;
    GAMDataPtr conn;

    if (fc == NULL)
        return (-1);
    conn = fc->client;
    if (conn == NULL)
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "FAMPending(fd = %d)\n", fc->fd);

    /*
     * make sure we won't block if reading
     */
    ret = gamin_data_available(fc->fd);
    if (ret < 0)
        return (-1);
    if (ret > 0) {
        if (gamin_read_data(conn, fc->fd) < 0) {
	    gamin_try_reconnect(conn, fc->fd);
	}
    }

    return (gamin_data_event_ready(conn));
}

/**
 * FAMCancelMonitor:
 * @fc: pointer to a connection structure.
 * @fr: pointer to a request structure.
 *
 * This function is used to permanently stop a monitoring request.
 * the routine will free the FAMRequest structure provided.
 *
 * Returns 0 in case of success and -1 in case of error.
 */
int
FAMCancelMonitor(FAMConnection * fc, FAMRequest * fr)
{
    GAMDataPtr conn;
    int ret;

    if ((fc == NULL) || (fr == NULL))
        return (-1);
    if ((fc->fd < 0) || (fc->client == NULL))
        return (-1);

    GAM_DEBUG(DEBUG_INFO, "FAMCancelMonitor(%d)\n", fr->reqnum);

    /*
     * destroy the request internally
     */
    conn = fc->client;
    ret = gamin_data_del_req(conn, fr->reqnum);
    if (ret < 0)
        return (-1);

    /*
     * send destruction message to the server
     */
    ret = gamin_send_request(GAM_REQ_CANCEL, fc->fd, NULL,
                             fr, NULL, fc->client, 0);

    /*
     * TODO: check should this *really* be freed ?
     */
    free(fr);

    return (ret);
}
