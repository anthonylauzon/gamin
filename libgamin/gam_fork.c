/**
 * gam_data.c: implementation of the automatic launch of the server side
 *             if apparently missing
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include "gam_fork.h"
#include "gam_error.h"

/**
 * TODO: the patch is computed statically at build time, maybe more
 *       flexibility might be needed.
 */
static const char *server_path = BINDIR "/gam_server";

/**
 * gamin_fork_server:
 * @fam_client_id: the client ID string to use
 *
 * Forks and try to launch the server processing the requests for
 * libgamin under the current process id and using the given client ID
 *
 * Returns 0 in case of success or -1 in case of detected error.
 */
int
gamin_fork_server(const char *fam_client_id)
{
    int ret, pid, status;

    gam_debug(DEBUG_INFO, "Asking to launch %s with client id %s\n",
              server_path, fam_client_id);
    /* Become a daemon */
    pid = fork();
    if (pid == 0) {
        setsid();
        if (fork() == 0) {
            setenv("GAM_CLIENT_ID", fam_client_id, 0);
            execl(server_path, server_path, NULL);
            gam_error(DEBUG_INFO, "failed to exec %s\n", server_path);
        }
	/*
	 * calling exit() generate troubles for termination handlers
	 * for example if the client uses bonobo/ORBit
	 */
        _exit(0);
    }

    /*
     * do a waitpid on the intermediate process to avoid zombies.
     */
retry_wait:
    ret = waitpid (pid, &status, 0);
    if (ret < 0) {
        if (errno == EINTR)
	    goto retry_wait;
    }

    return (0);
}
