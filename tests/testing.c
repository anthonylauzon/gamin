#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>


#include "fam.h"

#ifndef MAXPATHLEN
#define MAXPATHLEN FILENAME_MAX
#endif

#define MAX_REQUESTS 2048

char pwd[250];
char filename[MAXPATHLEN + 250];

struct testState {
    int connected;
    FAMConnection fc;
    int nb_requests;
    FAMRequest fr[MAX_REQUESTS];
} testState;

#define IS_BLANK(p) ((*(p) == ' ') || (*(p) == '\t') ||		\
                     (*(p) == '\n') || (*(p) == '\r'))

static int
scanCommand(char *line, char **command, char **arg, char **arg2)
{
    char *cur = line;

    while (IS_BLANK(cur))
        cur++;
    if (*cur == 0)
        return (0);
    *command = cur;
    while ((*cur != 0) && (!IS_BLANK(cur)))
        cur++;
    if (*cur == 0)
        return (1);
    *cur = 0;
    cur++;
    while (IS_BLANK(cur))
        cur++;
    if (*cur == 0)
        return (1);
    *arg = cur;
    while ((*cur != 0) && (!IS_BLANK(cur)))
        cur++;
    if (*cur == 0)
        return (2);
    *cur = 0;
    cur++;
    while (IS_BLANK(cur))
        cur++;
    if (*cur == 0)
        return (2);
    *arg2 = cur;
    while ((*cur != 0) && (!IS_BLANK(cur)))
        cur++;
    if (*cur == 0)
        return (3);
    *cur = 0;
    cur++;
    while (IS_BLANK(cur))
        cur++;
    if (*cur == 0)
        return (3);
    /* too many args */
    return (-1);
}

static const char *
codeName(int code)
{
    static char error[15];

    switch (code) {
        case FAMChanged:
            return ("Changed");
        case FAMDeleted:
            return ("Deleted");
        case FAMStartExecuting:
            return ("StartExecuting");
        case FAMStopExecuting:
            return ("StopExecuting");
        case FAMCreated:
            return ("Created");
        case FAMMoved:
            return ("Moved");
        case FAMAcknowledge:
            return ("Acknowledge");
        case FAMExists:
            return ("Exists");
        case FAMEndExist:
            return ("EndExist");
        default:
            snprintf(error, 15, "Error %d", code);
            return (error);
    }
    return ("Error");
}

static int
printEvent(int no)
{
    int ret;
    FAMEvent fe;
    char *data;

    ret = FAMNextEvent(&(testState.fc), &fe);
    if (ret < 0) {
        fprintf(stderr, "event(s) line %d: FAMNextEvent failed\n", no);
        return (-1);
    }
    if (fe.userdata == NULL)
        data = "NULL";
    else
        data = fe.userdata;
    printf("%d: %s %s: %s\n",
           fe.fr.reqnum, fe.filename, codeName(fe.code), data);
    return (0);
}

static int
printEvents(int no)
{
    int ret;

    ret = FAMPending(&(testState.fc));
    if (ret < 0) {
        fprintf(stderr, "events line %d: FAMPending failed\n", no);
        return (-1);
    }
    if (ret == 0) {
        printf("no events\n");
    }
    while (ret != 0) {
        ret = printEvent(no);
        if (ret < 0)
            return (-1);

        ret = FAMPending(&(testState.fc));
        if (ret < 0) {
            fprintf(stderr, "events line %d: FAMPending failed\n", no);
            return (-1);
        }
    }
    return (0);
}

static int
processCommand(char *line, int no)
{
    int ret, args;
    char *command = NULL;
    char *arg = NULL;
    char *arg2 = NULL;

    if (line == NULL)
        return (-1);
    if (line[0] == '#')
        return (0);

    args = scanCommand(line, &command, &arg, &arg2);
    if (args < 0)
        return (-1);
    if (args == 0)
        return (0);

    if (!strcmp(command, "connect")) {
        if (testState.connected) {
            fprintf(stderr, "connect line %d: already connected\n", no);
            return (-1);
        }
        if (arg != NULL) {
            setenv("GAM_CLIENT_ID", arg, 1);
        }
        ret = FAMOpen(&(testState.fc));
        if (ret < 0) {
            fprintf(stderr, "connect line %d: failed to connect\n", no);
            return (-1);
        }
        testState.connected = 1;
	if (arg != NULL)
	    printf("connected to %s\n", arg);
	else
	    printf("connected\n");
    } else if (!strcmp(command, "disconnect")) {
        if (testState.connected == 0) {
            fprintf(stderr, "disconnect line %d: not connected\n", no);
            return (-1);
        }
        ret = FAMClose(&(testState.fc));
        if (ret < 0) {
            fprintf(stderr, "connect line %d: failed to disconnect\n", no);
            return (-1);
        }
        testState.connected = 0;
        printf("disconnected\n");
    } else if (!strcmp(command, "mondir")) {
        if (args == 2) {
	    snprintf(filename, sizeof(filename), "%s/%s", pwd, arg);
	    ret = FAMMonitorDirectory(&(testState.fc), filename,
				      &(testState.fr[testState.nb_requests]),
				      NULL);
        } else if (args == 3) {
	    int index;

            if (sscanf(arg2, "%d", &index) <= 0) {
		fprintf(stderr, "mondir line %d: invalid index value %s\n",
		        no, arg2);
		return (-1);
	    }
	    snprintf(filename, sizeof(filename), "%s/%s", pwd, arg);
	    testState.fr[testState.nb_requests].reqnum = index;
	    ret = FAMMonitorDirectory2(&(testState.fc), filename,
				      &(testState.fr[testState.nb_requests]));
	} else {
            fprintf(stderr, "mondir line %d: invalid format\n", no);
            return (-1);
	}
        if (ret < 0) {
            fprintf(stderr, "mondir line %d: failed to monitor %s\n", no,
                    arg);
            return (-1);
        }
        printf("mondir %s %d\n", arg, testState.nb_requests);
        testState.nb_requests++;
    } else if (!strcmp(command, "monfile")) {
        if (args != 2) {
            fprintf(stderr, "mkdir line %d: lacks name\n", no);
            return (-1);
        }
        snprintf(filename, sizeof(filename), "%s/%s", pwd, arg);
        ret = FAMMonitorFile(&(testState.fc), filename,
                             &(testState.fr[testState.nb_requests]), NULL);
        if (ret < 0) {
            fprintf(stderr, "monfile line %d: failed to monitor %s\n", no,
                    arg);
            return (-1);
        }
        printf("monfile %s %d\n", arg, testState.nb_requests);
        testState.nb_requests++;
    } else if (!strcmp(command, "pending")) {
        if (args != 1) {
            fprintf(stderr, "pending line %d: extra argument %s\n", no,
                    arg);
            return (-1);
        }
        ret = FAMPending(&(testState.fc));
        if (ret < 0) {
            fprintf(stderr, "pending line %d: failed\n", no);
            return (-1);
        }
        printf("pending %d\n", ret);
    } else if (!strcmp(command, "mkdir")) {
        if (args != 2) {
            fprintf(stderr, "mkdir line %d: lacks name\n", no);
            return (-1);
        }
        ret = mkdir(arg, 0755);
        if (ret < 0) {
            fprintf(stderr, "mkdir line %d: failed to create %s\n", no,
                    arg);
            return (-1);
        }
        printf("mkdir %s\n", arg);
    } else if (!strcmp(command, "mkfile")) {
        if (args != 2) {
            fprintf(stderr, "mkfile line %d: lacks name\n", no);
            return (-1);
        }
        ret = open(arg, O_CREAT | O_WRONLY, 0666);
        if (ret < 0) {
            fprintf(stderr, "mkfile line %d: failed to open %s\n", no,
                    arg);
            return (-1);
        }
        close(ret);
        printf("mkfile %s\n", arg);
    } else if (!strcmp(command, "append")) {
        if (args != 2) {
            fprintf(stderr, "mkfile line %d: lacks name\n", no);
            return (-1);
        }
        ret = open(arg, O_RDWR | O_APPEND);
        if (ret < 0) {
            fprintf(stderr, "append line %d: failed to open %s\n", no,
                    arg);
            return (-1);
        }
        write(ret, "a", 1);
        close(ret);
        printf("append %s\n", arg);
    } else if (!strcmp(command, "rmdir")) {
        if (args != 2) {
            fprintf(stderr, "rmdir line %d: lacks name\n", no);
            return (-1);
        }
        ret = rmdir(arg);
        if (ret < 0) {
            fprintf(stderr, "rmdir line %d: failed to remove %s\n", no,
                    arg);
            return (-1);
        }
        printf("rmdir %s\n", arg);
    } else if (!strcmp(command, "rmfile")) {
        if (args != 2) {
            fprintf(stderr, "rmfile line %d: lacks name\n", no);
            return (-1);
        }
        ret = unlink(arg);
        if (ret < 0) {
            fprintf(stderr, "rmfile line %d: failed to unlink %s\n", no,
                    arg);
            return (-1);
        }
        printf("rmfile %s\n", arg);
    } else if (!strcmp(command, "event")) {
        printEvent(no);
    } else if (!strcmp(command, "events")) {
        printEvents(no);
    } else if (!strcmp(command, "sleep")) {
        int i;

        for (i = 0; (i < 30) && (FAMPending(&(testState.fc)) == 0); i++)
            usleep(50);
    } else if (!strcmp(command, "wait")) {
        sleep(1);
    } else {
        fprintf(stderr, "Unable to parse line %d: %s\n", no, line);
        return (-1);
    }
    return (0);
}

static void
debugPrompt(void) {
    printf("> ");
    fflush(stdout);
}

static int
debugLoop(void) {
    fd_set read_set;
    int avail;
    int fd;

    debugPrompt();

retry:
    FD_ZERO(&read_set);
    FD_SET(0, &read_set);
    fd = 0;
    if (testState.connected) {
        FD_SET(testState.fc.fd, &read_set);
	fd = testState.fc.fd;
    }
    avail = select(fd + 1, &read_set, NULL, NULL, NULL);
    if (avail < 0) {
        if (errno == EINTR)
	    goto retry;
	fprintf(stderr, "debugLoop: select() failed \n");
	return (-1);
    }
    if (testState.connected) {
        if (FD_ISSET(testState.fc.fd, &read_set)) {
	    if (FAMPending(&(testState.fc)) > 0) {
	        printf("\n");
	        printEvents(0);
		debugPrompt();
	    }
	}
    }
    if (!(FD_ISSET(0, &read_set))) goto retry;
    return(0);
}

static int
playTest(const char *filename)
{
    FILE *f;
    char command[MAXPATHLEN + 201];
    int clen = 0, ret;
    int no = 0;
    int interactive = 0;

    testState.connected = 0;
    testState.nb_requests = 0;
    if (strcmp(filename, "-")) {
	f = fopen(filename, "r");
    } else {
        f = fdopen(0, "r");
	interactive = 1;
    }
    if (f == NULL) {
        fprintf(stderr, "Unable to read %s\n", filename);
        return (-1);
    }
    if (interactive) {
        while (debugLoop() == 0) {
	    ret = read(0, &command[clen], MAXPATHLEN + 200 - clen);
	    if (ret < 0)
	        break;
	    clen += ret;
	    if ((clen > 0) && ((command[clen -1] == '\n') ||
	        (command[clen -1] == '\r'))) {
		command[clen -1] = 0;
		no++;
		/* in interactive mode we don't exit on parse errors */
		processCommand(command, no);
		clen = 0;
	    }
	}
    } else {
	while (fgets(command, MAXPATHLEN + 200, f)) {
	    no++;
	    if (processCommand(command, no) < 0)
		break;
	}
    }
    fclose(f);
    return (0);
}

int
main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s testfile\n use - for stdin\n", argv[0]);
        exit(1);
    }
    getcwd(pwd, sizeof(pwd));
    playTest(argv[1]);
    return (0);
}
