#include <config.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include "gam_error.h"

typedef void (*signal_handler)(int);

extern void gam_show_debug(void);

int gam_debug_active = 0;
static int initialized = 0;
static int do_debug = 0;
static int got_signal = 0;
static FILE *debug_out = NULL;

static void
gam_error_handle_signal(void) 
{
	if (got_signal == 0)
		return;

	got_signal = 0;

	if (do_debug == 0) 
	{
		char path[50] = "/tmp/gamin_debug_XXXXXX";
		int fd = mkstemp(path);
		if (fd >= 0) 
		{
			debug_out = fdopen(fd, "a");
			if (debug_out != NULL) 
			{
				do_debug = 1;
				gam_debug_active = 1;
				gam_show_debug();
			}
		}
	} else {
		do_debug = 0;
		gam_debug_active = 0;
		if (debug_out != NULL) 
		{
			fflush(debug_out);
			fclose(debug_out);
			debug_out = NULL;
		}
	}
}

static void 
gam_error_signal(int no) 
{
	got_signal = !got_signal;
	gam_debug_active = -1; /* force going into gam_debug() */
}

/**
 * gam_error_init:
 *
 * Initialization routine for the error and debug handling.
 */
void
gam_error_init(void) 
{
	if (initialized == 0) 
	{
		signal_handler prev;

		initialized = 1;

		if (getenv("GAM_DEBUG") != NULL) 
		{
			/* Fake the signal */
			got_signal = 1;
			gam_error_handle_signal();
		}

		prev = signal(SIGUSR2, gam_error_signal);
		/* if there is already an handler switch back to the original
		to avoid disturbing the application behaviour */
		if ((prev != SIG_IGN) && (prev != SIG_DFL) && (prev != NULL))
			signal(SIGUSR2, prev);
	}
}

/**
 * gam_error_init:
 *
 * Checking routine to call from time to time to handle asynchronous
 * error debugging events.
 */
void
gam_error_check(void) 
{
	if (initialized == 0)
		gam_error_init();

	if (got_signal)
		gam_error_handle_signal();
}

int
gam_errno(void)
{
	return (errno);
}

/**
 * gam_error:
 * @file: the filename where the error was detected
 * @line: the line where the error was detected
 * @function: the function where the error was detected
 * @format: *printf format
 * @...:  extra arguments
 *
 * Log an error, currently only stderr, but could go into syslog
 */
void
gam_error(const char *file, int line, const char *function,
          const char *format, ...)
{
	va_list args;

	if (initialized == 0)
		gam_error_init();

	if (got_signal)
		gam_error_handle_signal();

	if ((file == NULL) || (function == NULL) || (format == NULL))
		return;

	va_start(args, format);
	vfprintf((debug_out ? debug_out : stderr), format, args);
	va_end(args);

	if (debug_out)
		fflush(debug_out);
}

/**
 * gam_debug:
 * @file: the filename where the error was detected
 * @line: the line where the error was detected
 * @function: the function where the error was detected
 * @format: *printf format
 * @...:  extra arguments
 *
 * Log a debug message, fi those are activated by the GAM_DEBUG environment
 */
void
gam_debug(const char *file, int line, const char *function,
          const char *format, ...)
{
	va_list args;

	if (initialized == 0)
		gam_error_init();

	if (got_signal)
		gam_error_handle_signal();

	if ((do_debug == 0) || (gam_debug_active == 0))
		return;

	if ((file == NULL) || (function == NULL) || (format == NULL))
		return;

	va_start(args, format);
	vfprintf((debug_out ? debug_out : stdout), format, args);
	va_end(args);
	if (debug_out)
		fflush(debug_out);
}
