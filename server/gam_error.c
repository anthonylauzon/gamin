#include <config.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include "gam_error.h"


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

    if ((file == NULL) || (function == NULL) || (format == NULL))
        return;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
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
    static int initialized = 0;
    static int do_debug = 0;
    va_list args;

    if (initialized == 0) {
        initialized = 1;
        if (getenv("GAM_DEBUG") != NULL)
            do_debug = 1;
    }
    if (do_debug == 0)
        return;
    if ((file == NULL) || (function == NULL) || (format == NULL))
        return;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}
