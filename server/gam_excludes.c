#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include "gam_excludes.h"

typedef struct _gam_exclude gam_exclude;
typedef gam_exclude* gam_exclude_ptr;

struct _gam_exclude {
    const char *pattern;
    GPatternSpec *comp;
    int exclude;	/* 0 == notify, 1 == poll */
};

static int initialized = 0;
static GList *excludes = NULL;
static char *static_excludes[] = {
#ifdef HAVE_LINUX
    "/media/*",
    "/mnt/*",
    "/dev/*",
    "/proc/*",
#endif
    NULL
};

/**
 * gam_exclude_add:
 * @pattern: the pattern to exclude
 * @exclude: 1 to exclude, 0 to include
 *
 * Add an exclude pattern
 *
 * Returns -1 in case of error, and 0 otherwise
 */
static int
gam_exclude_add(const char *pattern, int exclude) {
    GPatternSpec *comp;
    gam_exclude_ptr ptr;

    comp = g_pattern_spec_new((const gchar *) pattern);
    if (comp == NULL)
        return(-1);
    ptr = (gam_exclude_ptr) malloc(sizeof(gam_exclude));
    if (ptr == NULL) {
        g_pattern_spec_free(comp);
	return(-1);
    }
    ptr->pattern = g_strdup(pattern);
    ptr->comp = comp;
    ptr->exclude = exclude;
    excludes = g_list_append(excludes, ptr);
#if 0
    fprintf(stderr, "added %s,%d to excludes\n", pattern, exclude);
#endif
    return(0);
}

/**
 * gam_exclude_check_all:
 * @filename: the filename to check
 *
 * Check a filename against the exclude patterns
 * The first matching pattern counts, whether positive or negative
 *
 * Returns 1 if a match is found and 0 otherwise.
 */
static int
gam_exclude_check_all(const char *filename) {
    GList *cur;
    gam_exclude_ptr ptr;
    unsigned int len;

    if ((filename == NULL) || (excludes == NULL))
        return(0);
    
    cur = excludes;
    len = strlen(filename);
    while (cur != NULL) {
        ptr = cur->data;
	if ((ptr != NULL) && (ptr->comp != NULL) &&
	    (g_pattern_match(ptr->comp, len, filename, NULL))) {
	    return(ptr->exclude);
	}
	cur = g_list_next(cur);
    }
    return(0);
}

/************************************************************************
 *									*
 *  Files to exclude from kernel watching due to dnotify limitations 	*
 *									*
 ************************************************************************/

/**
 * gam_exclude_read_config:
 *
 * Read the user configuration file in $HOME/.gaminrc
 * and populate the include/exclude lists accordingly.
 */
static void
gam_exclude_read_config(void) {
    gchar *filename;
    gchar *contents, **lines, *line, **words;
    gsize len;
    int x, y;
    int exclude = 1;

    filename = g_strconcat(g_get_home_dir(), "/.gaminrc", NULL);
    if (filename == NULL)
        return;
    g_file_get_contents(filename, &contents, &len, NULL);
    g_free(filename);
    if (contents == NULL)
        return;
    lines = g_strsplit(contents, "\n", 0);
    if (lines != NULL) {
        for (x = 0; lines[x] != NULL ; x++) {
	    line = lines[x];
	    if ((line[0] == 0) || (line[0] == '#'))
	        continue;
	    words = g_strsplit(line, " ", 0);
	    if (words == NULL)
	        continue;
	    
	    if (!strcmp(words[0], "poll")) {
	        exclude = 1;
	    } else if (!strcmp(words[0], "notify")) {
	        exclude = 0;
	    } else {
	        g_strfreev(words);
		continue;
	    }
	    for (y = 1; words[y] != NULL ; y++) {
	        if (words[y][0] == 0)
		    continue;
		if (words[y][0] == '#')
		    break;
		if (words[y][0] != '/')
		    continue;
		gam_exclude_add(words[y], exclude);
	    }
	    g_strfreev(words);
	}
	g_strfreev(lines);
    }
    g_free(contents);
}

/**
 * gam_exclude_init:
 *
 * Initialize the excluding check mechanism
 *
 * Return 0 in case of success and -1 in case of failure.
 */
int
gam_exclude_init(void) {
    unsigned int i;

    if (initialized)
        return(-1);

    gam_exclude_read_config();
    for (i = 0;i < (sizeof(static_excludes)/sizeof(static_excludes[0]));i++) {
        if (static_excludes[i] != NULL)
	    gam_exclude_add(static_excludes[i], 1);
    }
    initialized = 1;
    return(0);
}

/**
 * gam_exclude_check:
 * @filename: the absolute file path
 *
 * Check if the file should be monitored using the kernel dnotify
 * mechanism or not.
 *
 * Returns TRUE if the file should not be monitored by dnotify, and FALSE
 *         otherwise.
 */
gboolean
gam_exclude_check(const char *filename) {
    if (gam_exclude_check_all(filename)) {
#if 0
	fprintf(stderr, "found %s in excludes\n", filename);
#endif
        return(TRUE);
    }
    return(FALSE);
}

