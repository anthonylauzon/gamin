/*
 * Inode based directory notification for Linux
 *
 * Copyright (C) 2004 John McCutchan
 *
 * Signed-off-by: John McCutchan ttb@tentacle.dhs.org
 */

#ifndef _LINUX_INOTIFY_H
#define _LINUX_INOTIFY_H

#include <linux/limits.h>

/* this size could limit things, since technically we could need PATH_MAX */
#define INOTIFY_FILENAME_MAX	256

/*
 * struct inotify_event - structure read from the inotify device for each event
 *
 * When you are watching a directory, you will receive the filename for events
 * such as IN_CREATE, IN_DELETE, IN_OPEN, IN_CLOSE, ...
 *
 * Note: When reading from the device you must provide a buffer that is a
 * multiple of sizeof(struct inotify_event)
 */
struct inotify_event {
	int wd;
	int mask;
	int cookie;
	char filename[INOTIFY_FILENAME_MAX];
};

/* the following are legal, implemented events */
#define IN_ACCESS		0x00000001	/* File was accessed */
#define IN_MODIFY		0x00000002	/* File was modified */
#define IN_ATTRIB		0x00000004	/* File changed attributes */
#define IN_CLOSE		0x00000008	/* File was closed */
#define IN_OPEN			0x00000010	/* File was opened */
#define IN_MOVED_FROM		0x00000020	/* File was moved from X */
#define IN_MOVED_TO		0x00000040	/* File was moved to Y */
#define IN_DELETE_SUBDIR	0x00000080	/* Subdir was deleted */ 
#define IN_DELETE_FILE		0x00000100	/* Subfile was deleted */
#define IN_CREATE_SUBDIR	0x00000200	/* Subdir was created */
#define IN_CREATE_FILE		0x00000400	/* Subfile was created */
#define IN_DELETE_SELF		0x00000800	/* Self was deleted */
#define IN_UNMOUNT		0x00001000	/* Backing filesystem was unmounted */
#define IN_Q_OVERFLOW		0x00002000	/* The event queued overflowed */
#define IN_IGNORED		0x00004000	/* File was ignored */

/* special flags */
#define IN_ALL_EVENTS	0xffffffff	/* All the events */

/*
 * struct inotify_watch_request - represents a watch request
 *
 * Pass to the inotify device via the INOTIFY_WATCH ioctl
 */
struct inotify_watch_request {
	char *dirname;		/* directory name */
	unsigned long mask;	/* event mask */
};

#define INOTIFY_IOCTL_MAGIC	'Q'
#define INOTIFY_IOCTL_MAXNR	4

#define INOTIFY_WATCH  		_IOR(INOTIFY_IOCTL_MAGIC, 1, struct inotify_watch_request)
#define INOTIFY_IGNORE 		_IOR(INOTIFY_IOCTL_MAGIC, 2, int)
#define INOTIFY_STATS		_IOR(INOTIFY_IOCTL_MAGIC, 3, int)
#define INOTIFY_SETDEBUG	_IOR(INOTIFY_IOCTL_MAGIC, 4, int)

#define INOTIFY_DEBUG_NONE	0x00000000
#define INOTIFY_DEBUG_ALLOC	0x00000001
#define INOTIFY_DEBUG_EVENTS	0x00000002
#define INOTIFY_DEBUG_INODE	0x00000004
#define INOTIFY_DEBUG_ERRORS	0x00000008
#define INOTIFY_DEBUG_FILEN	0x00000010
#define INOTIFY_DEBUG_ALL	0xffffffff

#ifdef __KERNEL__

#include <linux/dcache.h>
#include <linux/fs.h>

/* Adds event to all watchers on inode that are interested in mask */
void inotify_inode_queue_event (struct inode *inode, unsigned long mask,
		const char *filename);

/* Same as above but uses dentry's inode */
void inotify_dentry_parent_queue_event (struct dentry *dentry,
		unsigned long mask, const char *filename);

/* This will remove all watchers from all inodes on the superblock */
void inotify_super_block_umount (struct super_block *sb);

/* Call this when an inode is dead, and inotify should ignore it */
void inotify_inode_is_dead (struct inode *inode);

#endif	/* __KERNEL __ */

#endif	/* _LINUX_INOTIFY_H */
