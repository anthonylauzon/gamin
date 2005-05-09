
#ifndef __GAM_NODE_H__
#define __GAM_NODE_H__

#include <glib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "gam_event.h"
#include "gam_subscription.h"

G_BEGIN_DECLS

typedef struct _GamNode GamNode;

typedef gboolean (*GamSubFilterFunc) (GamSubscription *sub);

struct _GamNode {
        /* the node informations proper */
	char *path;		/* The file path */
	GList *subs;		/* the list of subscriptions */
	GNode *node;		/* pointer in the tree */
	gboolean is_dir;	/* is that a directory or expected to be one */
	int flags;		/* generic flags */

        /* what used to be stored in a separate data structure */
	int pflags;		/* A combination of MON_xxx flags */
	time_t lasttime;	/* Epoch of last time checking was done */
	int checks;		/* the number of checks in that Epoch */
	struct stat sbuf;	/* The stat() informations in last check */
};


GamNode               *gam_node_new                 (const char     *path,
						   GamSubscription *initial_sub,
						   gboolean        is_dir);

void                  gam_node_free                (GamNode         *node);

GamNode               *gam_node_parent              (GamNode         *node);

gboolean              gam_node_is_dir              (GamNode         *node);

void                  gam_node_set_is_dir          (GamNode         *node,
						   gboolean        is_dir);
	
G_CONST_RETURN char  *gam_node_get_path            (GamNode         *node);

GList                *gam_node_get_subscriptions   (GamNode         *node);

gboolean              gam_node_add_subscription    (GamNode         *node,
						   GamSubscription *sub);

gboolean              gam_node_remove_subscription (GamNode         *node,
						   GamSubscription *sub);

gboolean              gam_node_has_dir_subscriptions(GamNode * node);

void                  gam_node_set_node            (GamNode         *node,
						   GNode          *gnode);
GNode                *gam_node_get_node            (GamNode         *node);

void                  gam_node_set_data            (GamNode         *node,
						   gpointer        data,
						   GDestroyNotify  destroy);

gpointer              gam_node_get_data            (GamNode         *node);

void                  gam_node_set_flag            (GamNode         *node,
						   int             flag);
void                  gam_node_unset_flag          (GamNode         *node,
						   int             flag);
gboolean              gam_node_has_flag            (GamNode         *node,
						   int             flag);

G_END_DECLS

#endif /* __GAM_NODE_H__ */
