
#ifndef __GAM_NODE_H__
#define __GAM_NODE_H__

#include <glib.h>
#include "gam_event.h"
#include "gam_subscription.h"

G_BEGIN_DECLS

typedef struct _GamNode GamNode;

typedef gboolean (*GamSubFilterFunc) (GamSubscription *sub);

struct _GamNode {
	char *path;

	GList *subs;
	gpointer data;
	GDestroyNotify data_destroy;

	int flags;

	GNode *node;
	gboolean is_dir;
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

int                   gam_node_copy_subscriptions  (GamNode         *src,
						   GamNode         *dest,
						   GamSubFilterFunc filter);

gboolean              gam_node_has_recursive_sub   (GamNode         *node);

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
