
#ifndef __MD_TREE_H__
#define __MD_TREE_H__

#include <glib.h>
#include "gam_node.h"

G_BEGIN_DECLS

typedef gboolean (*GamTreeForeachFunc) (GamNode *node);

typedef struct _GamTree GamTree;

GamTree        *gam_tree_new                   (void);

void           gam_tree_free                  (GamTree *tree);

gboolean       gam_tree_add                   (GamTree *tree,
					      GamNode *parent,
					      GamNode *child);

gboolean       gam_tree_remove                (GamTree *tree,
					      GamNode *node);

GamNode        *gam_tree_add_at_path           (GamTree        *tree,
					      const char    *path,
					      gboolean       is_dir);

GamNode        *gam_tree_get_at_path           (GamTree        *tree,
					      const char    *path);

GList         *gam_tree_find_subscriptions    (GamTree        *tree,
					      GamListener    *listener);

void           gam_tree_foreach_directory     (GamTree            *tree,
					      GamTreeForeachFunc  func);

void           gam_tree_foreach_file          (GamTree            *tree,
					      GamNode            *dir,
					      GamTreeForeachFunc  func);

GList         *gam_tree_get_directories       (GamTree            *tree,
					      GamNode            *root);

GList         *gam_tree_get_files             (GamTree            *tree,
					      GamNode            *dir);

GList         *gam_tree_get_children          (GamTree            *tree,
					      GamNode            *dir);

gboolean       gam_tree_has_children          (GamTree            *tree,
					      GamNode            *node);

void           gam_tree_dump                  (GamTree *tree, GamNode *node);

guint          gam_tree_get_size              (GamTree *tree);

G_END_DECLS

#endif /* __MD_TREE_H__ */
