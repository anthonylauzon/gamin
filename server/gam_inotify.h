
#ifndef __MD_INOTIFY_H__
#define __MD_INOTIFY_H__

#include <glib.h>
#include "gam_poll.h"
#include "gam_subscription.h"

G_BEGIN_DECLS

gboolean   gam_inotify_init                  (void);
gboolean   gam_inotify_add_subscription      (GamSubscription *sub);
gboolean   gam_inotify_remove_subscription   (GamSubscription *sub);
gboolean   gam_inotify_remove_all_for        (GamListener *listener);

G_END_DECLS

#endif /* __MD_INOTIFY_H__ */
