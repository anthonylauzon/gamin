
#ifndef __MD_KQUEUE_H__
#define __MD_KQUEUE_H__

#include <glib.h>
#include "gam_poll.h"
#include "gam_subscription.h"

#define VN_NOTE_MOST	(NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | \
			 NOTE_ATTRIB | NOTE_LINK | NOTE_RENAME | \
			 NOTE_REVOKE)
#define VN_NOTE_ALL	VN_NOTE_MOST
#define VN_NOTE_CHANGED	(NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB | NOTE_LINK)

G_BEGIN_DECLS

gboolean   gam_kqueue_init                  (void);
gboolean   gam_kqueue_add_subscription      (GamSubscription *sub);
gboolean   gam_kqueue_remove_subscription   (GamSubscription *sub);
gboolean   gam_kqueue_remove_all_for        (GamListener *listener);

G_END_DECLS

#endif /* __MD_KQUEUE_H__ */
