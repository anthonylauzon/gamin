
#ifndef __MD_POLL_H__
#define __MD_POLL_H__

#include <glib.h>
#include "gam_subscription.h"
#include "gam_node.h"

G_BEGIN_DECLS

enum pollHandlerModes {
    GAMIN_ACTIVATE = 1,		/* Activate kernel monitoring */
    GAMIN_DESACTIVATE = 2,	/* Desactivate kernel monitoring */
    GAMIN_FLOWCONTROL = 3	/* Request flow control */
};

typedef void (*GamPollHandler) (const char *path, gboolean added);

gboolean   gam_poll_init_full             (gboolean start_scan_thread);

gboolean   gam_poll_init                  (void);

gboolean   gam_poll_add_subscription      (GamSubscription *sub);

gboolean   gam_poll_remove_subscription   (GamSubscription *sub);

gboolean   gam_poll_remove_all_for        (GamListener *listener);

void       gam_poll_set_directory_handler (GamPollHandler handler);
void       gam_poll_set_file_handler      (GamPollHandler handler);

void       gam_poll_scan_directory        (const char *path);

void       gam_poll_consume_subscriptions (void);
						 
G_END_DECLS

#endif /* __MD_POLL_H__ */
