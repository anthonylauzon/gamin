#ifndef __GAM_POLL_H
#define __GAM_POLL_H

#include <glib.h>
#include "gam_subscription.h"
#include "gam_node.h"

G_BEGIN_DECLS

gboolean	gam_poll_init			(void);
gboolean	gam_poll_init_full		(gboolean start_scan_thread);
void		gam_poll_scan_directory		(const char *path);
void		gam_poll_debug			(void);
void		gam_poll_consume_subscriptions	(void);
						 
G_END_DECLS

#endif /* __GAM_POLL_H */
