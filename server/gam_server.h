#ifndef __GAM_SERVER_H__
#define __GAM_SERVER_H__ 1

#include <glib.h>
#include "gam_connection.h"
#include "gam_subscription.h"

#ifdef __cplusplus
extern "C" {
#endif

gboolean        gam_init_subscriptions          (void);
gboolean        gam_add_subscription            (GamSubscription *sub);
gboolean        gam_remove_subscription         (GamSubscription *sub);
int             gam_server_num_listeners        (void);
void            gam_server_emit_event           (const char *path,
						 GaminEventType event,
						 GList *subs);
void		gam_shutdown			(void);
#ifdef __cplusplus
}
#endif

#endif /* __GAM_SERVER_H__ */


