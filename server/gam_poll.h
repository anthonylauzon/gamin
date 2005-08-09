
#ifndef __MD_POLL_H__
#define __MD_POLL_H__

#include <glib.h>
#include "gam_subscription.h"
#include "gam_node.h"

G_BEGIN_DECLS

enum pollHandlerKernel {
    GAMIN_K_NONE = 0,
    GAMIN_K_DNOTIFY = 1,
    GAMIN_K_INOTIFY = 2,
    GAMIN_K_KQUEUE = 3,
    GAMIN_K_MACH = 4,
	GAMIN_K_INOTIFY2 = 5
};
typedef enum pollHandlerKernel pollHandlerKernel;

enum pollHandlerMode {
    GAMIN_ACTIVATE = 1,		/* Activate kernel monitoring */
    GAMIN_DESACTIVATE = 2,	/* Desactivate kernel monitoring */
    GAMIN_FLOWCONTROLSTART = 3,	/* Request flow control start */
    GAMIN_FLOWCONTROLSTOP = 4	/* Request flow control stop */
};
typedef enum pollHandlerMode pollHandlerMode;

typedef void (*GamPollHandler) (const char *path,
				pollHandlerMode mode);

void       gam_poll_debug                 (void);
gboolean   gam_poll_init_full             (gboolean start_scan_thread);

gboolean   gam_poll_init                  (void);

gboolean   gam_poll_add_subscription      (GamSubscription *sub);

gboolean   gam_poll_remove_subscription   (GamSubscription *sub);

gboolean   gam_poll_remove_all_for        (GamListener *listener);

void       gam_poll_set_kernel_handler    (GamPollHandler dir_handler,
                                           GamPollHandler file_handler,
					   pollHandlerKernel type);

void       gam_poll_scan_directory        (const char *path);

void       gam_poll_consume_subscriptions (void);
						 
G_END_DECLS

#endif /* __MD_POLL_H__ */
