#ifndef __GAM_EXCLUDES_H__
#define __GAM_EXCLUDES_H__ 1

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

int		gam_exclude_init	(void);
gboolean	gam_exclude_check	(const char *filename);
#ifdef __cplusplus
}
#endif

#endif /* __GAM_EXCLUDES_H__ */

