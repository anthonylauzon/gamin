INCLUDES =						\
	$(default_includes)				\
	-I$(top_builddir) 				\
	-I$(top_builddir)/libgamin			\
	-I$(top_builddir)/protocol			\
	-I$(top_srcdir)/lib				\
	$(LIBGAMIN_CFLAGS)				\
	-DBINDIR=\""$(libexecdir)"\"			\
	-DG_DISABLE_DEPRECATED				

if GAMIN_DEBUG
INCLUDES += -DGAM_DEBUG_ENABLED
endif


libexec_PROGRAMS= gam_server

gam_server_SOURCES =					\
	gam_subscription.c				\
	gam_subscription.h				\
	gam_listener.c					\
	gam_listener.h					\
	gam_server.c					\
	gam_server.h					\
	gam_node.c					\
	gam_node.h					\
	gam_tree.c					\
	gam_tree.h					\
	gam_poll.c					\
	gam_poll.h					\
	gam_channel.c					\
	gam_channel.h					\
	gam_connection.c				\
	gam_connection.h				\
	gam_debugging.h					\
	gam_debugging.c					\
	gam_excludes.c					\
	gam_excludes.h					\
	local_inotify.h					\
	gam_debug_lists.c				\
	server_config.h

if ENABLE_INOTIFY
gam_server_SOURCES += gam_inotify.c gam_inotify.h
endif

if ENABLE_DNOTIFY
gam_server_SOURCES += gam_dnotify.c gam_dnotify.h
endif

if ENABLE_KQUEUE
gam_server_SOURCES += gam_kqueue.c gam_kqueue.h
endif

gam_server_LDFLAGS =
gam_server_DEPENDENCIES = $(DEPS)
gam_server_LDADD= $(top_builddir)/lib/libgamin_shared.a $(LDADDS) $(LIBGAMIN_LIBS)
