INCLUDES =						\
	$(default_includes)				\
	-I$(top_builddir) 				\
	-I$(top_builddir)/libgamin			\
	-I$(top_builddir)/protocol			\
	$(LIBGAMIN_CFLAGS)				\
	-DBINDIR=\""$(bindir)"\"			\
	-DG_DISABLE_DEPRECATED				\
	-DGAM_DEBUG_ENABLED


bin_PROGRAMS= gam_server

gam_server_SOURCES =					\
	gam_subscription.c				\
	gam_subscription.h				\
	gam_listener.c					\
	gam_listener.h					\
	gam_server.c					\
	gam_server.h					\
	gam_event.c					\
	gam_event.h					\
	gam_node.c					\
	gam_node.h					\
	gam_tree.c					\
	gam_tree.h					\
	gam_poll.c					\
	gam_poll.h					\
	gam_error.c					\
	gam_error.h					\
	gam_dnotify.c					\
	gam_dnotify.h					\
	gam_inotify.c					\
	gam_inotify.h					\
	gam_channel.c					\
	gam_channel.h					\
	gam_connection.c				\
	gam_connection.h

gam_server_LDFLAGS =
gam_server_DEPENDENCIES = $(DEPS)
gam_server_LDADD= $(LDADDS) $(LIBGAMIN_LIBS)
