INCLUDES =						\
	$(default_includes)				\
	-I$(top_builddir) 				\
	-DBINDIR=\""$(bindir)"\"			\
	-DGAM_DEBUG_ENABLED

EXTRA_DIST = 						\
	gamin_sym.version

lib_LTLIBRARIES = libgamin-1.la

gaminincludedir = $(includedir)/
gamininclude_HEADERS =	\
	fam.h

libgamin_1_la_SOURCES =					\
	gam_api.c					\
	gam_data.c					\
	gam_data.h					\
	gam_error.c					\
	gam_error.h					\
	gam_fork.c					\
	gam_fork.h					\
	gam_protocol.h

libgamin_1_la_LIBADD = 

libgamin_1_la_LDFLAGS = -Wl,--version-script=gamin_sym.version \
                        -version-info @GAMIN_VERSION_INFO@

#
# Compile a program locally to check
#
noinst_PROGRAMS= gamin

gamin_SOURCES = gamin.c
gamin_LDFLAGS =
gamin_DEPENDENCIES = $(DEPS) 
gamin_LDADD= $(LDADDS) -lgamin-1

#
# This ensure the binary replacement when using gamin to replace libfam
#
install-data-local:
	cd $(libdir) && cp libgamin-1.so.$(VERSION) libfam.so.0.0.0 && ln -s libfam.so.0.0.0 libfam.so.0

