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

install-data-local:
	cd $(libdir) && cp libgamin-1.so.$(VERSION) libfam.so.0.0.0 && ln -s libfam.so.0.0.0 libfam.so.0

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

noinst_PROGRAMS= gamin testgam # testfam

gamin_SOURCES = gamin.c
gamin_LDFLAGS =
gamin_DEPENDENCIES = $(DEPS) 
gamin_LDADD= $(LDADDS) -lgamin-1

testgam_SOURCES = testing.c
testgam_LDFLAGS =
testgam_DEPENDENCIES = $(DEPS)
testgam_LDADD= $(LDADDS) -lgamin-1

#testfam_SOURCES = testing.c
#testfam_LDFLAGS =
#testfam_DEPENDENCIES = 
#testfam_LDADD= -lfam
#

check-local: tests

tests: testgam testfam
	-@(for i in $(top_srcdir)/tests/*.tst ; do \
	   name=`basename $$i .tst`; \
	   if [ ! -f $(top_srcdir)/tests/$$name.out ] ; then \
	       echo New test file $$name ; \
	       ./testfam $$i > $(top_srcdir)/tests/$$name.out ; \
	   else \
	       echo $$name ; \
	       ./testgam $$i > result.$$name ; \
	       diff -c $(top_srcdir)/tests/$$name.out result.$$name ; \
	   fi ; done )
