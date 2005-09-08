noinst_PROGRAMS = testgam

INCLUDES = 					\
	-I$(top_builddir) -I$(top_srcdir)	\
	-I$(top_builddir)/libgamin		\
	-I$(top_srcdir)/libgamin

LDADD = $(top_builddir)/libgamin/libgamin-1.la

testgam_SOURCES = testing.c
testgam_LDFLAGS =
testgam_DEPENDENCIES = $(DEPS)
testgam_LDADD= $(LDADDS) -L$(top_builddir)/libgamin -lgamin-1

dist-hook:
	(cd $(srcdir) ; tar -cf - --exclude CVS scenario result ) | (cd $(distdir); tar xf -)

check-local: tests

tests: testgam
	-@(unset GAM_CLIENT_ID ; unset GAM_DEBUG;			\
	   GAM_CLIENT_ID="regtests" ;					\
	   export GAM_CLIENT_ID ;					\
	   if [ "$(CHECKER)" != "" ] ; then				\
	       $(CHECKER) ../server/gam_server &			\
	       GAMIN_DEBUG_SERVER="../server/gam_server" ;		\
	   else								\
	       GAMIN_DEBUG_SERVER="../server/gam_server" ;		\
	   fi;								\
	   export GAMIN_DEBUG_SERVER ;					\
	   for i in $(top_srcdir)/tests/scenario/*.tst ; do		\
	   rm -rf /tmp/test_gamin ; 					\
	   name=`basename $$i .tst`;					\
	   if [ ! -f $(top_srcdir)/tests/result/$$name ] ; then		\
	       echo New test file $$name ; 				\
	       if [ -x ./testgam ] ; then 				\
	       $(CHECKER) ./testgam $$i > $(top_srcdir)/tests/result/$$name 2>/dev/null;\
	       fi							\
	   else								\
	       echo running test $$name ;				\
	       $(CHECKER) ./testgam $$i > result.$$name 2>/dev/null;	\
	       diff -c $(top_srcdir)/tests/result/$$name result.$$name ;\
	       rm -f result.$$name ;					\
	   fi ; done )

valgrind:
	@echo '## Running the regression tests under Valgrind'
	$(MAKE) CHECKER='valgrind' tests

