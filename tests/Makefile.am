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

testfam: testing.c
	@(if [ -f libfam.a ] ; then					\
	      $(CC) $(CFLAGS) -o testfam testing.c libfam.a -lstdc++;	\
	  else 								\
	      echo Need libfam.a to build testfam ;			\
	  fi )

tests: testgam testfam
	-@(for i in $(top_srcdir)/tests/scenario/*.tst ; do		\
	   name=`basename $$i .tst`;					\
	   if [ ! -f $(top_srcdir)/tests/result/$$name ] ; then		\
	       echo New test file $$name ; 				\
	       if [ -x ./testfam ] ; then 				\
	       ./testfam $$i > $(top_srcdir)/tests/result/$$name ;	\
	       fi							\
	   else								\
	       echo $$name ;						\
	       ./testgam $$i > result.$$name ;				\
	       diff -c $(top_srcdir)/tests/result/$$name result.$$name ;\
	   fi ; done )
