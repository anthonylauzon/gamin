## Process this file with automake to produce Makefile.in

SUBDIRS = lib libgamin server @PYTHON_SUBDIR@ tests doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gamin.pc

#if BUILD_DOCS
#install-data-local:
#	-doxygen
#	cd $(srcdir)/doc/api/html; find -exec \
#	$(INSTALL_DATA) -D {} $(datadir)/doc/gamin/html/{} \;
#endif

EXTRA_DIST =			\
	gamin.pc.in		\
	gamin.spec.in		\
	gamin.spec		\
	ChangeLog  		\
	README 			\
	Copyright		\
	TODO 

rpm: clean
	@(unset CDPATH ; $(MAKE) dist && rpmbuild -ta $(distdir).tar.gz)

tests: all
	(cd tests ; $(MAKE) CHECKER='$(CHECKER)' tests)
	(cd python ; $(MAKE) CHECKER='$(CHECKER)' tests)
	
valgrind:
	@echo '## Running the regression tests under Valgrind'
	$(MAKE) CHECKER='valgrind' tests

dist-hook:
	(cd $(srcdir) ; tar -cf - --exclude CVS doc) | (cd $(distdir); tar xf -)
