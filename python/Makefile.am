## Process this file with automake to produce Makefile.in
SUBDIRS=tests

INCLUDES =			\
	-I$(PYTHON_INCLUDES)	\
	-I$(top_srcdir)/libgamin\
	-I$(top_srcdir)/lib

EXTRA_DIST =			\
	gamin.c			\
	gamin.py

_gamin_la_LDFLAGS = -module -avoid-version -L$(top_builddir)/libgamin/.libs

if WITH_PYTHON
mylibs =			\
	$(top_builddir)/libgamin/libgamin-1.la

all-local: gamin.py

python_LTLIBRARIES = _gamin.la

_gamin_la_SOURCES = gamin.c
_gamin_la_LIBADD = $(mylibs) 

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pythondir)
	@INSTALL@ -m 0644 gamin.py $(DESTDIR)$(pythondir)

test:
	@(cd tests ; make tests)

tests: test

else
all:
endif

