PYTESTS=        		\
		basic.py	\
		basic2.py	\
		noexists.py

EXTRA_DIST = $(PYTESTS)

if WITH_PYTHON
tests: $(PYTESTS)
	@(PYTHONPATH="..:../.libs:$(srcdir)/..:$$PYTHONPATH" ; \
	  export PYTHONPATH; \
	  unset GAM_CLIENT_ID ; unset GAM_DEBUG; \
	  GAMIN_DEBUG_SERVER="../../server/gam_server" ;\
	  export GAMIN_DEBUG_SERVER ;\
	  for test in $(PYTESTS) ; \
	  do log=`$(PYTHON) $(srcdir)/$$test` ; \
	  if [ "`echo $$log | grep OK`" = "" ] ; then \
	  echo "-- $$test" ; echo "$$log" ; fi ; done)
else
tests:
endif
