PYTESTS=        		\
		basic.py	\
		basic2.py	\
		basic3.py	\
		basic4.py	\
		basic5.py	\
		basic6.py	\
		noexists.py	\
		level.py	\
		multiple.py	\
		multiple2.py	\
		multiple3.py

EXTRA_DIST = $(PYTESTS)

if WITH_PYTHON
tests: $(PYTESTS)
	@(LD_LIBRARY_PATH="..:../.libs:../libgamin:../libgamin/.libs"; \
	  export LD_LIBRARY_PATH; \
	  PYTHONPATH="..:../.libs:../libgamin:../libgamin/.libs:$(srcdir)/..:$$PYTHONPATH" ; \
	  export PYTHONPATH; \
	  unset GAM_DEBUG; \
	  GAMIN_DEBUG_SERVER="../../server/gam_server" ;\
	  export GAMIN_DEBUG_SERVER ;\
	  GAM_CLIENT_ID=test; \
	  export GAM_CLIENT_ID; \
	  for test in $(PYTESTS) ; \
	  do echo -n . ; \
	  log=`$(PYTHON) $(srcdir)/$$test` ; \
	  if [ "`echo $$log | grep OK`" = "" ] ; then \
	  echo "-- $$test" ; echo "$$log" ; fi ; done)
else
tests:
endif
