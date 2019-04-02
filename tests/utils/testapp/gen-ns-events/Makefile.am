AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(srcdir) \
	       -I$(top_srcdir)/tests/utils/testapp

noinst_PROGRAMS = gen-ns-events
gen_ns_events_SOURCES = gen-ns-events.c
gen_ns_events_LDADD = \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS) $(POPT_LIBS)
