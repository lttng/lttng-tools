AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(srcdir) \
	       -I$(top_srcdir)/tests/utils/testapp

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-events-ns
gen_ust_events_ns_SOURCES = gen-ust-events-ns.c tp.c tp.h
gen_ust_events_ns_LDADD = -llttng-ust -lurcu-bp -llttng-ust-fork \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS) $(POPT_LIBS)
endif
