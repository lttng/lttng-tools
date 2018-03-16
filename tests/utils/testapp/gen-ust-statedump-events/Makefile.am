AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(srcdir) \
	-I$(top_srcdir)/tests/utils/testapp

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-statedump-events
gen_ust_statedump_events_SOURCES = gen-ust-statedump-events.c tp.h
gen_ust_statedump_events_LDADD = -llttng-ust -lurcu-bp \
		$(top_builddir)/tests/utils/libtestutils.la \
		$(DL_LIBS)
endif
