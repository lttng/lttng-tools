AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests -I$(srcdir) -O2 -g
AM_LDFLAGS =

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-events
gen_ust_events_SOURCES = gen-ust-events.c tp.c tp.h
gen_ust_events_LDADD = -llttng-ust
endif

noinst_SCRIPTS = unsupported-ops invalid-filters valid-filters babelstats.pl
EXTRA_DIST = unsupported-ops invalid-filters valid-filters babelstats.pl
