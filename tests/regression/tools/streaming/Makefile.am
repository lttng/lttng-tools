AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests/utils -I$(srcdir) -O2 -g
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

noinst_SCRIPTS = runall test_ust test_kernel test_uri_switch test_high_throughput_limits
EXTRA_DIST = runall test_ust test_kernel test_uri_switch test_high_throughput_limits
