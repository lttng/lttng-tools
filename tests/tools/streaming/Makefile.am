AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests -I$(srcdir) -O2 -g
AM_LDFLAGS =

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

#UTILS=../../utils.h
UTILS=
LIBSESSIOND_COMM=$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la
LIBCOMMON=$(top_builddir)/src/common/libcommon.la

noinst_PROGRAMS = unit_tests
unit_tests_SOURCES = unit_tests.c $(UTILS)
unit_tests_LDADD = $(LIBCOMMON)

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS += gen-ust-events
gen_ust_events_SOURCES = gen-ust-events.c tp.c tp.h
gen_ust_events_LDADD = -llttng-ust
endif

noinst_SCRIPTS = runall run-ust run-kernel uri_switch
EXTRA_DIST = runall run-ust run-kernel uri_switch
