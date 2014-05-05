AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests/utils/ -I$(srcdir)
AM_LDFLAGS =

if LTTNG_TOOLS_BUILD_WITH_LIBDL
AM_LDFLAGS += -ldl
endif
if LTTNG_TOOLS_BUILD_WITH_LIBC_DL
AM_LDFLAGS += -lc
endif

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBCOMMON=$(top_builddir)/src/common/libcommon.la
LIBSESSIOND_COMM=$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la
LIBHASHTABLE=$(top_builddir)/src/common/hashtable/libhashtable.la
LIBRELAYD=$(top_builddir)/src/common/relayd/librelayd.la
LIBHEALTH=$(top_builddir)/src/common/health/libhealth.la

LIVE=$(top_builddir)/src/bin/lttng-sessiond/session.o \
	 $(top_builddir)/src/bin/lttng-sessiond/consumer.o \
	 $(top_builddir)/src/bin/lttng-sessiond/utils.o \
	 $(top_builddir)/src/bin/lttng-sessiond/snapshot.o

noinst_PROGRAMS = live_test
EXTRA_DIST = test_kernel

if HAVE_LIBLTTNG_UST_CTL
EXTRA_DIST += test_ust test_ust_tracefile_count
endif

live_test_SOURCES = live_test.c
live_test_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBRELAYD) $(LIBSESSIOND_COMM) \
				  $(LIBHASHTABLE) $(LIBHEALTH) -lrt
live_test_LDADD += $(LIVE) \
				   $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

all-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			cp -f $(srcdir)/$$script $(builddir); \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
