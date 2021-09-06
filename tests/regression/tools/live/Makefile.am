# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBCOMMON=$(top_builddir)/src/common/libcommon.la
LIBSESSIOND_COMM=$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la
LIBHASHTABLE=$(top_builddir)/src/common/hashtable/libhashtable.la
LIBRELAYD=$(top_builddir)/src/common/relayd/librelayd.la
LIBHEALTH=$(top_builddir)/src/common/health/libhealth.la
LIBCOMPAT=$(top_builddir)/src/common/compat/libcompat.la
LIBLTTNG_SESSIOND_COMMON=$(top_builddir)/src/bin/lttng-sessiond/liblttng-sessiond-common.la

noinst_PROGRAMS = live_test
EXTRA_DIST = test_kernel test_lttng_kernel

if HAVE_LIBLTTNG_UST_CTL
EXTRA_DIST += test_ust test_ust_tracefile_count test_lttng_ust
endif

live_test_SOURCES = live_test.cpp
live_test_LDADD = $(LIBTAP) $(LIBLTTNG_SESSIOND_COMMON) $(DL_LIBS)

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
