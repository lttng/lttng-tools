# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la
LIBLTTNG_SESSIOND_COMMON=$(top_builddir)/src/bin/lttng-sessiond/liblttng-sessiond-common.la

noinst_PROGRAMS = live_test
EXTRA_DIST = test_kernel test_lttng_kernel test_per_application_leaks.py

if HAVE_LIBLTTNG_UST_CTL
EXTRA_DIST += test_early_inactive_app.py \
	test_lttng_ust \
	test_miss_short_lived_app.py \
	test_ust \
	test_ust_tracefile_count
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
