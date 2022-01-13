# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la
LIBLTTNG_CTL=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

noinst_PROGRAMS = schedule_api
schedule_api_SOURCES = schedule_api.c
schedule_api_LDADD = $(LIBTAP) $(LIBLTTNG_CTL)

noinst_SCRIPTS = test_kernel test_ust test_ust_kernel test_save_load_mi test_schedule_api rotate_utils.sh
EXTRA_DIST = test_kernel test_ust test_ust_kernel test_save_load_mi test_schedule_api rotate_utils.sh

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
