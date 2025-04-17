# SPDX-License-Identifier: GPL-2.0-only

LOG_DRIVER_FLAGS = --merge --post-script $(top_srcdir)/tests/utils/warn_processes.sh
LOG_DRIVER = env PGREP='$(PGREP)' AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_builddir)/tests/utils/tap-driver.sh

if LTTNG_TOOLS_BUILD_WITH_LIBPFM
LIBS += -lpfm

TESTS = test_perf_raw

noinst_PROGRAMS = find_event
find_event_SOURCES = find_event.c
endif
