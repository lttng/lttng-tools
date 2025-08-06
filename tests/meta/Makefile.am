# SPDX-FileCopyrightText: 2026 EfficiOS Inc.
#
# SPDX-License-Identifier: GPL-2.0-only

LOG_DRIVER_FLAGS = --merge
# The meta tests operate on the source files, but may be launched from an
# out-of-tree build. They can get the absolute path of the source tree
# from LTTNG_TEST_ABS_TOP_SRCDIR.
LOG_DRIVER = env PGREP='$(PGREP)' AM_TAP_AWK='$(AWK)' \
		LTTNG_TEST_ABS_TOP_SRCDIR='$(abs_top_srcdir)' $(SHELL) \
		$(top_builddir)/tests/utils/tap-driver.sh

TESTS = test_black.py \
	test_vermin.py

if HAVE_SHELLCHECK
TESTS += test_shellcheck
endif

EXTRA_DIST = $(TESTS)

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
