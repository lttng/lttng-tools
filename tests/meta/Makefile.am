# SPDX-License-Identifier: GPL-2.0-only

LOG_DRIVER_FLAGS = --merge
LOG_DRIVER = env PGREP='$(PGREP)' AM_TAP_AWK='$(AWK)' $(SHELL) \
		$(top_srcdir)/tests/utils/tap-driver.sh

TESTS = test_shellcheck

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
