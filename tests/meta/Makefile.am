# SPDX-License-Identifier: GPL-2.0-only

LOG_DRIVER_FLAGS = --merge
LOG_DRIVER = env PGREP='$(PGREP)' AM_TAP_AWK='$(AWK)' $(SHELL) \
		$(top_builddir)/tests/utils/tap-driver.sh

TESTS =

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
