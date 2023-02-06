# SPDX-License-Identifier: GPL-2.0-only

LOG_DRIVER_FLAGS = --merge
LOG_DRIVER = env PGREP='$(PGREP)' AM_TAP_AWK='$(AWK)' $(SHELL) \
		$(top_srcdir)/tests/utils/tap-driver.sh

TESTS = shellcheck-tests
