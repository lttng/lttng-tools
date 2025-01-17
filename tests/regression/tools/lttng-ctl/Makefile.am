# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>

noinst_SCRIPTS = test_liblttng-ctl_abi.py
EXTRA_DIST = test_liblttng-ctl_abi.py

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
