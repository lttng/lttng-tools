# SPDX-License-Identifier: GPL-2.0-only

noinst_SCRIPTS = test_kernel test_ust test_live_hang.py
EXTRA_DIST = test_kernel test_ust test_live_hang.py

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
