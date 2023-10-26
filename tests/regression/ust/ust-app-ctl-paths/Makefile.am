# SPDX-License-Identifier: GPL-2.0-only

noinst_SCRIPTS = test_blocking \
	test_path_separators \
	test_ust_app_ctl_paths

EXTRA_DIST = test_blocking \
	test_path_separators \
	test_ust_app_ctl_paths

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
