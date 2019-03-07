# SPDX-License-Identifier: GPL-2.0-only

noinst_SCRIPTS = test_save test_load test_autoload
EXTRA_DIST = $(noinst_SCRIPTS) load-42.lttng load-42-complex.lttng \
	load-42-trackers.lttng

SUBDIRS = configuration

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
