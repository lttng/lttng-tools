# SPDX-License-Identifier: GPL-2.0-only

AM_CPPFLAGS += -I$(top_srcdir)/tests -I$(srcdir)

noinst_SCRIPTS = test_channel
EXTRA_DIST = test_channel

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
