# SPDX-License-Identifier: GPL-2.0-only

noinst_SCRIPTS = test_session_commands.py test_event_rule_listing.py \
	test_bug1373_events_differ_only_by_loglevel
EXTRA_DIST = test_session_commands.py test_event_rule_listing.py \
	test_bug1373_events_differ_only_by_loglevel

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
