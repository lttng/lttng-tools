# SPDX-License-Identifier: GPL-2.0-only

noinst_SCRIPTS = test_session_commands.py test_event_rule_listing.py \
	test_add_trigger.py \
	test_bug1373_events_differ_only_by_loglevel \
	test_warn_on_shm_too_small.py
EXTRA_DIST = test_session_commands.py test_event_rule_listing.py \
	test_add_trigger.py \
	test_bug1373_events_differ_only_by_loglevel \
	test_warn_on_shm_too_small.py

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
