# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>

noinst_SCRIPTS = test_trace_format_ust.py		\
		test_trace_format_kernel.py		\
		trace_format_helpers.py

EXTRA_DIST = test_trace_format_ust.py			\
	test_trace_format_kernel.py			\
	trace_format_helpers.py				\
	kernel-local-trace-pretty.expect		\
	ust-local-trace-pretty.expect

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
