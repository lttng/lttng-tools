# SPDX-License-Identifier: GPL-2.0-only

noinst_SCRIPTS =					\
	common.py					\
	gdb_helper.py					\
	test_stall_buffer_complex.py			\
	test_stall_buffer_simple.py			\
	test_stall_buffer_timer.py

EXTRA_DIST =						\
	common.py					\
	gdb_helper.py					\
	test_stall_buffer_complex.py			\
	test_stall_buffer_simple.py			\
	test_stall_buffer_timer.py

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
