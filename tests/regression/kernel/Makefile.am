# SPDX-License-Identifier: GPL-2.0-only

EXTRA_DIST = test_all_events test_syscall \
						 test_callstack \
						 test_clock_override \
						 test_event_basic \
						 test_kernel_function \
						 test_lttng_logger \
						 test_ns_contexts \
						 test_ns_contexts_change
						 test_rotation_destroy_flush \
						 test_select_poll_epoll \
						 test_syscall \
						 test_userspace_probe \
						 validate_select_poll_epoll.py

noinst_PROGRAMS = select_poll_epoll
select_poll_epoll_SOURCES = select_poll_epoll.c
select_poll_epoll_LDADD = $(POPT_LIBS)
select_poll_epoll_CFLAGS = $(POPT_CFLAGS) -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 $(AM_CFLAGS)

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
