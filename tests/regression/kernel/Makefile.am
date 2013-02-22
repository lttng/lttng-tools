AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests/utils -g -Wall
AM_LDFLAGS = -lurcu -lurcu-cds

EXTRA_DIST = runall.sh run-kernel-tests.sh test_all_events

noinst_PROGRAMS = kernel_event_basic

UTILS=$(top_srcdir)/tests/utils/utils.h
LIBLTTNG=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

SESSIONDSRC=$(top_srcdir)/src/common/sessiond-comm/sessiond-comm.c \
		 $(top_srcdir)/src/common/sessiond-comm/unix.c \
		 $(top_srcdir)/src/common/sessiond-comm/inet.c \
		 $(top_srcdir)/src/common/sessiond-comm/inet6.c

kernel_event_basic_SOURCES = kernel_event_basic.c $(UTILS) \
		$(SESSIONDSRC)
kernel_event_basic_LDADD = $(LIBLTTNG)
