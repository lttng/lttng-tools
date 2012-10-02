AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_srcdir)/tests -g -Wall
AM_LDFLAGS = -lurcu -lurcu-cds

EXTRA_DIST = runall.sh run-kernel-tests.sh

noinst_PROGRAMS = kernel_all_events_basic kernel_event_basic

UTILS=../utils.h
LIBLTTNG=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

SESSIONDSRC=$(top_srcdir)/src/common/sessiond-comm/sessiond-comm.c \
		 $(top_srcdir)/src/common/sessiond-comm/unix.c \
		 $(top_srcdir)/src/common/sessiond-comm/inet.c \
		 $(top_srcdir)/src/common/sessiond-comm/inet6.c

kernel_all_events_basic_SOURCES = kernel_all_events_basic.c $(UTILS) \
		$(SESSIONDSRC)
kernel_all_events_basic_LDADD = $(LIBLTTNG)

kernel_event_basic_SOURCES = kernel_event_basic.c $(UTILS) \
		$(SESSIONDSRC)
kernel_event_basic_LDADD = $(LIBLTTNG)
