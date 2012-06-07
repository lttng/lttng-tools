AM_CFLAGS = -g -Wall -I../
AM_LDFLAGS = -lurcu -lurcu-cds

EXTRA_DIST = runall.sh run-kernel-tests.sh

noinst_PROGRAMS = kernel_all_events_basic kernel_event_basic

UTILS=utils.h
LIBLTTNG=$(top_srcdir)/src/lib/lttng-ctl/lttng-ctl.c \
		 $(top_srcdir)/src/common/sessiond-comm/sessiond-comm.c \
		 $(top_srcdir)/src/common/sessiond-comm/unix.c

kernel_all_events_basic_SOURCES = kernel_all_events_basic.c $(UTILS) $(LIBLTTNG)

kernel_event_basic_SOURCES = kernel_event_basic.c $(UTILS) $(LIBLTTNG)
