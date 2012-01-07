AM_CFLAGS=-I$(top_srcdir)/include -I$(top_srcdir)/libkernelctl \
		  -I$(top_srcdir)/liblttngctl -g -Wall -lurcu -lurcu-cds

EXTRA_DIST = runall.sh lttng/runall.sh lttng/run-kernel-tests.sh

noinst_PROGRAMS = test_sessions test_kernel_data_trace kernel_all_events_basic \
				  kernel_event_basic

UTILS=utils.h
SESSIONS=$(top_srcdir)/lttng-sessiond/session.c
KERN_DATA_TRACE=$(top_srcdir)/lttng-sessiond/trace-kernel.c
LIBLTTNG=$(top_srcdir)/liblttngctl/lttngctl.c \
		 $(top_srcdir)/liblttng-sessiond-comm/lttng-sessiond-comm.c

test_sessions_SOURCES = test_sessions.c $(UTILS) $(SESSIONS)
test_sessions_LDADD = $(top_builddir)/common/libcommon.la $(top_builddir)/librunas/librunas.la

test_kernel_data_trace_SOURCES = test_kernel_data_trace.c $(UTILS) $(KERN_DATA_TRACE)

kernel_all_events_basic_SOURCES = lttng/kernel_all_events_basic.c $(UTILS) $(LIBLTTNG)

kernel_event_basic_SOURCES = lttng/kernel_event_basic.c $(UTILS) $(LIBLTTNG)

check-am:
	./runall.sh
