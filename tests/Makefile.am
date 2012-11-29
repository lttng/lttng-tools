SUBDIRS = .

AM_CFLAGS = -g -Wall
AM_LDFLAGS = -lurcu

EXTRA_DIST = runall.sh utils.sh lttng/runall.sh lttng/run-kernel-tests.sh

noinst_PROGRAMS = test_sessions test_kernel_data_trace \
				  kernel_all_events_basic kernel_event_basic

UTILS=utils.h
SESSIONS=$(top_srcdir)/src/bin/lttng-sessiond/session.c
KERN_DATA_TRACE=$(top_srcdir)/src/bin/lttng-sessiond/trace-kernel.c
LIBLTTNG=$(top_srcdir)/src/lib/lttng-ctl/lttng-ctl.c \
		 $(top_srcdir)/src/common/sessiond-comm/sessiond-comm.c

test_sessions_SOURCES = test_sessions.c $(UTILS) $(SESSIONS)
test_sessions_LDADD = $(top_builddir)/src/common/libcommon.la \
					  $(top_builddir)/src/common/hashtable/libhashtable.la

test_kernel_data_trace_SOURCES = test_kernel_data_trace.c $(UTILS) $(KERN_DATA_TRACE)
test_kernel_data_trace_LDADD = $(top_builddir)/src/common/libcommon.la

kernel_all_events_basic_SOURCES = lttng/kernel_all_events_basic.c $(UTILS) $(LIBLTTNG)
kernel_all_events_basic_LDADD = $(top_builddir)/src/common/libcommon.la

kernel_event_basic_SOURCES = lttng/kernel_event_basic.c $(UTILS) $(LIBLTTNG)
kernel_event_basic_LDADD = $(top_builddir)/src/common/libcommon.la

if HAVE_LIBLTTNG_UST_CTL
SUBDIRS += ust-nevents ust-nprocesses
EXTRA_DIST += lttng/run-ust-global-tests.sh
noinst_PROGRAMS += ust_global_event_basic ust_global_all_events_basic test_ust_data_trace

UST_DATA_TRACE=$(top_srcdir)/src/bin/lttng-sessiond/trace-ust.c

test_ust_data_trace_SOURCES = test_ust_data_trace.c $(UTILS) $(UST_DATA_TRACE)
test_ust_data_trace_LDADD = $(top_builddir)/src/common/libcommon.la \
							$(top_builddir)/src/common/hashtable/libhashtable.la

ust_global_all_events_basic_SOURCES = lttng/ust_global_all_events_basic.c $(UTILS) $(LIBLTTNG)
ust_global_all_events_basic_LDADD = $(top_builddir)/src/common/libcommon.la

ust_global_event_basic_SOURCES = lttng/ust_global_event_basic.c $(UTILS) $(LIBLTTNG)
ust_global_event_basic_LDADD = $(top_builddir)/src/common/libcommon.la
endif # HAVE_LIBLTTNG_UST_CTL

check-am:
	./runall.sh
