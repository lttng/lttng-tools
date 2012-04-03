if HAVE_LIBLTTNG_UST_CTL
SUBDIRS = nprocesses high-throughput low-throughput before-after

AM_CFLAGS = -g -Wall -I../
AM_LDFLAGS = -lurcu -lurcu-cds

EXTRA_DIST = runall.sh utils.sh run-ust-global-tests.sh

noinst_PROGRAMS = ust_global_event_basic ust_global_all_events_basic

UTILS=utils.h
LIBLTTNG=$(top_srcdir)/src/lib/lttng-ctl/lttng-ctl.c \
		 $(top_srcdir)/src/common/sessiond-comm/sessiond-comm.c

ust_global_all_events_basic_SOURCES = ust_global_all_events_basic.c $(UTILS) $(LIBLTTNG)

ust_global_event_basic_SOURCES = ust_global_event_basic.c $(UTILS) $(LIBLTTNG)
endif
