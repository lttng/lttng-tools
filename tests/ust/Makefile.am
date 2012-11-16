if HAVE_LIBLTTNG_UST_CTL
SUBDIRS = nprocesses high-throughput low-throughput before-after multi-session \
		  overlap

AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/tests -I$(top_srcdir)/src -g -Wall 
AM_LDFLAGS = -lurcu -lurcu-cds

EXTRA_DIST = runall.sh run-ust-global-tests.sh

noinst_PROGRAMS = ust_global_event_basic ust_global_event_wildcard

UTILS=../utils.h
LIBLTTNG=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

SESSIONDSRC=$(top_srcdir)/src/common/sessiond-comm/sessiond-comm.c \
		 $(top_srcdir)/src/common/sessiond-comm/unix.c \
		 $(top_srcdir)/src/common/sessiond-comm/inet.c \
		 $(top_srcdir)/src/common/sessiond-comm/inet6.c

ust_global_event_wildcard_SOURCES = ust_global_event_wildcard.c $(UTILS) \
		$(SESSIONDSRC)
ust_global_event_wildcard_LDADD = $(LIBLTTNG)

ust_global_event_basic_SOURCES = ust_global_event_basic.c $(UTILS) \
		$(SESSIONDSRC)
ust_global_event_basic_LDADD = $(LIBLTTNG)

endif
