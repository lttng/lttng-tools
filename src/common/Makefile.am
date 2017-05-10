AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = string-utils

# Make sure to always distribute all folders
# since SUBDIRS is decided at configure time.
DIST_SUBDIRS = compat health hashtable kernel-ctl sessiond-comm relayd \
	  kernel-consumer ust-consumer testpoint index config consumer \
	  string-utils

if BUILD_LIB_COMPAT
SUBDIRS += compat
endif

if BUILD_LIB_HEALTH
SUBDIRS += health
endif

if BUILD_LIB_HASHTABLE
SUBDIRS += hashtable
endif

if BUILD_LIB_KERNEL_CTL
SUBDIRS += kernel-ctl
endif

if BUILD_LIB_SESSIOND_COMM
SUBDIRS += sessiond-comm
endif

if BUILD_LIB_RELAYD
SUBDIRS += relayd
endif

if BUILD_LIB_KERNEL_CONSUMER
SUBDIRS += kernel-consumer
endif

if BUILD_LIB_UST_CONSUMER
SUBDIRS += ust-consumer
endif

if BUILD_LIB_TESTPOINT
SUBDIRS += testpoint
endif

if BUILD_LIB_INDEX
SUBDIRS += index
endif

if BUILD_LIB_CONFIG
SUBDIRS += config
endif

if BUILD_LIB_CONSUMER
SUBDIRS += consumer
endif

noinst_HEADERS = lttng-kernel.h defaults.h macros.h error.h futex.h \
				 uri.h utils.h lttng-kernel-old.h \
				 align.h bitfield.h bug.h time.h

# Common library
noinst_LTLIBRARIES = libcommon.la
EXTRA_DIST = mi-lttng-3.0.xsd

libcommon_la_SOURCES = error.h error.c utils.c utils.h runas.c runas.h \
                       common.h futex.c futex.h uri.c uri.h defaults.c \
                       pipe.c pipe.h readwrite.c readwrite.h \
                       mi-lttng.h mi-lttng.c \
                       daemonize.c daemonize.h \
                       unix.c unix.h \
                       filter.c filter.h context.c context.h \
                       action.c notify.c condition.c buffer-usage.c \
                       evaluation.c notification.c trigger.c endpoint.c \
                       dynamic-buffer.h dynamic-buffer.c \
                       buffer-view.h buffer-view.c \
                       waiter.h waiter.c

libcommon_la_LIBADD = \
		$(top_builddir)/src/common/config/libconfig.la \
		$(UUID_LIBS)

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
