# SPDX-License-Identifier: GPL-2.0-only

AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = \
	argpar \
	bytecode \
	compat \
	config \
	fd-tracker \
	string-utils \
	filter \
	hashtable \
	argpar-utils

# Make sure to always distribute all folders
# since SUBDIRS is decided at configure time.
DIST_SUBDIRS = \
	compat \
	health \
	hashtable \
	kernel-ctl \
	sessiond-comm \
	relayd \
	kernel-consumer \
	ust-consumer \
	testpoint \
	index \
	config \
	consumer \
	string-utils \
	fd-tracker \
	bytecode \
	filter \
	argpar \
	argpar-utils

# Common library
noinst_LTLIBRARIES = libpath.la libcommon-lgpl.la libcommon-gpl.la
EXTRA_DIST = mi-lttng-4.1.xsd

# The libcommon-lgpl static archive contains only LGPLv2.1 code. It is
# meant to be used by LGPLv2.1 libraries such as liblttng-ctl. It also
# contains libcommon-lgpl.la.

libcommon_lgpl_la_SOURCES = \
	actions/action.c \
	actions/list.c \
	actions/notify.c \
	actions/path.c \
	actions/rotate-session.c \
	actions/snapshot-session.c \
	actions/start-session.c \
	actions/stop-session.c \
	actions/rate-policy.c \
	buffer-view.h buffer-view.c \
	channel.c \
	conditions/buffer-usage.c \
	conditions/condition.c \
	conditions/event-rule-matches.c \
	conditions/session-consumed-size.c \
	conditions/session-rotation.c \
	credentials.c credentials.h \
	defaults.c \
	domain.c \
	dynamic-array.c dynamic-array.h \
	dynamic-buffer.c dynamic-buffer.h \
	endpoint.c \
	error.c error.h \
	error-query.c \
	evaluation.c \
	event-expr/event-expr.c \
	event-field-value.c \
	event-rule/event-rule.c \
	event-rule/kernel-kprobe.c \
	event-rule/kernel-syscall.c \
	event-rule/kernel-uprobe.c \
	event-rule/kernel-tracepoint.c \
	event-rule/user-tracepoint.c \
	event-rule/log4j-logging.c \
	event-rule/jul-logging.c \
	event-rule/python-logging.c \
	fd-handle.c fd-handle.h \
	kernel-probe.c \
	location.c \
	log-level-rule.c \
	mi-lttng.c mi-lttng.h \
	notification.c \
	payload.c payload.h \
	payload-view.c payload-view.h \
	readwrite.c readwrite.h \
	runas.c runas.h \
	session-descriptor.c \
	snapshot.c snapshot.h \
	spawn-viewer.c spawn-viewer.h \
	thread.c thread.h \
	time.c \
	tracker.c tracker.h \
	trigger.c \
	unix.c unix.h \
	uri.c uri.h \
	userspace-probe.c \
	utils.c utils.h

if HAVE_ELF_H
libcommon_lgpl_la_SOURCES += \
	lttng-elf.c lttng-elf.h
endif

libcommon_lgpl_la_LIBADD = \
	$(top_builddir)/src/common/bytecode/libbytecode.la \
	$(top_builddir)/src/common/compat/libcompat.la \
	$(top_builddir)/src/common/config/libconfig.la \
	$(top_builddir)/src/common/filter/libfilter.la \
	$(top_builddir)/src/common/hashtable/libhashtable-lgpl.la \
	$(top_builddir)/src/vendor/msgpack/libmsgpack.la

# The libpath static archive contains GPLv2 compatible code. It is
# meant to be used by GPL executables.

libpath_la_SOURCES = \
	path.c path.h

# The libcommon-gpl static archive contains GPLv2 compatible code. It is
# meant to be used by GPL executables.

libcommon_gpl_la_SOURCES = \
	common.h \
	context.c context.h \
	daemonize.c daemonize.h \
	event.c \
	filter.c filter.h \
	fs-handle.c fs-handle.h fs-handle-internal.h \
	futex.c futex.h \
	index-allocator.c index-allocator.h \
	optional.h \
	pipe.c pipe.h \
	shm.c shm.h \
	trace-chunk.c trace-chunk.h \
	trace-chunk-registry.h \
	uuid.c uuid.h \
	waiter.c waiter.h

libcommon_gpl_la_LIBADD = \
	libcommon-lgpl.la \
	libpath.la \
	$(top_builddir)/src/common/hashtable/libhashtable-gpl.la \
	$(top_builddir)/src/common/fd-tracker/libfd-tracker.la

if BUILD_LIB_HEALTH
SUBDIRS += health
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

if BUILD_LIB_CONSUMER
SUBDIRS += consumer
endif

noinst_HEADERS = \
	align.h \
	bug.h \
	defaults.h \
	error.h \
	futex.h \
	lttng-kernel.h \
	lttng-kernel-old.h \
	macros.h \
	time.h \
	uri.h \
	utils.h

noinst_PROGRAMS = filter-grammar-test
filter_grammar_test_SOURCES = filter-grammar-test.c
filter_grammar_test_LDADD = libcommon-gpl.la

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
