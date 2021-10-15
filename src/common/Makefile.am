# SPDX-License-Identifier: GPL-2.0-only

AUTOMAKE_OPTIONS = subdir-objects

SUBDIRS = \
	argpar \
	bytecode \
	compat \
	config \
	ini-config \
	fd-tracker \
	string-utils \
	filter \
	hashtable

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
	ini-config \
	consumer \
	string-utils \
	fd-tracker \
	bytecode \
	filter \
	argpar

# Common library
noinst_LTLIBRARIES = libcommon.la
EXTRA_DIST = mi-lttng-4.1.xsd

libcommon_la_SOURCES = \
	actions/action.cpp \
	actions/list.cpp \
	actions/notify.cpp \
	actions/path.cpp \
	actions/rotate-session.cpp \
	actions/snapshot-session.cpp \
	actions/start-session.cpp \
	actions/stop-session.cpp \
	actions/rate-policy.cpp \
	buffer-view.h buffer-view.cpp \
	common.h \
	conditions/buffer-usage.cpp \
	conditions/condition.cpp \
	conditions/event-rule-matches.cpp \
	conditions/session-consumed-size.cpp \
	conditions/session-rotation.cpp \
	context.cpp context.h \
	credentials.cpp credentials.h \
	daemonize.cpp daemonize.h \
	defaults.cpp \
	domain.cpp \
	dynamic-array.cpp dynamic-array.h \
	dynamic-buffer.cpp dynamic-buffer.h \
	endpoint.cpp \
	error.cpp error.h \
	error-query.cpp \
	evaluation.cpp \
	event.cpp \
	event-expr/event-expr.cpp \
	event-field-value.cpp \
	event-rule/event-rule.cpp \
	event-rule/kernel-kprobe.cpp \
	event-rule/kernel-syscall.cpp \
	event-rule/kernel-uprobe.cpp \
	event-rule/kernel-tracepoint.cpp \
	event-rule/user-tracepoint.cpp \
	event-rule/log4j-logging.cpp \
	event-rule/jul-logging.cpp \
	event-rule/python-logging.cpp \
	filter.cpp filter.h \
	fd-handle.cpp fd-handle.h \
	fs-handle.cpp fs-handle.h fs-handle-internal.h \
	futex.cpp futex.h \
	kernel-probe.cpp \
	index-allocator.cpp index-allocator.h \
	location.cpp \
	log-level-rule.cpp \
	mi-lttng.cpp mi-lttng.h \
	notification.cpp \
	optional.h \
	payload.cpp payload.h \
	payload-view.cpp payload-view.h \
	pipe.cpp pipe.h \
	readwrite.cpp readwrite.h \
	runas.cpp runas.h \
	shm.cpp shm.h \
	session-descriptor.cpp \
	snapshot.cpp snapshot.h \
	spawn-viewer.cpp spawn-viewer.h \
	time.cpp \
	trace-chunk.cpp trace-chunk.h \
	trace-chunk-registry.h \
	trigger.cpp \
	unix.cpp unix.h \
	uri.cpp uri.h \
	userspace-probe.cpp \
	utils.cpp utils.h \
	uuid.cpp uuid.h \
	thread.cpp thread.h \
	tracker.cpp tracker.h \
	waiter.cpp waiter.h

if HAVE_ELF_H
libcommon_la_SOURCES += \
	lttng-elf.cpp lttng-elf.h
endif

libcommon_la_LIBADD = \
	$(top_builddir)/src/common/bytecode/libbytecode.la \
	$(top_builddir)/src/common/config/libconfig.la \
	$(top_builddir)/src/common/ini-config/libini-config.la \
	$(top_builddir)/src/common/compat/libcompat.la \
	$(top_builddir)/src/common/hashtable/libhashtable.la \
	$(top_builddir)/src/common/fd-tracker/libfd-tracker.la \
	$(top_builddir)/src/common/filter/libfilter.la \
	$(top_builddir)/src/vendor/msgpack/libmsgpack.la

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
filter_grammar_test_SOURCES = filter-grammar-test.cpp
filter_grammar_test_LDADD = \
	libcommon.la

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
