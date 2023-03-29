# SPDX-License-Identifier: GPL-2.0-only

AUTOMAKE_OPTIONS = subdir-objects
noinst_LTLIBRARIES =

BUILT_SOURCES =

noinst_HEADERS = \
	align.hpp \
	bug.hpp \
	defaults.hpp \
	error.hpp \
	futex.hpp \
	lttng-kernel.hpp \
	lttng-kernel-old.hpp \
	macros.hpp \
	time.hpp \
	uri.hpp \
	utils.hpp


# libargpar
noinst_LTLIBRARIES += libargpar.la
libargpar_la_SOURCES = \
	argpar/argpar.c \
	argpar/argpar.h


# libargpar-utils
noinst_LTLIBRARIES += libargpar-utils.la
libargpar_utils_la_SOURCES = \
	argpar-utils/argpar-utils.cpp \
	argpar-utils/argpar-utils.hpp


# libbytecode
noinst_LTLIBRARIES += libbytecode.la
libbytecode_la_SOURCES = \
	bytecode/bytecode.cpp \
	bytecode/bytecode.hpp


# The libcommon-lgpl static archive contains only LGPLv2.1 code. It is
# meant to be used by LGPLv2.1 libraries such as liblttng-ctl. It also
# contains libcommon-lgpl.la.

noinst_LTLIBRARIES += libcommon-lgpl.la
libcommon_lgpl_la_SOURCES = \
	actions/action.cpp \
	actions/list.cpp \
	actions/notify.cpp \
	actions/path.cpp \
	actions/rotate-session.cpp \
	actions/snapshot-session.cpp \
	actions/start-session.cpp \
	actions/stop-session.cpp \
	actions/rate-policy.cpp \
	buffer-view.hpp buffer-view.cpp \
	channel.cpp \
	compiler.hpp \
	conditions/buffer-usage.cpp \
	conditions/condition.cpp \
	conditions/event-rule-matches.cpp \
	conditions/session-consumed-size.cpp \
	conditions/session-rotation.cpp \
	credentials.cpp credentials.hpp \
	defaults.cpp \
	domain.cpp \
	dynamic-array.cpp dynamic-array.hpp \
	dynamic-buffer.cpp dynamic-buffer.hpp \
	endpoint.cpp \
	error.cpp error.hpp \
	error-query.cpp \
	evaluation.cpp \
	event.cpp \
	eventfd.hpp eventfd.cpp \
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
	exception.cpp exception.hpp \
	file-descriptor.hpp file-descriptor.cpp \
	fd-handle.cpp fd-handle.hpp\
	format.hpp \
	kernel-probe.cpp \
	location.cpp \
	locked-reference.hpp \
	logging-utils.hpp logging-utils.cpp \
	log-level-rule.cpp \
	make-unique.hpp \
	make-unique-wrapper.hpp \
	mi-lttng.cpp mi-lttng.hpp \
	notification.cpp \
	payload.cpp payload.hpp \
	payload-view.cpp payload-view.hpp \
	pthread-lock.hpp \
	random.cpp random.hpp \
	readwrite.cpp readwrite.hpp \
	runas.cpp runas.hpp \
	scope-exit.hpp \
	session-descriptor.cpp \
	snapshot.cpp snapshot.hpp \
	spawn-viewer.cpp spawn-viewer.hpp \
	thread.cpp thread.hpp \
	time.cpp \
	tracker.cpp tracker.hpp \
	trigger.cpp \
	unix.cpp unix.hpp \
	uri.cpp uri.hpp \
	userspace-probe.cpp \
	urcu.hpp \
	utils.cpp utils.hpp

if HAVE_ELF_H
libcommon_lgpl_la_SOURCES += \
	lttng-elf.cpp lttng-elf.hpp
endif

libcommon_lgpl_la_LIBADD = \
	libbytecode.la \
	libcompat.la \
	libconfig.la \
	libfilter.la \
	libhashtable-lgpl.la \
	$(top_builddir)/src/vendor/msgpack/libmsgpack.la


# The libpath static archive contains GPLv2 compatible code. It is
# meant to be used by GPL executables.
noinst_LTLIBRARIES += libpath.la
libpath_la_SOURCES = \
	path.cpp path.hpp


# The libcommon-gpl static archive contains GPLv2 compatible code. It is
# meant to be used by GPL executables.
noinst_LTLIBRARIES += libcommon-gpl.la
libcommon_gpl_la_SOURCES = \
	common.hpp \
	context.cpp context.hpp \
	daemonize.cpp daemonize.hpp \
	filter.cpp filter.hpp \
	fs-handle.cpp fs-handle.hpp fs-handle-internal.hpp \
	futex.cpp futex.hpp \
	index-allocator.cpp index-allocator.hpp \
	optional.hpp \
	pipe.cpp pipe.hpp \
	shm.cpp shm.hpp \
	trace-chunk.cpp trace-chunk.hpp \
	trace-chunk-registry.hpp \
	uuid.cpp uuid.hpp \
	waiter.cpp waiter.hpp

libcommon_gpl_la_LIBADD = \
	libcommon-lgpl.la \
	libpath.la \
	libini-config.la \
	libhashtable-gpl.la \
	libfd-tracker.la


# libcompat
noinst_LTLIBRARIES += libcompat.la
libcompat_la_SOURCES = \
        compat/compat-fcntl.cpp \
        compat/directory-handle.cpp \
        compat/directory-handle.hpp \
        compat/dirent.hpp \
        compat/endian.hpp \
        compat/errno.hpp \
        compat/fcntl.hpp \
        compat/getenv.hpp \
        compat/mman.hpp \
        compat/netdb.hpp \
        compat/path.hpp \
        compat/paths.hpp \
        compat/poll.cpp \
        compat/poll.hpp \
        compat/pthread.hpp \
        compat/socket.hpp \
        compat/string.hpp \
        compat/tid.hpp \
        compat/time.hpp


# libconfig
noinst_LTLIBRARIES += libconfig.la
libconfig_la_SOURCES = \
	config/config-internal.hpp \
	config/config-session-abi.hpp \
	config/session-config.cpp \
	config/session-config.hpp

libconfig_la_CPPFLAGS = $(libxml2_CFLAGS) $(AM_CPPFLAGS)
libconfig_la_LIBADD = ${libxml2_LIBS}


if BUILD_LIB_CONSUMER
noinst_LTLIBRARIES += libconsumer.la

libconsumer_la_SOURCES = \
	consumer/consumer.cpp \
	consumer/consumer.hpp \
	consumer/consumer-metadata-cache.cpp \
	consumer/consumer-metadata-cache.hpp \
	consumer/consumer-stream.cpp \
	consumer/consumer-stream.hpp \
	consumer/consumer-testpoint.hpp \
	consumer/consumer-timer.cpp \
	consumer/consumer-timer.hpp \
	consumer/metadata-bucket.cpp \
	consumer/metadata-bucket.hpp

libconsumer_la_LIBADD = \
	libkernel-consumer.la \
	librelayd.la \
	libsessiond-comm.la

if HAVE_LIBLTTNG_UST_CTL
libconsumer_la_LIBADD += \
	libust-consumer.la
endif
endif # BUILD_LIB_CONSUMER


# libfd-tracker
noinst_LTLIBRARIES += libfd-tracker.la
libfd_tracker_la_SOURCES = \
	fd-tracker/fd-tracker.cpp \
	fd-tracker/fd-tracker.hpp \
	fd-tracker/inode.cpp \
	fd-tracker/inode.hpp \
	fd-tracker/utils.cpp \
	fd-tracker/utils.hpp \
	fd-tracker/utils-poll.cpp


# libfilter
noinst_LTLIBRARIES += libfilter.la

libfilter_la_SOURCES = \
	filter/filter-ast.hpp \
	filter/filter-ir.hpp \
	filter/filter-lexer.lpp \
	filter/filter-parser.ypp \
	filter/filter-symbols.hpp \
	filter/filter-visitor-generate-bytecode.cpp \
	filter/filter-visitor-generate-ir.cpp \
	filter/filter-visitor-ir-check-binary-op-nesting.cpp \
	filter/filter-visitor-ir-normalize-glob-patterns.cpp \
	filter/filter-visitor-ir-validate-globbing.cpp \
	filter/filter-visitor-ir-validate-string.cpp \
	filter/filter-visitor-xml.cpp \
	filter/memstream.hpp

BUILT_SOURCES += filter/filter-parser.hpp

# Disable some warning flags for generated sources.
FILTER_WARN_FLAGS = \
	-Wno-null-dereference \
	-Wno-redundant-decls \
	-Wno-unused-parameter

libfilter_la_CFLAGS = $(AM_CFLAGS) $(FILTER_WARN_FLAGS)
libfilter_la_CXXFLAGS = -include filter-symbols.hpp $(AM_CXXFLAGS) $(FILTER_WARN_FLAGS)
libfilter_la_CPPFLAGS = -I$(srcdir)/filter -I$(builddir)/filter $(AM_CPPFLAGS)
libfilter_la_LIBADD = libstring-utils.la

AM_YFLAGS = -t -d -v -Wno-yacc

# start with empty files to clean
CLEANFILES =

if HAVE_BISON
# we have bison: we can clean the generated parser files
CLEANFILES += \
	filter/filter-parser.cpp \
	filter/filter-parser.hpp \
	filter/filter-parser.output
else # HAVE_BISON
# create target used to stop the build if we want to build the parser,
# but we don't have the necessary tool to do so
filter/filter-parser.cpp filter/filter-parser.hpp: filter/filter-parser.ypp
	@echo "Error: Cannot build target because bison is missing."
	@echo "Make sure bison is installed and run the configure script again."
	@false

BUILT_SOURCES += filter/filter-parser.cpp filter/filter-parser.hpp
endif # HAVE_BISON

if HAVE_FLEX
# we have flex: we can clean the generated lexer files
CLEANFILES += filter/filter-lexer.cpp
else # HAVE_FLEX
# create target used to stop the build if we want to build the lexer,
# but we don't have the necessary tool to do so
filter/filter-lexer.cpp: filter/filter-lexer.lpp
	@echo "Error: Cannot build target because flex is missing."
	@echo "Make sure flex is installed and run the configure script again."
	@false

BUILT_SOURCES += filter/filter-lexer.cpp
endif # HAVE_FLEX


noinst_LTLIBRARIES += libhashtable-lgpl.la
libhashtable_lgpl_la_SOURCES = \
	hashtable/seed.cpp \
	hashtable/utils.cpp \
	hashtable/utils.hpp


noinst_LTLIBRARIES += libhashtable-gpl.la
libhashtable_gpl_la_SOURCES = \
	hashtable/hashtable.cpp \
	hashtable/hashtable.hpp \
	hashtable/hashtable-symbols.hpp

libhashtable_gpl_la_LIBADD = \
	$(URCU_LIBS) \
	$(URCU_CDS_LIBS)


if BUILD_LIB_HEALTH
noinst_LTLIBRARIES += libhealth.la

libhealth_la_SOURCES = \
	health/health.cpp
endif


# libini-config
noinst_LTLIBRARIES += libini-config.la
libini_config_la_SOURCES = \
	ini-config/ini.cpp \
	ini-config/ini.hpp \
	ini-config/ini-config.cpp \
	ini-config/ini-config.hpp


if BUILD_LIB_INDEX
noinst_LTLIBRARIES += libindex.la

libindex_la_SOURCES = \
	index/ctf-index.hpp \
	index/index.cpp \
	index/index.hpp
endif


if BUILD_LIB_KERNEL_CTL
noinst_LTLIBRARIES += libkernel-ctl.la

libkernel_ctl_la_SOURCES = \
	kernel-ctl/kernel-ctl.cpp \
	kernel-ctl/kernel-ctl.hpp \
	kernel-ctl/kernel-ioctl.hpp
endif

if BUILD_LIB_SESSIOND_COMM
noinst_LTLIBRARIES += libsessiond-comm.la

libsessiond_comm_la_SOURCES = \
	sessiond-comm/agent.hpp \
	sessiond-comm/inet.cpp \
	sessiond-comm/inet.hpp \
	sessiond-comm/inet6.cpp \
	sessiond-comm/inet6.hpp \
	sessiond-comm/relayd.hpp \
	sessiond-comm/sessiond-comm.cpp \
	sessiond-comm/sessiond-comm.hpp
endif

if BUILD_LIB_RELAYD
noinst_LTLIBRARIES += librelayd.la

librelayd_la_SOURCES = \
	relayd/relayd.cpp \
	relayd/relayd.hpp

librelayd_la_LIBADD = libsessiond-comm.la
endif


if BUILD_LIB_KERNEL_CONSUMER
noinst_LTLIBRARIES += libkernel-consumer.la

libkernel_consumer_la_SOURCES = \
	kernel-consumer/kernel-consumer.cpp \
	kernel-consumer/kernel-consumer.hpp

libkernel_consumer_la_LIBADD = \
	libkernel-ctl.la
endif

if BUILD_LIB_UST_CONSUMER
if HAVE_LIBLTTNG_UST_CTL
noinst_LTLIBRARIES += libust-consumer.la

libust_consumer_la_SOURCES = \
	ust-consumer/ust-consumer.cpp \
	ust-consumer/ust-consumer.hpp

libust_consumer_la_LIBADD = \
	$(UST_CTL_LIBS)
endif
endif

if BUILD_LIB_TESTPOINT
noinst_LTLIBRARIES += libtestpoint.la

libtestpoint_la_SOURCES = \
	testpoint/testpoint.cpp \
	testpoint/testpoint.hpp

libtestpoint_la_LIBADD = $(DL_LIBS)
endif


# libstring-utils
noinst_LTLIBRARIES += libstring-utils.la
libstring_utils_la_SOURCES = \
	string-utils/format.hpp \
	string-utils/string-utils.cpp \
	string-utils/string-utils.hpp


noinst_PROGRAMS = filter-grammar-test
filter_grammar_test_SOURCES = filter-grammar-test.cpp
filter_grammar_test_LDADD = libcommon-gpl.la

EXTRA_DIST = \
	mi-lttng-4.1.xsd \
	session.xsd

xmldir = $(datadir)/xml/lttng
dist_xml_DATA = session.xsd

# Copy EXTRA_DIST files to the build directory
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
