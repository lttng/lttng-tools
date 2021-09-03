# SPDX-License-Identifier: GPL-2.0-only

AM_CFLAGS += -I$(top_srcdir)/tests/utils

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la
LIB_LTTNG_CTL = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

noinst_PROGRAMS = base_client notification rotation default_pipe_size_getter

if NO_SHARED

CLEANFILES = libpause_consumer.so libpause_consumer.so.debug libpause_sessiond.so libpause_sessiond.so.debug
EXTRA_DIST = \
	     base_client.c \
	     consumer_testpoints.cpp \
	     sessiond_testpoints.cpp \
	     notification.c \
	     test_notification_kernel_buffer_usage \
	     test_notification_kernel_capture \
	     test_notification_kernel_error \
	     test_notification_kernel_instrumentation \
	     test_notification_kernel_syscall \
	     test_notification_kernel_userspace_probe \
	     test_notification_multi_app \
	     test_notification_notifier_discarded_count \
	     test_notification_ust_buffer_usage \
	     test_notification_ust_capture \
	     test_notification_ust_error \
	     test_notification_ust_event_rule_condition_exclusion \
	     util_event_generator.sh
else

# In order to test the health check feature, the helper library
# must be built as .so to be able to LD_PRELOAD it.
FORCE_SHARED_LIB_OPTIONS = -module -shared -avoid-version \
			   -rpath $(abs_builddir)

libpause_consumer_la_SOURCES = consumer_testpoints.cpp
libpause_consumer_la_LIBADD = \
	$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
	$(DL_LIBS)
libpause_consumer_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)

libpause_sessiond_la_SOURCES = sessiond_testpoints.cpp
libpause_sessiond_la_LIBADD = \
	$(top_builddir)/src/common/libcommon.la \
	$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
	$(DL_LIBS)
libpause_sessiond_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)
noinst_LTLIBRARIES = libpause_sessiond.la libpause_consumer.la

base_client_SOURCES = base_client.c
base_client_LDADD = $(LIB_LTTNG_CTL)

notification_SOURCES = notification.c
# Tests the deprecated lttng_register_trigger() interface
notification_CFLAGS = -Wno-deprecated-declarations $(AM_CFLAGS)
notification_LDADD = $(LIB_LTTNG_CTL) $(LIBTAP) -lm

rotation_SOURCES = rotation.c
rotation_LDADD = $(LIB_LTTNG_CTL) $(LIBTAP) -lm

default_pipe_size_getter_SOURCES = default_pipe_size_getter.c
default_pipe_size_getter_LDADD = $(top_builddir)/src/common/libcommon.la

noinst_SCRIPTS = \
	test_notification_kernel_buffer_usage \
	test_notification_kernel_error \
	test_notification_kernel_instrumentation \
	test_notification_kernel_syscall \
	test_notification_kernel_userspace_probe \
	test_notification_multi_app \
	test_notification_notifier_discarded_count \
	test_notification_ust_buffer_usage \
	test_notification_ust_error \
	test_notification_ust_event_rule_condition_exclusion \
	test_rotation \
	util_event_generator.sh

EXTRA_DIST = \
	test_notification_kernel_buffer_usage \
	test_notification_kernel_capture \
	test_notification_kernel_error \
	test_notification_kernel_instrumentation \
	test_notification_kernel_syscall \
	test_notification_kernel_userspace_probe \
	test_notification_multi_app \
	test_notification_notifier_discarded_count \
	test_notification_ust_buffer_usage \
	test_notification_ust_capture \
	test_notification_ust_error \
	test_notification_ust_event_rule_condition_exclusion \
	test_rotation \
	util_event_generator.sh

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
endif
