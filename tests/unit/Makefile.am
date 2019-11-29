# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS = ini_config

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LOG_DRIVER_FLAGS='--merge'
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTS = test_kernel_data \
	test_session \
	test_uri \
	test_utils_parse_size_suffix \
	test_utils_parse_time_suffix \
	test_utils_expand_path \
	test_utils_compat_poll \
	test_string_utils \
	test_notification \
	test_directory_handle \
	test_relayd_backward_compat_group_by_session \
	ini_config/test_ini_config \
	test_fd_tracker \
	test_uuid \
	test_buffer_view

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBCOMMON=$(top_builddir)/src/common/libcommon.la
LIBSTRINGUTILS=$(top_builddir)/src/common/string-utils/libstring-utils.la
LIBFDTRACKER=$(top_builddir)/src/common/fd-tracker/libfd-tracker.la
LIBSESSIOND_COMM=$(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la
LIBHASHTABLE=$(top_builddir)/src/common/hashtable/libhashtable.la
LIBRELAYD=$(top_builddir)/src/common/relayd/librelayd.la
LIBLTTNG_CTL=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la

# Define test programs
noinst_PROGRAMS = test_uri test_session test_kernel_data \
                  test_utils_parse_size_suffix test_utils_parse_time_suffix \
                  test_utils_expand_path test_utils_compat_poll \
                  test_string_utils test_notification test_directory_handle \
                  test_relayd_backward_compat_group_by_session \
                  test_fd_tracker test_uuid \
                  test_buffer_view

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS += test_ust_data
TESTS += test_ust_data
endif

# URI unit tests
test_uri_SOURCES = test_uri.c
test_uri_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBHASHTABLE) $(DL_LIBS)

# Sessiond objects
SESSIOND_OBJS = $(top_builddir)/src/bin/lttng-sessiond/buffer-registry.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/cmd.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/save.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/notification-thread-commands.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/shm.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/kernel.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/ht-cleanup.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/notification-thread.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/lttng-syscall.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/channel.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/agent.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/kernel-consumer.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/trace-kernel.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/rotation-thread.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/context.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/consumer.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/utils.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/fd-limit.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/notification-thread-events.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/event.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/timer.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/snapshot.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/sessiond-config.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/rotate.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/modprobe.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/session.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/globals.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/thread-utils.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/process-utils.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/thread.$(OBJEXT) \
	 $(top_builddir)/src/bin/lttng-sessiond/tracker.$(OBJEXT) \
	 $(top_builddir)/src/common/libcommon.la \
	 $(top_builddir)/src/common/testpoint/libtestpoint.la \
	 $(top_builddir)/src/common/compat/libcompat.la \
	 $(top_builddir)/src/common/health/libhealth.la \
	 $(top_builddir)/src/common/sessiond-comm/libsessiond-comm.la

if HAVE_LIBLTTNG_UST_CTL
SESSIOND_OBJS += $(top_builddir)/src/bin/lttng-sessiond/trace-ust.$(OBJEXT) \
		 $(top_builddir)/src/bin/lttng-sessiond/ust-registry.$(OBJEXT) \
		 $(top_builddir)/src/bin/lttng-sessiond/ust-app.$(OBJEXT) \
		 $(top_builddir)/src/bin/lttng-sessiond/ust-consumer.$(OBJEXT) \
		 $(top_builddir)/src/bin/lttng-sessiond/notify-apps.$(OBJEXT) \
		 $(top_builddir)/src/bin/lttng-sessiond/ust-metadata.$(OBJEXT) \
		 $(top_builddir)/src/bin/lttng-sessiond/agent-thread.$(OBJEXT) \
		 $(top_builddir)/src/bin/lttng-sessiond/ust-field-utils.$(OBJEXT)
endif

RELAYD_OBJS = $(top_builddir)/src/bin/lttng-relayd/backward-compatibility-group-by.$(OBJEXT)

test_session_SOURCES = test_session.c
test_session_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBRELAYD) $(LIBSESSIOND_COMM) \
		     $(LIBHASHTABLE) $(DL_LIBS) -lrt -lurcu-common -lurcu \
		     $(KMOD_LIBS) \
		     $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
		     $(top_builddir)/src/common/kernel-ctl/libkernel-ctl.la \
		     $(top_builddir)/src/common/compat/libcompat.la \
		     $(top_builddir)/src/common/testpoint/libtestpoint.la \
		     $(top_builddir)/src/common/health/libhealth.la \
		     $(top_builddir)/src/common/config/libconfig.la \
		     $(top_builddir)/src/common/string-utils/libstring-utils.la

test_session_LDADD += $(SESSIOND_OBJS)

if HAVE_LIBLTTNG_UST_CTL
test_session_LDADD += $(UST_CTL_LIBS)
endif

# UST data structures unit test
if HAVE_LIBLTTNG_UST_CTL
test_ust_data_SOURCES = test_ust_data.c
test_ust_data_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBRELAYD) $(LIBSESSIOND_COMM) \
		      $(LIBHASHTABLE) $(DL_LIBS) -lrt -lurcu-common -lurcu \
		      $(UST_CTL_LIBS) \
		      $(KMOD_LIBS) \
		      $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la \
		      $(top_builddir)/src/common/kernel-ctl/libkernel-ctl.la \
		      $(top_builddir)/src/common/compat/libcompat.la \
		      $(top_builddir)/src/common/testpoint/libtestpoint.la \
		      $(top_builddir)/src/common/health/libhealth.la \
		      $(top_builddir)/src/common/config/libconfig.la \
		      $(top_builddir)/src/common/string-utils/libstring-utils.la
test_ust_data_LDADD += $(SESSIOND_OBJS)
endif

# Kernel data structures unit test
KERN_DATA_TRACE=$(top_builddir)/src/bin/lttng-sessiond/trace-kernel.$(OBJEXT) \
		$(top_builddir)/src/common/compat/libcompat.la \
		$(top_builddir)/src/bin/lttng-sessiond/consumer.$(OBJEXT) \
		$(top_builddir)/src/bin/lttng-sessiond/globals.$(OBJEXT) \
		$(top_builddir)/src/bin/lttng-sessiond/utils.$(OBJEXT) \
		$(top_builddir)/src/bin/lttng-sessiond/tracker.$(OBJEXT) \
		$(top_builddir)/src/common/health/libhealth.la \
		$(top_builddir)/src/bin/lttng-sessiond/notification-thread-commands.$(OBJEXT) \
		$(LIBLTTNG_CTL)

test_kernel_data_SOURCES = test_kernel_data.c
test_kernel_data_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBRELAYD) $(LIBSESSIOND_COMM) \
			 $(LIBHASHTABLE) $(DL_LIBS) -lrt
test_kernel_data_LDADD += $(KERN_DATA_TRACE)

# utils suffix for unit test

# parse_size_suffix unit test
test_utils_parse_size_suffix_SOURCES = test_utils_parse_size_suffix.c
test_utils_parse_size_suffix_LDADD = $(LIBTAP) $(LIBHASHTABLE) $(LIBCOMMON) $(DL_LIBS)

# parse_time_suffix unit test
test_utils_parse_time_suffix_SOURCES = test_utils_parse_time_suffix.c
test_utils_parse_time_suffix_LDADD = $(LIBTAP) $(LIBHASHTABLE) $(LIBCOMMON)

# compat_poll unit test
test_utils_compat_poll_SOURCES = test_utils_compat_poll.c
test_utils_compat_poll_LDADD  = $(LIBTAP) $(LIBHASHTABLE) $(DL_LIBS) \
		      $(top_builddir)/src/common/compat/libcompat.la $(LIBCOMMON)

# expand_path unit test
test_utils_expand_path_SOURCES = test_utils_expand_path.c
test_utils_expand_path_LDADD = $(LIBTAP) $(LIBHASHTABLE) $(LIBCOMMON) $(DL_LIBS)

# directory handle unit test
test_directory_handle_SOURCES = test_directory_handle.c
test_directory_handle_LDADD = $(LIBTAP) $(LIBHASHTABLE) $(LIBCOMMON) $(DL_LIBS)

# string utilities unit test
test_string_utils_SOURCES = test_string_utils.c
test_string_utils_LDADD = $(LIBTAP) $(LIBCOMMON) $(LIBSTRINGUTILS) $(DL_LIBS)

# Notification api
test_notification_SOURCES = test_notification.c
test_notification_LDADD = $(LIBTAP) $(LIBLTTNG_CTL) $(DL_LIBS)

# relayd backward compat for groou-by-session utilities
test_relayd_backward_compat_group_by_session_SOURCES = test_relayd_backward_compat_group_by_session.c
test_relayd_backward_compat_group_by_session_LDADD = $(LIBTAP) $(LIBCOMMON) $(RELAYD_OBJS)
test_relayd_backward_compat_group_by_session_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/bin/lttng-relayd

# fd tracker unit test
test_fd_tracker_SOURCES = test_fd_tracker.c
test_fd_tracker_LDADD = $(LIBTAP) $(LIBFDTRACKER) $(DL_LIBS) -lurcu $(LIBCOMMON) $(LIBHASHTABLE)

# uuid unit test
test_uuid_SOURCES = test_uuid.c
test_uuid_LDADD = $(LIBTAP) $(LIBCOMMON)

# buffer view unit test
test_buffer_view_SOURCES = test_buffer_view.c
test_buffer_view_LDADD = $(LIBTAP) $(LIBCOMMON)
