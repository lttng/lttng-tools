# SPDX-FileCopyrightText: 2013-2025 EfficiOS Inc.
# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS = ini_config

# test_event_rule_rule links against lttng-loglevel.o, so needs
# to be aware of CODE_COVERAGE provided by the static include.
include $(top_srcdir)/aminclude_static.am

AM_CPPFLAGS += -I$(top_srcdir)/tests/utils/ -I$(srcdir)

LOG_DRIVER_FLAGS='--merge'
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_builddir)/tests/utils/tap-driver.sh

EXTRA_DIST =
TESTS = \
	ini_config/test_ini_config \
	test_action \
	test_buffer_view \
	test_directory_handle \
	test_event_expr_to_bytecode \
	test_event_rule \
	test_fd_tracker \
	test_rate_policy \
	test_kernel_data \
	test_kernel_probe \
	test_kprobe_event_rule_event_name \
	test_uprobe_event_rule_event_name \
	test_log_level_rule \
	test_notification \
	test_payload \
	test_poller \
	test_relayd_backward_compat_group_by_session \
	test_scheduler \
	test_session \
	test_string_utils \
	test_unix_socket \
	test_uri \
	test_utils_compat_poll \
	test_utils_compat_pthread \
	test_utils_expand_path \
	test_utils_parse_size_suffix \
	test_utils_parse_time_suffix \
	test_uuid

LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la

LIBCOMMON_GPL=$(top_builddir)/src/common/libcommon-gpl.la
LIBCOMMON_LGPL=$(top_builddir)/src/common/libcommon-lgpl.la
LIBSTRINGUTILS=$(top_builddir)/src/common/libstring-utils.la
LIBFDTRACKER=$(top_builddir)/src/common/libfd-tracker.la
LIBSESSIOND_COMM=$(top_builddir)/src/common/libsessiond-comm.la
LIBRELAYD=$(top_builddir)/src/common/librelayd.la
LIBLTTNG_CTL=$(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la
LIBLTTNG_SESSIOND_COMMON=$(top_builddir)/src/bin/lttng-sessiond/liblttng-sessiond-common.la
LIBSCHEDULING=$(top_builddir)/src/common/libscheduling.la

# Define test programs
noinst_PROGRAMS = \
	test_action \
	test_buffer_view \
	test_condition \
	test_directory_handle \
	test_event_expr_to_bytecode \
	test_event_rule \
	test_fd_tracker \
	test_rate_policy \
	test_kernel_data \
	test_kernel_probe \
	test_kprobe_event_rule_event_name \
	test_uprobe_event_rule_event_name \
	test_log_level_rule \
	test_notification \
	test_payload \
	test_poller \
	test_relayd_backward_compat_group_by_session \
	test_scheduler \
	test_session \
	test_string_utils \
	test_unix_socket \
	test_uri \
	test_utils_compat_poll \
	test_utils_compat_pthread \
	test_utils_expand_path \
	test_utils_parse_size_suffix \
	test_utils_parse_time_suffix \
	test_uuid

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS += \
	test_ust_data

CLEANFILES=
if HAVE_CLANG2PY

CLANG_ARGS=-I$(top_srcdir)/include -I$(top_srcdir)/src
liblttngctl/lttngctl/lttng.py: $(top_srcdir)/include/lttng/lttng.h $(LIBLTTNG_CTL)
	mkdir -p $(dir $@)
	PYTHONPATH=$(PYTHONPATH) $(PYTHON3_BIN) $(CLANG2PY) -i --clang-args="$(CLANG_ARGS)" -l $(abs_top_builddir)/src/lib/lttng-ctl/.libs/liblttng-ctl.so $(top_srcdir)/include/lttng/lttng.h > liblttngctl/lttngctl/lttng.py || rm -f liblttngctl/lttngctl/lttng.py

# BUILT_SOURCES can't be used since it's evaluated early during `make dist` on a clean
# tree, and this target requires a tree that's in the process of being built.
CLEANFILES += liblttngctl/lttngctl/lttng.py
TESTS += \
	liblttngctl/test_automatic_memory_reclamation_policy.py \
	liblttngctl/test_preallocation_policy.py \
	liblttngctl/test_reclaim_channel_memory.py \
	liblttngctl/test_session_trace_format.py \
	liblttngctl/test_stream_info.py \
	liblttngctl/test_watchdog_timer.py
endif

EXTRA_DIST += \
	liblttngctl/common.py \
	liblttngctl/test_automatic_memory_reclamation_policy.py \
	liblttngctl/test_preallocation_policy.py \
	liblttngctl/test_reclaim_channel_memory.py \
	liblttngctl/test_session_trace_format.py \
	liblttngctl/test_stream_info.py \
	liblttngctl/test_watchdog_timer.py
TESTS += test_ust_data
endif

# URI unit tests
test_uri_SOURCES = test_uri.cpp
test_uri_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(DL_LIBS)

RELAYD_OBJS = $(top_builddir)/src/bin/lttng-relayd/backward-compatibility-group-by.$(OBJEXT)

test_session_SOURCES = test_session.cpp
test_session_LDADD = $(LIBTAP) $(LIBLTTNG_SESSIOND_COMMON) $(DL_LIBS)

if HAVE_LIBLTTNG_UST_CTL
test_session_SOURCES += ust-sigbus.cpp
test_session_LDADD += $(UST_CTL_LIBS)
endif

# UST data structures unit test
if HAVE_LIBLTTNG_UST_CTL
test_ust_data_SOURCES = test_ust_data.cpp
test_ust_data_LDADD = $(LIBTAP) $(LIBLTTNG_SESSIOND_COMMON) $(DL_LIBS)
endif

test_kernel_data_SOURCES = test_kernel_data.cpp
test_kernel_data_LDADD = $(LIBTAP) $(LIBLTTNG_SESSIOND_COMMON) $(DL_LIBS)

# utils suffix for unit test

# parse_size_suffix unit test
test_utils_parse_size_suffix_SOURCES = test_utils_parse_size_suffix.cpp
test_utils_parse_size_suffix_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(DL_LIBS)

# parse_time_suffix unit test
test_utils_parse_time_suffix_SOURCES = test_utils_parse_time_suffix.cpp
test_utils_parse_time_suffix_LDADD = $(LIBTAP) $(LIBCOMMON_GPL)

# compat_poll unit test
test_utils_compat_poll_SOURCES = test_utils_compat_poll.cpp
test_utils_compat_poll_LDADD  = $(LIBTAP) $(DL_LIBS) \
		      $(top_builddir)/src/common/libcompat.la $(LIBCOMMON_GPL)

# compat_pthread unit test
test_utils_compat_pthread_SOURCES = test_utils_compat_pthread.cpp
test_utils_compat_pthread_LDADD  = $(LIBTAP) \
		      $(top_builddir)/src/common/libcompat.la $(LIBCOMMON_GPL)

# expand_path unit test
test_utils_expand_path_SOURCES = test_utils_expand_path.cpp
test_utils_expand_path_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(DL_LIBS)

# directory handle unit test
test_directory_handle_SOURCES = test_directory_handle.cpp
test_directory_handle_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(DL_LIBS)

# string utilities unit test
test_string_utils_SOURCES = test_string_utils.cpp
test_string_utils_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(LIBSTRINGUTILS) $(DL_LIBS)

# Notification api
test_notification_SOURCES = test_notification.cpp
test_notification_LDADD = $(LIBTAP) $(LIBLTTNG_CTL) $(DL_LIBS)

# Event rule api
test_event_rule_SOURCES = test_event_rule.cpp
test_event_rule_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(LIBLTTNG_CTL) $(DL_LIBS) \
		      $(top_builddir)/src/bin/lttng/lttng-loglevel.$(OBJEXT)

# Condition api
test_condition_SOURCES = test_condition.cpp
test_condition_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(LIBLTTNG_CTL) $(DL_LIBS)

# relayd backward compat for groou-by-session utilities
test_relayd_backward_compat_group_by_session_SOURCES = test_relayd_backward_compat_group_by_session.cpp
test_relayd_backward_compat_group_by_session_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(RELAYD_OBJS)
test_relayd_backward_compat_group_by_session_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/src/bin/lttng-relayd

# rate policy object unit test
test_rate_policy_SOURCES = test_rate_policy.cpp
test_rate_policy_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(LIBLTTNG_CTL) $(DL_LIBS) \
		      $(top_builddir)/src/bin/lttng/lttng-loglevel.$(OBJEXT)

# fd tracker unit test
test_fd_tracker_SOURCES = test_fd_tracker.cpp
test_fd_tracker_LDADD = $(LIBTAP) $(LIBFDTRACKER) $(DL_LIBS) $(URCU_LIBS) $(LIBCOMMON_GPL)

# uuid unit test
test_uuid_SOURCES = test_uuid.cpp
test_uuid_LDADD = $(LIBTAP) $(LIBCOMMON_GPL)

# buffer view unit test
test_buffer_view_SOURCES = test_buffer_view.cpp
test_buffer_view_LDADD = $(LIBTAP) $(LIBCOMMON_GPL)

# payload unit test
test_payload_SOURCES = test_payload.cpp
test_payload_LDADD = $(LIBTAP) $(LIBSESSIOND_COMM) $(LIBCOMMON_GPL)

# unix socket test
test_unix_socket_SOURCES = test_unix_socket.cpp
test_unix_socket_LDADD = $(LIBTAP) $(LIBSESSIOND_COMM) $(LIBCOMMON_GPL)

# Kernel probe location api test
test_kernel_probe_SOURCES = test_kernel_probe.cpp
test_kernel_probe_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(LIBLTTNG_CTL) $(DL_LIBS)

# Kernel probe event rule event name test
test_kprobe_event_rule_event_name_SOURCES = test_kprobe_event_rule_event_name.cpp
test_kprobe_event_rule_event_name_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(LIBLTTNG_CTL) $(DL_LIBS)

# User space probe event rule event name test
test_uprobe_event_rule_event_name_SOURCES = test_uprobe_event_rule_event_name.cpp
test_uprobe_event_rule_event_name_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(LIBLTTNG_CTL) $(DL_LIBS)

# Event expression to bytecode test
test_event_expr_to_bytecode_SOURCES = test_event_expr_to_bytecode.cpp
test_event_expr_to_bytecode_LDADD = $(LIBTAP) $(LIBLTTNG_CTL) $(LIBCOMMON_GPL)

# Log level rule api
test_log_level_rule_SOURCES = test_log_level_rule.cpp
test_log_level_rule_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(LIBLTTNG_CTL) $(DL_LIBS)

# Action api
test_action_SOURCES = test_action.cpp
test_action_LDADD = $(LIBTAP) $(LIBCOMMON_GPL) $(LIBLTTNG_CTL) $(DL_LIBS)

# Scheduler
test_scheduler_SOURCES = test_scheduler.cpp
test_scheduler_LDADD = $(LIBTAP) $(LIBCOMMON_LGPL) $(LIBSCHEDULING)

# Poller
test_poller_SOURCES = test_poller.cpp
test_poller_LDADD = $(LIBTAP) $(LIBCOMMON_GPL)

# Copy test scripts to the builddir for OOT builds
if HAVE_CLANG2PY
all-local: liblttngctl/lttngctl/lttng.py
else
all-local:
endif
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			if [ x"$$(dirname $$script)" != x"." ]; then \
				mkdir -p $(builddir)/$$(dirname $$script); \
			fi; \
			cp -f $(srcdir)/$$script $(builddir)/$$script; \
		done; \
	fi

clean-local:
	@if [ x"$(srcdir)" != x"$(builddir)" ]; then \
		for script in $(EXTRA_DIST); do \
			rm -f $(builddir)/$$script; \
		done; \
	fi
