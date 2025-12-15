# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2013-2025 EfficiOS Inc.
include $(top_srcdir)/aminclude_static.am

CLEANFILES =
EXTRA_DIST =
noinst_PROGRAMS =
noinst_LTLIBRARIES =
noinst_SCRIPTS =
SUBDIRS =

FORCE_SHARED_LIB_OPTIONS = -module -shared -avoid-version \
			   -rpath $(abs_builddir)
LIB_COMMON_GPL = $(top_builddir)/src/common/libcommon-gpl.la
LIB_LTTNG_CTL = $(top_builddir)/src/lib/lttng-ctl/liblttng-ctl.la
LIBTAP=$(top_builddir)/tests/utils/tap/libtap.la
UTILS_DIR = $(top_srcdir)/tests/utils

#	working-directory

if HAVE_LIBLTTNG_UST_CTL
# Disable some warnings flags to accomodate the tracepoint headers
WARN_FLAGS = \
	-Wno-redundant-decls

noinst_PROGRAMS += filtering/gen-ust-events
filtering_gen_ust_events_SOURCES = filtering/gen-ust-events.c filtering/tp.c filtering/tp.h
filtering_gen_ust_events_LDADD = $(UST_LIBS) $(DL_LIBS)
filtering_gen_ust_events_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/tests -I$(srcdir)/filtering
filtering_gen_ust_events_CFLAGS = $(AM_CFLAGS) $(WARN_FLAGS)
filtering_gen_ust_events_CXXFLAGS = $(AM_CXXFLAGS) $(WARN_FLAGS)

endif

include lttng-ctl/Makefile.am

if NO_SHARED
# Do not build the health test
EXTRA_DIST += \
	health/health_check.c \
	health/health_fail.c \
	health/health_stall.c
else
# In order to test the health check feature, the libhealth* libs
# must be built as .so to be able to LD_PRELOAD them.

# Health thread stall ld_preloaded test lib
health_libhealthstall_la_SOURCES = health/health_stall.c
health_libhealthstall_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)
health_libhealthstall_la_LIBADD  = $(DL_LIBS)
health_libhealthstall_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/health

# Health thread fail ld_preloaded test lib
health_libhealthtpfail_la_SOURCES = health/health_fail.c
health_libhealthtpfail_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)
health_libhealthtpfail_la_LIBADD  = $(DL_LIBS)
health_libhealthtpfail_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/health

noinst_PROGRAMS += health/health_check
noinst_LTLIBRARIES += health/libhealthstall.la health/libhealthtpfail.la

health_health_check_SOURCES = health/health_check.c
health_health_check_LDADD = $(LIB_LTTNG_CTL) \
		     $(LIB_COMMON_GPL) \
		     $(DL_LIBS)
health_health_check_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)
endif

noinst_PROGRAMS += live/live_test
live_live_test_SOURCES = live/live_test.cpp
live_live_test_LDADD = $(top_builddir)/tests/utils/tap/libtap.la \
	$(top_builddir)/src/bin/lttng-sessiond/liblttng-sessiond-common.la \
	$(DL_LIBS)
live_live_test_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)

noinst_PROGRAMS += notification/base_client \
	notification/notification \
	notification/rotation
if NO_SHARED
CLEANFILES += \
	notification/libpause_consumer.so \
	notification/libpause_consumer.so.debug \
	notification/libpause_sessiond.so \
	notification/libpause_sessiond.so.debug

EXTRA_DIST += \
	notification/base_client.c \
	notification/consumer_testpoints.cpp \
	notification/sessiond_testpoints.cpp \
	notification/notification.cpp \
	notification/rotation.c
else
# build notification libs
notification_libpause_consumer_la_SOURCES = notification/consumer_testpoints.cpp
notification_libpause_consumer_la_LIBADD = \
	$(top_builddir)/src/common/libsessiond-comm.la \
	$(LIB_COMMON_GPL) \
	$(LIB_LTTNG_CTL) \
	$(DL_LIBS)
notification_libpause_consumer_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)

notification_libpause_sessiond_la_SOURCES = notification/sessiond_testpoints.cpp
notification_libpause_sessiond_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)
notification_libpause_sessiond_la_LIBADD = \
	$(LIB_COMMON_GPL) \
	$(LIB_LTTNG_CTL) \
	$(DL_LIBS)
notification_libpause_sessiond_la_LDFLAGS = $(FORCE_SHARED_LIB_OPTIONS)
noinst_LTLIBRARIES += notification/libpause_sessiond.la notification/libpause_consumer.la

notification_base_client_SOURCES = notification/base_client.c
notification_base_client_LDADD = $(LIB_LTTNG_CTL)

notification_notification_SOURCES = notification/notification.cpp
# Tests the deprecated lttng_register_trigger() interface
notification_notification_CXXFLAGS = -Wno-deprecated-declarations $(AM_CXXFLAGS)
notification_notification_LDADD = $(LIB_LTTNG_CTL) $(LIBTAP) -lm
notification_notification_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)

notification_rotation_SOURCES = notification/rotation.c
notification_rotation_LDADD = $(LIB_LTTNG_CTL) $(LIBTAP) -lm
notification_rotation_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)
endif

noinst_PROGRAMS += rotation/schedule_api
rotation_schedule_api_SOURCES = rotation/schedule_api.c
rotation_schedule_api_LDADD = $(LIBTAP) $(LIB_LTTNG_CTL)
rotation_schedule_api_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)

noinst_PROGRAMS += \
	trigger/hidden/hidden_trigger \
	trigger/name/trigger_name \
	trigger/utils/notification-client \
	trigger/utils/register-some-triggers


trigger_hidden_hidden_trigger_SOURCES = trigger/hidden/hidden_trigger.cpp
trigger_hidden_hidden_trigger_LDADD = $(LIBTAP) $(LIB_LTTNG_CTL)
trigger_hidden_hidden_trigger_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)

trigger_name_trigger_name_CXXFLAGS = -Wno-deprecated-declarations $(AM_CXXFLAGS)
trigger_name_trigger_name_SOURCES = trigger/name/trigger_name.cpp
trigger_name_trigger_name_LDADD = $(LIBTAP) $(LIB_LTTNG_CTL)
trigger_name_trigger_name_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)

trigger_utils_notification_client_SOURCES = trigger/utils/notification-client.cpp
trigger_utils_notification_client_LDADD = $(LIB_LTTNG_CTL) $(LIB_COMMON_GPL) \
	$(top_builddir)/tests/utils/libtestutils.la
trigger_utils_notification_client_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)

trigger_utils_register_some_triggers_SOURCES = trigger/utils/register-some-triggers.cpp
trigger_utils_register_some_triggers_LDADD = $(LIB_LTTNG_CTL) \
	$(top_builddir)/src/common/libfilter.la \
	$(top_builddir)/src/common/libbytecode.la
trigger_utils_register_some_triggers_CPPFLAGS = $(AM_CPPFLAGS) -I$(UTILS_DIR)

noinst_SCRIPTS += \
	base-path/test_ust \
	channel/test_channel \
	channel/test_cli_legacy_channel_buffering_policies.py \
	channel/test_channel_allocation_policy_per_channel.py \
	channel/test_channel_allocation_policy_per_cpu.py \
	channel/test_channel_watchdog_timer.py \
	clear/test_disallow.py \
	clear/test_kernel \
	clear/test_live_hang.py \
	clear/test_ust.py \
	clear/test_ust_multi_user.py \
	client/test_session_commands.py \
	client/test_event_rule_listing.py \
	client/test_add_trigger.py \
	client/test_bug1373_events_differ_only_by_loglevel \
	client/test_warn_on_shm_too_small.py \
	context/test_ust.py \
	crash/test_crash \
	exclusion/test_exclusion \
	filtering/test_unsupported_op \
	filtering/test_invalid_filter \
	filtering/test_valid_filter \
	health/test_health.sh \
	health/test_thread_ok \
	health/test_thread_stall \
	health/test_tp_fail \
	live/test_early_inactive_app.py \
	live/test_high_latency.py \
	live/test_kernel \
	live/test_list_sessions.py \
	live/test_lttng_kernel \
	live/test_lttng_ust \
	live/test_lttng_ust_two_apps.py \
	live/test_miss_short_lived_app.py \
	live/test_per_application_leaks.py \
	live/test_ust \
	live/test_ust_tracefile_count \
	lttng-ctl/test_liblttng-ctl_abi.py \
	metadata/test_kernel \
	metadata/test_ust \
	metadata/utils.sh \
	mi/test_mi \
	notification/test_notification_kernel_buffer_usage \
	notification/test_notification_kernel_capture \
	notification/test_notification_kernel_error \
	notification/test_notification_kernel_instrumentation \
	notification/test_notification_kernel_syscall \
	notification/test_notification_kernel_userspace_probe \
	notification/test_notification_multi_app \
	notification/test_notification_notifier_discarded_count \
	notification/test_notification_ust_buffer_usage \
	notification/test_notification_ust_capture \
	notification/test_notification_ust_error \
	notification/test_notification_ust_event_rule_condition_exclusion \
	notification/test_rotation \
	notification/util_event_generator.py \
	regen-metadata/test_ust \
	regen-metadata/test_kernel \
	regen-statedump/test_ust \
	regen-statedump/test_kernel \
	relayd-grouping/test_ust \
	rotation/rotate_utils.sh \
	rotation/test_kernel \
	rotation/test_save_load_mi \
	rotation/test_schedule_api \
	rotation/test_ust \
	rotation/test_ust_kernel \
	save-load/test_autoload \
	save-load/test_load \
	save-load/test_save \
	snapshots/test_kernel \
	snapshots/test_kernel_streaming \
	snapshots/test_ust_fast \
	snapshots/test_ust_long \
	snapshots/test_ust_streaming \
	snapshots/ust_test \
	streaming/test_high_throughput_limits \
	streaming/test_kernel \
	streaming/test_ust \
	tracefile-limits/test_tracefile_count \
	tracefile-limits/test_tracefile_size \
	trace-format/test_sessiond_default_trace_format.py \
	trace-format/test_trace_format_kernel.py \
	trace-format/test_trace_format_ust.py \
	trace-format/trace_format_helpers.py \
	tracker/test_event_tracker \
	trigger/hidden/test_hidden_trigger \
	trigger/name/test_trigger_name_backwards_compat \
	trigger/rate-policy/test_ust_rate_policy \
	trigger/start-stop/test_start_stop \
	trigger/test_add_trigger_cli \
	trigger/test_list_triggers_cli \
	trigger/test_remove_trigger_cli \
	wildcard/test_event_wildcard \
	working-directory/test_relayd_working_directory

EXTRA_DIST += $(noinst_SCRIPTS) \
	base-path/load-stream-extra-path.lttng \
	save-load/configuration/load-42-live.lttng \
	save-load/configuration/load-42-snapshot.lttng \
	save-load/load-42-complex.lttng \
	save-load/load-42-ctf-1.8.lttng \
	save-load/load-42-no-trace-format.lttng \
	save-load/load-42-trackers.lttng \
	save-load/load-42.lttng \
	save-load/tracker_legacy_none.lttng \
	save-load/tracker_legacy_all.lttng \
	save-load/tracker_legacy_selective.lttng \
	trace-format/kernel-local-trace-pretty.expect \
	trace-format/ust-local-trace-pretty.expect

# Copy test scripts to the builddir for OOT builds
all-local:
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
