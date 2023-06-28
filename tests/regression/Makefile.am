# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS = tools

LOG_DRIVER_FLAGS = --merge --post-script $(top_srcdir)/tests/utils/warn_processes.sh
LOG_DRIVER = env PGREP='$(PGREP)' AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/tests/utils/tap-driver.sh

TESTS = tools/base-path/test_ust \
	tools/channel/test_channel \
	tools/filtering/test_invalid_filter \
	tools/filtering/test_unsupported_op \
	tools/filtering/test_valid_filter \
	tools/streaming/test_kernel \
	tools/streaming/test_ust \
	tools/health/test_thread_ok \
	tools/live/test_kernel \
	tools/live/test_lttng_kernel \
	tools/live/test_ust \
	tools/live/test_ust_tracefile_count \
	tools/live/test_lttng_ust \
	tools/tracefile-limits/test_tracefile_count \
	tools/tracefile-limits/test_tracefile_size \
	tools/exclusion/test_exclusion \
	tools/snapshots/test_kernel \
	tools/snapshots/test_ust_fast \
	tools/snapshots/test_ust_streaming \
	tools/snapshots/test_kernel_streaming \
	tools/save-load/test_save \
	tools/save-load/test_load \
	tools/save-load/test_autoload \
	tools/mi/test_mi \
	tools/wildcard/test_event_wildcard \
	tools/crash/test_crash \
	tools/regen-metadata/test_kernel \
	tools/regen-metadata/test_ust \
	tools/regen-statedump/test_kernel \
	tools/regen-statedump/test_ust \
	tools/notification/test_notification_ust_error \
	tools/notification/test_notification_ust_buffer_usage \
	tools/notification/test_notification_ust_capture \
	tools/notification/test_notification_ust_event_rule_condition_exclusion \
	tools/notification/test_notification_kernel_error \
	tools/notification/test_notification_kernel_buffer_usage \
	tools/notification/test_notification_kernel_capture \
	tools/notification/test_notification_kernel_instrumentation \
	tools/notification/test_notification_kernel_syscall \
	tools/notification/test_notification_notifier_discarded_count \
	tools/notification/test_notification_kernel_userspace_probe \
	tools/notification/test_notification_multi_app \
	tools/rotation/test_ust \
	tools/rotation/test_kernel \
	tools/rotation/test_ust_kernel \
	tools/rotation/test_save_load_mi \
	tools/rotation/test_schedule_api \
	tools/metadata/test_kernel \
	tools/working-directory/test_relayd_working_directory \
	tools/clear/test_ust \
	tools/clear/test_kernel \
	tools/tracker/test_event_tracker \
	tools/trigger/start-stop/test_start_stop \
	tools/trigger/test_add_trigger_cli \
	tools/trigger/test_list_triggers_cli \
	tools/trigger/test_remove_trigger_cli \
	tools/trigger/name/test_trigger_name_backwards_compat \
	tools/trigger/hidden/test_hidden_trigger \
	tools/context/test_ust.py \
	tools/client/test_session_commands.py \
	tools/client/test_event_rule_listing.py \
	tools/client/test_bug1373_events_differ_only_by_loglevel

# Only build kernel tests on Linux.
if IS_LINUX
SUBDIRS += kernel
endif # IS_LINUX

if HAVE_LIBLTTNG_UST_CTL
SUBDIRS += ust
TESTS += ust/before-after/test_before_after \
	ust/buffers-pid/test_buffers_pid \
	ust/multi-session/test_multi_session \
	ust/nprocesses/test_nprocesses \
	ust/overlap/test_overlap \
	ust/python-logging/test_python_logging \
	ust/getcpu-override/test_getcpu_override \
	ust/clock-override/test_clock_override \
	ust/test_event_basic \
	ust/test_event_tracef \
	ust/test_event_perf \
	ust/blocking/test_blocking \
	ust/multi-lib/test_multi_lib \
	ust/rotation-destroy-flush/test_rotation_destroy_flush \
	ust/ust-constructor/test_ust_constructor.py \
	tools/metadata/test_ust \
	tools/relayd-grouping/test_ust \
	tools/trigger/rate-policy/test_ust_rate_policy

if TEST_JAVA_JUL_AGENT
TESTS += ust/java-jul/test_java_jul
endif # TEST_JAVA_JUL_AGENT

if TEST_JAVA_LOG4J_AGENT
TESTS += ust/java-log4j/test_java_log4j
endif # TEST_JAVA_LOG4J_AGENT

if TEST_JAVA_LOG4J2_AGENT
TESTS += ust/java-log4j2/test_agent_log4j2_domain_log4j
endif # TEST_JAVA_LOG4J2_AGENT

if IS_LINUX
TESTS += \
	kernel/test_all_events \
	kernel/test_callstack \
	kernel/test_channel \
	kernel/test_clock_override \
	kernel/test_event_basic \
	kernel/test_kernel_function \
	kernel/test_lttng_logger \
	kernel/test_ns_contexts \
	kernel/test_ns_contexts_change \
	kernel/test_rotation_destroy_flush \
	kernel/test_select_poll_epoll \
	kernel/test_syscall \
	kernel/test_userspace_probe \
	ust/namespaces/test_ns_contexts \
	ust/namespaces/test_ns_contexts_change
endif # IS_LINUX
endif # HAVE_LIBLTTNG_UST_CTL

if PYTHON_BINDING
TESTS += ust/linking/test_linking \
	ust/daemon/test_daemon \
	ust/exit-fast/test_exit-fast \
	ust/fork/test_fork \
	ust/libc-wrapper/test_libc-wrapper \
	ust/baddr-statedump/test_baddr-statedump \
	ust/ust-dl/test_ust-dl \
	ust/type-declarations/test_type_declarations
endif
