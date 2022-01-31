# SPDX-License-Identifier: GPL-2.0-only

SUBDIRS = tools kernel ust

LOG_DRIVER_FLAGS = --merge --post-script $(top_srcdir)/tests/utils/warn_processes.sh
LOG_DRIVER = env PGREP='$(PGREP)' AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/tests/utils/tap-driver.sh

TESTS = tools/base-path/test_ust \
	tools/clear/test_kernel \
	tools/clear/test_ust \
	tools/crash/test_crash \
	tools/exclusion/test_exclusion \
	tools/filtering/test_invalid_filter \
	tools/filtering/test_unsupported_op \
	tools/filtering/test_valid_filter \
	tools/health/test_thread_ok \
	tools/live/test_kernel \
	tools/live/test_lttng_kernel \
	tools/live/test_lttng_ust \
	tools/live/test_ust \
	tools/live/test_ust_tracefile_count \
	tools/metadata/test_kernel \
	tools/mi/test_mi \
	tools/notification/test_notification_kernel \
	tools/notification/test_notification_multi_app \
	tools/notification/test_notification_ust \
	tools/regen-metadata/test_kernel \
	tools/regen-metadata/test_ust \
	tools/regen-statedump/test_kernel \
	tools/regen-statedump/test_ust \
	tools/rotation/test_kernel \
	tools/rotation/test_save_load_mi \
	tools/rotation/test_schedule_api \
	tools/rotation/test_ust \
	tools/save-load/test_autoload \
	tools/save-load/test_load \
	tools/save-load/test_save \
	tools/snapshots/test_kernel \
	tools/snapshots/test_kernel_streaming \
	tools/snapshots/test_ust_fast \
	tools/snapshots/test_ust_streaming \
	tools/streaming/test_kernel \
	tools/streaming/test_ust \
	tools/tracefile-limits/test_tracefile_count \
	tools/tracefile-limits/test_tracefile_size \
	tools/tracker/test_event_tracker \
	tools/wildcard/test_event_wildcard \
	tools/working-directory/test_relayd_working_directory

if HAVE_LIBLTTNG_UST_CTL
SUBDIRS += ust
TESTS += ust/before-after/test_before_after \
	ust/buffers-pid/test_buffers_pid \
	ust/multi-session/test_multi_session \
	ust/nprocesses/test_nprocesses \
	ust/overlap/test_overlap \
	ust/java-jul/test_java_jul \
	ust/java-log4j/test_java_log4j \
	ust/python-logging/test_python_logging \
	ust/getcpu-override/test_getcpu_override \
	ust/clock-override/test_clock_override \
	ust/test_event_basic \
	ust/test_event_tracef \
	ust/test_event_perf \
	ust/blocking/test_blocking \
	ust/multi-lib/test_multi_lib \
	ust/rotation-destroy-flush/test_rotation_destroy_flush \
	ust/namespaces/test_ns_contexts \
	ust/namespaces/test_ns_contexts_change \
	tools/metadata/test_ust \
	tools/relayd-grouping/test_ust \
	ust/test_event_perf
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

TESTS += kernel/test_all_events \
	kernel/test_callstack \
	kernel/test_channel \
	kernel/test_clock_override \
	kernel/test_event_basic \
	kernel/test_lttng_logger \
	kernel/test_ns_contexts \
	kernel/test_ns_contexts_change \
	kernel/test_rotation_destroy_flush \
	kernel/test_select_poll_epoll \
	kernel/test_syscall \
	kernel/test_userspace_probe

