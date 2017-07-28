SUBDIRS = tools kernel ust

LOG_DRIVER_FLAGS='--merge'
LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
	$(top_srcdir)/config/tap-driver.sh

TESTS = tools/filtering/test_invalid_filter \
	tools/filtering/test_unsupported_op \
	tools/filtering/test_valid_filter \
	tools/streaming/test_ust \
	tools/health/test_thread_ok \
	tools/live/test_ust \
	tools/live/test_ust_tracefile_count \
	tools/live/test_lttng_ust \
	tools/tracefile-limits/test_tracefile_count \
	tools/tracefile-limits/test_tracefile_size \
	tools/exclusion/test_exclusion \
	tools/snapshots/test_ust_fast \
	tools/snapshots/test_ust_streaming \
	tools/save-load/test_save \
	tools/save-load/test_load \
	tools/mi/test_mi \
	tools/wildcard/test_event_wildcard \
	tools/crash/test_crash \
	tools/regen-metadata/test_ust \
	tools/regen-statedump/test_ust \
	tools/notification/test_notification_ust \
	tools/notification/test_notification_kernel \
	tools/notification/test_notification_multi_app

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
	ust/blocking/test_blocking
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
