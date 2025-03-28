/*
 * SPDX-FileCopyrightText: 2014 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "lttng/tracker.h"
#define _LGPL_SOURCE
#include "mi-lttng.hpp"

#include <common/config/session-config.hpp>
#include <common/defaults.hpp>
#include <common/tracker.hpp>

#include <lttng/channel.h>
#include <lttng/snapshot-internal.hpp>

#define MI_SCHEMA_MAJOR_VERSION 4
#define MI_SCHEMA_MINOR_VERSION 1

/* Machine interface namespace URI */
const char *const mi_lttng_xmlns = "xmlns";
const char *const mi_lttng_xmlns_xsi = "xmlns:xsi";
const char *const mi_lttng_w3_schema_uri = "http://www.w3.org/2001/XMLSchema-instance";
const char *const mi_lttng_schema_location = "xsi:schemaLocation";
const char *const mi_lttng_schema_location_uri = DEFAULT_LTTNG_MI_NAMESPACE
	" "
	"https://lttng.org/xml/schemas/lttng-mi/" XSTR(MI_SCHEMA_MAJOR_VERSION) "/lttng-mi-" XSTR(
		MI_SCHEMA_MAJOR_VERSION) "." XSTR(MI_SCHEMA_MINOR_VERSION) ".xsd";
const char *const mi_lttng_schema_version = "schemaVersion";
const char *const mi_lttng_schema_version_value =
	XSTR(MI_SCHEMA_MAJOR_VERSION) "." XSTR(MI_SCHEMA_MINOR_VERSION);

/* Strings related to command */
const char *const mi_lttng_element_command = "command";
const char *const mi_lttng_element_command_action = "snapshot_action";
const char *const mi_lttng_element_command_add_context = "add-context";
const char *const mi_lttng_element_command_add_trigger = "add-trigger";
const char *const mi_lttng_element_command_create = "create";
const char *const mi_lttng_element_command_destroy = "destroy";
const char *const mi_lttng_element_command_disable_channel = "disable-channel";
const char *const mi_lttng_element_command_disable_event = "disable-event";
const char *const mi_lttng_element_command_enable_channels = "enable-channel";
const char *const mi_lttng_element_command_enable_event = "enable-event";
const char *const mi_lttng_element_command_list = "list";
const char *const mi_lttng_element_command_list_trigger = "list-trigger";
const char *const mi_lttng_element_command_load = "load";
const char *const mi_lttng_element_command_metadata = "metadata";
const char *const mi_lttng_element_command_metadata_action = "metadata_action";
const char *const mi_lttng_element_command_regenerate = "regenerate";
const char *const mi_lttng_element_command_regenerate_action = "regenerate_action";
const char *const mi_lttng_element_command_name = "name";
const char *const mi_lttng_element_command_output = "output";
const char *const mi_lttng_element_command_remove_trigger = "remove-trigger";
const char *const mi_lttng_element_command_save = "save";
const char *const mi_lttng_element_command_set_session = "set-session";
const char *const mi_lttng_element_command_snapshot = "snapshot";
const char *const mi_lttng_element_command_snapshot_add = "add_snapshot";
const char *const mi_lttng_element_command_snapshot_del = "del_snapshot";
const char *const mi_lttng_element_command_snapshot_list = "list_snapshot";
const char *const mi_lttng_element_command_snapshot_record = "record_snapshot";
const char *const mi_lttng_element_command_start = "start";
const char *const mi_lttng_element_command_stop = "stop";
const char *const mi_lttng_element_command_success = "success";
const char *const mi_lttng_element_command_track = "track";
const char *const mi_lttng_element_command_untrack = "untrack";
const char *const mi_lttng_element_command_version = "version";
const char *const mi_lttng_element_command_rotate = "rotate";
const char *const mi_lttng_element_command_enable_rotation = "enable-rotation";
const char *const mi_lttng_element_command_disable_rotation = "disable-rotation";
const char *const mi_lttng_element_command_clear = "clear";

/* Strings related to version command */
const char *const mi_lttng_element_version = "version";
const char *const mi_lttng_element_version_commit = "commit";
const char *const mi_lttng_element_version_description = "description";
const char *const mi_lttng_element_version_license = "license";
const char *const mi_lttng_element_version_major = "major";
const char *const mi_lttng_element_version_minor = "minor";
const char *const mi_lttng_element_version_patch_level = "patchLevel";
const char *const mi_lttng_element_version_str = "string";
const char *const mi_lttng_element_version_web = "url";

/* String related to a lttng_event_field */
const char *const mi_lttng_element_event_field = "event_field";
const char *const mi_lttng_element_event_fields = "event_fields";

/* String related to lttng_event_perf_counter_ctx */
const char *const mi_lttng_element_perf_counter_context = "perf";

/* Strings related to pid */
const char *const mi_lttng_element_pid_id = "id";

/* Strings related to save command */
const char *const mi_lttng_element_save = "save";

/* Strings related to load command */
const char *const mi_lttng_element_load = "load";
const char *const mi_lttng_element_load_overrides = "overrides";
const char *const mi_lttng_element_load_override_url = "url";

/* General elements of mi_lttng */
const char *const mi_lttng_element_empty = "";
const char *const mi_lttng_element_id = "id";
const char *const mi_lttng_element_nowrite = "nowrite";
const char *const mi_lttng_element_success = "success";
const char *const mi_lttng_element_type_enum = "ENUM";
const char *const mi_lttng_element_type_float = "FLOAT";
const char *const mi_lttng_element_type_integer = "INTEGER";
const char *const mi_lttng_element_type_other = "OTHER";
const char *const mi_lttng_element_type_string = "STRING";

/* String related to loglevel */
const char *const mi_lttng_loglevel_str_alert = "TRACE_ALERT";
const char *const mi_lttng_loglevel_str_crit = "TRACE_CRIT";
const char *const mi_lttng_loglevel_str_debug = "TRACE_DEBUG";
const char *const mi_lttng_loglevel_str_debug_function = "TRACE_DEBUG_FUNCTION";
const char *const mi_lttng_loglevel_str_debug_line = "TRACE_DEBUG_LINE";
const char *const mi_lttng_loglevel_str_debug_module = "TRACE_DEBUG_MODULE";
const char *const mi_lttng_loglevel_str_debug_process = "TRACE_DEBUG_PROCESS";
const char *const mi_lttng_loglevel_str_debug_program = "TRACE_DEBUG_PROGRAM";
const char *const mi_lttng_loglevel_str_debug_system = "TRACE_DEBUG_SYSTEM";
const char *const mi_lttng_loglevel_str_debug_unit = "TRACE_DEBUG_UNIT";
const char *const mi_lttng_loglevel_str_emerg = "TRACE_EMERG";
const char *const mi_lttng_loglevel_str_err = "TRACE_ERR";
const char *const mi_lttng_loglevel_str_info = "TRACE_INFO";
const char *const mi_lttng_loglevel_str_notice = "TRACE_NOTICE";
const char *const mi_lttng_loglevel_str_unknown = "UNKNOWN";
const char *const mi_lttng_loglevel_str_warning = "TRACE_WARNING";

/* String related to loglevel JUL */
const char *const mi_lttng_loglevel_str_jul_all = "JUL_ALL";
const char *const mi_lttng_loglevel_str_jul_config = "JUL_CONFIG";
const char *const mi_lttng_loglevel_str_jul_fine = "JUL_FINE";
const char *const mi_lttng_loglevel_str_jul_finer = "JUL_FINER";
const char *const mi_lttng_loglevel_str_jul_finest = "JUL_FINEST";
const char *const mi_lttng_loglevel_str_jul_info = "JUL_INFO";
const char *const mi_lttng_loglevel_str_jul_off = "JUL_OFF";
const char *const mi_lttng_loglevel_str_jul_severe = "JUL_SEVERE";
const char *const mi_lttng_loglevel_str_jul_warning = "JUL_WARNING";

/* String related to loglevel LOG4J */
const char *const mi_lttng_loglevel_str_log4j_off = "LOG4J_OFF";
const char *const mi_lttng_loglevel_str_log4j_fatal = "LOG4J_FATAL";
const char *const mi_lttng_loglevel_str_log4j_error = "LOG4J_ERROR";
const char *const mi_lttng_loglevel_str_log4j_warn = "LOG4J_WARN";
const char *const mi_lttng_loglevel_str_log4j_info = "LOG4J_INFO";
const char *const mi_lttng_loglevel_str_log4j_debug = "LOG4J_DEBUG";
const char *const mi_lttng_loglevel_str_log4j_trace = "LOG4J_TRACE";
const char *const mi_lttng_loglevel_str_log4j_all = "LOG4J_ALL";

/* String related to loglevel LOG4J2 */
const char *const mi_lttng_loglevel_str_log4j2_off = "LOG4J2_OFF";
const char *const mi_lttng_loglevel_str_log4j2_fatal = "LOG4J2_FATAL";
const char *const mi_lttng_loglevel_str_log4j2_error = "LOG4J2_ERROR";
const char *const mi_lttng_loglevel_str_log4j2_warn = "LOG4J2_WARN";
const char *const mi_lttng_loglevel_str_log4j2_info = "LOG4J2_INFO";
const char *const mi_lttng_loglevel_str_log4j2_debug = "LOG4J2_DEBUG";
const char *const mi_lttng_loglevel_str_log4j2_trace = "LOG4J2_TRACE";
const char *const mi_lttng_loglevel_str_log4j2_all = "LOG4J2_ALL";

/* String related to loglevel Python */
const char *const mi_lttng_loglevel_str_python_critical = "PYTHON_CRITICAL";
const char *const mi_lttng_loglevel_str_python_error = "PYTHON_ERROR";
const char *const mi_lttng_loglevel_str_python_warning = "PYTHON_WARNING";
const char *const mi_lttng_loglevel_str_python_info = "PYTHON_INFO";
const char *const mi_lttng_loglevel_str_python_debug = "PYTHON_DEBUG";
const char *const mi_lttng_loglevel_str_python_notset = "PYTHON_NOTSET";

/* String related to loglevel type */
const char *const mi_lttng_loglevel_type_all = "ALL";
const char *const mi_lttng_loglevel_type_range = "RANGE";
const char *const mi_lttng_loglevel_type_single = "SINGLE";
const char *const mi_lttng_loglevel_type_unknown = "UNKNOWN";

/* String related to a lttng_snapshot_output */
const char *const mi_lttng_element_snapshot_ctrl_url = "ctrl_url";
const char *const mi_lttng_element_snapshot_data_url = "data_url";
const char *const mi_lttng_element_snapshot_max_size = "max_size";
const char *const mi_lttng_element_snapshot_n_ptr = "n_ptr";
const char *const mi_lttng_element_snapshot_session_name = "session_name";
const char *const mi_lttng_element_snapshots = "snapshots";

/* String related to track/untrack command */
const char *const mi_lttng_element_track_untrack_all_wildcard = "*";

const char *const mi_lttng_element_session_name = "session_name";

/* String related to rotate command */
const char *const mi_lttng_element_rotation = "rotation";
const char *const mi_lttng_element_rotate_status = "status";
const char *const mi_lttng_element_rotation_schedule = "rotation_schedule";
const char *const mi_lttng_element_rotation_schedules = "rotation_schedules";
const char *const mi_lttng_element_rotation_schedule_result = "rotation_schedule_result";
const char *const mi_lttng_element_rotation_schedule_results = "rotation_schedule_results";
const char *const mi_lttng_element_rotation_schedule_periodic = "periodic";
const char *const mi_lttng_element_rotation_schedule_periodic_time_us = "time_us";
const char *const mi_lttng_element_rotation_schedule_size_threshold = "size_threshold";
const char *const mi_lttng_element_rotation_schedule_size_threshold_bytes = "bytes";
const char *const mi_lttng_element_rotation_state = "state";
const char *const mi_lttng_element_rotation_location = "location";
const char *const mi_lttng_element_rotation_location_local = "local";
const char *const mi_lttng_element_rotation_location_local_absolute_path = "absolute_path";
const char *const mi_lttng_element_rotation_location_relay = "relay";
const char *const mi_lttng_element_rotation_location_relay_host = "host";
const char *const mi_lttng_element_rotation_location_relay_control_port = "control_port";
const char *const mi_lttng_element_rotation_location_relay_data_port = "data_port";
const char *const mi_lttng_element_rotation_location_relay_protocol = "protocol";
const char *const mi_lttng_element_rotation_location_relay_relative_path = "relative_path";

/* String related to enum lttng_rotation_state */
const char *const mi_lttng_rotation_state_str_ongoing = "ONGOING";
const char *const mi_lttng_rotation_state_str_completed = "COMPLETED";
const char *const mi_lttng_rotation_state_str_expired = "EXPIRED";
const char *const mi_lttng_rotation_state_str_error = "ERROR";

/* String related to enum lttng_trace_archive_location_relay_protocol_type */
const char *const mi_lttng_rotation_location_relay_protocol_str_tcp = "TCP";

/* String related to rate_policy elements */
const char *const mi_lttng_element_rate_policy = "rate_policy";
const char *const mi_lttng_element_rate_policy_every_n = "rate_policy_every_n";
const char *const mi_lttng_element_rate_policy_once_after_n = "rate_policy_once_after_n";

const char *const mi_lttng_element_rate_policy_every_n_interval = "interval";
const char *const mi_lttng_element_rate_policy_once_after_n_threshold = "threshold";

/* String related to action elements */
const char *const mi_lttng_element_action = "action";
const char *const mi_lttng_element_action_list = "action_list";
const char *const mi_lttng_element_action_notify = "action_notify";
const char *const mi_lttng_element_action_start_session = "action_start_session";
const char *const mi_lttng_element_action_stop_session = "action_stop_session";
const char *const mi_lttng_element_action_rotate_session = "action_rotate_session";
const char *const mi_lttng_element_action_snapshot_session = "action_snapshot_session";
const char *const mi_lttng_element_action_snapshot_session_output = "output";

/* String related to condition */
const char *const mi_lttng_element_condition = "condition";
const char *const mi_lttng_element_condition_buffer_usage_high = "condition_buffer_usage_high";
const char *const mi_lttng_element_condition_buffer_usage_low = "condition_buffer_usage_low";
const char *const mi_lttng_element_condition_event_rule_matches = "condition_event_rule_matches";
const char *const mi_lttng_element_condition_session_consumed_size =
	"condition_session_consumed_size";
const char *const mi_lttng_element_condition_session_rotation = "condition_session_rotation";
const char *const mi_lttng_element_condition_session_rotation_completed =
	"condition_session_rotation_completed";
const char *const mi_lttng_element_condition_session_rotation_ongoing =
	"condition_session_rotation_ongoing";

const char *const mi_lttng_element_condition_channel_name = "channel_name";
const char *const mi_lttng_element_condition_threshold_bytes = "threshold_bytes";
const char *const mi_lttng_element_condition_threshold_ratio = "threshold_ratio";

/* String related to capture descriptor */
const char *const mi_lttng_element_capture_descriptor = "capture_descriptor";
const char *const mi_lttng_element_capture_descriptors = "capture_descriptors";

/* String related to event expression */
const char *const mi_lttng_element_event_expr = "event_expr";
const char *const mi_lttng_element_event_expr_payload_field = "event_expr_payload_field";
const char *const mi_lttng_element_event_expr_channel_context_field =
	"event_expr_channel_context_field";
const char *const mi_lttng_element_event_expr_app_specific_context_field =
	"event_expr_app_specific_context_field";
const char *const mi_lttng_element_event_expr_array_field_element =
	"event_expr_array_field_element";
const char *const mi_lttng_element_event_expr_provider_name = "provider_name";
const char *const mi_lttng_element_event_expr_type_name = "type_name";
const char *const mi_lttng_element_event_expr_index = "index";

/* String related to event rule */
const char *const mi_lttng_element_event_rule = "event_rule";

/* String related to lttng_event_rule_type */
const char *const mi_lttng_element_event_rule_event_name = "event_name";
const char *const mi_lttng_element_event_rule_name_pattern = "name_pattern";
const char *const mi_lttng_element_event_rule_filter_expression = "filter_expression";

const char *const mi_lttng_element_event_rule_jul_logging = "event_rule_jul_logging";
const char *const mi_lttng_element_event_rule_kernel_kprobe = "event_rule_kernel_kprobe";
const char *const mi_lttng_element_event_rule_kernel_syscall = "event_rule_kernel_syscall";
const char *const mi_lttng_element_event_rule_kernel_tracepoint = "event_rule_kernel_tracepoint";
const char *const mi_lttng_element_event_rule_kernel_uprobe = "event_rule_kernel_uprobe";
const char *const mi_lttng_element_event_rule_log4j_logging = "event_rule_log4j_logging";
const char *const mi_lttng_element_event_rule_log4j2_logging = "event_rule_log4j2_logging";
const char *const mi_lttng_element_event_rule_python_logging = "event_rule_python_logging";
const char *const mi_lttng_element_event_rule_user_tracepoint = "event_rule_user_tracepoint";

/* String related to lttng_event_rule_kernel_syscall. */
const char *const mi_lttng_element_event_rule_kernel_syscall_emission_site = "emission_site";

/* String related to enum lttng_event_rule_kernel_syscall_emission_site. */
const char *const mi_lttng_event_rule_kernel_syscall_emission_site_entry_exit = "entry+exit";
const char *const mi_lttng_event_rule_kernel_syscall_emission_site_entry = "entry";
const char *const mi_lttng_event_rule_kernel_syscall_emission_site_exit = "exit";

/* String related to lttng_event_rule_user_tracepoint */
const char *const mi_lttng_element_event_rule_user_tracepoint_name_pattern_exclusions =
	"name_pattern_exclusions";
const char *const mi_lttng_element_event_rule_user_tracepoint_name_pattern_exclusion =
	"name_pattern_exclusion";

/* String related to log level rule. */
const char *const mi_lttng_element_log_level_rule = "log_level_rule";
const char *const mi_lttng_element_log_level_rule_exactly = "log_level_rule_exactly";
const char *const mi_lttng_element_log_level_rule_at_least_as_severe_as =
	"log_level_rule_at_least_as_severe_as";
const char *const mi_lttng_element_log_level_rule_level = "level";

/* String related to kernel probe location. */
const char *const mi_lttng_element_kernel_probe_location = "kernel_probe_location";
const char *const mi_lttng_element_kernel_probe_location_symbol_offset =
	"kernel_probe_location_symbol_offset";
const char *const mi_lttng_element_kernel_probe_location_symbol_offset_name = "name";
const char *const mi_lttng_element_kernel_probe_location_symbol_offset_offset = "offset";

const char *const mi_lttng_element_kernel_probe_location_address = "kernel_probe_location_address";
const char *const mi_lttng_element_kernel_probe_location_address_address = "address";

/* String related to userspace probe location. */
const char *const mi_lttng_element_userspace_probe_location = "userspace_probe_location";
const char *const mi_lttng_element_userspace_probe_location_binary_path = "binary_path";
const char *const mi_lttng_element_userspace_probe_location_function =
	"userspace_probe_location_function";
const char *const mi_lttng_element_userspace_probe_location_function_name = "name";
const char *const mi_lttng_element_userspace_probe_location_lookup_method =
	"userspace_probe_location_lookup_method";
const char *const mi_lttng_element_userspace_probe_location_lookup_method_function_default =
	"userspace_probe_location_lookup_method_function_default";
const char *const mi_lttng_element_userspace_probe_location_lookup_method_function_elf =
	"userspace_probe_location_lookup_method_function_elf";
const char *const mi_lttng_element_userspace_probe_location_lookup_method_tracepoint_sdt =
	"userspace_probe_location_lookup_method_tracepoint_sdt";
const char *const mi_lttng_element_userspace_probe_location_tracepoint =
	"userspace_probe_location_tracepoint";
const char *const mi_lttng_element_userspace_probe_location_tracepoint_probe_name = "probe_name";
const char *const mi_lttng_element_userspace_probe_location_tracepoint_provider_name =
	"provider_name";

/* String related to enum
 * lttng_userspace_probe_location_function_instrumentation_type */
const char *const mi_lttng_element_userspace_probe_location_function_instrumentation_type =
	"instrumentation_type";
const char *const mi_lttng_userspace_probe_location_function_instrumentation_type_entry = "ENTRY";

/* String related to trigger */
const char *const mi_lttng_element_triggers = "triggers";
const char *const mi_lttng_element_trigger = "trigger";
const char *const mi_lttng_element_trigger_owner_uid = "owner_uid";

/* String related to error_query. */
const char *const mi_lttng_element_error_query_result = "error_query_result";
const char *const mi_lttng_element_error_query_result_counter = "error_query_result_counter";
const char *const mi_lttng_element_error_query_result_counter_value = "value";
const char *const mi_lttng_element_error_query_result_description = "description";
const char *const mi_lttng_element_error_query_result_name = "name";
const char *const mi_lttng_element_error_query_result_type = "type";
const char *const mi_lttng_element_error_query_results = "error_query_results";

/* String related to add-context command */
const char *const mi_lttng_element_context_symbol = "symbol";

/* This is a merge of jul loglevel and regular loglevel
 * Those should never overlap by definition
 * (see struct lttng_event loglevel)
 */
const char *mi_lttng_loglevel_string(int value, enum lttng_domain_type domain)
{
	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	case LTTNG_DOMAIN_UST:
		switch (value) {
		case -1:
			return mi_lttng_element_empty;
		case LTTNG_LOGLEVEL_EMERG:
			return mi_lttng_loglevel_str_emerg;
		case LTTNG_LOGLEVEL_ALERT:
			return mi_lttng_loglevel_str_alert;
		case LTTNG_LOGLEVEL_CRIT:
			return mi_lttng_loglevel_str_crit;
		case LTTNG_LOGLEVEL_ERR:
			return mi_lttng_loglevel_str_err;
		case LTTNG_LOGLEVEL_WARNING:
			return mi_lttng_loglevel_str_warning;
		case LTTNG_LOGLEVEL_NOTICE:
			return mi_lttng_loglevel_str_notice;
		case LTTNG_LOGLEVEL_INFO:
			return mi_lttng_loglevel_str_info;
		case LTTNG_LOGLEVEL_DEBUG_SYSTEM:
			return mi_lttng_loglevel_str_debug_system;
		case LTTNG_LOGLEVEL_DEBUG_PROGRAM:
			return mi_lttng_loglevel_str_debug_program;
		case LTTNG_LOGLEVEL_DEBUG_PROCESS:
			return mi_lttng_loglevel_str_debug_process;
		case LTTNG_LOGLEVEL_DEBUG_MODULE:
			return mi_lttng_loglevel_str_debug_module;
		case LTTNG_LOGLEVEL_DEBUG_UNIT:
			return mi_lttng_loglevel_str_debug_unit;
		case LTTNG_LOGLEVEL_DEBUG_FUNCTION:
			return mi_lttng_loglevel_str_debug_function;
		case LTTNG_LOGLEVEL_DEBUG_LINE:
			return mi_lttng_loglevel_str_debug_line;
		case LTTNG_LOGLEVEL_DEBUG:
			return mi_lttng_loglevel_str_debug;
		default:
			return mi_lttng_loglevel_str_unknown;
		}
		break;
	case LTTNG_DOMAIN_LOG4J:
		switch (value) {
		case -1:
			return mi_lttng_element_empty;
		case LTTNG_LOGLEVEL_LOG4J_OFF:
			return mi_lttng_loglevel_str_log4j_off;
		case LTTNG_LOGLEVEL_LOG4J_FATAL:
			return mi_lttng_loglevel_str_log4j_fatal;
		case LTTNG_LOGLEVEL_LOG4J_ERROR:
			return mi_lttng_loglevel_str_log4j_error;
		case LTTNG_LOGLEVEL_LOG4J_WARN:
			return mi_lttng_loglevel_str_log4j_warn;
		case LTTNG_LOGLEVEL_LOG4J_INFO:
			return mi_lttng_loglevel_str_log4j_info;
		case LTTNG_LOGLEVEL_LOG4J_DEBUG:
			return mi_lttng_loglevel_str_log4j_debug;
		case LTTNG_LOGLEVEL_LOG4J_TRACE:
			return mi_lttng_loglevel_str_log4j_trace;
		case LTTNG_LOGLEVEL_LOG4J_ALL:
			return mi_lttng_loglevel_str_log4j_all;
		default:
			return mi_lttng_loglevel_str_unknown;
		}
		break;
	case LTTNG_DOMAIN_LOG4J2:
		switch (value) {
		case -1:
			return mi_lttng_element_empty;
		case LTTNG_LOGLEVEL_LOG4J2_OFF:
			return mi_lttng_loglevel_str_log4j2_off;
		case LTTNG_LOGLEVEL_LOG4J2_FATAL:
			return mi_lttng_loglevel_str_log4j2_fatal;
		case LTTNG_LOGLEVEL_LOG4J2_ERROR:
			return mi_lttng_loglevel_str_log4j2_error;
		case LTTNG_LOGLEVEL_LOG4J2_WARN:
			return mi_lttng_loglevel_str_log4j2_warn;
		case LTTNG_LOGLEVEL_LOG4J2_INFO:
			return mi_lttng_loglevel_str_log4j2_info;
		case LTTNG_LOGLEVEL_LOG4J2_DEBUG:
			return mi_lttng_loglevel_str_log4j2_debug;
		case LTTNG_LOGLEVEL_LOG4J2_TRACE:
			return mi_lttng_loglevel_str_log4j2_trace;
		case LTTNG_LOGLEVEL_LOG4J2_ALL:
			return mi_lttng_loglevel_str_log4j2_all;
		default:
			return mi_lttng_loglevel_str_unknown;
		}
		break;
	case LTTNG_DOMAIN_JUL:
		switch (value) {
		case -1:
			return mi_lttng_element_empty;
		case LTTNG_LOGLEVEL_JUL_OFF:
			return mi_lttng_loglevel_str_jul_off;
		case LTTNG_LOGLEVEL_JUL_SEVERE:
			return mi_lttng_loglevel_str_jul_severe;
		case LTTNG_LOGLEVEL_JUL_WARNING:
			return mi_lttng_loglevel_str_jul_warning;
		case LTTNG_LOGLEVEL_JUL_INFO:
			return mi_lttng_loglevel_str_jul_info;
		case LTTNG_LOGLEVEL_JUL_CONFIG:
			return mi_lttng_loglevel_str_jul_config;
		case LTTNG_LOGLEVEL_JUL_FINE:
			return mi_lttng_loglevel_str_jul_fine;
		case LTTNG_LOGLEVEL_JUL_FINER:
			return mi_lttng_loglevel_str_jul_finer;
		case LTTNG_LOGLEVEL_JUL_FINEST:
			return mi_lttng_loglevel_str_jul_finest;
		case LTTNG_LOGLEVEL_JUL_ALL:
			return mi_lttng_loglevel_str_jul_all;
		default:
			return mi_lttng_loglevel_str_unknown;
		}
		break;
	case LTTNG_DOMAIN_PYTHON:
		switch (value) {
		case LTTNG_LOGLEVEL_PYTHON_CRITICAL:
			return mi_lttng_loglevel_str_python_critical;
		case LTTNG_LOGLEVEL_PYTHON_ERROR:
			return mi_lttng_loglevel_str_python_error;
		case LTTNG_LOGLEVEL_PYTHON_WARNING:
			return mi_lttng_loglevel_str_python_warning;
		case LTTNG_LOGLEVEL_PYTHON_INFO:
			return mi_lttng_loglevel_str_python_info;
		case LTTNG_LOGLEVEL_PYTHON_DEBUG:
			return mi_lttng_loglevel_str_python_debug;
		case LTTNG_LOGLEVEL_PYTHON_NOTSET:
			return mi_lttng_loglevel_str_python_notset;
		default:
			return mi_lttng_loglevel_str_unknown;
		}
		break;
	default:
		return mi_lttng_loglevel_str_unknown;
	}
}

const char *mi_lttng_logleveltype_string(enum lttng_loglevel_type value)
{
	switch (value) {
	case LTTNG_EVENT_LOGLEVEL_ALL:
		return mi_lttng_loglevel_type_all;
	case LTTNG_EVENT_LOGLEVEL_RANGE:
		return mi_lttng_loglevel_type_range;
	case LTTNG_EVENT_LOGLEVEL_SINGLE:
		return mi_lttng_loglevel_type_single;
	default:
		return mi_lttng_loglevel_type_unknown;
	}
}

static const char *mi_lttng_eventtype_string(enum lttng_event_type value)
{
	switch (value) {
	case LTTNG_EVENT_ALL:
		return config_event_type_all;
	case LTTNG_EVENT_TRACEPOINT:
		return config_event_type_tracepoint;
	case LTTNG_EVENT_PROBE:
		return config_event_type_probe;
	case LTTNG_EVENT_USERSPACE_PROBE:
		return config_event_type_userspace_probe;
	case LTTNG_EVENT_FUNCTION:
		return config_event_type_function;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		return config_event_type_function_entry;
	case LTTNG_EVENT_SYSCALL:
		return config_event_type_syscall;
	case LTTNG_EVENT_NOOP:
		return config_event_type_noop;
	default:
		return mi_lttng_element_empty;
	}
}

static const char *mi_lttng_event_contexttype_string(enum lttng_event_context_type val)
{
	switch (val) {
	case LTTNG_EVENT_CONTEXT_PID:
		return config_event_context_pid;
	case LTTNG_EVENT_CONTEXT_PROCNAME:
		return config_event_context_procname;
	case LTTNG_EVENT_CONTEXT_PRIO:
		return config_event_context_prio;
	case LTTNG_EVENT_CONTEXT_NICE:
		return config_event_context_nice;
	case LTTNG_EVENT_CONTEXT_VPID:
		return config_event_context_vpid;
	case LTTNG_EVENT_CONTEXT_TID:
		return config_event_context_tid;
	case LTTNG_EVENT_CONTEXT_VTID:
		return config_event_context_vtid;
	case LTTNG_EVENT_CONTEXT_PPID:
		return config_event_context_ppid;
	case LTTNG_EVENT_CONTEXT_VPPID:
		return config_event_context_vppid;
	case LTTNG_EVENT_CONTEXT_PTHREAD_ID:
		return config_event_context_pthread_id;
	case LTTNG_EVENT_CONTEXT_HOSTNAME:
		return config_event_context_hostname;
	case LTTNG_EVENT_CONTEXT_IP:
		return config_event_context_ip;
	case LTTNG_EVENT_CONTEXT_INTERRUPTIBLE:
		return config_event_context_interruptible;
	case LTTNG_EVENT_CONTEXT_PREEMPTIBLE:
		return config_event_context_preemptible;
	case LTTNG_EVENT_CONTEXT_NEED_RESCHEDULE:
		return config_event_context_need_reschedule;
	case LTTNG_EVENT_CONTEXT_MIGRATABLE:
		return config_event_context_migratable;
	case LTTNG_EVENT_CONTEXT_CALLSTACK_USER:
		return config_event_context_callstack_user;
	case LTTNG_EVENT_CONTEXT_CALLSTACK_KERNEL:
		return config_event_context_callstack_kernel;
	case LTTNG_EVENT_CONTEXT_CGROUP_NS:
		return config_event_context_cgroup_ns;
	case LTTNG_EVENT_CONTEXT_IPC_NS:
		return config_event_context_ipc_ns;
	case LTTNG_EVENT_CONTEXT_MNT_NS:
		return config_event_context_mnt_ns;
	case LTTNG_EVENT_CONTEXT_NET_NS:
		return config_event_context_net_ns;
	case LTTNG_EVENT_CONTEXT_PID_NS:
		return config_event_context_pid_ns;
	case LTTNG_EVENT_CONTEXT_TIME_NS:
		return config_event_context_time_ns;
	case LTTNG_EVENT_CONTEXT_USER_NS:
		return config_event_context_user_ns;
	case LTTNG_EVENT_CONTEXT_UTS_NS:
		return config_event_context_uts_ns;
	case LTTNG_EVENT_CONTEXT_UID:
		return config_event_context_uid;
	case LTTNG_EVENT_CONTEXT_EUID:
		return config_event_context_euid;
	case LTTNG_EVENT_CONTEXT_SUID:
		return config_event_context_suid;
	case LTTNG_EVENT_CONTEXT_GID:
		return config_event_context_gid;
	case LTTNG_EVENT_CONTEXT_EGID:
		return config_event_context_egid;
	case LTTNG_EVENT_CONTEXT_SGID:
		return config_event_context_sgid;
	case LTTNG_EVENT_CONTEXT_VUID:
		return config_event_context_vuid;
	case LTTNG_EVENT_CONTEXT_VEUID:
		return config_event_context_veuid;
	case LTTNG_EVENT_CONTEXT_VSUID:
		return config_event_context_vsuid;
	case LTTNG_EVENT_CONTEXT_VGID:
		return config_event_context_vgid;
	case LTTNG_EVENT_CONTEXT_VEGID:
		return config_event_context_vegid;
	case LTTNG_EVENT_CONTEXT_VSGID:
		return config_event_context_vsgid;
	case LTTNG_EVENT_CONTEXT_CPU_ID:
		return config_event_context_cpu_id;
	default:
		return nullptr;
	}
}

const char *mi_lttng_eventfieldtype_string(enum lttng_event_field_type val)
{
	switch (val) {
	case (LTTNG_EVENT_FIELD_INTEGER):
		return mi_lttng_element_type_integer;
	case (LTTNG_EVENT_FIELD_ENUM):
		return mi_lttng_element_type_enum;
	case (LTTNG_EVENT_FIELD_FLOAT):
		return mi_lttng_element_type_float;
	case (LTTNG_EVENT_FIELD_STRING):
		return mi_lttng_element_type_string;
	default:
		return mi_lttng_element_type_other;
	}
}

const char *mi_lttng_domaintype_string(enum lttng_domain_type value)
{
	switch (value) {
	case LTTNG_DOMAIN_KERNEL:
		return config_domain_type_kernel;
	case LTTNG_DOMAIN_UST:
		return config_domain_type_ust;
	case LTTNG_DOMAIN_JUL:
		return config_domain_type_jul;
	case LTTNG_DOMAIN_LOG4J:
		return config_domain_type_log4j;
	case LTTNG_DOMAIN_LOG4J2:
		return config_domain_type_log4j2;
	case LTTNG_DOMAIN_PYTHON:
		return config_domain_type_python;
	default:
		/* Should not have an unknown domain */
		abort();
		return nullptr;
	}
}

const char *mi_lttng_buffertype_string(enum lttng_buffer_type value)
{
	switch (value) {
	case LTTNG_BUFFER_PER_PID:
		return config_buffer_type_per_pid;
	case LTTNG_BUFFER_PER_UID:
		return config_buffer_type_per_uid;
	case LTTNG_BUFFER_GLOBAL:
		return config_buffer_type_global;
	default:
		/* Should not have an unknow buffer type */
		abort();
		return nullptr;
	}
}

const char *mi_lttng_rotation_state_string(enum lttng_rotation_state value)
{
	switch (value) {
	case LTTNG_ROTATION_STATE_ONGOING:
		return mi_lttng_rotation_state_str_ongoing;
	case LTTNG_ROTATION_STATE_COMPLETED:
		return mi_lttng_rotation_state_str_completed;
	case LTTNG_ROTATION_STATE_EXPIRED:
		return mi_lttng_rotation_state_str_expired;
	case LTTNG_ROTATION_STATE_ERROR:
		return mi_lttng_rotation_state_str_error;
	default:
		/* Should not have an unknow rotation state. */
		abort();
		return nullptr;
	}
}

const char *mi_lttng_trace_archive_location_relay_protocol_type_string(
	enum lttng_trace_archive_location_relay_protocol_type value)
{
	switch (value) {
	case LTTNG_TRACE_ARCHIVE_LOCATION_RELAY_PROTOCOL_TYPE_TCP:
		return mi_lttng_rotation_location_relay_protocol_str_tcp;
	default:
		/* Should not have an unknown relay protocol. */
		abort();
		return nullptr;
	}
}

struct mi_writer *mi_lttng_writer_create(int fd_output, int mi_output_type)
{
	struct mi_writer *mi_writer;

	mi_writer = zmalloc<struct mi_writer>();
	if (!mi_writer) {
		PERROR("zmalloc mi_writer_create");
		goto end;
	}
	if (mi_output_type == LTTNG_MI_XML) {
		mi_writer->writer = config_writer_create(fd_output, 0);
		if (!mi_writer->writer) {
			goto err_destroy;
		}
		mi_writer->type = LTTNG_MI_XML;
	} else {
		goto err_destroy;
	}

end:
	return mi_writer;

err_destroy:
	free(mi_writer);
	return nullptr;
}

int mi_lttng_writer_destroy(struct mi_writer *writer)
{
	int ret;

	if (!writer) {
		ret = -EINVAL;
		goto end;
	}

	ret = config_writer_destroy(writer->writer);
	if (ret < 0) {
		goto end;
	}

	free(writer);
end:
	return ret;
}

int mi_lttng_writer_command_open(struct mi_writer *writer, const char *command)
{
	int ret;

	/*
	 * A command is always the MI's root node, it must declare the current
	 * namespace and schema URIs and the schema's version.
	 */
	ret = config_writer_open_element(writer->writer, mi_lttng_element_command);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_attribute(
		writer->writer, mi_lttng_xmlns, DEFAULT_LTTNG_MI_NAMESPACE);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_attribute(
		writer->writer, mi_lttng_xmlns_xsi, mi_lttng_w3_schema_uri);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_attribute(
		writer->writer, mi_lttng_schema_location, mi_lttng_schema_location_uri);
	if (ret) {
		goto end;
	}

	ret = config_writer_write_attribute(
		writer->writer, mi_lttng_schema_version, mi_lttng_schema_version_value);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(writer, mi_lttng_element_command_name, command);
end:
	return ret;
}

int mi_lttng_writer_command_close(struct mi_writer *writer)
{
	return mi_lttng_writer_close_element(writer);
}

int mi_lttng_writer_open_element(struct mi_writer *writer, const char *element_name)
{
	return config_writer_open_element(writer->writer, element_name);
}

int mi_lttng_writer_close_element(struct mi_writer *writer)
{
	return config_writer_close_element(writer->writer);
}

int mi_lttng_close_multi_element(struct mi_writer *writer, unsigned int nb_element)
{
	int ret, i;

	if (nb_element < 1) {
		ret = 0;
		goto end;
	}
	for (i = 0; i < nb_element; i++) {
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

int mi_lttng_writer_write_element_unsigned_int(struct mi_writer *writer,
					       const char *element_name,
					       uint64_t value)
{
	return config_writer_write_element_unsigned_int(writer->writer, element_name, value);
}

int mi_lttng_writer_write_element_signed_int(struct mi_writer *writer,
					     const char *element_name,
					     int64_t value)
{
	return config_writer_write_element_signed_int(writer->writer, element_name, value);
}

int mi_lttng_writer_write_element_bool(struct mi_writer *writer,
				       const char *element_name,
				       int value)
{
	return config_writer_write_element_bool(writer->writer, element_name, value);
}

int mi_lttng_writer_write_element_string(struct mi_writer *writer,
					 const char *element_name,
					 const char *value)
{
	return config_writer_write_element_string(writer->writer, element_name, value);
}

int mi_lttng_writer_write_element_double(struct mi_writer *writer,
					 const char *element_name,
					 double value)
{
	return config_writer_write_element_double(writer->writer, element_name, value);
}

int mi_lttng_version(struct mi_writer *writer,
		     struct mi_lttng_version_data *version,
		     const char *lttng_description,
		     const char *lttng_license)
{
	int ret;

	/* Open version */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_version);
	if (ret) {
		goto end;
	}

	/* Version string (contain info like rc etc.) */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_version_str, version->version);
	if (ret) {
		goto end;
	}

	/* Major version number */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, mi_lttng_element_version_major, version->version_major);
	if (ret) {
		goto end;
	}

	/* Minor version number */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, mi_lttng_element_version_minor, version->version_minor);
	if (ret) {
		goto end;
	}

	/* Commit version number */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_version_commit, version->version_commit);
	if (ret) {
		goto end;
	}

	/* Patch number */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, mi_lttng_element_version_patch_level, version->version_patchlevel);
	if (ret) {
		goto end;
	}

	/* Name of the version */
	ret = mi_lttng_writer_write_element_string(
		writer, config_element_name, version->version_name);
	if (ret) {
		goto end;
	}

	/* Description mostly related to beer... */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_version_description, lttng_description);
	if (ret) {
		goto end;
	}

	/* url */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_version_web, version->package_url);
	if (ret) {
		goto end;
	}

	/* License: free as in free beer...no...*speech* */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_version_license, lttng_license);
	if (ret) {
		goto end;
	}

	/* Close version element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

int mi_lttng_sessions_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_sessions);
}

int mi_lttng_session(struct mi_writer *writer, const struct lttng_session *session, int is_open)
{
	int ret;

	LTTNG_ASSERT(session);

	/* Open sessions element */
	ret = mi_lttng_writer_open_element(writer, config_element_session);
	if (ret) {
		goto end;
	}

	/* Name of the session */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, session->name);
	if (ret) {
		goto end;
	}

	/* Path */
	ret = mi_lttng_writer_write_element_string(writer, config_element_path, session->path);
	if (ret) {
		goto end;
	}

	/* Enabled ? */
	ret = mi_lttng_writer_write_element_bool(writer, config_element_enabled, session->enabled);
	if (ret) {
		goto end;
	}

	/* Snapshot mode */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_snapshot_mode, session->snapshot_mode);
	if (ret) {
		goto end;
	}

	/* Live timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_live_timer_interval, session->live_timer_interval);
	if (ret) {
		goto end;
	}

	if (!is_open) {
		/* Closing session element */
		ret = mi_lttng_writer_close_element(writer);
	}
end:
	return ret;
}

int mi_lttng_domains_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_domains);
}

int mi_lttng_domain(struct mi_writer *writer, struct lttng_domain *domain, int is_open)
{
	int ret = 0;
	const char *str_domain;
	const char *str_buffer;

	LTTNG_ASSERT(domain);

	/* Open domain element */
	ret = mi_lttng_writer_open_element(writer, config_element_domain);
	if (ret) {
		goto end;
	}

	/* Domain Type */
	str_domain = mi_lttng_domaintype_string(domain->type);
	ret = mi_lttng_writer_write_element_string(writer, config_element_type, str_domain);
	if (ret) {
		goto end;
	}

	/* Buffer Type */
	str_buffer = mi_lttng_buffertype_string(domain->buf_type);
	ret = mi_lttng_writer_write_element_string(writer, config_element_buffer_type, str_buffer);
	if (ret) {
		goto end;
	}

	/* TODO: union  attr
	 * This union is not currently used and was added for
	 * future ust domain support.
	 * Date: 25-06-2014
	 * */

	if (!is_open) {
		/* Closing domain element */
		ret = mi_lttng_writer_close_element(writer);
	}

end:
	return ret;
}

int mi_lttng_channels_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_channels);
}

int mi_lttng_channel(struct mi_writer *writer, struct lttng_channel *channel, int is_open)
{
	int ret = 0;

	LTTNG_ASSERT(channel);

	/* Opening channel element */
	ret = mi_lttng_writer_open_element(writer, config_element_channel);
	if (ret) {
		goto end;
	}

	/* Name */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, channel->name);
	if (ret) {
		goto end;
	}

	/* Enabled ? */
	ret = mi_lttng_writer_write_element_bool(writer, config_element_enabled, channel->enabled);
	if (ret) {
		goto end;
	}

	/* Attribute */
	ret = mi_lttng_channel_attr(writer, &channel->attr);
	if (ret) {
		goto end;
	}

	if (!is_open) {
		/* Closing channel element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

static const char *allocation_policy_to_string(enum lttng_channel_allocation_policy policy)
{
	switch (policy) {
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU:
		return config_element_channel_allocation_policy_per_cpu;
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CHANNEL:
		return config_element_channel_allocation_policy_per_channel;
	default:
		return nullptr;
	}
}

int mi_lttng_channel_attr(struct mi_writer *writer, struct lttng_channel_attr *attr)
{
	int ret = 0;
	struct lttng_channel *chan = caa_container_of(attr, struct lttng_channel, attr);
	uint64_t discarded_events, lost_packets, monitor_timer_interval;
	int64_t blocking_timeout;
	enum lttng_channel_allocation_policy allocation_policy;
	const char *allocation_policy_str;

	LTTNG_ASSERT(attr);

	ret = lttng_channel_get_discarded_event_count(chan, &discarded_events);
	if (ret) {
		goto end;
	}

	ret = lttng_channel_get_lost_packet_count(chan, &lost_packets);
	if (ret) {
		goto end;
	}

	ret = lttng_channel_get_monitor_timer_interval(chan, &monitor_timer_interval);
	if (ret) {
		goto end;
	}

	ret = lttng_channel_get_blocking_timeout(chan, &blocking_timeout);
	if (ret) {
		goto end;
	}

	ret = lttng_channel_get_allocation_policy(chan, &allocation_policy);
	if (ret != LTTNG_OK) {
		goto end;
	}

	allocation_policy_str = allocation_policy_to_string(allocation_policy);
	if (!allocation_policy_str) {
		ret = LTTNG_ERR_SAVE_IO_FAIL;
		goto end;
	}

	/* Opening Attributes */
	ret = mi_lttng_writer_open_element(writer, config_element_attributes);
	if (ret) {
		goto end;
	}

	/* Overwrite */
	ret = mi_lttng_writer_write_element_string(
		writer,
		config_element_overwrite_mode,
		attr->overwrite ? config_overwrite_mode_overwrite : config_overwrite_mode_discard);
	if (ret) {
		goto end;
	}

	/* Sub buffer size in byte */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_subbuf_size, attr->subbuf_size);
	if (ret) {
		goto end;
	}

	/* Number of subbuffer (power of two) */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_num_subbuf, attr->num_subbuf);
	if (ret) {
		goto end;
	}

	/* Switch timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_switch_timer_interval, attr->switch_timer_interval);
	if (ret) {
		goto end;
	}

	/* Read timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_read_timer_interval, attr->read_timer_interval);
	if (ret) {
		goto end;
	}

	/* Monitor timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_monitor_timer_interval, monitor_timer_interval);
	if (ret) {
		goto end;
	}

	/* Retry timeout in usec */
	ret = mi_lttng_writer_write_element_signed_int(
		writer, config_element_blocking_timeout, blocking_timeout);
	if (ret) {
		goto end;
	}

	/* Allocation policy */
	ret = mi_lttng_writer_write_element_string(
		writer, config_element_channel_allocation_policy, allocation_policy_str);
	if (ret) {
		goto end;
	}

	/* Event output */
	ret = mi_lttng_writer_write_element_string(writer,
						   config_element_output_type,
						   attr->output == LTTNG_EVENT_SPLICE ?
							   config_output_type_splice :
							   config_output_type_mmap);
	if (ret) {
		goto end;
	}

	/* Tracefile size in bytes */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_tracefile_size, attr->tracefile_size);
	if (ret) {
		goto end;
	}

	/* Count of tracefiles */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_tracefile_count, attr->tracefile_count);
	if (ret) {
		goto end;
	}

	/* Live timer interval in usec */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_live_timer_interval, attr->live_timer_interval);
	if (ret) {
		goto end;
	}

	/* Discarded events */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_discarded_events, discarded_events);
	if (ret) {
		goto end;
	}

	/* Lost packets */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_lost_packets, lost_packets);
	if (ret) {
		goto end;
	}

	/* Closing attributes */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

int mi_lttng_event_common_attributes(struct mi_writer *writer, struct lttng_event *event)
{
	int ret;
	const char *filter_expression;

	/* Open event element */
	ret = mi_lttng_writer_open_element(writer, config_element_event);
	if (ret) {
		goto end;
	}

	/* Event name */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, event->name);
	if (ret) {
		goto end;
	}

	/* Event type */
	ret = mi_lttng_writer_write_element_string(
		writer, config_element_type, mi_lttng_eventtype_string(event->type));
	if (ret) {
		goto end;
	}

	/* Is event enabled */
	ret = mi_lttng_writer_write_element_bool(writer, config_element_enabled, event->enabled);
	if (ret) {
		goto end;
	}

	/* Event filter expression */
	ret = lttng_event_get_filter_expression(event, &filter_expression);
	if (ret) {
		goto end;
	}

	if (filter_expression) {
		ret = mi_lttng_writer_write_element_string(
			writer, config_element_filter_expression, filter_expression);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static int write_event_exclusions(struct mi_writer *writer, struct lttng_event *event)
{
	int i;
	int ret;
	int exclusion_count;

	/* Open event exclusions */
	ret = mi_lttng_writer_open_element(writer, config_element_exclusions);
	if (ret) {
		goto end;
	}

	exclusion_count = lttng_event_get_exclusion_name_count(event);
	if (exclusion_count < 0) {
		ret = exclusion_count;
		goto end;
	}

	for (i = 0; i < exclusion_count; i++) {
		const char *name;

		ret = lttng_event_get_exclusion_name(event, i, &name);
		if (ret) {
			/* Close exclusions */
			mi_lttng_writer_close_element(writer);
			goto end;
		}

		ret = mi_lttng_writer_write_element_string(writer, config_element_exclusion, name);
		if (ret) {
			/* Close exclusions */
			mi_lttng_writer_close_element(writer);
			goto end;
		}
	}

	/* Close exclusions */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

int mi_lttng_event_tracepoint_loglevel(struct mi_writer *writer,
				       struct lttng_event *event,
				       enum lttng_domain_type domain)
{
	int ret;

	/* Event loglevel */
	ret = mi_lttng_writer_write_element_string(
		writer, config_element_loglevel, mi_lttng_loglevel_string(event->loglevel, domain));
	if (ret) {
		goto end;
	}

	/* Log level type */
	ret = mi_lttng_writer_write_element_string(
		writer,
		config_element_loglevel_type,
		mi_lttng_logleveltype_string(event->loglevel_type));
	if (ret) {
		goto end;
	}

	/* Event exclusions */
	ret = write_event_exclusions(writer, event);

end:
	return ret;
}

int mi_lttng_event_tracepoint_no_loglevel(struct mi_writer *writer, struct lttng_event *event)
{
	/* event exclusion filter */
	return write_event_exclusions(writer, event);
}

int mi_lttng_event_function_probe(struct mi_writer *writer, struct lttng_event *event)
{
	int ret;

	ret = mi_lttng_writer_open_element(writer, config_element_attributes);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer, config_element_probe_attributes);
	if (ret) {
		goto end;
	}

	if (event->attr.probe.addr != 0) {
		/* event probe address */
		ret = mi_lttng_writer_write_element_unsigned_int(
			writer, config_element_address, event->attr.probe.addr);
		if (ret) {
			goto end;
		}
	} else {
		/* event probe offset */
		ret = mi_lttng_writer_write_element_unsigned_int(
			writer, config_element_offset, event->attr.probe.offset);
		if (ret) {
			goto end;
		}

		/* event probe symbol_name */
		ret = mi_lttng_writer_write_element_string(
			writer, config_element_symbol_name, event->attr.probe.symbol_name);
		if (ret) {
			goto end;
		}
	}

	/* Close probe_attributes and attributes */
	ret = mi_lttng_close_multi_element(writer, 2);
end:
	return ret;
}

static int mi_lttng_event_userspace_probe(struct mi_writer *writer, struct lttng_event *event)
{
	int ret;
	const struct lttng_userspace_probe_location *location;
	const struct lttng_userspace_probe_location_lookup_method *lookup_method;
	enum lttng_userspace_probe_location_lookup_method_type lookup_type;

	location = lttng_event_get_userspace_probe_location(event);
	if (!location) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	lookup_method = lttng_userspace_probe_location_get_lookup_method(location);
	if (!lookup_method) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	lookup_type = lttng_userspace_probe_location_lookup_method_get_type(lookup_method);

	ret = mi_lttng_writer_open_element(writer, config_element_attributes);
	if (ret) {
		goto end;
	}

	switch (lttng_userspace_probe_location_get_type(location)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_FUNCTION:
	{
		const char *function_name;
		const char *binary_path;

		ret = mi_lttng_writer_open_element(
			writer, config_element_userspace_probe_function_attributes);
		if (ret) {
			goto end;
		}

		switch (lookup_type) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
			ret = mi_lttng_writer_write_element_string(
				writer,
				config_element_userspace_probe_lookup,
				config_element_userspace_probe_lookup_function_elf);
			if (ret) {
				goto end;
			}
			break;
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_DEFAULT:
			ret = mi_lttng_writer_write_element_string(
				writer,
				config_element_userspace_probe_lookup,
				config_element_userspace_probe_lookup_function_default);
			if (ret) {
				goto end;
			}
			break;
		default:
			goto end;
		}

		binary_path = lttng_userspace_probe_location_function_get_binary_path(location);
		ret = mi_lttng_writer_write_element_string(
			writer, config_element_userspace_probe_location_binary_path, binary_path);
		if (ret) {
			goto end;
		}

		function_name = lttng_userspace_probe_location_function_get_function_name(location);
		ret = mi_lttng_writer_write_element_string(
			writer,
			config_element_userspace_probe_function_location_function_name,
			function_name);
		if (ret) {
			goto end;
		}

		break;
	}
	case LTTNG_USERSPACE_PROBE_LOCATION_TYPE_TRACEPOINT:
	{
		const char *probe_name, *provider_name;
		const char *binary_path;

		ret = mi_lttng_writer_open_element(
			writer, config_element_userspace_probe_function_attributes);
		if (ret) {
			goto end;
		}

		switch (lookup_type) {
		case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
			ret = mi_lttng_writer_write_element_string(
				writer,
				config_element_userspace_probe_lookup,
				config_element_userspace_probe_lookup_tracepoint_sdt);
			if (ret) {
				goto end;
			}
			break;
		default:
			goto end;
		}

		binary_path = lttng_userspace_probe_location_tracepoint_get_binary_path(location);
		ret = mi_lttng_writer_write_element_string(
			writer, config_element_userspace_probe_location_binary_path, binary_path);
		if (ret) {
			goto end;
		}

		provider_name =
			lttng_userspace_probe_location_tracepoint_get_provider_name(location);
		ret = mi_lttng_writer_write_element_string(
			writer,
			config_element_userspace_probe_tracepoint_location_provider_name,
			provider_name);
		if (ret) {
			goto end;
		}

		probe_name = lttng_userspace_probe_location_tracepoint_get_probe_name(location);
		ret = mi_lttng_writer_write_element_string(
			writer,
			config_element_userspace_probe_tracepoint_location_probe_name,
			probe_name);
		if (ret) {
			goto end;
		}
		break;
	}
	default:
		ERR("Invalid probe type encountered");
	}
	/* Close probe_attributes and attributes */
	ret = mi_lttng_close_multi_element(writer, 2);
end:
	return ret;
}

int mi_lttng_event_function_entry(struct mi_writer *writer, struct lttng_event *event)
{
	int ret;

	ret = mi_lttng_writer_open_element(writer, config_element_attributes);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer, config_element_probe_attributes);
	if (ret) {
		goto end;
	}

	/* event probe symbol_name */
	ret = mi_lttng_writer_write_element_string(
		writer, config_element_symbol_name, event->attr.ftrace.symbol_name);
	if (ret) {
		goto end;
	}

	/* Close function_attributes and attributes */
	ret = mi_lttng_close_multi_element(writer, 2);
end:
	return ret;
}

int mi_lttng_events_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_events);
}

int mi_lttng_event(struct mi_writer *writer,
		   struct lttng_event *event,
		   int is_open,
		   enum lttng_domain_type domain)
{
	int ret;

	ret = mi_lttng_event_common_attributes(writer, event);
	if (ret) {
		goto end;
	}

	switch (event->type) {
	case LTTNG_EVENT_TRACEPOINT:
	{
		if (event->loglevel != -1) {
			ret = mi_lttng_event_tracepoint_loglevel(writer, event, domain);
		} else {
			ret = mi_lttng_event_tracepoint_no_loglevel(writer, event);
		}
		break;
	}
	case LTTNG_EVENT_FUNCTION:
		/* Fallthrough */
	case LTTNG_EVENT_PROBE:
		ret = mi_lttng_event_function_probe(writer, event);
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		ret = mi_lttng_event_function_entry(writer, event);
		break;
	case LTTNG_EVENT_USERSPACE_PROBE:
		ret = mi_lttng_event_userspace_probe(writer, event);
		break;
	case LTTNG_EVENT_ALL:
		/* Fallthrough */
	default:
		break;
	}

	if (ret) {
		goto end;
	}

	if (!is_open) {
		ret = mi_lttng_writer_close_element(writer);
	}

end:
	return ret;
}

int mi_lttng_trackers_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_process_attr_trackers);
}

static int get_tracker_elements(enum lttng_process_attr process_attr,
				const char **element_process_attr_tracker,
				const char **element_process_attr_value)
{
	int ret = 0;

	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
		*element_process_attr_tracker = config_element_process_attr_tracker_pid;
		*element_process_attr_value = config_element_process_attr_pid_value;
		break;
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		*element_process_attr_tracker = config_element_process_attr_tracker_vpid;
		*element_process_attr_value = config_element_process_attr_vpid_value;
		break;
	case LTTNG_PROCESS_ATTR_USER_ID:
		*element_process_attr_tracker = config_element_process_attr_tracker_uid;
		*element_process_attr_value = config_element_process_attr_uid_value;
		break;
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		*element_process_attr_tracker = config_element_process_attr_tracker_vuid;
		*element_process_attr_value = config_element_process_attr_vuid_value;
		break;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
		*element_process_attr_tracker = config_element_process_attr_tracker_gid;
		*element_process_attr_value = config_element_process_attr_gid_value;
		break;
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		*element_process_attr_tracker = config_element_process_attr_tracker_vgid;
		*element_process_attr_value = config_element_process_attr_vgid_value;
		break;
	default:
		ret = LTTNG_ERR_SAVE_IO_FAIL;
	}
	return ret;
}

int mi_lttng_process_attribute_tracker_open(struct mi_writer *writer,
					    enum lttng_process_attr process_attr)
{
	int ret;
	const char *element_tracker, *element_value;

	ret = get_tracker_elements(process_attr, &element_tracker, &element_value);
	if (ret) {
		return ret;
	}

	/* Open process attribute tracker element */
	ret = mi_lttng_writer_open_element(writer, element_tracker);
	if (ret) {
		goto end;
	}

	/* Open values element */
	ret = mi_lttng_process_attr_values_open(writer);
end:
	return ret;
}

int mi_lttng_pids_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_pids);
}

/*
 * TODO: move the listing of pid for user agent to process semantic on
 * mi api bump. The use of process element break the mi api.
 */
int mi_lttng_pid(struct mi_writer *writer, pid_t pid, const char *name, int is_open)
{
	int ret;

	/* Open pid process */
	ret = mi_lttng_writer_open_element(writer, config_element_pid);
	if (ret) {
		goto end;
	}

	/* Writing pid number */
	ret = mi_lttng_writer_write_element_signed_int(writer, mi_lttng_element_pid_id, (int) pid);
	if (ret) {
		goto end;
	}

	/* Writing name of the process */
	if (name) {
		ret = mi_lttng_writer_write_element_string(writer, config_element_name, name);
		if (ret) {
			goto end;
		}
	}

	if (!is_open) {
		/* Closing Pid */
		ret = mi_lttng_writer_close_element(writer);
	}

end:
	return ret;
}

int mi_lttng_process_attr_values_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, config_element_process_attr_values);
}

int mi_lttng_all_process_attribute_value(struct mi_writer *writer,
					 enum lttng_process_attr process_attr,
					 bool is_open)
{
	int ret;
	const char *element_id_tracker, *element_target_id;

	ret = get_tracker_elements(process_attr, &element_id_tracker, &element_target_id);
	if (ret) {
		return ret;
	}

	ret = mi_lttng_writer_open_element(writer, element_target_id);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer, config_element_type);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_bool(writer, config_element_all, 1);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}

	if (!is_open) {
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}
end:
	return ret;
}

int mi_lttng_integral_process_attribute_value(struct mi_writer *writer,
					      enum lttng_process_attr process_attr,
					      int64_t value,
					      bool is_open)
{
	int ret;
	const char *element_id_tracker, *element_target_id;

	ret = get_tracker_elements(process_attr, &element_id_tracker, &element_target_id);
	if (ret) {
		return ret;
	}

	ret = mi_lttng_writer_open_element(writer, element_target_id);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer, config_element_type);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_signed_int(
		writer, config_element_process_attr_id, value);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}

	if (!is_open) {
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

int mi_lttng_string_process_attribute_value(struct mi_writer *writer,
					    enum lttng_process_attr process_attr,
					    const char *value,
					    bool is_open)

{
	int ret;
	const char *element_id_tracker, *element_target_id;

	ret = get_tracker_elements(process_attr, &element_id_tracker, &element_target_id);
	if (ret) {
		return ret;
	}

	ret = mi_lttng_writer_open_element(writer, element_target_id);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer, config_element_type);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(writer, config_element_name, value);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}

	if (!is_open) {
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

int mi_lttng_event_fields_open(struct mi_writer *writer)
{
	return mi_lttng_writer_open_element(writer, mi_lttng_element_event_fields);
}

int mi_lttng_event_field(struct mi_writer *writer, struct lttng_event_field *field)
{
	int ret;

	if (!field->field_name[0]) {
		ret = 0;
		goto end;
	}

	/* Open field */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_event_field);
	if (ret) {
		goto end;
	}

	if (!field->field_name[0]) {
		goto close;
	}

	/* Name */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, field->field_name);
	if (ret) {
		goto end;
	}

	/* Type */
	ret = mi_lttng_writer_write_element_string(
		writer, config_element_type, mi_lttng_eventfieldtype_string(field->type));
	if (ret) {
		goto end;
	}

	/* nowrite  */
	ret = mi_lttng_writer_write_element_signed_int(
		writer, mi_lttng_element_nowrite, field->nowrite);
	if (ret) {
		goto end;
	}

close:
	/* Close field element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

int mi_lttng_perf_counter_context(struct mi_writer *writer,
				  struct lttng_event_perf_counter_ctx *perf_context)
{
	int ret;

	/* Open perf_counter_context */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_perf_counter_context);
	if (ret) {
		goto end;
	}

	/* Type */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_type, perf_context->type);
	if (ret) {
		goto end;
	}

	/* Config */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, config_element_config, perf_context->config);
	if (ret) {
		goto end;
	}

	/* Name of the perf counter */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, perf_context->name);
	if (ret) {
		goto end;
	}

	/* Close perf_counter_context */
	ret = mi_lttng_writer_close_element(writer);
end:
	return ret;
}

static int
mi_lttng_app_context(struct mi_writer *writer, const char *provider_name, const char *ctx_name)
{
	int ret;

	/* Open app */
	ret = mi_lttng_writer_open_element(writer, config_element_context_app);
	if (ret) {
		goto end;
	}

	/* provider_name */
	ret = mi_lttng_writer_write_element_string(
		writer, config_element_context_app_provider_name, provider_name);
	if (ret) {
		goto end;
	}

	/* ctx_name */
	ret = mi_lttng_writer_write_element_string(
		writer, config_element_context_app_ctx_name, ctx_name);
	if (ret) {
		goto end;
	}

	/* Close app */
	ret = mi_lttng_writer_close_element(writer);
end:
	return ret;
}

int mi_lttng_context(struct mi_writer *writer, struct lttng_event_context *context, int is_open)
{
	int ret;

	/* Open context */
	ret = mi_lttng_writer_open_element(writer, config_element_context);
	if (ret) {
		goto end;
	}

	/* Special case for PERF_*_COUNTER
	 * print the lttng_event_perf_counter_ctx */
	switch (context->ctx) {
	case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
	{
		struct lttng_event_perf_counter_ctx *perf_context = &context->u.perf_counter;
		ret = mi_lttng_perf_counter_context(writer, perf_context);
		if (ret) {
			goto end;
		}
		break;
	}
	case LTTNG_EVENT_CONTEXT_APP_CONTEXT:
	{
		ret = mi_lttng_app_context(
			writer, context->u.app_ctx.provider_name, context->u.app_ctx.ctx_name);
		if (ret) {
			goto end;
		}
		break;
	}
	default:
	{
		const char *type_string = mi_lttng_event_contexttype_string(context->ctx);
		if (!type_string) {
			ret = -LTTNG_ERR_INVALID;
			goto end;
		}

		/* Print context type */
		ret = mi_lttng_writer_write_element_string(
			writer, config_element_type, type_string);
		break;
	}
	}

	/* Close context */
	if (!is_open) {
		ret = mi_lttng_writer_close_element(writer);
	}

end:
	return ret;
}

int mi_lttng_snapshot_output_session_name(struct mi_writer *writer, const char *session_name)
{
	int ret;

	/* Open session element */
	ret = mi_lttng_writer_open_element(writer, config_element_session);
	if (ret) {
		goto end;
	}

	/* Snapshot output list for current session name */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, session_name);
	if (ret) {
		goto end;
	}

	/* Open element snapshots (sequence one snapshot) */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_snapshots);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

int mi_lttng_snapshot_list_output(struct mi_writer *writer,
				  const struct lttng_snapshot_output *output)
{
	int ret;

	/* Open element snapshot output */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_snapshot);
	if (ret) {
		goto end;
	}

	/* ID of the snapshot output */
	ret = mi_lttng_writer_write_element_unsigned_int(writer, mi_lttng_element_id, output->id);
	if (ret) {
		goto end;
	}

	/* Name of the output */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, output->name);
	if (ret) {
		goto end;
	}

	/* Destination of the output (ctrl_url) */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_snapshot_ctrl_url, output->ctrl_url);
	if (ret) {
		goto end;
	}

	/* Destination of the output (data_url) */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_snapshot_data_url, output->data_url);
	if (ret) {
		goto end;
	}

	/* total size of all stream combined */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, mi_lttng_element_snapshot_max_size, output->max_size);
	if (ret) {
		goto end;
	}

	/* Close snapshot output element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

int mi_lttng_snapshot_del_output(struct mi_writer *writer,
				 int id,
				 const char *name,
				 const char *current_session_name)
{
	int ret;

	/* Open element del_snapshot */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_snapshot);
	if (ret) {
		goto end;
	}

	if (id != UINT32_MAX) {
		/* "Snapshot output "id" successfully deleted
		 * for "current_session_name"
		 * ID of the snapshot output
		 */
		ret = mi_lttng_writer_write_element_unsigned_int(writer, mi_lttng_element_id, id);
		if (ret) {
			goto end;
		}
	} else {
		/* "Snapshot output "name" successfully deleted
		 * for session "current_session_name"
		 * Name of the output
		 */
		ret = mi_lttng_writer_write_element_string(writer, config_element_name, name);
		if (ret) {
			goto end;
		}
	}

	/* Snapshot was deleted for session "current_session_name" */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_snapshot_session_name, current_session_name);
	if (ret) {
		goto end;
	}

	/* Close snapshot element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

int mi_lttng_snapshot_add_output(struct mi_writer *writer,
				 const char *current_session_name,
				 const char *n_ptr,
				 struct lttng_snapshot_output *output)
{
	int ret;

	/* Open element snapshot */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_snapshot);
	if (ret) {
		goto end;
	}

	/* Snapshot output id */
	ret = mi_lttng_writer_write_element_unsigned_int(writer, mi_lttng_element_id, output->id);
	if (ret) {
		goto end;
	}

	/* Snapshot output names */
	ret = mi_lttng_writer_write_element_string(writer, config_element_name, n_ptr);
	if (ret) {
		goto end;
	}

	/* Destination of the output (ctrl_url) */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_snapshot_ctrl_url, output->ctrl_url);
	if (ret) {
		goto end;
	}

	/* Snapshot added for session "current_session_name" */
	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_snapshot_session_name, current_session_name);
	if (ret) {
		goto end;
	}

	/* total size of all stream combined */
	ret = mi_lttng_writer_write_element_unsigned_int(
		writer, mi_lttng_element_snapshot_max_size, output->max_size);
	if (ret) {
		goto end;
	}

	/* Close snapshot element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

int mi_lttng_snapshot_record(struct mi_writer *writer,
			     const char *url,
			     const char *cmdline_ctrl_url,
			     const char *cmdline_data_url)
{
	int ret;

	/* Open element snapshot */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_snapshot);
	if (ret) {
		goto end;
	}

	/*
	 * If a valid an URL was given, serialize it,
	 * else take the command line data and ctrl urls */
	if (url) {
		/* Destination of the output (ctrl_url) */
		ret = mi_lttng_writer_write_element_string(
			writer, mi_lttng_element_snapshot_ctrl_url, url);
		if (ret) {
			goto end;
		}
	} else if (cmdline_ctrl_url) {
		/* Destination of the output (ctrl_url) */
		ret = mi_lttng_writer_write_element_string(
			writer, mi_lttng_element_snapshot_ctrl_url, cmdline_ctrl_url);
		if (ret) {
			goto end;
		}

		/* Destination of the output (data_url) */
		ret = mi_lttng_writer_write_element_string(
			writer, mi_lttng_element_snapshot_data_url, cmdline_data_url);
		if (ret) {
			goto end;
		}
	}

	/* Close record_snapshot element */
	ret = mi_lttng_writer_close_element(writer);

end:
	return ret;
}

int mi_lttng_rotation_schedule(struct mi_writer *writer,
			       const struct lttng_rotation_schedule *schedule)
{
	int ret = 0;
	enum lttng_rotation_status status;
	uint64_t value;
	const char *element_name;
	const char *value_name;
	bool empty_schedule = false;

	switch (lttng_rotation_schedule_get_type(schedule)) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
		status = lttng_rotation_schedule_periodic_get_period(schedule, &value);
		element_name = mi_lttng_element_rotation_schedule_periodic;
		value_name = mi_lttng_element_rotation_schedule_periodic_time_us;
		break;
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
		status = lttng_rotation_schedule_size_threshold_get_threshold(schedule, &value);
		element_name = mi_lttng_element_rotation_schedule_size_threshold;
		value_name = mi_lttng_element_rotation_schedule_size_threshold_bytes;
		break;
	default:
		ret = -1;
		goto end;
	}

	if (status != LTTNG_ROTATION_STATUS_OK) {
		if (status == LTTNG_ROTATION_STATUS_UNAVAILABLE) {
			empty_schedule = true;
		} else {
			ret = -1;
			goto end;
		}
	}

	ret = mi_lttng_writer_open_element(writer, element_name);
	if (ret) {
		goto end;
	}

	if (!empty_schedule) {
		ret = mi_lttng_writer_write_element_unsigned_int(writer, value_name, value);
		if (ret) {
			goto end;
		}
	}

	/* Close schedule descriptor element. */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

int mi_lttng_rotation_schedule_result(struct mi_writer *writer,
				      const struct lttng_rotation_schedule *schedule,
				      bool success)
{
	int ret = 0;

	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_rotation_schedule_result);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_rotation_schedule);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_rotation_schedule(writer, schedule);
	if (ret) {
		goto end;
	}

	/* Close rotation_schedule element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_bool(writer, mi_lttng_element_command_success, success);
	if (ret) {
		goto end;
	}

	/* Close rotation_schedule_result element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static int mi_lttng_location(struct mi_writer *writer,
			     const struct lttng_trace_archive_location *location)
{
	int ret = 0;
	enum lttng_trace_archive_location_type location_type;
	enum lttng_trace_archive_location_status status;

	location_type = lttng_trace_archive_location_get_type(location);

	switch (location_type) {
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_LOCAL:
	{
		const char *absolute_path;

		status = lttng_trace_archive_location_local_get_absolute_path(location,
									      &absolute_path);
		if (status != LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK) {
			ret = -1;
			goto end;
		}

		ret = mi_lttng_writer_open_element(writer,
						   mi_lttng_element_rotation_location_local);
		if (ret) {
			goto end;
		}

		ret = mi_lttng_writer_write_element_string(
			writer,
			mi_lttng_element_rotation_location_local_absolute_path,
			absolute_path);
		if (ret) {
			goto end;
		}

		/* Close local element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
		break;
	}
	case LTTNG_TRACE_ARCHIVE_LOCATION_TYPE_RELAY:
	{
		uint16_t control_port, data_port;
		const char *host, *relative_path;
		enum lttng_trace_archive_location_relay_protocol_type protocol;

		/* Fetch all relay location parameters. */
		status = lttng_trace_archive_location_relay_get_protocol_type(location, &protocol);
		if (status != LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK) {
			ret = -1;
			goto end;
		}

		status = lttng_trace_archive_location_relay_get_host(location, &host);
		if (status != LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK) {
			ret = -1;
			goto end;
		}

		status = lttng_trace_archive_location_relay_get_control_port(location,
									     &control_port);
		if (status != LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK) {
			ret = -1;
			goto end;
		}

		status = lttng_trace_archive_location_relay_get_data_port(location, &data_port);
		if (status != LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK) {
			ret = -1;
			goto end;
		}

		status = lttng_trace_archive_location_relay_get_relative_path(location,
									      &relative_path);
		if (status != LTTNG_TRACE_ARCHIVE_LOCATION_STATUS_OK) {
			ret = -1;
			goto end;
		}

		ret = mi_lttng_writer_open_element(writer,
						   mi_lttng_element_rotation_location_relay);
		if (ret) {
			goto end;
		}

		ret = mi_lttng_writer_write_element_string(
			writer, mi_lttng_element_rotation_location_relay_host, host);
		if (ret) {
			goto end;
		}

		ret = mi_lttng_writer_write_element_unsigned_int(
			writer,
			mi_lttng_element_rotation_location_relay_control_port,
			control_port);
		if (ret) {
			goto end;
		}

		ret = mi_lttng_writer_write_element_unsigned_int(
			writer, mi_lttng_element_rotation_location_relay_data_port, data_port);
		if (ret) {
			goto end;
		}

		ret = mi_lttng_writer_write_element_string(
			writer,
			mi_lttng_element_rotation_location_relay_protocol,
			mi_lttng_trace_archive_location_relay_protocol_type_string(protocol));
		if (ret) {
			goto end;
		}

		ret = mi_lttng_writer_write_element_string(
			writer,
			mi_lttng_element_rotation_location_relay_relative_path,
			relative_path);
		if (ret) {
			goto end;
		}

		/* Close relay element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
		break;
	}
	default:
		abort();
	}
end:
	return ret;
}

int mi_lttng_rotate(struct mi_writer *writer,
		    const char *session_name,
		    enum lttng_rotation_state rotation_state,
		    const struct lttng_trace_archive_location *location)
{
	int ret;

	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_rotation);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(
		writer, mi_lttng_element_session_name, session_name);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_writer_write_element_string(writer,
						   mi_lttng_element_rotation_state,
						   mi_lttng_rotation_state_string(rotation_state));
	if (ret) {
		goto end;
	}

	if (!location) {
		/* Not a serialization error. */
		goto close_rotation;
	}

	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_rotation_location);
	if (ret) {
		goto end;
	}

	ret = mi_lttng_location(writer, location);
	if (ret) {
		goto close_location;
	}

close_location:
	/* Close location element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}

close_rotation:
	/* Close rotation element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		goto end;
	}
end:
	return ret;
}
