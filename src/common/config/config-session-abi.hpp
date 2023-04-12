/*
 * Copyright (C) 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef CONFIG_SESSION_INTERNAL_H
#define CONFIG_SESSION_INTERNAL_H

#include <lttng/lttng-export.h>

extern const char *const config_element_all;
LTTNG_EXPORT extern const char *const config_element_channel;
LTTNG_EXPORT extern const char *const config_element_channels;
LTTNG_EXPORT extern const char *const config_element_domain;
LTTNG_EXPORT extern const char *const config_element_domains;
LTTNG_EXPORT extern const char *const config_element_event;
LTTNG_EXPORT extern const char *const config_element_events;
LTTNG_EXPORT extern const char *const config_element_context;
LTTNG_EXPORT extern const char *const config_element_contexts;
LTTNG_EXPORT extern const char *const config_element_attributes;
LTTNG_EXPORT extern const char *const config_element_exclusion;
LTTNG_EXPORT extern const char *const config_element_exclusions;
LTTNG_EXPORT extern const char *const config_element_function_attributes;
LTTNG_EXPORT extern const char *const config_element_probe_attributes;
LTTNG_EXPORT extern const char *const config_element_symbol_name;
LTTNG_EXPORT extern const char *const config_element_address;
LTTNG_EXPORT extern const char *const config_element_offset;
extern const char *const config_element_userspace_probe_lookup;
extern const char *const config_element_userspace_probe_lookup_function_default;
extern const char *const config_element_userspace_probe_lookup_function_elf;
extern const char *const config_element_userspace_probe_lookup_tracepoint_sdt;
extern const char *const config_element_userspace_probe_location_binary_path;
extern const char *const config_element_userspace_probe_function_attributes;
extern const char *const config_element_userspace_probe_function_location_function_name;
extern const char *const config_element_userspace_probe_tracepoint_attributes;
extern const char *const config_element_userspace_probe_tracepoint_location_provider_name;
extern const char *const config_element_userspace_probe_tracepoint_location_probe_name;
extern const char *const config_element_name;
LTTNG_EXPORT extern const char *const config_element_enabled;
LTTNG_EXPORT extern const char *const config_element_overwrite_mode;
LTTNG_EXPORT extern const char *const config_element_subbuf_size;
LTTNG_EXPORT extern const char *const config_element_num_subbuf;
LTTNG_EXPORT extern const char *const config_element_switch_timer_interval;
LTTNG_EXPORT extern const char *const config_element_read_timer_interval;
extern const char *const config_element_monitor_timer_interval;
extern const char *const config_element_blocking_timeout;
LTTNG_EXPORT extern const char *const config_element_output;
LTTNG_EXPORT extern const char *const config_element_output_type;
LTTNG_EXPORT extern const char *const config_element_tracefile_size;
LTTNG_EXPORT extern const char *const config_element_tracefile_count;
LTTNG_EXPORT extern const char *const config_element_live_timer_interval;
extern const char *const config_element_discarded_events;
extern const char *const config_element_lost_packets;
LTTNG_EXPORT extern const char *const config_element_type;
LTTNG_EXPORT extern const char *const config_element_buffer_type;
LTTNG_EXPORT extern const char *const config_element_session;
LTTNG_EXPORT extern const char *const config_element_sessions;
extern const char *const config_element_context_perf;
extern const char *const config_element_context_app;
extern const char *const config_element_context_app_provider_name;
extern const char *const config_element_context_app_ctx_name;
LTTNG_EXPORT extern const char *const config_element_config;
LTTNG_EXPORT extern const char *const config_element_started;
LTTNG_EXPORT extern const char *const config_element_snapshot_mode;
LTTNG_EXPORT extern const char *const config_element_loglevel;
LTTNG_EXPORT extern const char *const config_element_loglevel_type;
LTTNG_EXPORT extern const char *const config_element_filter;
extern const char *const config_element_filter_expression;
LTTNG_EXPORT extern const char *const config_element_snapshot_outputs;
LTTNG_EXPORT extern const char *const config_element_consumer_output;
LTTNG_EXPORT extern const char *const config_element_destination;
LTTNG_EXPORT extern const char *const config_element_path;
LTTNG_EXPORT extern const char *const config_element_net_output;
LTTNG_EXPORT extern const char *const config_element_control_uri;
LTTNG_EXPORT extern const char *const config_element_data_uri;
LTTNG_EXPORT extern const char *const config_element_max_size;
LTTNG_EXPORT extern const char *const config_element_pid;
extern const char *const config_element_process_attr_id;
LTTNG_EXPORT extern const char *const config_element_pids;
LTTNG_EXPORT extern const char *const config_element_name;
LTTNG_EXPORT extern const char *const config_element_shared_memory_path;
extern const char *const config_element_process_attr_tracker_pid;
extern const char *const config_element_process_attr_tracker_vpid;
extern const char *const config_element_process_attr_tracker_uid;
extern const char *const config_element_process_attr_tracker_vuid;
extern const char *const config_element_process_attr_tracker_gid;
extern const char *const config_element_process_attr_tracker_vgid;
extern const char *const config_element_process_attr_trackers;
extern const char *const config_element_process_attr_values;
extern const char *const config_element_process_attr_value_type;
extern const char *const config_element_process_attr_pid_value;
extern const char *const config_element_process_attr_vpid_value;
extern const char *const config_element_process_attr_uid_value;
extern const char *const config_element_process_attr_vuid_value;
extern const char *const config_element_process_attr_gid_value;
extern const char *const config_element_process_attr_vgid_value;
extern const char *const config_element_process_attr_tracker_type;
extern const char *const config_element_rotation_timer_interval;
extern const char *const config_element_rotation_size;
extern const char *const config_element_rotation_schedule;

LTTNG_EXPORT extern const char *const config_domain_type_kernel;
LTTNG_EXPORT extern const char *const config_domain_type_ust;
LTTNG_EXPORT extern const char *const config_domain_type_jul;
LTTNG_EXPORT extern const char *const config_domain_type_log4j;
LTTNG_EXPORT extern const char *const config_domain_type_python;

LTTNG_EXPORT extern const char *const config_buffer_type_per_pid;
LTTNG_EXPORT extern const char *const config_buffer_type_per_uid;
LTTNG_EXPORT extern const char *const config_buffer_type_global;

LTTNG_EXPORT extern const char *const config_overwrite_mode_discard;
LTTNG_EXPORT extern const char *const config_overwrite_mode_overwrite;

LTTNG_EXPORT extern const char *const config_output_type_splice;
LTTNG_EXPORT extern const char *const config_output_type_mmap;

LTTNG_EXPORT extern const char *const config_loglevel_type_all;
LTTNG_EXPORT extern const char *const config_loglevel_type_range;
LTTNG_EXPORT extern const char *const config_loglevel_type_single;

LTTNG_EXPORT extern const char *const config_event_type_all;
LTTNG_EXPORT extern const char *const config_event_type_tracepoint;
LTTNG_EXPORT extern const char *const config_event_type_probe;
extern const char *const config_event_type_userspace_probe;
LTTNG_EXPORT extern const char *const config_event_type_function;
LTTNG_EXPORT extern const char *const config_event_type_function_entry;
LTTNG_EXPORT extern const char *const config_event_type_noop;
LTTNG_EXPORT extern const char *const config_event_type_syscall;
LTTNG_EXPORT extern const char *const config_event_type_kprobe;
LTTNG_EXPORT extern const char *const config_event_type_kretprobe;

LTTNG_EXPORT extern const char *const config_event_context_pid;
LTTNG_EXPORT extern const char *const config_event_context_procname;
LTTNG_EXPORT extern const char *const config_event_context_prio;
LTTNG_EXPORT extern const char *const config_event_context_nice;
LTTNG_EXPORT extern const char *const config_event_context_vpid;
LTTNG_EXPORT extern const char *const config_event_context_tid;
LTTNG_EXPORT extern const char *const config_event_context_vtid;
LTTNG_EXPORT extern const char *const config_event_context_ppid;
LTTNG_EXPORT extern const char *const config_event_context_vppid;
LTTNG_EXPORT extern const char *const config_event_context_pthread_id;
LTTNG_EXPORT extern const char *const config_event_context_hostname;
LTTNG_EXPORT extern const char *const config_event_context_ip;
LTTNG_EXPORT extern const char *const config_event_context_perf_thread_counter;
extern const char *const config_event_context_app;
extern const char *const config_event_context_interruptible;
extern const char *const config_event_context_preemptible;
extern const char *const config_event_context_need_reschedule;
extern const char *const config_event_context_migratable;
extern const char *const config_event_context_callstack_user;
extern const char *const config_event_context_callstack_kernel;

extern const char *const config_element_rotation_schedules;
extern const char *const config_element_rotation_schedule_periodic;
extern const char *const config_element_rotation_schedule_periodic_time_us;
extern const char *const config_element_rotation_schedule_size_threshold;
extern const char *const config_element_rotation_schedule_size_threshold_bytes;
extern const char *const config_event_context_cgroup_ns;
extern const char *const config_event_context_ipc_ns;
extern const char *const config_event_context_mnt_ns;
extern const char *const config_event_context_net_ns;
extern const char *const config_event_context_pid_ns;
extern const char *const config_event_context_time_ns;
extern const char *const config_event_context_user_ns;
extern const char *const config_event_context_uts_ns;
extern const char *const config_event_context_uid;
extern const char *const config_event_context_euid;
extern const char *const config_event_context_suid;
extern const char *const config_event_context_gid;
extern const char *const config_event_context_egid;
extern const char *const config_event_context_sgid;
extern const char *const config_event_context_vuid;
extern const char *const config_event_context_veuid;
extern const char *const config_event_context_vsuid;
extern const char *const config_event_context_vgid;
extern const char *const config_event_context_vegid;
extern const char *const config_event_context_vsgid;

#endif /* CONFIG_SESSION_INTERNAL_H */
