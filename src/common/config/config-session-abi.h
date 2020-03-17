/*
 * Copyright (C) 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef CONFIG_SESSION_INTERNAL_H
#define CONFIG_SESSION_INTERNAL_H

extern const char * const config_element_all;
extern const char * const config_element_channel;
extern const char * const config_element_channels;
extern const char * const config_element_domain;
extern const char * const config_element_domains;
extern const char * const config_element_event;
extern const char * const config_element_events;
extern const char * const config_element_context;
extern const char * const config_element_contexts;
extern const char * const config_element_attributes;
extern const char * const config_element_exclusion;
extern const char * const config_element_exclusions;
extern const char * const config_element_function_attributes;
extern const char * const config_element_probe_attributes;
extern const char * const config_element_symbol_name;
extern const char * const config_element_address;
extern const char * const config_element_offset;
extern const char * const config_element_userspace_probe_lookup;
extern const char * const config_element_userspace_probe_lookup_function_default;
extern const char * const config_element_userspace_probe_lookup_function_elf;
extern const char * const config_element_userspace_probe_lookup_tracepoint_sdt;
extern const char * const config_element_userspace_probe_location_binary_path;
extern const char * const config_element_userspace_probe_function_attributes;
extern const char * const config_element_userspace_probe_function_location_function_name;
extern const char * const config_element_userspace_probe_tracepoint_attributes;
extern const char * const config_element_userspace_probe_tracepoint_location_provider_name;
extern const char * const config_element_userspace_probe_tracepoint_location_probe_name;
extern const char * const config_element_name;
extern const char * const config_element_enabled;
extern const char * const config_element_overwrite_mode;
extern const char * const config_element_subbuf_size;
extern const char * const config_element_num_subbuf;
extern const char * const config_element_switch_timer_interval;
extern const char * const config_element_read_timer_interval;
extern const char * const config_element_monitor_timer_interval;
extern const char * const config_element_blocking_timeout;
extern const char * const config_element_output;
extern const char * const config_element_output_type;
extern const char * const config_element_tracefile_size;
extern const char * const config_element_tracefile_count;
extern const char * const config_element_live_timer_interval;
extern const char * const config_element_discarded_events;
extern const char * const config_element_lost_packets;
extern const char * const config_element_type;
extern const char * const config_element_buffer_type;
extern const char * const config_element_session;
extern const char * const config_element_sessions;
extern const char * const config_element_context_perf;
extern const char * const config_element_context_app;
extern const char * const config_element_context_app_provider_name;
extern const char * const config_element_context_app_ctx_name;
extern const char * const config_element_config;
extern const char * const config_element_started;
extern const char * const config_element_snapshot_mode;
extern const char * const config_element_loglevel;
extern const char * const config_element_loglevel_type;
extern const char * const config_element_filter;
extern const char * const config_element_filter_expression;
extern const char * const config_element_snapshot_outputs;
extern const char * const config_element_consumer_output;
extern const char * const config_element_destination;
extern const char * const config_element_path;
extern const char * const config_element_net_output;
extern const char * const config_element_control_uri;
extern const char * const config_element_data_uri;
extern const char * const config_element_max_size;
extern const char * const config_element_pid;
extern const char * const config_element_process_attr_id;
extern const char * const config_element_pids;
extern const char * const config_element_name;
extern const char * const config_element_shared_memory_path;
extern const char * const config_element_process_attr_tracker_pid;
extern const char * const config_element_process_attr_tracker_vpid;
extern const char * const config_element_process_attr_tracker_uid;
extern const char * const config_element_process_attr_tracker_vuid;
extern const char * const config_element_process_attr_tracker_gid;
extern const char * const config_element_process_attr_tracker_vgid;
extern const char * const config_element_process_attr_trackers;
extern const char * const config_element_process_attr_values;
extern const char * const config_element_process_attr_value_type;
extern const char * const config_element_process_attr_pid_value;
extern const char * const config_element_process_attr_vpid_value;
extern const char * const config_element_process_attr_uid_value;
extern const char * const config_element_process_attr_vuid_value;
extern const char * const config_element_process_attr_gid_value;
extern const char * const config_element_process_attr_vgid_value;
extern const char * const config_element_process_attr_tracker_type;
extern const char * const config_element_rotation_timer_interval;
extern const char * const config_element_rotation_size;
extern const char * const config_element_rotation_schedule;

extern const char * const config_domain_type_kernel;
extern const char * const config_domain_type_ust;
extern const char * const config_domain_type_jul;
extern const char * const config_domain_type_log4j;
extern const char * const config_domain_type_python;

extern const char * const config_buffer_type_per_pid;
extern const char * const config_buffer_type_per_uid;
extern const char * const config_buffer_type_global;

extern const char * const config_overwrite_mode_discard;
extern const char * const config_overwrite_mode_overwrite;

extern const char * const config_output_type_splice;
extern const char * const config_output_type_mmap;

extern const char * const config_loglevel_type_all;
extern const char * const config_loglevel_type_range;
extern const char * const config_loglevel_type_single;

extern const char * const config_event_type_all;
extern const char * const config_event_type_tracepoint;
extern const char * const config_event_type_probe;
extern const char * const config_event_type_userspace_probe;
extern const char * const config_event_type_function;
extern const char * const config_event_type_function_entry;
extern const char * const config_event_type_noop;
extern const char * const config_event_type_syscall;
extern const char * const config_event_type_kprobe;
extern const char * const config_event_type_kretprobe;

extern const char * const config_event_context_pid;
extern const char * const config_event_context_procname;
extern const char * const config_event_context_prio;
extern const char * const config_event_context_nice;
extern const char * const config_event_context_vpid;
extern const char * const config_event_context_tid;
extern const char * const config_event_context_vtid;
extern const char * const config_event_context_ppid;
extern const char * const config_event_context_vppid;
extern const char * const config_event_context_pthread_id;
extern const char * const config_event_context_hostname;
extern const char * const config_event_context_ip;
extern const char * const config_event_context_perf_thread_counter;
extern const char * const config_event_context_app;
extern const char * const config_event_context_interruptible;
extern const char * const config_event_context_preemptible;
extern const char * const config_event_context_need_reschedule;
extern const char * const config_event_context_migratable;
extern const char * const config_event_context_callstack_user;
extern const char * const config_event_context_callstack_kernel;

extern const char * const config_element_rotation_schedules;
extern const char * const config_element_rotation_schedule_periodic;
extern const char * const config_element_rotation_schedule_periodic_time_us;
extern const char * const config_element_rotation_schedule_size_threshold;
extern const char * const config_element_rotation_schedule_size_threshold_bytes;
extern const char * const config_event_context_cgroup_ns;
extern const char * const config_event_context_ipc_ns;
extern const char * const config_event_context_mnt_ns;
extern const char * const config_event_context_net_ns;
extern const char * const config_event_context_pid_ns;
extern const char * const config_event_context_user_ns;
extern const char * const config_event_context_uts_ns;
extern const char * const config_event_context_uid;
extern const char * const config_event_context_euid;
extern const char * const config_event_context_suid;
extern const char * const config_event_context_gid;
extern const char * const config_event_context_egid;
extern const char * const config_event_context_sgid;
extern const char * const config_event_context_vuid;
extern const char * const config_event_context_veuid;
extern const char * const config_event_context_vsuid;
extern const char * const config_event_context_vgid;
extern const char * const config_event_context_vegid;
extern const char * const config_event_context_vsgid;

#endif /* CONFIG_SESSION_INTERNAL_H */
