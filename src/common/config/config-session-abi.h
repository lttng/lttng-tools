/*
 * Copyright (C) 2014 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CONFIG_SESSION_INTERNAL_H
#define CONFIG_SESSION_INTERNAL_H

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
extern const char * const config_element_pids;
extern const char * const config_element_shared_memory_path;
extern const char * const config_element_pid_tracker;
extern const char * const config_element_trackers;
extern const char * const config_element_targets;
extern const char * const config_element_target_pid;

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

#endif /* CONFIG_SESSION_INTERNAL_H */
