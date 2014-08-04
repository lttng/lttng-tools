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

const char * const config_element_channel;
const char * const config_element_channels;
const char * const config_element_domain;
const char * const config_element_domains;
const char * const config_element_event;
const char * const config_element_events;
const char * const config_element_context;
const char * const config_element_contexts;
const char * const config_element_attributes;
const char * const config_element_exclusion;
const char * const config_element_exclusions;
const char * const config_element_function_attributes;
const char * const config_element_probe_attributes;
const char * const config_element_symbol_name;
const char * const config_element_address;
const char * const config_element_offset;
const char * const config_element_name;
const char * const config_element_enabled;
const char * const config_element_overwrite_mode;
const char * const config_element_subbuf_size;
const char * const config_element_num_subbuf;
const char * const config_element_switch_timer_interval;
const char * const config_element_read_timer_interval;
const char * const config_element_output;
const char * const config_element_output_type;
const char * const config_element_tracefile_size;
const char * const config_element_tracefile_count;
const char * const config_element_live_timer_interval;
const char * const config_element_type;
const char * const config_element_buffer_type;
const char * const config_element_session;
const char * const config_element_sessions;
const char * const config_element_perf;
const char * const config_element_config;
const char * const config_element_started;
const char * const config_element_snapshot_mode;
const char * const config_element_loglevel;
const char * const config_element_loglevel_type;
const char * const config_element_filter;
const char * const config_element_snapshot_outputs;
const char * const config_element_consumer_output;
const char * const config_element_destination;
const char * const config_element_path;
const char * const config_element_net_output;
const char * const config_element_control_uri;
const char * const config_element_data_uri;
const char * const config_element_max_size;

const char * const config_domain_type_kernel;
const char * const config_domain_type_ust;
const char * const config_domain_type_jul;
const char * const config_domain_type_log4j;

const char * const config_buffer_type_per_pid;
const char * const config_buffer_type_per_uid;
const char * const config_buffer_type_global;

const char * const config_overwrite_mode_discard;
const char * const config_overwrite_mode_overwrite;

const char * const config_output_type_splice;
const char * const config_output_type_mmap;

const char * const config_loglevel_type_all;
const char * const config_loglevel_type_range;
const char * const config_loglevel_type_single;

const char * const config_event_type_all;
const char * const config_event_type_tracepoint;
const char * const config_event_type_probe;
const char * const config_event_type_function;
const char * const config_event_type_function_entry;
const char * const config_event_type_noop;
const char * const config_event_type_syscall;
const char * const config_event_type_kprobe;
const char * const config_event_type_kretprobe;

const char * const config_event_context_pid;
const char * const config_event_context_procname;
const char * const config_event_context_prio;
const char * const config_event_context_nice;
const char * const config_event_context_vpid;
const char * const config_event_context_tid;
const char * const config_event_context_vtid;
const char * const config_event_context_ppid;
const char * const config_event_context_vppid;
const char * const config_event_context_pthread_id;
const char * const config_event_context_hostname;
const char * const config_event_context_ip;
const char * const config_event_context_perf_thread_counter;

#endif /* CONFIG_SESSION_INTERNAL_H */
