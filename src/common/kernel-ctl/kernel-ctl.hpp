/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_KERNEL_CTL_H
#define _LTTNG_KERNEL_CTL_H

#include <common/lttng-kernel-old.hpp>
#include <common/lttng-kernel.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp> /* for struct lttng_filter_bytecode */

#include <lttng/lttng.h>

#include <stdbool.h>
#include <string>
#include <vector>

int kernctl_create_session(int fd);
int kernctl_open_metadata(int fd, const struct lttng_kernel_abi_channel& channel_config);
int kernctl_create_channel(int fd, const struct lttng_kernel_abi_channel& channel_config);
int kernctl_create_stream(int fd);
int kernctl_create_event(int fd, const struct lttng_kernel_abi_event& ev);
int kernctl_add_context(int fd, const struct lttng_kernel_abi_context& ctx);

int kernctl_enable(int fd);
int kernctl_disable(int fd);
int kernctl_start_session(int fd);
int kernctl_stop_session(int fd);

int kernctl_create_event_notifier_group(int fd);

/* Apply on event notifier_group file descriptor. */
int kernctl_create_event_notifier_group_notification_fd(int fd);
int kernctl_create_event_notifier_group_error_counter(
	int fd, const struct lttng_kernel_abi_counter_conf *error_counter_conf);
int kernctl_create_event_notifier(int fd,
				  const struct lttng_kernel_abi_event_notifier *event_notifier);

/* Apply on a recording-session file descriptor. */
int kernctl_create_session_counter(int session_fd,
				   const struct lttng_kernel_abi_counter_conf *counter_conf);

int kernctl_counter_read(int counter_fd, struct lttng_kernel_abi_counter_read *counter_read);
int kernctl_counter_get_aggregate_value(int counter_fd,
					struct lttng_kernel_abi_counter_aggregate *value);
int kernctl_counter_clear(int counter_fd, struct lttng_kernel_abi_counter_clear *clear);

/*
 * Query the number of dynamically-allocated keys currently registered
 * in the counter (across all dimensions).
 *
 * Returns 0 on success and writes the snapshot to `*nr`. Returns a
 * negative errno on failure. The value is a snapshot: new keys may be
 * registered concurrently (e.g. on module load), so callers iterating
 * over [0, nr) must tolerate races.
 */
int kernctl_counter_map_nr_descriptors(int counter_fd, uint64_t *nr);

/*
 * Pull one descriptor by index. The wrapper handles the -ENOSPC retry
 * internally: it grows temporary buffers for the key string and the
 * per-dimension array indexes as needed and returns the populated
 * descriptor on success.
 *
 * On success, returns 0 and writes the scalar fields and the populated
 * key string / array indexes to the corresponding output pointers.
 * Any output pointer may be NULL if the caller does not need that
 * field.
 *
 * On failure, returns a negative errno. -EBADMSG is returned if the
 * retry loop fails resize.
 */
int kernctl_counter_map_descriptor(int counter_fd,
				   uint64_t descriptor_index,
				   uint32_t *out_dimension,
				   uint64_t *out_user_token,
				   std::string *out_key_string,
				   std::vector<uint64_t> *out_array_indexes);

/* Apply on event file descriptor. */
int kernctl_filter(int fd, const struct lttng_bytecode *filter);
int kernctl_add_callsite(int fd, struct lttng_kernel_abi_event_callsite *callsite);
int kernctl_capture(int fd, const struct lttng_bytecode *capture);

int kernctl_tracepoint_list(int fd);
int kernctl_syscall_list(int fd);
int kernctl_tracer_version(int fd, struct lttng_kernel_abi_tracer_version *v);
int kernctl_tracer_abi_version(int fd, struct lttng_kernel_abi_tracer_abi_version *v);
int kernctl_wait_quiescent(int fd);

/*
 * kernctl_syscall_mask - Get syscall mask associated to a channel file
 * descriptor.
 *
 * The parameter @syscall_mask should initially be either NULL or point
 * to memory allocated with malloc(3) or realloc(3). When the function
 * returns, it will point to a memory area of the size required for the
 * bitmask (using realloc(3) to resize the memory).
 *
 * It returns 0 if OK, -1 on error. In all cases (error and OK),
 * @syscall_mask should be freed by the caller with free(3).
 */
int kernctl_syscall_mask(int fd, char **syscall_mask, uint32_t *nr_bits);

/* Process ID tracking can be applied to session file descriptor. */
int kernctl_track_pid(int fd, int pid);
int kernctl_untrack_pid(int fd, int pid);
int kernctl_list_tracker_pids(int fd);

int kernctl_track_id(int fd, lttng_kernel_abi_tracker_type process_attr, int id);
int kernctl_untrack_id(int fd, lttng_kernel_abi_tracker_type process_attr, int id);
int kernctl_list_tracker_ids(int fd, lttng_kernel_abi_tracker_type process_attr);

int kernctl_session_regenerate_metadata(int fd);
int kernctl_session_regenerate_statedump(int fd);
int kernctl_session_set_name(int fd, const char *name);
int kernctl_session_set_creation_time(int fd, time_t time);
int kernctl_session_set_output_format(int fd, enum lttng_kernel_abi_output_format format);

/* Buffer operations */

/* For mmap mode, readable without "get" operation */
int kernctl_get_mmap_len(int fd, unsigned long *len);
int kernctl_get_max_subbuf_size(int fd, unsigned long *len);

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */
int kernctl_get_mmap_read_offset(int fd, unsigned long *len);
int kernctl_get_subbuf_size(int fd, unsigned long *len);
int kernctl_get_padded_subbuf_size(int fd, unsigned long *len);

int kernctl_get_next_subbuf(int fd);
int kernctl_put_next_subbuf(int fd);

/* snapshot */
int kernctl_snapshot(int fd);
int kernctl_snapshot_sample_positions(int fd);
int kernctl_snapshot_get_consumed(int fd, unsigned long *pos);
int kernctl_snapshot_get_produced(int fd, unsigned long *pos);
int kernctl_get_subbuf(int fd, unsigned long *pos);
int kernctl_put_subbuf(int fd);

int kernctl_buffer_flush(int fd);
int kernctl_buffer_flush_empty(int fd);
int kernctl_buffer_flush_or_populate_packet(
	int fd, struct lttng_kernel_abi_ring_buffer_packet_flush_or_populate_packet_args *args);
int kernctl_buffer_clear(int fd);
int kernctl_get_metadata_version(int fd, uint64_t *version);
int kernctl_metadata_cache_dump(int fd);
int kernctl_get_next_subbuf_metadata_check(int fd, bool *consistent);

/* index */
int kernctl_get_timestamp_begin(int fd, uint64_t *timestamp_begin);
int kernctl_get_timestamp_end(int fd, uint64_t *timestamp_end);
int kernctl_get_events_discarded(int fd, uint64_t *events_discarded);
int kernctl_get_content_size(int fd, uint64_t *content_size);
int kernctl_get_packet_size(int fd, uint64_t *packet_size);
int kernctl_get_stream_id(int fd, uint64_t *stream_id);
int kernctl_get_current_timestamp(int fd, uint64_t *ts);
int kernctl_get_sequence_number(int fd, uint64_t *seq);
int kernctl_get_instance_id(int fd, uint64_t *seq);

#endif /* _LTTNG_KERNEL_CTL_H */
