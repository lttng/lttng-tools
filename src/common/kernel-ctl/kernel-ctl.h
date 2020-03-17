/*
 * Copyright (C) 2011 Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_KERNEL_CTL_H
#define _LTTNG_KERNEL_CTL_H

#include <lttng/lttng.h>
#include <common/lttng-kernel.h>
#include <common/lttng-kernel-old.h>
#include <common/sessiond-comm/sessiond-comm.h>	/* for struct lttng_filter_bytecode */

int kernctl_create_session(int fd);
int kernctl_open_metadata(int fd, struct lttng_channel_attr *chops);
int kernctl_create_channel(int fd, struct lttng_channel_attr *chops);
int kernctl_create_stream(int fd);
int kernctl_create_event(int fd, struct lttng_kernel_event *ev);
int kernctl_add_context(int fd, struct lttng_kernel_context *ctx);

int kernctl_enable(int fd);
int kernctl_disable(int fd);
int kernctl_start_session(int fd);
int kernctl_stop_session(int fd);

/* Apply on event FD */
int kernctl_filter(int fd, struct lttng_filter_bytecode *filter);
int kernctl_add_callsite(int fd, struct lttng_kernel_event_callsite *callsite);

int kernctl_tracepoint_list(int fd);
int kernctl_syscall_list(int fd);
int kernctl_tracer_version(int fd, struct lttng_kernel_tracer_version *v);
int kernctl_tracer_abi_version(int fd, struct lttng_kernel_tracer_abi_version *v);
int kernctl_wait_quiescent(int fd);

/*
 * kernctl_syscall_mask - Get syscall mask associated to a channel FD.
 *
 * The parameter @syscall_mask should initially be either NULL or point
 * to memory allocated with malloc(3) or realloc(3). When the function
 * returns, it will point to a memory area of the size required for the
 * bitmask (using realloc(3) to resize the memory).
 *
 * It returns 0 if OK, -1 on error. In all cases (error and OK),
 * @syscall_mask should be freed by the caller with free(3).
 */
int kernctl_syscall_mask(int fd, char **syscall_mask,
		uint32_t *nr_bits);

/* Process ID tracking can be applied to session FD */
int kernctl_track_pid(int fd, int pid);
int kernctl_untrack_pid(int fd, int pid);
int kernctl_list_tracker_pids(int fd);

int kernctl_track_id(int fd, enum lttng_process_attr process_attr, int id);
int kernctl_untrack_id(int fd, enum lttng_process_attr process_attr, int id);
int kernctl_list_tracker_ids(int fd, enum lttng_process_attr process_attr);

int kernctl_session_regenerate_metadata(int fd);
int kernctl_session_regenerate_statedump(int fd);
int kernctl_session_set_name(int fd, const char *name);
int kernctl_session_set_creation_time(int fd, time_t time);

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
int kernctl_buffer_clear(int fd);
int kernctl_get_metadata_version(int fd, uint64_t *version);
int kernctl_metadata_cache_dump(int fd);

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
