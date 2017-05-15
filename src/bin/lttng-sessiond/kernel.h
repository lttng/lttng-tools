/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTT_KERNEL_CTL_H
#define _LTT_KERNEL_CTL_H

#include "session.h"
#include "snapshot.h"
#include "trace-kernel.h"

/*
 * Default size for the event list when kernel_list_events is called. This size
 * value is based on the initial LTTng 2.0 version set of tracepoints.
 *
 * This is NOT an upper bound because if the real event list size is bigger,
 * dynamic reallocation is performed.
 */
#define KERNEL_EVENT_INIT_LIST_SIZE 64
#define KERNEL_TRACKER_PIDS_INIT_LIST_SIZE 64

int kernel_add_channel_context(struct ltt_kernel_channel *chan,
		struct ltt_kernel_context *ctx);
int kernel_create_session(struct ltt_session *session, int tracer_fd);
int kernel_create_channel(struct ltt_kernel_session *session,
		struct lttng_channel *chan);
int kernel_create_event(struct lttng_event *ev, struct ltt_kernel_channel *channel,
		char *filter_expression, struct lttng_filter_bytecode *filter);
int kernel_disable_channel(struct ltt_kernel_channel *chan);
int kernel_disable_event(struct ltt_kernel_event *event);
int kernel_enable_event(struct ltt_kernel_event *event);
int kernel_enable_channel(struct ltt_kernel_channel *chan);
int kernel_track_pid(struct ltt_kernel_session *session, int pid);
int kernel_untrack_pid(struct ltt_kernel_session *session, int pid);
int kernel_open_metadata(struct ltt_kernel_session *session);
int kernel_open_metadata_stream(struct ltt_kernel_session *session);
int kernel_open_channel_stream(struct ltt_kernel_channel *channel);
int kernel_flush_buffer(struct ltt_kernel_channel *channel);
int kernel_metadata_flush_buffer(int fd);
int kernel_start_session(struct ltt_kernel_session *session);
int kernel_stop_session(struct ltt_kernel_session *session);
ssize_t kernel_list_events(int tracer_fd, struct lttng_event **event_list);
void kernel_wait_quiescent(int fd);
int kernel_validate_version(int tracer_fd);
void kernel_destroy_session(struct ltt_kernel_session *ksess);
void kernel_destroy_channel(struct ltt_kernel_channel *kchan);
int kernel_snapshot_record(struct ltt_kernel_session *ksess,
		struct snapshot_output *output, int wait,
		uint64_t nb_packets_per_stream);
int kernel_syscall_mask(int chan_fd, char **syscall_mask, uint32_t *nr_bits);

int init_kernel_workarounds(void);
ssize_t kernel_list_tracker_pids(struct ltt_kernel_session *session,
		int **_pids);
int kernel_supports_ring_buffer_snapshot_sample_positions(int tracer_fd);

#endif /* _LTT_KERNEL_CTL_H */
