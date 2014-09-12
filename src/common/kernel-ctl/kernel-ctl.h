/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifndef _LTTNG_KERNEL_CTL_H
#define _LTTNG_KERNEL_CTL_H

#include <lttng/lttng.h>
#include <common/lttng-kernel.h>
#include <common/lttng-kernel-old.h>

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

int kernctl_tracepoint_list(int fd);
int kernctl_syscall_list(int fd);
int kernctl_tracer_version(int fd, struct lttng_kernel_tracer_version *v);
int kernctl_wait_quiescent(int fd);
int kernctl_calibrate(int fd, struct lttng_kernel_calibrate *calibrate);

int kernctl_enable_syscall(int fd, const char *syscall_name);
int kernctl_disable_syscall(int fd, const char *syscall_name);

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
int kernctl_snapshot_get_consumed(int fd, unsigned long *pos);
int kernctl_snapshot_get_produced(int fd, unsigned long *pos);
int kernctl_get_subbuf(int fd, unsigned long *pos);
int kernctl_put_subbuf(int fd);

int kernctl_buffer_flush(int fd);

/* index */
int kernctl_get_timestamp_begin(int fd, uint64_t *timestamp_begin);
int kernctl_get_timestamp_end(int fd, uint64_t *timestamp_end);
int kernctl_get_events_discarded(int fd, uint64_t *events_discarded);
int kernctl_get_content_size(int fd, uint64_t *content_size);
int kernctl_get_packet_size(int fd, uint64_t *packet_size);
int kernctl_get_stream_id(int fd, uint64_t *stream_id);
int kernctl_get_current_timestamp(int fd, uint64_t *ts);

#endif /* _LTTNG_KERNEL_CTL_H */
