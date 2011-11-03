/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTTNG_UST_CTL_H
#define _LTTNG_UST_CTL_H

#include <ust/lttng-ust-abi.h>

int ustctl_register_done(int sock);
int ustctl_create_session(int sock);
int ustctl_open_metadata(int sock, int session_handle,
		struct lttng_ust_channel_attr *chops,
		struct lttng_ust_object_data **metadata_data);
int ustctl_create_channel(int sock, int session_handle,
		struct lttng_ust_channel_attr *chops,
		struct lttng_ust_object_data **channel_data);
int ustctl_create_stream(int sock, struct lttng_ust_object_data *channel_data,
		struct lttng_ust_object_data **stream_data);
int ustctl_create_event(int sock, struct lttng_ust_event *ev,
		struct lttng_ust_object_data *channel_data,
		struct lttng_ust_object_data **event_data);
int ustctl_add_context(int sock, struct lttng_ust_context *ctx,
		struct lttng_ust_object_data *obj_data,
		struct lttng_ust_object_data **context_data);

int ustctl_enable(int sock, struct lttng_ust_object_data *object);
int ustctl_disable(int sock, struct lttng_ust_object_data *object);
int ustctl_start_session(int sock, int handle);
int ustctl_stop_session(int sock, int handle);

int ustctl_tracepoint_list(int sock);	/* not implemented yet */
int ustctl_tracer_version(int sock, struct lttng_ust_tracer_version *v);
int ustctl_wait_quiescent(int sock);

/* Flush each buffers in this channel */
int ustctl_flush_buffer(int sock, struct lttng_ust_object_data *channel_data);

/* not implemented yet */
struct lttng_ust_calibrate;
int ustctl_calibrate(int sock, struct lttng_ust_calibrate *calibrate);

/*
 * Map channel lttng_ust_shm_handle and add streams. Typically performed by the
 * consumer to map the objects into its memory space.
 */
struct lttng_ust_shm_handle *ustctl_map_channel(struct lttng_ust_object_data *chan_data);
int ustctl_add_stream(struct lttng_ust_shm_handle *lttng_ust_shm_handle,
		struct lttng_ust_object_data *stream_data);
/*
 * Note: the lttng_ust_object_data from which the lttng_ust_shm_handle is derived can only
 * be released after unmapping the handle.
 */
void ustctl_unmap_channel(struct lttng_ust_shm_handle *lttng_ust_shm_handle);

/* Buffer operations */

struct lttng_ust_shm_handle;
struct lttng_ust_lib_ring_buffer;

/* Open/close stream buffers for read */
struct lttng_ust_lib_ring_buffer *ustctl_open_stream_read(struct lttng_ust_shm_handle *handle,
		int cpu);
void ustctl_close_stream_read(struct lttng_ust_shm_handle *handle,
                struct lttng_ust_lib_ring_buffer *buf);

/* For mmap mode, readable without "get" operation */
int ustctl_get_mmap_len(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf,
		unsigned long *len);
int ustctl_get_max_subbuf_size(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf,
		unsigned long *len);

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */
void *ustctl_get_mmap_base(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf);
int ustctl_get_mmap_read_offset(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *off);
int ustctl_get_subbuf_size(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *len);
int ustctl_get_padded_subbuf_size(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *len);
int ustctl_get_next_subbuf(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf);
int ustctl_put_next_subbuf(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf);

/* snapshot */

int ustctl_snapshot(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf);
int ustctl_snapshot_get_consumed(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *pos);
int ustctl_snapshot_get_produced(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *pos);
int ustctl_get_subbuf(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf, unsigned long *pos);
int ustctl_put_subbuf(struct lttng_ust_shm_handle *handle,
		struct lttng_ust_lib_ring_buffer *buf);

/* Release object created by members of this API */
void release_object(int sock, struct lttng_ust_object_data *data);

#endif /* _LTTNG_UST_CTL_H */
