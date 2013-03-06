/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011-2013 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License only.
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

#ifndef _LTTNG_UST_CTL_H
#define _LTTNG_UST_CTL_H

#include <lttng/ust-abi.h>

#ifndef LTTNG_PACKED
#define LTTNG_PACKED __attribute__((packed))
#endif

#ifndef LTTNG_UST_UUID_LEN
#define LTTNG_UST_UUID_LEN	16
#endif

struct lttng_ust_shm_handle;
struct lttng_ust_lib_ring_buffer;

struct ustctl_consumer_channel_attr {
	enum lttng_ust_chan_type type;
	uint64_t subbuf_size;			/* bytes */
	uint64_t num_subbuf;			/* power of 2 */
	int overwrite;				/* 1: overwrite, 0: discard */
	unsigned int switch_timer_interval;	/* usec */
	unsigned int read_timer_interval;	/* usec */
	enum lttng_ust_output output;		/* splice, mmap */
	unsigned char uuid[LTTNG_UST_UUID_LEN]; /* Trace session unique ID */
} LTTNG_PACKED;

/*
 * API used by sessiond.
 */

/*
 * Error values: all the following functions return:
 * >= 0: Success (LTTNG_UST_OK)
 * < 0: error code.
 */
int ustctl_register_done(int sock);
int ustctl_create_session(int sock);
int ustctl_create_event(int sock, struct lttng_ust_event *ev,
		struct lttng_ust_object_data *channel_data,
		struct lttng_ust_object_data **event_data);
int ustctl_add_context(int sock, struct lttng_ust_context *ctx,
		struct lttng_ust_object_data *obj_data,
		struct lttng_ust_object_data **context_data);
int ustctl_set_filter(int sock, struct lttng_ust_filter_bytecode *bytecode,
		struct lttng_ust_object_data *obj_data);

int ustctl_enable(int sock, struct lttng_ust_object_data *object);
int ustctl_disable(int sock, struct lttng_ust_object_data *object);
int ustctl_start_session(int sock, int handle);
int ustctl_stop_session(int sock, int handle);

/*
 * ustctl_tracepoint_list returns a tracepoint list handle, or negative
 * error value.
 */
int ustctl_tracepoint_list(int sock);

/*
 * ustctl_tracepoint_list_get is used to iterate on the tp list
 * handle. End is iteration is reached when -LTTNG_UST_ERR_NOENT is
 * returned.
 */
int ustctl_tracepoint_list_get(int sock, int tp_list_handle,
		struct lttng_ust_tracepoint_iter *iter);

/*
 * ustctl_tracepoint_field_list returns a tracepoint field list handle,
 * or negative error value.
 */
int ustctl_tracepoint_field_list(int sock);

/*
 * ustctl_tracepoint_field_list_get is used to iterate on the tp field
 * list handle. End is iteration is reached when -LTTNG_UST_ERR_NOENT is
 * returned.
 */
int ustctl_tracepoint_field_list_get(int sock, int tp_field_list_handle,
		struct lttng_ust_field_iter *iter);

int ustctl_tracer_version(int sock, struct lttng_ust_tracer_version *v);
int ustctl_wait_quiescent(int sock);

int ustctl_sock_flush_buffer(int sock, struct lttng_ust_object_data *object);

int ustctl_calibrate(int sock, struct lttng_ust_calibrate *calibrate);

/* Release object created by members of this API. */
int ustctl_release_object(int sock, struct lttng_ust_object_data *data);
/* Release handle returned by create session. */
int ustctl_release_handle(int sock, int handle);

int ustctl_recv_channel_from_consumer(int sock,
		struct lttng_ust_object_data **channel_data);
int ustctl_recv_stream_from_consumer(int sock,
		struct lttng_ust_object_data **stream_data);
int ustctl_send_channel_to_ust(int sock, int session_handle,
		struct lttng_ust_object_data *channel_data);
int ustctl_send_stream_to_ust(int sock,
		struct lttng_ust_object_data *channel_data,
		struct lttng_ust_object_data *stream_data);

/*
 * API used by consumer.
 */

struct ustctl_consumer_channel;
struct ustctl_consumer_stream;
struct ustctl_consumer_channel_attr;

struct ustctl_consumer_channel *
	ustctl_create_channel(struct ustctl_consumer_channel_attr *attr);
/*
 * Each stream created needs to be destroyed before calling
 * ustctl_destroy_channel().
 */
void ustctl_destroy_channel(struct ustctl_consumer_channel *chan);

int ustctl_send_channel_to_sessiond(int sock,
		struct ustctl_consumer_channel *channel);
int ustctl_channel_close_wait_fd(struct ustctl_consumer_channel *consumer_chan);
int ustctl_channel_close_wakeup_fd(struct ustctl_consumer_channel *consumer_chan);
int ustctl_channel_get_wait_fd(struct ustctl_consumer_channel *consumer_chan);
int ustctl_channel_get_wakeup_fd(struct ustctl_consumer_channel *consumer_chan);

/*
 * Send a NULL stream to finish iteration over all streams of a given
 * channel.
 */
int ustctl_send_stream_to_sessiond(int sock,
		struct ustctl_consumer_stream *stream);
int ustctl_stream_close_wait_fd(struct ustctl_consumer_stream *stream);
int ustctl_stream_close_wakeup_fd(struct ustctl_consumer_stream *stream);
int ustctl_stream_get_wait_fd(struct ustctl_consumer_stream *stream);
int ustctl_stream_get_wakeup_fd(struct ustctl_consumer_stream *stream);

/* Create/destroy stream buffers for read */
struct ustctl_consumer_stream *
	ustctl_create_stream(struct ustctl_consumer_channel *channel,
			int cpu);
void ustctl_destroy_stream(struct ustctl_consumer_stream *stream);

/* For mmap mode, readable without "get" operation */
int ustctl_get_mmap_len(struct ustctl_consumer_stream *stream,
		unsigned long *len);
int ustctl_get_max_subbuf_size(struct ustctl_consumer_stream *stream,
		unsigned long *len);

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */
void *ustctl_get_mmap_base(struct ustctl_consumer_stream *stream);
int ustctl_get_mmap_read_offset(struct ustctl_consumer_stream *stream,
		unsigned long *off);
int ustctl_get_subbuf_size(struct ustctl_consumer_stream *stream,
		unsigned long *len);
int ustctl_get_padded_subbuf_size(struct ustctl_consumer_stream *stream,
		unsigned long *len);
int ustctl_get_next_subbuf(struct ustctl_consumer_stream *stream);
int ustctl_put_next_subbuf(struct ustctl_consumer_stream *stream);

/* snapshot */

int ustctl_snapshot(struct ustctl_consumer_stream *stream);
int ustctl_snapshot_get_consumed(struct ustctl_consumer_stream *stream,
		unsigned long *pos);
int ustctl_snapshot_get_produced(struct ustctl_consumer_stream *stream,
		unsigned long *pos);
int ustctl_get_subbuf(struct ustctl_consumer_stream *stream,
		unsigned long *pos);
int ustctl_put_subbuf(struct ustctl_consumer_stream *stream);

void ustctl_flush_buffer(struct ustctl_consumer_stream *stream,
		int producer_active);

#endif /* _LTTNG_UST_CTL_H */
