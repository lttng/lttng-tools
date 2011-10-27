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

/*
 * ust-ctl stub API when UST is not present.
*/

#include "lttng-ust-abi.h"
#include <errno.h>

/*
 * Tracer channel attributes.
 */
struct lttng_ust_channel_attr {
	int overwrite;				/* 1: overwrite, 0: discard */
	uint64_t subbuf_size;			/* bytes */
	uint64_t num_subbuf;			/* power of 2 */
	unsigned int switch_timer_interval;	/* usec */
	unsigned int read_timer_interval;	/* usec */
	enum lttng_ust_output output;		/* splice, mmap */
};

struct object_data {
	int handle;
	int shm_fd;
	int wait_fd;
	uint64_t memory_map_size;
};

static inline
int ustctl_register_done(int sock)
{
	return -ENOSYS;
}
static inline
int ustctl_create_session(int sock)
{
	return -ENOSYS;
}
static inline
int ustctl_open_metadata(int sock, int session_handle,
		struct lttng_ust_channel_attr *chops,
		struct object_data **metadata_data)
{
	return -ENOSYS;
}
static inline
int ustctl_create_channel(int sock, int session_handle,
		struct lttng_ust_channel_attr *chops,
		struct object_data **channel_data)
{
	return -ENOSYS;
}
static inline
int ustctl_create_stream(int sock, struct object_data *channel_data,
		struct object_data **stream_data)
{
	return -ENOSYS;
}
static inline
int ustctl_create_event(int sock, struct lttng_ust_event *ev,
		struct object_data *channel_data,
		struct object_data **event_data)
{
	return -ENOSYS;
}
static inline
int ustctl_add_context(int sock, struct lttng_ust_context *ctx,
		struct object_data *obj_data,
		struct object_data **context_data)
{
	return -ENOSYS;
}

static inline
int ustctl_enable(int sock, struct object_data *object)
{
	return -ENOSYS;
}
static inline
int ustctl_disable(int sock, struct object_data *object)
{
	return -ENOSYS;
}
static inline
int ustctl_start_session(int sock, int handle)
{
	return -ENOSYS;
}
static inline
int ustctl_stop_session(int sock, int handle)
{
	return -ENOSYS;
}

static inline
int ustctl_tracepoint_list(int sock)	/* not implemented yet */
{
	return -ENOSYS;
}
static inline
int ustctl_tracer_version(int sock, struct lttng_ust_tracer_version *v)
{
	return -ENOSYS;
}
static inline
int ustctl_wait_quiescent(int sock)
{
	return -ENOSYS;
}

/* Flush each buffers in this channel */
static inline
int ustctl_flush_buffer(int sock, struct object_data *channel_data)
{
	return -ENOSYS;
}

/* not implemented yet */
struct lttng_ust_calibrate;
static inline
int ustctl_calibrate(int sock, struct lttng_ust_calibrate *calibrate)
{
	return -ENOSYS;
}

/*
 * Map channel shm_handle and add streams. Typically performed by the
 * consumer to map the objects into its memory space.
 */
static inline
struct shm_handle *ustctl_map_channel(struct object_data *chan_data)
{
	return NULL;
}
static inline
int ustctl_add_stream(struct shm_handle *shm_handle,
		struct object_data *stream_data)
{
	return -ENOSYS;
}
/*
 * Note: the object_data from which the shm_handle is derived can only
 * be released after unmapping the handle.
 */
static inline
void ustctl_unmap_channel(struct shm_handle *shm_handle)
{
}

/* Buffer operations */

struct shm_handle;
struct lib_ring_buffer;

/* Open/close stream buffers for read */
static inline
struct lib_ring_buffer *ustctl_open_stream_read(struct shm_handle *handle,
		int cpu)
{
	return NULL;
}
static inline
void ustctl_close_stream_read(struct shm_handle *handle,
                struct lib_ring_buffer *buf)
{
}

/* For mmap mode, readable without "get" operation */
static inline
int ustctl_get_mmap_len(struct shm_handle *handle,
		struct lib_ring_buffer *buf,
		unsigned long *len)
{
	return -ENOSYS;
}
static inline
int ustctl_get_max_subbuf_size(struct shm_handle *handle,
		struct lib_ring_buffer *buf,
		unsigned long *len)
{
	return -ENOSYS;
}

/*
 * For mmap mode, operate on the current packet (between get/put or
 * get_next/put_next).
 */
static inline
void *ustctl_get_mmap_base(struct shm_handle *handle,
		struct lib_ring_buffer *buf)
{
	return NULL;
}
static inline
int ustctl_get_mmap_read_offset(struct shm_handle *handle,
		struct lib_ring_buffer *buf, unsigned long *off)
{
	return -ENOSYS;
}
static inline
int ustctl_get_subbuf_size(struct shm_handle *handle,
		struct lib_ring_buffer *buf, unsigned long *len)
{
	return -ENOSYS;
}
static inline
int ustctl_get_padded_subbuf_size(struct shm_handle *handle,
		struct lib_ring_buffer *buf, unsigned long *len)
{
	return -ENOSYS;
}
static inline
int ustctl_get_next_subbuf(struct shm_handle *handle,
		struct lib_ring_buffer *buf)
{
	return -ENOSYS;
}
static inline
int ustctl_put_next_subbuf(struct shm_handle *handle,
		struct lib_ring_buffer *buf)
{
	return -ENOSYS;
}

/* snapshot */

static inline
int ustctl_snapshot(struct shm_handle *handle,
		struct lib_ring_buffer *buf)
{
	return -ENOSYS;
}
static inline
int ustctl_snapshot_get_consumed(struct shm_handle *handle,
		struct lib_ring_buffer *buf, unsigned long *pos)
{
	return -ENOSYS;
}
static inline
int ustctl_snapshot_get_produced(struct shm_handle *handle,
		struct lib_ring_buffer *buf, unsigned long *pos)
{
	return -ENOSYS;
}
static inline
int ustctl_get_subbuf(struct shm_handle *handle,
		struct lib_ring_buffer *buf, unsigned long *pos)
{
	return -ENOSYS;
}
static inline
int ustctl_put_subbuf(struct shm_handle *handle,
		struct lib_ring_buffer *buf)
{
	return -ENOSYS;
}

/* Release object created by members of this API */
static inline
void release_object(int sock, struct object_data *data)
{
}

#endif /* _LTTNG_UST_CTL_H */
