/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _LTTNG_USTCONSUMER_H
#define _LTTNG_USTCONSUMER_H

#include <config.h>
#include <lttng/lttng-consumer.h>
#include <errno.h>

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * Mmap the ring buffer, read it and write the data to the tracefile.
 *
 * Returns the number of bytes written.
 */
extern int lttng_ustconsumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len);

/* Not implemented */
extern int lttng_ustconsumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len);

/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_ustconsumer_take_snapshot(struct lttng_consumer_local_data *ctx,
        struct lttng_consumer_stream *stream);

/*
 * Get the produced position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_ustconsumer_get_produced_snapshot(
        struct lttng_consumer_local_data *ctx,
        struct lttng_consumer_stream *stream,
        unsigned long *pos);

int lttng_ustconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll);

extern int lttng_ustconsumer_allocate_channel(struct lttng_consumer_channel *chan);
extern void lttng_ustconsumer_del_channel(struct lttng_consumer_channel *chan);
extern int lttng_ustconsumer_allocate_stream(struct lttng_consumer_stream *stream);
extern void lttng_ustconsumer_del_stream(struct lttng_consumer_stream *stream);

int lttng_ustconsumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx);
int lttng_ustconsumer_on_recv_stream(struct lttng_consumer_stream *stream);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline
int lttng_ustconsumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len)
{
	return -ENOSYS;
}

static inline
int lttng_ustconsumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *uststream, unsigned long len)
{
	return -ENOSYS;
}

static inline
int lttng_ustconsumer_take_snapshot(struct lttng_consumer_local_data *ctx,
        struct lttng_consumer_stream *stream)
{
	return -ENOSYS;
}

static inline
int lttng_ustconsumer_get_produced_snapshot(
        struct lttng_consumer_local_data *ctx,
        struct lttng_consumer_stream *stream,
        unsigned long *pos)
{
	return -ENOSYS;
}

static inline
int lttng_ustconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll)
{
	return -ENOSYS;
}

static inline
int lttng_ustconsumer_allocate_channel(struct lttng_consumer_channel *chan)
{
	return -ENOSYS;
}

static inline
void lttng_ustconsumer_del_channel(struct lttng_consumer_channel *chan)
{
}

static inline
int lttng_ustconsumer_allocate_stream(struct lttng_consumer_stream *stream)
{
	return -ENOSYS;
}

static inline
void lttng_ustconsumer_del_stream(struct lttng_consumer_stream *stream)
{
}

static inline
int lttng_ustconsumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx)
{
	return -ENOSYS;
}

static inline
int lttng_ustconsumer_on_recv_stream(struct lttng_consumer_stream *stream)
{
	return -ENOSYS;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTTNG_USTCONSUMER_H */
