/*
 * Copyright (C) 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 * Copyright (C) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifndef _LTTNG_KCONSUMER_H
#define _LTTNG_KCONSUMER_H

#include <common/consumer.h>

/*
 * Mmap the ring buffer, read it and write the data to the tracefile.
 *
 * Returns the number of bytes written, or negative value on error.
 */
extern ssize_t lttng_kconsumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len);

/*
 * Splice the data from the ring buffer to the tracefile.
 *
 * Returns the number of bytes spliced, or negative error value on
 * error.
 */
extern ssize_t lttng_kconsumer_on_read_subbuffer_splice(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len);

/*
 * Take a snapshot for a specific fd
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_take_snapshot(struct lttng_consumer_local_data *ctx,
        struct lttng_consumer_stream *stream);

/*
 * Get the produced position
 *
 * Returns 0 on success, < 0 on error
 */
int lttng_kconsumer_get_produced_snapshot(
        struct lttng_consumer_local_data *ctx,
        struct lttng_consumer_stream *stream,
        unsigned long *pos);

int lttng_kconsumer_recv_cmd(struct lttng_consumer_local_data *ctx,
		int sock, struct pollfd *consumer_sockpoll);


ssize_t lttng_kconsumer_read_subbuffer(struct lttng_consumer_stream *stream,
		struct lttng_consumer_local_data *ctx);
int lttng_kconsumer_on_recv_stream(struct lttng_consumer_stream *stream);

#endif /* _LTTNG_KCONSUMER_H */
