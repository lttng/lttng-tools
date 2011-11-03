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

#ifndef _LTTNG_KCONSUMER_H
#define _LTTNG_KCONSUMER_H

#include <lttng/lttng-consumer.h>

/*
 * Mmap the ring buffer, read it and write the data to the tracefile.
 *
 * Returns the number of bytes written.
 */
extern int lttng_kconsumer_on_read_subbuffer_mmap(
		struct lttng_consumer_local_data *ctx,
		struct lttng_consumer_stream *stream, unsigned long len);

/*
 * Splice the data from the ring buffer to the tracefile.
 *
 * Returns the number of bytes spliced.
 */
extern int lttng_kconsumer_on_read_subbuffer_splice(
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

#endif /* _LTTNG_KCONSUMER_H */
