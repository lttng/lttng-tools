/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_CONSUMER_STREAM_H
#define LTTNG_CONSUMER_STREAM_H

#include "consumer.h"

/*
 * Close stream's file descriptors and, if needed, close stream also on the
 * relayd side.
 *
 * The stream lock MUST be acquired.
 * The consumer data lock MUST be acquired.
 */
void consumer_stream_close(struct lttng_consumer_stream *stream);

/*
 * Close stream on the relayd side. This call can destroy a relayd if the
 * conditions are met.
 *
 * A RCU read side lock MUST be acquired if the relayd object was looked up in
 * a hash table before calling this.
 */
void consumer_stream_relayd_close(struct lttng_consumer_stream *stream,
		struct consumer_relayd_sock_pair *relayd);

/*
 * Delete the stream from all possible hash tables.
 *
 * The consumer data lock MUST be acquired.
 */
void consumer_stream_delete(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht);

/*
 * Free the given stream within a RCU call.
 */
void consumer_stream_free(struct lttng_consumer_stream *stream);

/*
 * Destroy a stream completely. This will delete, close and free the stream.
 * Once return, the stream is NO longer usable. Its channel may get destroyed
 * if conditions are met.
 *
 * This MUST be called WITHOUT the consumer data and stream lock acquired.
 */
void consumer_stream_destroy(struct lttng_consumer_stream *stream,
		struct lttng_ht *ht);

/*
 * Destroy the stream's buffers on the tracer side. This is also called in a
 * stream destroy.
 */
void consumer_stream_destroy_buffers(struct lttng_consumer_stream *stream);

/*
 * Write index of a specific stream either on the relayd or local disk.
 */
int consumer_stream_write_index(struct lttng_consumer_stream *stream,
		struct ctf_packet_index *index);

int consumer_stream_sync_metadata(struct lttng_consumer_local_data *ctx,
		uint64_t session_id);

#endif /* LTTNG_CONSUMER_STREAM_H */
