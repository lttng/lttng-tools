/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CONSUMER_STREAM_H
#define LTTNG_CONSUMER_STREAM_H

#include "consumer.hpp"

enum consumer_stream_open_packet_status {
	CONSUMER_STREAM_OPEN_PACKET_STATUS_OPENED,
	CONSUMER_STREAM_OPEN_PACKET_STATUS_NO_SPACE,
	CONSUMER_STREAM_OPEN_PACKET_STATUS_ERROR,
};

/*
 * Create a consumer stream.
 *
 * The channel lock MUST be acquired.
 */
struct lttng_consumer_stream *consumer_stream_create(struct lttng_consumer_channel *channel,
						     uint64_t channel_key,
						     uint64_t stream_key,
						     const char *channel_name,
						     uint64_t relayd_id,
						     uint64_t session_id,
						     struct lttng_trace_chunk *trace_chunk,
						     int cpu,
						     int *alloc_ret,
						     enum consumer_channel_type type,
						     unsigned int monitor);

/*
 * Close stream's file descriptors and, if needed, close stream also on the
 * relayd side.
 *
 * The stream lock MUST be acquired.
 * The consumer data lock MUST be acquired.
 */
void consumer_stream_close_output(struct lttng_consumer_stream *stream);

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
void consumer_stream_delete(struct lttng_consumer_stream *stream, struct lttng_ht *ht);

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
void consumer_stream_destroy(struct lttng_consumer_stream *stream, struct lttng_ht *ht);

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

int consumer_stream_sync_metadata(struct lttng_consumer_local_data *ctx, uint64_t session_id);

/*
 * Create the output files of a local stream.
 *
 * This must be called with the channel's and the stream's lock held.
 */
int consumer_stream_create_output_files(struct lttng_consumer_stream *stream, bool create_index);

/*
 * Rotate the output files of a local stream. This will change the
 * active output files of both the binary and index in accordance
 * with the stream's configuration (stream file count).
 *
 * This must be called with the channel's and the stream's lock held.
 */
int consumer_stream_rotate_output_files(struct lttng_consumer_stream *stream);

/*
 * Indicates whether or not a stream is logically deleted. A deleted stream
 * should no longer be used; its existence is only garanteed by the RCU lock
 * held by the caller.
 *
 * This function must be called with the RCU read side lock held.
 */
bool consumer_stream_is_deleted(struct lttng_consumer_stream *stream);

/*
 * Enable metadata bucketization. This must only be enabled if the tracer
 * provides a reliable metadata `coherent` flag.
 *
 * This must be called on initialization before any subbuffer is consumed.
 */
int consumer_stream_enable_metadata_bucketization(struct lttng_consumer_stream *stream);

/*
 * Set the version of a metadata stream (i.e. following a metadata
 * regeneration).
 *
 * Changing the version of a metadata stream will cause any bucketized metadata
 * to be discarded and will mark the metadata stream for future `reset`.
 */
void consumer_stream_metadata_set_version(struct lttng_consumer_stream *stream,
					  uint64_t new_version);

/*
 * Attempt to open a packet in a stream.
 *
 * This function must be called with the stream and channel locks held.
 */
enum consumer_stream_open_packet_status
consumer_stream_open_packet(struct lttng_consumer_stream *stream);

/*
 * Flush a stream's buffer.
 *
 * producer_active: if true, causes a flush to occur only if there is
 * content present in the current sub-buffer. If false, forces a flush to take
 * place (otherwise known as "flush_empty").
 *
 * This function must be called with the stream and channel locks held.
 */
int consumer_stream_flush_buffer(struct lttng_consumer_stream *stream, bool producer_active);

#endif /* LTTNG_CONSUMER_STREAM_H */
