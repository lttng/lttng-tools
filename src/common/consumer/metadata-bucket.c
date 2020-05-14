/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "metadata-bucket.h"

#include <common/buffer-view.h>
#include <common/consumer/consumer.h>
#include <common/dynamic-buffer.h>
#include <common/macros.h>
#include <common/error.h>

struct metadata_bucket {
	struct lttng_dynamic_buffer content;
	struct {
		metadata_bucket_flush_cb fn;
		void *data;
	} flush;
	unsigned int buffer_count;
};

struct metadata_bucket *metadata_bucket_create(
		metadata_bucket_flush_cb flush, void *data)
{
	struct metadata_bucket *bucket;

	bucket = zmalloc(sizeof(typeof(*bucket)));
	if (!bucket) {
		PERROR("Failed to allocate buffer bucket");
		goto end;
	}

	bucket->flush.fn = flush;
	bucket->flush.data = data;
	lttng_dynamic_buffer_init(&bucket->content);
end:
	return bucket;
}

void metadata_bucket_destroy(struct metadata_bucket *bucket)
{
	if (!bucket) {
		return;
	}

	if (bucket->content.size > 0) {
		WARN("Stream metadata bucket destroyed with remaining data: size = %zu, buffer count = %u",
				bucket->content.size, bucket->buffer_count);
	}

	lttng_dynamic_buffer_reset(&bucket->content);
	free(bucket);
}

void metadata_bucket_reset(struct metadata_bucket *bucket)
{
	lttng_dynamic_buffer_reset(&bucket->content);
	lttng_dynamic_buffer_init(&bucket->content);
	bucket->buffer_count = 0;
}

enum metadata_bucket_status metadata_bucket_fill(struct metadata_bucket *bucket,
		const struct stream_subbuffer *buffer)
{
	ssize_t ret;
	struct lttng_buffer_view flushed_view;
	struct stream_subbuffer flushed_subbuffer;
	enum metadata_bucket_status status;
	const bool should_flush =
			LTTNG_OPTIONAL_GET(buffer->info.metadata.coherent);
	const size_t padding_this_buffer =
			buffer->info.metadata.padded_subbuf_size -
			buffer->info.metadata.subbuf_size;
	size_t flush_size;

	DBG("Metadata bucket filled with %zu bytes buffer view, sub-buffer size: %lu, padded sub-buffer size: %lu, coherent: %s",
			buffer->buffer.buffer.size,
			buffer->info.metadata.subbuf_size,
			buffer->info.metadata.padded_subbuf_size,
			buffer->info.metadata.coherent.value ? "true" : "false");
	/*
	 * If no metadata was accumulated and this buffer should be
	 * flushed, don't copy it unecessarily; just flush it directly.
	 */
	if (!should_flush || bucket->buffer_count != 0) {
		/*
		 * Append the _padded_ subbuffer since they are combined
		 * into a single "virtual" subbuffer that will be
		 * flushed at once.
		 *
		 * This means that some padding will be sent over the
		 * network, but should not represent a large amount
		 * of data as incoherent subbuffers are typically
		 * pretty full.
		 *
		 * The padding of the last subbuffer (coherent) added to
		 * the bucket is not sent, which is what really matters
		 * from an efficiency point of view.
		 */
		ret = lttng_dynamic_buffer_append_view(
			&bucket->content, &buffer->buffer.buffer);
		if (ret) {
			status = METADATA_BUCKET_STATUS_ERROR;
			goto end;
		}
	}

	bucket->buffer_count++;
	if (!should_flush) {
		status = METADATA_BUCKET_STATUS_OK;
		goto end;
	}

	flushed_view = bucket->content.size != 0 ?
		lttng_buffer_view_from_dynamic_buffer(&bucket->content, 0, -1) :
		lttng_buffer_view_from_view(&buffer->buffer.buffer, 0, -1);

	/*
	 * The flush is done with the size of all padded sub-buffers, except
	 * for the last one which we can safely "trim". The padding of the last
	 * packet will be reconstructed by the relay daemon.
	 */
	flush_size = flushed_view.size - padding_this_buffer;

	flushed_subbuffer = (typeof(flushed_subbuffer)) {
		.buffer.buffer = flushed_view,
		.info.metadata.subbuf_size = flush_size,
		.info.metadata.padded_subbuf_size = flushed_view.size,
		.info.metadata.version = buffer->info.metadata.version,
		.info.metadata.coherent = buffer->info.metadata.coherent,
	};

	DBG("Metadata bucket flushing %zu bytes (%u sub-buffer%s)",
			flushed_view.size, bucket->buffer_count,
			bucket->buffer_count > 1 ? "s" : "");
	ret = bucket->flush.fn(&flushed_subbuffer, bucket->flush.data);
	if (ret >= 0) {
		status = METADATA_BUCKET_STATUS_OK;
	} else {
		status = METADATA_BUCKET_STATUS_ERROR;
	}

	metadata_bucket_reset(bucket);

end:
	return status;
}
