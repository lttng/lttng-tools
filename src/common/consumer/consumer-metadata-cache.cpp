/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "consumer-metadata-cache.hpp"

#include <common/common.hpp>
#include <common/consumer/consumer.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/ust-consumer/ust-consumer.hpp>
#include <common/utils.hpp>

#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

enum metadata_cache_update_version_status {
	METADATA_CACHE_UPDATE_STATUS_VERSION_UPDATED,
	METADATA_CACHE_UPDATE_STATUS_VERSION_NOT_UPDATED,
};

extern struct lttng_consumer_global_data the_consumer_data;

/*
 * Reset the metadata cache.
 */
static void metadata_cache_reset(struct consumer_metadata_cache *cache)
{
	const int ret = lttng_dynamic_buffer_set_size(&cache->contents, 0);

	LTTNG_ASSERT(ret == 0);
}

/*
 * Check if the metadata cache version changed.
 * If it did, reset the metadata cache.
 * The metadata cache lock MUST be held.
 */
static enum metadata_cache_update_version_status
metadata_cache_update_version(struct consumer_metadata_cache *cache, uint64_t version)
{
	enum metadata_cache_update_version_status status;

	if (cache->version == version) {
		status = METADATA_CACHE_UPDATE_STATUS_VERSION_NOT_UPDATED;
		goto end;
	}

	DBG("Metadata cache version update to %" PRIu64, version);
	cache->version = version;
	status = METADATA_CACHE_UPDATE_STATUS_VERSION_UPDATED;

end:
	return status;
}

/*
 * Write metadata to the cache, extend the cache if necessary. We support
 * overlapping updates, but they need to be contiguous. Send the
 * contiguous metadata in cache to the ring buffer. The metadata cache
 * lock MUST be acquired to write in the cache.
 *
 * See `enum consumer_metadata_cache_write_status` for the meaning of the
 * various returned status codes.
 */
enum consumer_metadata_cache_write_status
consumer_metadata_cache_write(struct consumer_metadata_cache *cache,
			      unsigned int offset,
			      unsigned int len,
			      uint64_t version,
			      const char *data)
{
	int ret = 0;
	enum consumer_metadata_cache_write_status status;
	bool cache_is_invalidated = false;
	uint64_t original_size;

	LTTNG_ASSERT(cache);
	ASSERT_LOCKED(cache->lock);
	original_size = cache->contents.size;

	if (metadata_cache_update_version(cache, version) ==
	    METADATA_CACHE_UPDATE_STATUS_VERSION_UPDATED) {
		metadata_cache_reset(cache);
		cache_is_invalidated = true;
	}

	DBG("Writing %u bytes from offset %u in metadata cache", len, offset);
	if (offset + len > cache->contents.size) {
		ret = lttng_dynamic_buffer_set_size(&cache->contents, offset + len);
		if (ret) {
			ERR("Extending metadata cache");
			status = CONSUMER_METADATA_CACHE_WRITE_STATUS_ERROR;
			goto end;
		}
	}

	memcpy(cache->contents.data + offset, data, len);

	if (cache_is_invalidated) {
		status = CONSUMER_METADATA_CACHE_WRITE_STATUS_INVALIDATED;
	} else if (cache->contents.size > original_size) {
		status = CONSUMER_METADATA_CACHE_WRITE_STATUS_APPENDED_CONTENT;
	} else {
		status = CONSUMER_METADATA_CACHE_WRITE_STATUS_NO_CHANGE;
		LTTNG_ASSERT(cache->contents.size == original_size);
	}

end:
	return status;
}

/*
 * Create the metadata cache, original allocated size: max_sb_size
 *
 * Return 0 on success, a negative value on error.
 */
int consumer_metadata_cache_allocate(struct lttng_consumer_channel *channel)
{
	int ret;

	LTTNG_ASSERT(channel);

	channel->metadata_cache = zmalloc<consumer_metadata_cache>();
	if (!channel->metadata_cache) {
		PERROR("zmalloc metadata cache struct");
		ret = -1;
		goto end;
	}
	ret = pthread_mutex_init(&channel->metadata_cache->lock, nullptr);
	if (ret != 0) {
		PERROR("mutex init");
		goto end_free_cache;
	}

	lttng_dynamic_buffer_init(&channel->metadata_cache->contents);
	ret = lttng_dynamic_buffer_set_capacity(&channel->metadata_cache->contents,
						DEFAULT_METADATA_CACHE_SIZE);
	if (ret) {
		PERROR("Failed to pre-allocate metadata cache storage of %d bytes on creation",
		       DEFAULT_METADATA_CACHE_SIZE);
		ret = -1;
		goto end_free_mutex;
	}

	DBG("Allocated metadata cache: current capacity = %zu",
	    lttng_dynamic_buffer_get_capacity_left(&channel->metadata_cache->contents));

	ret = 0;
	goto end;

end_free_mutex:
	pthread_mutex_destroy(&channel->metadata_cache->lock);
end_free_cache:
	free(channel->metadata_cache);
end:
	return ret;
}

/*
 * Destroy and free the metadata cache
 */
void consumer_metadata_cache_destroy(struct lttng_consumer_channel *channel)
{
	if (!channel || !channel->metadata_cache) {
		return;
	}

	DBG("Destroying metadata cache");

	pthread_mutex_destroy(&channel->metadata_cache->lock);
	lttng_dynamic_buffer_reset(&channel->metadata_cache->contents);
	free(channel->metadata_cache);
}

/*
 * Check if the cache is flushed up to the offset passed in parameter.
 *
 * Return true if everything has been flushed, false if there is data not flushed.
 */
namespace {
bool consumer_metadata_cache_is_flushed(struct lttng_consumer_channel *channel,
					uint64_t offset,
					int timer)
{
	bool done_flushing = false;
	struct lttng_consumer_stream *metadata_stream;

	/*
	 * If not called from a timer handler, we have to take the
	 * channel lock to be mutually exclusive with channel teardown.
	 * Timer handler does not need to take this lock because it is
	 * already synchronized by timer stop (and, more importantly,
	 * taking this lock in a timer handler would cause a deadlock).
	 */
	if (!timer) {
		pthread_mutex_lock(&channel->lock);
	}
	pthread_mutex_lock(&channel->timer_lock);
	metadata_stream = channel->metadata_stream;
	if (!metadata_stream) {
		/*
		 * Having no metadata stream means the channel is being destroyed so there
		 * is no cache to flush anymore.
		 */
		done_flushing = true;
		goto end_unlock_channel;
	}

	pthread_mutex_lock(&metadata_stream->lock);
	pthread_mutex_lock(&channel->metadata_cache->lock);

	if (metadata_stream->ust_metadata_pushed >= offset) {
		done_flushing = true;
	} else if (channel->metadata_stream->endpoint_status != CONSUMER_ENDPOINT_ACTIVE) {
		/* An inactive endpoint means we don't have to flush anymore. */
		done_flushing = true;
	} else {
		/* Still not completely flushed. */
		done_flushing = false;
	}

	pthread_mutex_unlock(&channel->metadata_cache->lock);
	pthread_mutex_unlock(&metadata_stream->lock);

end_unlock_channel:
	pthread_mutex_unlock(&channel->timer_lock);
	if (!timer) {
		pthread_mutex_unlock(&channel->lock);
	}

	return done_flushing;
}
} /* namespace */

/*
 * Wait until the cache is flushed up to the offset passed in parameter or the
 * metadata stream has been destroyed.
 */
void consumer_wait_metadata_cache_flushed(struct lttng_consumer_channel *channel,
					  uint64_t offset,
					  bool invoked_by_timer)
{
	assert(channel);
	assert(channel->metadata_cache);

	if (consumer_metadata_cache_is_flushed(channel, offset, invoked_by_timer)) {
		return;
	}

	/* Metadata cache is not currently flushed, wait on wait queue. */
	for (;;) {
		lttng::synchro::waiter waiter;

		channel->metadata_pushed_wait_queue.add(waiter);
		if (consumer_metadata_cache_is_flushed(channel, offset, invoked_by_timer)) {
			/* Wake up all waiters, ourself included. */
			channel->metadata_pushed_wait_queue.wake_all();
			/* Ensure proper teardown of waiter. */
			waiter.wait();
			break;
		}

		waiter.wait();
	}
}
