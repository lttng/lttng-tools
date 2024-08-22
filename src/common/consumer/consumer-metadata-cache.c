/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>

#include <common/common.h>
#include <common/utils.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/ust-consumer/ust-consumer.h>
#include <common/consumer/consumer.h>

#include "consumer-metadata-cache.h"

enum metadata_cache_update_version_status {
	METADATA_CACHE_UPDATE_STATUS_VERSION_UPDATED,
	METADATA_CACHE_UPDATE_STATUS_VERSION_NOT_UPDATED,
};

extern struct lttng_consumer_global_data consumer_data;

/*
 * Extend the allocated size of the metadata cache. Called only from
 * lttng_ustconsumer_write_metadata_cache.
 *
 * Return 0 on success, a negative value on error.
 */
static int extend_metadata_cache(struct lttng_consumer_channel *channel,
		unsigned int size)
{
	int ret = 0;
	char *tmp_data_ptr;
	unsigned int new_size, old_size;

	assert(channel);
	assert(channel->metadata_cache);

	old_size = channel->metadata_cache->cache_alloc_size;
	new_size = max_t(unsigned int, old_size + size, old_size << 1);
	DBG("Extending metadata cache to %u", new_size);
	tmp_data_ptr = realloc(channel->metadata_cache->data, new_size);
	if (!tmp_data_ptr) {
		ERR("Reallocating metadata cache");
		free(channel->metadata_cache->data);
		ret = -1;
		goto end;
	}
	/* Zero newly allocated memory */
	memset(tmp_data_ptr + old_size, 0, new_size - old_size);
	channel->metadata_cache->data = tmp_data_ptr;
	channel->metadata_cache->cache_alloc_size = new_size;

end:
	return ret;
}

/*
 * Reset the metadata cache.
 */
static
void metadata_cache_reset(struct consumer_metadata_cache *cache)
{
	memset(cache->data, 0, cache->cache_alloc_size);
	cache->max_offset = 0;
}

/*
 * Check if the metadata cache version changed.
 * If it did, reset the metadata cache.
 * The metadata cache lock MUST be held.
 */
static enum metadata_cache_update_version_status metadata_cache_update_version(
		struct consumer_metadata_cache *cache, uint64_t version)
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
consumer_metadata_cache_write(struct lttng_consumer_channel *channel,
		unsigned int offset, unsigned int len, uint64_t version,
		char *data)
{
	int ret = 0;
	struct consumer_metadata_cache *cache;
	enum consumer_metadata_cache_write_status status;
	bool cache_is_invalidated = false;
	uint64_t original_max_offset;

	assert(channel);
	assert(channel->metadata_cache);

	cache = channel->metadata_cache;
	ASSERT_LOCKED(cache->lock);
	original_max_offset = cache->max_offset;

	if (metadata_cache_update_version(cache, version) ==
			METADATA_CACHE_UPDATE_STATUS_VERSION_UPDATED) {
		metadata_cache_reset(cache);
		cache_is_invalidated = true;
	}

	DBG("Writing %u bytes from offset %u in metadata cache", len, offset);

	if (offset + len > cache->cache_alloc_size) {
		ret = extend_metadata_cache(channel,
				len - cache->cache_alloc_size + offset);
		if (ret < 0) {
			ERR("Extending metadata cache");
			status = CONSUMER_METADATA_CACHE_WRITE_STATUS_ERROR;
			goto end;
		}
	}

	memcpy(cache->data + offset, data, len);
	cache->max_offset = max(cache->max_offset, offset + len);

	if (cache_is_invalidated) {
		status = CONSUMER_METADATA_CACHE_WRITE_STATUS_INVALIDATED;
	} else if (cache->max_offset > original_max_offset) {
		status = CONSUMER_METADATA_CACHE_WRITE_STATUS_APPENDED_CONTENT;
	} else {
		status = CONSUMER_METADATA_CACHE_WRITE_STATUS_NO_CHANGE;
		assert(cache->max_offset == original_max_offset);
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

	assert(channel);
	assert(!channel->is_deleted);

	channel->metadata_cache = zmalloc(
			sizeof(struct consumer_metadata_cache));
	if (!channel->metadata_cache) {
		PERROR("zmalloc metadata cache struct");
		ret = -1;
		goto end;
	}
	ret = pthread_mutex_init(&channel->metadata_cache->lock, NULL);
	if (ret != 0) {
		PERROR("mutex init");
		goto end_free_cache;
	}

	channel->metadata_cache->cache_alloc_size = DEFAULT_METADATA_CACHE_SIZE;
	channel->metadata_cache->data = zmalloc(
			channel->metadata_cache->cache_alloc_size * sizeof(char));
	if (!channel->metadata_cache->data) {
		PERROR("zmalloc metadata cache data");
		ret = -1;
		goto end_free_mutex;
	}
	DBG("Allocated metadata cache of %" PRIu64 " bytes",
			channel->metadata_cache->cache_alloc_size);

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
	free(channel->metadata_cache->data);
	free(channel->metadata_cache);
}

/*
 * Check if the cache is flushed up to the offset passed in parameter.
 *
 * Return 0 if everything has been flushed, 1 if there is data not flushed.
 */
int consumer_metadata_cache_flushed(struct lttng_consumer_channel *channel,
		uint64_t offset, int timer)
{
	int ret = 0;
	struct lttng_consumer_stream *metadata_stream;

	assert(channel);
	assert(!channel->is_deleted);
	assert(channel->metadata_cache);

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
		ret = 0;
		goto end_unlock_channel;
	}

	pthread_mutex_lock(&metadata_stream->lock);
	pthread_mutex_lock(&channel->metadata_cache->lock);

	if (metadata_stream->ust_metadata_pushed >= offset) {
		ret = 0;
	} else if (channel->metadata_stream->endpoint_status !=
			CONSUMER_ENDPOINT_ACTIVE) {
		/* An inactive endpoint means we don't have to flush anymore. */
		ret = 0;
	} else {
		/* Still not completely flushed. */
		ret = 1;
	}

	pthread_mutex_unlock(&channel->metadata_cache->lock);
	pthread_mutex_unlock(&metadata_stream->lock);
end_unlock_channel:
	pthread_mutex_unlock(&channel->timer_lock);
	if (!timer) {
		pthread_mutex_unlock(&channel->lock);
	}

	return ret;
}
