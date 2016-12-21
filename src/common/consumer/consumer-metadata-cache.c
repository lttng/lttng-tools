/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
 *
 * Returns 0 on success, a negative value on error.
 */
static
int metadata_cache_check_version(struct consumer_metadata_cache *cache,
		struct lttng_consumer_channel *channel, uint64_t version)
{
	int ret = 0;

	if (cache->version == version) {
		goto end;
	}

	DBG("Metadata cache version update to %" PRIu64, version);
	metadata_cache_reset(cache);
	cache->version = version;

end:
	return ret;
}

/*
 * Write metadata to the cache, extend the cache if necessary. We support
 * overlapping updates, but they need to be contiguous. Send the
 * contiguous metadata in cache to the ring buffer. The metadata cache
 * lock MUST be acquired to write in the cache.
 *
 * Return 0 on success, a negative value on error.
 */
int consumer_metadata_cache_write(struct lttng_consumer_channel *channel,
		unsigned int offset, unsigned int len, uint64_t version,
		char *data)
{
	int ret = 0;
	int size_ret;
	struct consumer_metadata_cache *cache;

	assert(channel);
	assert(channel->metadata_cache);

	cache = channel->metadata_cache;

	ret = metadata_cache_check_version(cache, channel, version);
	if (ret < 0) {
		goto end;
	}

	DBG("Writing %u bytes from offset %u in metadata cache", len, offset);

	if (offset + len > cache->cache_alloc_size) {
		ret = extend_metadata_cache(channel,
				len - cache->cache_alloc_size + offset);
		if (ret < 0) {
			ERR("Extending metadata cache");
			goto end;
		}
	}

	memcpy(cache->data + offset, data, len);
	if (offset + len > cache->max_offset) {
		char dummy = 'c';

		cache->max_offset = offset + len;
		if (channel->monitor && channel->metadata_stream) {
			size_ret = lttng_write(channel->metadata_stream->ust_metadata_poll_pipe[1],
					&dummy, 1);
			if (size_ret < 1) {
				ERR("Wakeup UST metadata pipe");
				ret = -1;
				goto end;
			}
		}
	}

end:
	return ret;
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
	pthread_mutex_lock(&channel->metadata_cache->lock);

	metadata_stream = channel->metadata_stream;

	if (!metadata_stream) {
		/*
		 * Having no metadata stream means the channel is being destroyed so there
		 * is no cache to flush anymore.
		 */
		ret = 0;
	} else if (metadata_stream->ust_metadata_pushed >= offset) {
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
	pthread_mutex_unlock(&channel->timer_lock);
	if (!timer) {
		pthread_mutex_unlock(&channel->lock);
	}

	return ret;
}
