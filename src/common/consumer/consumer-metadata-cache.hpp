/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef CONSUMER_METADATA_CACHE_H
#define CONSUMER_METADATA_CACHE_H

#include <common/consumer/consumer.hpp>
#include <common/dynamic-buffer.hpp>

enum consumer_metadata_cache_write_status {
	CONSUMER_METADATA_CACHE_WRITE_STATUS_ERROR = -1,
	/*
	 * New metadata content was appended to the cache successfully.
	 * Previously available content remains valid.
	 */
	CONSUMER_METADATA_CACHE_WRITE_STATUS_APPENDED_CONTENT = 0,
	/*
	 * The new content pushed to the cache invalidated the content that
	 * was already present. The contents of the cache should be re-read.
	 */
	CONSUMER_METADATA_CACHE_WRITE_STATUS_INVALIDATED,
	/*
	 * A metadata cache write can simply overwrite an already existing
	 * section of the cache (and it should be a write-through with identical
	 * data). From the caller's standpoint, there is no change to the state
	 * of the cache.
	 */
	CONSUMER_METADATA_CACHE_WRITE_STATUS_NO_CHANGE,
};

struct consumer_metadata_cache {
	/* Current version of the metadata cache. */
	uint64_t version;
	/*
	 * Size is the upper-limit of data written inside the buffer.
	 * All cached data is contiguous.
	 */
	struct lttng_dynamic_buffer contents;
	/*
	 * Lock to update the metadata cache and push into the ring_buffer
	 * (lttng_ust_ctl_write_metadata_to_channel).
	 *
	 * This is nested INSIDE the consumer_data lock.
	 */
	pthread_mutex_t lock;
};

enum consumer_metadata_cache_write_status
consumer_metadata_cache_write(struct consumer_metadata_cache *cache,
			      unsigned int offset,
			      unsigned int len,
			      uint64_t version,
			      const char *data);
int consumer_metadata_cache_allocate(struct lttng_consumer_channel *channel);
void consumer_metadata_cache_destroy(struct lttng_consumer_channel *channel);
void consumer_wait_metadata_cache_flushed(struct lttng_consumer_channel *channel,
					  uint64_t offset,
					  bool invoked_by_timer);

#endif /* CONSUMER_METADATA_CACHE_H */
