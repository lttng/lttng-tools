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

#ifndef CONSUMER_METADATA_CACHE_H
#define CONSUMER_METADATA_CACHE_H

#include <common/consumer/consumer.h>

struct consumer_metadata_cache {
	char *data;
	uint64_t cache_alloc_size;
	/*
	 * Current version of the metadata cache.
	 */
	uint64_t version;
	/*
	 * The upper-limit of data written inside the buffer.
	 *
	 * With the total_bytes_written it allows us to keep track of when the
	 * cache contains contiguous metadata ready to be sent to the RB.
	 * All cached data is contiguous.
	 */
	uint64_t max_offset;
	/*
	 * Lock to update the metadata cache and push into the ring_buffer
	 * (ustctl_write_metadata_to_channel).
	 *
	 * This is nested INSIDE the consumer_data lock.
	 */
	pthread_mutex_t lock;
};

int consumer_metadata_cache_write(struct lttng_consumer_channel *channel,
		unsigned int offset, unsigned int len, uint64_t version,
		char *data);
int consumer_metadata_cache_allocate(struct lttng_consumer_channel *channel);
void consumer_metadata_cache_destroy(struct lttng_consumer_channel *channel);
int consumer_metadata_cache_flushed(struct lttng_consumer_channel *channel,
		uint64_t offset, int timer);

#endif /* CONSUMER_METADATA_CACHE_H */
