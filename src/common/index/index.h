/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2016 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#ifndef _INDEX_H
#define _INDEX_H

#include <inttypes.h>
#include <urcu/ref.h>

#include "ctf-index.h"

struct lttng_index_file {
	int fd;
	uint32_t major;
	uint32_t minor;
	uint32_t element_len;
	struct urcu_ref ref;
};

/*
 * create and open have refcount of 1. Use put to decrement the
 * refcount. Destroys when reaching 0. Use "get" to increment refcount.
 */
struct lttng_index_file *lttng_index_file_create(char *path_name,
		char *stream_name, int uid, int gid, uint64_t size,
		uint64_t count, uint32_t major, uint32_t minor);
struct lttng_index_file *lttng_index_file_open(const char *path_name,
		const char *channel_name, uint64_t tracefile_count,
		uint64_t tracefile_count_current);
int lttng_index_file_write(const struct lttng_index_file *index_file,
		const struct ctf_packet_index *element);
int lttng_index_file_read(const struct lttng_index_file *index_file,
		struct ctf_packet_index *element);

void lttng_index_file_get(struct lttng_index_file *index_file);
void lttng_index_file_put(struct lttng_index_file *index_file);

#endif /* _INDEX_H */
