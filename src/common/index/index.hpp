/*
 * SPDX-FileCopyrightText: 2013 Julien Desfossez <jdesfossez@efficios.com>
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 * SPDX-FileCopyrightText: 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _INDEX_H
#define _INDEX_H

#include "ctf-index.hpp"

#include <common/fs-handle.hpp>
#include <common/trace-chunk.hpp>

#include <inttypes.h>
#include <urcu/ref.h>

struct lttng_index_file {
	struct fs_handle *file;
	uint32_t major;
	uint32_t minor;
	uint32_t element_len;
	struct lttng_trace_chunk *trace_chunk;
	struct urcu_ref ref;
};

/*
 * create and open have refcount of 1. Use put to decrement the
 * refcount. Destroys when reaching 0. Use "get" to increment refcount.
 */
enum lttng_trace_chunk_status
lttng_index_file_create_from_trace_chunk(struct lttng_trace_chunk *chunk,
					 const char *channel_path,
					 const char *stream_name,
					 uint64_t stream_file_size,
					 uint64_t stream_count,
					 uint32_t index_major,
					 uint32_t index_minor,
					 bool unlink_existing_file,
					 struct lttng_index_file **file);

enum lttng_trace_chunk_status
lttng_index_file_create_from_trace_chunk_read_only(struct lttng_trace_chunk *chunk,
						   const char *channel_path,
						   const char *stream_name,
						   uint64_t stream_file_size,
						   uint64_t stream_file_index,
						   uint32_t index_major,
						   uint32_t index_minor,
						   bool expect_no_file,
						   struct lttng_index_file **file);

int lttng_index_file_write(const struct lttng_index_file *index_file,
			   const struct ctf_packet_index *element);
int lttng_index_file_read(const struct lttng_index_file *index_file,
			  struct ctf_packet_index *element);

void lttng_index_file_get(struct lttng_index_file *index_file);
void lttng_index_file_put(struct lttng_index_file *index_file);

#endif /* _INDEX_H */
