/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_TRACE_CHUNK_REGISTRY_H
#define LTTNG_TRACE_CHUNK_REGISTRY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <common/macros.h>
#include <common/trace-chunk.h>

struct lttng_trace_chunk_registry;

/*
 * Create an lttng_trace_chunk registry.
 *
 * A trace chunk registry maintains an association between a
 * (session_id, chunk_id) tuple and a trace chunk object. The chunk_id can
 * be "unset" in the case of an anonymous trace chunk.
 *
 * Note that a trace chunk registry holds no ownership of its trace
 * chunks. Trace chunks are unpublished when their last reference is released.
 * See the documentation of lttng_trace_chunk.
 *
 * Returns a trace chunk registry on success, NULL on error.
 *
 * Note that a trace chunk registry may only be accessed by an RCU thread.
 */
LTTNG_HIDDEN
struct lttng_trace_chunk_registry *lttng_trace_chunk_registry_create(void);

/*
 * Destroy an lttng trace chunk registry. The registry must be emptied
 * (i.e. all references to the trace chunks it contains must be released) before
 * it is destroyed.
 */
LTTNG_HIDDEN
void lttng_trace_chunk_registry_destroy(
		struct lttng_trace_chunk_registry *registry);

/*
 * Publish a trace chunk for a given session id.
 * A reference is acquired on behalf of the caller.
 *
 * The trace chunk that is returned is the published version of the trace
 * chunk. The chunk provided should be discarded on success and it's
 * published version used in its place.
 *
 * See the documentation of lttng_trace_chunk for more information on
 * the usage of the various parameters.
 *
 * Returns an lttng_trace_chunk on success, NULL on error.
 */
LTTNG_HIDDEN
struct lttng_trace_chunk *lttng_trace_chunk_registry_publish_chunk(
		struct lttng_trace_chunk_registry *registry,
		uint64_t session_id, struct lttng_trace_chunk *chunk);

/*
 * Look-up a trace chunk by session_id and chunk_id.
 * A reference is acquired on behalf of the caller.
 *
 * Returns an lttng_trace_chunk on success, NULL if the chunk does not exist.
 */
LTTNG_HIDDEN
struct lttng_trace_chunk *
lttng_trace_chunk_registry_find_chunk(
		const struct lttng_trace_chunk_registry *registry,
		uint64_t session_id, uint64_t chunk_id);

/*
 * Look-up an anonymous trace chunk by session_id.
 * A reference is acquired on behalf of the caller.
 *
 * Returns an lttng_trace_chunk on success, NULL if the chunk does not exist.
 */
LTTNG_HIDDEN
struct lttng_trace_chunk *
lttng_trace_chunk_registry_find_anonymous_chunk(
		const struct lttng_trace_chunk_registry *registry,
		uint64_t session_id);

LTTNG_HIDDEN
unsigned int lttng_trace_chunk_registry_put_each_chunk(
		struct lttng_trace_chunk_registry *registry);

#endif /* LTTNG_TRACE_CHUNK_REGISTRY_H */
