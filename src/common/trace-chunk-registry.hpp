/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TRACE_CHUNK_REGISTRY_H
#define LTTNG_TRACE_CHUNK_REGISTRY_H

#include <common/macros.hpp>
#include <common/trace-chunk.hpp>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
struct lttng_trace_chunk_registry *lttng_trace_chunk_registry_create();

/*
 * Destroy an lttng trace chunk registry. The registry must be emptied
 * (i.e. all references to the trace chunks it contains must be released) before
 * it is destroyed.
 */
void lttng_trace_chunk_registry_destroy(struct lttng_trace_chunk_registry *registry);

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
struct lttng_trace_chunk *
lttng_trace_chunk_registry_publish_chunk(struct lttng_trace_chunk_registry *registry,
					 uint64_t session_id,
					 struct lttng_trace_chunk *chunk);
/*
 * Adds the `previously_published` parameter which allows the caller
 * to know if a trace chunk equivalent to `chunk` was previously published.
 *
 * The registry holds a reference to the published trace chunks it contains.
 * Trace chunks automatically unpublish themselves from their registry on
 * destruction.
 *
 * This information is necessary to drop the reference of newly published
 * chunks when a user doesn't wish to explicitly maintain all references
 * to a given trace chunk.
 *
 * For instance, the relay daemon doesn't need the registry to hold a
 * reference since it controls the lifetime of its trace chunks.
 * Conversely, the consumer daemons rely on the session daemon to inform
 * them of the end of life of a trace chunk and the trace chunks don't
 * belong to a specific top-level object: they are always retrieved from
 * the registry by `id`.
 */
struct lttng_trace_chunk *
lttng_trace_chunk_registry_publish_chunk(struct lttng_trace_chunk_registry *registry,
					 uint64_t session_id,
					 struct lttng_trace_chunk *chunk,
					 bool *previously_published);

/*
 * Look-up a trace chunk by session_id and chunk_id.
 * A reference is acquired on behalf of the caller.
 *
 * Returns an lttng_trace_chunk on success, NULL if the chunk does not exist.
 */
struct lttng_trace_chunk *lttng_trace_chunk_registry_find_chunk(
	const struct lttng_trace_chunk_registry *registry, uint64_t session_id, uint64_t chunk_id);

/*
 * Query the existence of a trace chunk by session_id and chunk_id.
 *
 * Returns 0 on success, a negative value on error.
 */
int lttng_trace_chunk_registry_chunk_exists(const struct lttng_trace_chunk_registry *registry,
					    uint64_t session_id,
					    uint64_t chunk_id,
					    bool *chunk_exists);

/*
 * Look-up an anonymous trace chunk by session_id.
 * A reference is acquired on behalf of the caller.
 *
 * Returns an lttng_trace_chunk on success, NULL if the chunk does not exist.
 */
struct lttng_trace_chunk *
lttng_trace_chunk_registry_find_anonymous_chunk(const struct lttng_trace_chunk_registry *registry,
						uint64_t session_id);

unsigned int
lttng_trace_chunk_registry_put_each_chunk(const struct lttng_trace_chunk_registry *registry);

#endif /* LTTNG_TRACE_CHUNK_REGISTRY_H */
