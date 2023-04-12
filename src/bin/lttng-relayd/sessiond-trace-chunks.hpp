/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef SESSIOND_TRACE_CHUNK_REGISTRY_H
#define SESSIOND_TRACE_CHUNK_REGISTRY_H

#include <common/trace-chunk.hpp>
#include <common/uuid.hpp>

#include <stdint.h>

/*
 * A session trace chunk registry allows the relay daemon to share trace chunks
 * used by different "relay sessions" when they were created for the same
 * user-visible session daemon session. Tracing multiple domains (e.g. ust and
 * kernel) results in per-domain relay sessions being created.
 *
 * Sharing trace chunks, and their output directory more specifically, is
 * essential to properly implement session rotations. The sharing of output
 * directory handles allows directory renames to be performed once and without
 * races that would stem from from multiple renames.
 */
struct sessiond_trace_chunk_registry;

struct sessiond_trace_chunk_registry *sessiond_trace_chunk_registry_create(void);

void sessiond_trace_chunk_registry_destroy(struct sessiond_trace_chunk_registry *sessiond_registry);

int sessiond_trace_chunk_registry_session_created(
	struct sessiond_trace_chunk_registry *sessiond_registry, const lttng_uuid& sessiond_uuid);

int sessiond_trace_chunk_registry_session_destroyed(
	struct sessiond_trace_chunk_registry *sessiond_registry, const lttng_uuid& sessiond_uuid);

struct lttng_trace_chunk *
sessiond_trace_chunk_registry_publish_chunk(struct sessiond_trace_chunk_registry *sessiond_registry,
					    const lttng_uuid& sessiond_uuid,
					    uint64_t session_id,
					    struct lttng_trace_chunk *chunk);

struct lttng_trace_chunk *sessiond_trace_chunk_registry_get_anonymous_chunk(
	struct sessiond_trace_chunk_registry *sessiond_registry,
	const lttng_uuid& sessiond_uuid,
	uint64_t session_id);

struct lttng_trace_chunk *
sessiond_trace_chunk_registry_get_chunk(struct sessiond_trace_chunk_registry *sessiond_registry,
					const lttng_uuid& sessiond_uuid,
					uint64_t session_id,
					uint64_t chunk_id);

int sessiond_trace_chunk_registry_chunk_exists(
	struct sessiond_trace_chunk_registry *sessiond_registry,
	const lttng_uuid& sessiond_uuid,
	uint64_t session_id,
	uint64_t chunk_id,
	bool *chunk_exists);

#endif /* SESSIOND_TRACE_CHUNK_REGISTRY_H */
