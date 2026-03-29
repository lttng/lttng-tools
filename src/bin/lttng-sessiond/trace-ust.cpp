/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "trace-ust.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/utils.hpp>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace lsu = lttng::sessiond::ust;

/*
 * Allocate and initialize a ust session data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_session *trace_ust_create_session(uint64_t session_id)
{
	struct ltt_ust_session *lus;

	/* Allocate a new ltt ust session */
	lus = zmalloc<ltt_ust_session>();
	if (lus == nullptr) {
		PERROR("create ust session zmalloc");
		goto error_alloc;
	}

	/* Init data structure */
	lus->id = session_id;
	lus->active = false;

	/*
	 * Default buffer type. Locked to the first explicitly requested
	 * type by the UST domain orchestrator.
	 */
	lus->buffer_type = LTTNG_BUFFER_PER_UID;
	/* Alloc agent hash table. */
	lus->agents = lttng_ht_new(0, LTTNG_HT_TYPE_U64);

	lus->consumer = consumer_create_output(CONSUMER_DST_LOCAL);
	if (lus->consumer == nullptr) {
		goto error;
	}

	DBG2("UST trace session create successful");

	return lus;

error:
	lttng_ht_destroy(lus->agents);
	free(lus);
error_alloc:
	return nullptr;
}

/*
 * Cleanup ust session structure, keeping data required by
 * destroy notifier.
 */
void trace_ust_destroy_session(struct ltt_ust_session *session)
{
	LTTNG_ASSERT(session);

	DBG2("Trace UST destroy session %" PRIu64, session->id);
}

/* Free elements needed by destroy notifiers. */
void trace_ust_free_session(struct ltt_ust_session *session)
{
	free(session);
}

bool trace_ust_runtime_ctl_version_matches_build_version()
{
	uint32_t major, minor, patch_level;

	if (lttng_ust_ctl_get_version(&major, &minor, &patch_level)) {
		ERR("Failed to get liblttng-ust-ctl.so version");
		return false;
	}

	if (major != VERSION_MAJOR || minor != VERSION_MINOR) {
		ERR_FMT("Mismatch between liblttng-ust-ctl.so runtime version ({}.{}) and build version ({}.{})",
			major,
			minor,
			VERSION_MAJOR,
			VERSION_MINOR);
		return false;
	}

	return true;
}
