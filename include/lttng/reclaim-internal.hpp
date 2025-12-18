/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_RECLAIM_INTERNAL_ABI_H
#define LTTNG_RECLAIM_INTERNAL_ABI_H

#include <common/macros.hpp>

#include <lttng/domain.h>
#include <lttng/lttng.h>

/*
 * Payload for the LTTCOMM_SESSIOND_COMMAND_RECLAIM_CHANNEL_MEMORY command.
 * Sent after the lttcomm_lttng_msg header on success.
 */
struct lttng_reclaim_channel_memory_return {
	uint64_t reclaimed_subbuffer_count;
	uint64_t pending_subbuffer_count;
} LTTNG_PACKED;

/*
 * Async completion message sent by the session daemon when all pending
 * memory reclamation has completed. This is sent after the initial
 * lttng_reclaim_channel_memory_return response.
 */
struct lttng_reclaim_channel_memory_async_completion {
	/* lttng_reclaim_channel_memory_status code. */
	int8_t status;
} LTTNG_PACKED;

#endif /* LTTNG_RECLAIM_INTERNAL_ABI_H */
