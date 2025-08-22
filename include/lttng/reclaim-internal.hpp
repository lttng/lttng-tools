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

/* For the LTTCOMM_SESSIOND_COMMAND_RECLAIM_CHANNEL_MEMORY command. */
struct lttng_reclaim_channel_memory_return {
	uint64_t reclaimed_memory_size_bytes;
	uint64_t pending_memory_size_bytes;
} LTTNG_PACKED;

#endif /* LTTNG_RECLAIM_INTERNAL_ABI_H */
