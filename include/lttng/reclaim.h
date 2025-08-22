/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_RECLAIM_H
#define LTTNG_RECLAIM_H

#include <lttng/domain.h>
#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_reclaim_handle;

enum lttng_reclaim_channel_memory_status {
	LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_OK = 0,
	LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_ERROR = -1,
	LTTNG_RECLAIM_CHANNEL_MEMORY_STATUS_INVALID_PARAMETER = -2,
};

enum lttng_reclaim_handle_status {
	LTTNG_RECLAIM_HANDLE_STATUS_OK = 0,
	LTTNG_RECLAIM_HANDLE_STATUS_COMPLETED = 1,
	LTTNG_RECLAIM_HANDLE_STATUS_TIMEOUT = 2,
	LTTNG_RECLAIM_HANDLE_STATUS_INVALID = -1,
	LTTNG_RECLAIM_HANDLE_STATUS_ERROR = -2,
};

LTTNG_EXPORT extern enum lttng_reclaim_channel_memory_status
lttng_reclaim_channel_memory(const char *session_name,
			     const char *channel_name,
			     enum lttng_domain_type domain,
			     uint64_t older_than_us,
			     struct lttng_reclaim_handle **handle);

LTTNG_EXPORT extern void lttng_reclaim_handle_destroy(struct lttng_reclaim_handle *handle);
LTTNG_EXPORT extern enum lttng_reclaim_handle_status
lttng_reclaim_handle_wait_for_completion(struct lttng_reclaim_handle *handle, int timeout_ms);
LTTNG_EXPORT extern enum lttng_reclaim_handle_status
lttng_reclaim_handle_get_reclaimed_memory_size_bytes(const struct lttng_reclaim_handle *handle,
						     uint64_t *memory_size_bytes);
LTTNG_EXPORT extern enum lttng_reclaim_handle_status
lttng_reclaim_handle_get_pending_memory_size_bytes(const struct lttng_reclaim_handle *handle,
						   uint64_t *memory_size_bytes);
#ifdef __cplusplus
}
#endif

#endif /* LTTNG_RECLAIM_H */
