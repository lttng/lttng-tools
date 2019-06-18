/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_DESTRUCTION_HANDLE_H
#define LTTNG_DESTRUCTION_HANDLE_H

#include <lttng/rotation.h>
#include <lttng/lttng-error.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_destruction_handle;

enum lttng_destruction_handle_status {
	LTTNG_DESTRUCTION_HANDLE_STATUS_ERROR = -2,
	LTTNG_DESTRUCTION_HANDLE_STATUS_INVALID = -1,
	LTTNG_DESTRUCTION_HANDLE_STATUS_OK = 0,
	LTTNG_DESTRUCTION_HANDLE_STATUS_COMPLETED = 1,
	LTTNG_DESTRUCTION_HANDLE_STATUS_TIMEOUT = 2,
};

extern void lttng_destruction_handle_destroy(
		struct lttng_destruction_handle *handle);

extern enum lttng_destruction_handle_status
lttng_destruction_handle_wait_for_completion(
		struct lttng_destruction_handle *handle, int timeout_ms);

extern enum lttng_destruction_handle_status
lttng_destruction_handle_get_result(
		const struct lttng_destruction_handle *handle,
		enum lttng_error_code *result);

extern enum lttng_destruction_handle_status
lttng_destruction_handle_get_rotation_state(
		const struct lttng_destruction_handle *handle,
		enum lttng_rotation_state *rotation_state);

extern enum lttng_destruction_handle_status
lttng_destruction_handle_get_archive_location(
		const struct lttng_destruction_handle *handle,
		const struct lttng_trace_archive_location **location);

#endif /* LTTNG_DESTRUCTION_HANDLE_H */
