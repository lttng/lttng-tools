/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
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

#ifndef LTTNG_ROTATE_INTERNAL_ABI_H
#define LTTNG_ROTATE_INTERNAL_ABI_H

#include <limits.h>
#include <stdint.h>
#include <stdbool.h>

#include <lttng/constant.h>
#include <lttng/rotation.h>
#include <common/macros.h>

/*
 * Object used as input parameter to the rotate session API for immediate
 * rotations.
 * This is opaque to the public library.
 */
struct lttng_rotation_immediate_attr {
	/* Session name to rotate. */
	char session_name[LTTNG_NAME_MAX];
	/* For the rotate pending request. */
	uint64_t rotate_id;
};

/*
 * Object used as input parameter to the lttng_rotate_schedule API for
 * automatic rotations.
 * This is opaque to the public library.
 */
struct lttng_rotation_schedule_attr {
	/* Session name to rotate. */
	char session_name[LTTNG_NAME_MAX];
	/* > 0 if a timer is set. */
	uint64_t timer_us;
	/* > 0 if the session should rotate when it has written that many bytes. */
	uint64_t size;
} LTTNG_PACKED;

/*
 * Object returned by the rotate session API.
 * This is opaque to the public library.
 */
struct lttng_rotation_handle {
	char session_name[LTTNG_NAME_MAX];
	/*
	 * ID of the rotate command.
	 * This matches the session->rotate_count, so the handle is valid until
	 * the next rotate command. After that, the rotation_get_state command
	 * returns the "expired" state.
	 */
	uint64_t rotation_id;
	/*
	 * Where the rotated (readable) trace has been stored when the
	 * rotation is completed.
	 */
	struct {
		bool is_set;
		char path[LTTNG_PATH_MAX];
	} archive_location;
};

/*
 * Internal objects between lttng-ctl and the session daemon, the values
 * are then copied to the user's lttng_rotation_handle object.
 */

/* For the LTTNG_ROTATE_SESSION command. */
struct lttng_rotate_session_return {
	uint64_t rotation_id;
} LTTNG_PACKED;

/* For the LTTNG_ROTATION_GET_INFO command. */
struct lttng_rotation_get_info_return {
	/* Represents values defined in enum lttng_rotation_state. */
	int32_t status;
	char path[LTTNG_PATH_MAX];
} LTTNG_PACKED;

/* For the LTTNG_SESSION_GET_CURRENT_OUTPUT command. */
struct lttng_session_get_current_output_return {
	char path[LTTNG_PATH_MAX];
} LTTNG_PACKED;

/* For the LTTNG_ROTATION_SCHEDULE_GET_TIMER_PERIOD command. */
struct lttng_rotation_schedule_get_timer_period {
	uint64_t rotate_timer;
} LTTNG_PACKED;

/* For the LTTNG_ROTATION_SCHEDULE_GET_SIZE command. */
struct lttng_rotation_schedule_get_size {
	uint64_t rotate_size;
} LTTNG_PACKED;

#endif /* LTTNG_ROTATE_INTERNAL_ABI_H */
