/*
 * SPDX-FileCopyrightText: 2017 Julien Desfossez <jdesfossez@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ROTATE_INTERNAL_ABI_H
#define LTTNG_ROTATE_INTERNAL_ABI_H

#include <common/macros.hpp>

#include <lttng/constant.h>
#include <lttng/rotation.h>

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

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
	struct lttng_trace_archive_location *archive_location;
};

struct lttng_rotation_schedule {
	enum lttng_rotation_schedule_type type;
};

struct lttng_rotation_schedule_size_threshold {
	struct lttng_rotation_schedule parent;
	struct {
		bool set;
		uint64_t bytes;
	} size;
};

struct lttng_rotation_schedule_periodic {
	struct lttng_rotation_schedule parent;
	struct {
		bool set;
		uint64_t us;
	} period;
};

struct lttng_rotation_schedules {
	/*
	 * Only one rotation schedule per type is supported for now.
	 * Schedules are owned by this object.
	 */
	unsigned int count;
	struct lttng_rotation_schedule *schedules[2];
};

/*
 * Internal objects between lttng-ctl and the session daemon, the values
 * are then copied to the user's lttng_rotation_handle object.
 */

/* For the LTTCOMM_SESSIOND_COMMAND_ROTATE_SESSION command. */
struct lttng_rotate_session_return {
	uint64_t rotation_id;
} LTTNG_PACKED;

/* For the LTTCOMM_SESSIOND_COMMAND_ROTATION_GET_INFO command. */
struct lttng_rotation_get_info_return {
	/* Represents values defined in enum lttng_rotation_state. */
	int32_t status;
	/*
	 * Represents values defined in enum lttng_trace_archive_location_type.
	 */
	int8_t location_type;
	union {
		struct {
			char absolute_path[LTTNG_PATH_MAX];
		} LTTNG_PACKED local;
		struct {
			char host[LTTNG_HOST_NAME_MAX];
			/*
			 * Represents values defined in
			 * enum lttng_trace_archive_location_relay_protocol_type.
			 */
			int8_t protocol;
			struct {
				uint16_t control;
				uint16_t data;
			} LTTNG_PACKED ports;
			char relative_path[LTTNG_PATH_MAX];
		} LTTNG_PACKED relay;
	} location;
} LTTNG_PACKED;

/* For the LTTNG_SESSION_LIST_SCHEDULES command. */
struct lttng_session_list_schedules_return {
	struct {
		uint8_t set;
		uint64_t value;
	} LTTNG_PACKED periodic;
	struct {
		uint8_t set;
		uint64_t value;
	} LTTNG_PACKED size;
} LTTNG_PACKED;

#endif /* LTTNG_ROTATE_INTERNAL_ABI_H */
