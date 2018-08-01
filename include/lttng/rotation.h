/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef LTTNG_ROTATION_H
#define LTTNG_ROTATION_H

#include <stdint.h>
#include <lttng/location.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return codes for lttng_rotation_handle_get_state()
 */
enum lttng_rotation_state {
	/*
	 * Session has not been rotated.
	 */
	LTTNG_ROTATION_STATE_NO_ROTATION = 0,
	/*
	 * Rotation is ongoing, but has not been completed yet.
	 */
	LTTNG_ROTATION_STATE_ONGOING = 1,
	/*
	 * Rotation has been completed and the resulting chunk
	 * can now safely be read.
	 */
	LTTNG_ROTATION_STATE_COMPLETED = 2,
	/*
	 * The rotation has expired.
	 *
	 * The information associated with a given rotation is eventually
	 * purged by the session daemon. In such a case, the attributes of
	 * the rotation, such as its path, may no longer be available.
	 *
	 * Note that this state does not guarantee the the rotation was
	 * completed successfully.
	 */
	LTTNG_ROTATION_STATE_EXPIRED = 3,
	/*
	 * The rotation could not be completed due to an error.
	 */
	LTTNG_ROTATION_STATE_ERROR = 4,
};

enum lttng_rotation_status {
	LTTNG_ROTATION_STATUS_OK = 0,
	/* Information not available. */
	LTTNG_ROTATION_STATUS_UNAVAILABLE = 1,
	/* Generic error. */
	LTTNG_ROTATION_STATUS_ERROR = -1,
	/* Invalid parameters provided. */
	LTTNG_ROTATION_STATUS_INVALID = -2,
};

/*
 * Input parameter to the lttng_rotate_session command.
 *
 * An immediate rotation is performed as soon as possible by the tracers.
 */
struct lttng_rotation_immediate_attr;

/*
 * Input parameter to the lttng_rotate_schedule command.
 */
struct lttng_rotation_schedule_attr;

/*
 * Handle used to represent a specific rotation.
 */
struct lttng_rotation_handle;

/*
 * Return a newly allocated session rotation schedule descriptor object or NULL
 * on error.
 *
 * The rotation schedule may be expressed as a size or as a time period.
 */
extern struct lttng_rotation_schedule_attr *
lttng_rotation_schedule_attr_create(void);

/*
 * Destroy a given scheduled rotate session descriptor object.
 */
extern void lttng_rotation_schedule_attr_destroy(
		struct lttng_rotation_schedule_attr *attr);

/*
 * Set the timer to periodically rotate the session (in µs).
 */
extern enum lttng_rotation_status lttng_rotation_schedule_attr_set_timer_period(
		struct lttng_rotation_schedule_attr *attr, uint64_t timer);

/*
 * Set the size to rotate the session (in bytes).
 */
void lttng_rotation_schedule_attr_set_size(
		struct lttng_rotation_schedule_attr *attr, uint64_t size);

/*
 * lttng rotate session handle functions.
 */

/*
 * Get the current state of the rotation referenced by the handle.
 *
 * This will issue a request to the session daemon on every call. Hence,
 * the result of this call may change over time.
 */
extern enum lttng_rotation_status lttng_rotation_handle_get_state(
		struct lttng_rotation_handle *rotation_handle,
		enum lttng_rotation_state *rotation_state);

/*
 * Get the location of the rotation's resulting archive.
 *
 * The rotation must be completed in order for this call to succeed.
 * The location returned remains owned by the rotation handle.
 *
 * Note that location will not be set in case of error, or if the session
 * rotation handle has expired.
 */
extern enum lttng_rotation_status lttng_rotation_handle_get_archive_location(
		struct lttng_rotation_handle *rotation_handle,
		const struct lttng_trace_archive_location **location);

/*
 * Destroy an lttng_rotate_session handle.
 */
extern void lttng_rotation_handle_destroy(
		struct lttng_rotation_handle *rotation_handle);

/*
 * Rotate the output folder of the session.
 *
 * On success, handle is allocated and can be used to monitor the progress
 * of the rotation with lttng_rotation_get_state(). The handle must be freed
 * by the caller with lttng_rotation_handle_destroy().
 *
 * Passing NULL as the immediate rotation attribute results in the default
 * options being used.
 *
 * Return 0 if the rotate action was successfully launched or a negative
 * LTTng error code on error.
 */
extern int lttng_rotate_session(const char *session_name,
		struct lttng_rotation_immediate_attr *attr,
		struct lttng_rotation_handle **rotation_handle);

/*
 * Configure a session to rotate according to a given schedule.
 */
extern int lttng_rotation_set_schedule(const char *session_name,
		struct lttng_rotation_schedule_attr *attr);

/*
 * Ask the sessiond for the value of the rotate timer (in micro-seconds) of the
 * session.
 *
 * On success, return 0 and set the value or rotate_timer, on error return a
 * negative value.
 */
extern int lttng_rotation_schedule_get_timer_period(const char *session_name,
		uint64_t *rotate_timer);

/*
 * Ask the sessiond for the value of the rotate size (in micro-seconds) of the
 * session.
 *
 * On success, return 0 and set the value or rotate_size, on error return
 * a negative value.
 */
extern int lttng_rotation_schedule_get_size(const char *session_name,
		uint64_t *rotate_size);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ROTATION_H */
