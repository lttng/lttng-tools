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

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return codes for lttng_rotation_handle_get_state()
 */
enum lttng_rotation_state {
	/*
	 * Rotation is ongoing, but has not been completed yet.
	 */
	LTTNG_ROTATION_STATE_ONGOING = 0,
	/*
	 * Rotation has been completed and the resulting chunk
	 * can now safely be read.
	 */
	LTTNG_ROTATION_STATE_COMPLETED = 1,
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
	LTTNG_ROTATION_STATE_EXPIRED = 2,
	/*
	 * The rotation could not be completed due to an error.
	 */
	LTTNG_ROTATION_STATE_ERROR = 3,
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
 * Return a newly allocated immediate session rotation descriptor object or NULL
 * on error.
 */
extern struct lttng_rotation_immediate_attr *
lttng_rotation_immediate_attr_create(void);

/*
 * Return a newly allocated scheduled rotate session descriptor object or NULL
 * on error.
 */
extern struct lttng_rotation_schedule_attr *
lttng_rotation_schedule_attr_create(void);

/*
 * Destroy a given immediate session rotation descriptor object.
 */
extern void lttng_rotation_immediate_attr_destroy(
		struct lttng_rotation_immediate_attr *attr);

/*
 * Destroy a given scheduled rotate session descriptor object.
 */
extern void lttng_rotation_schedule_attr_destroy(
		struct lttng_rotation_schedule_attr *attr);

/*
 * Set the name of the session to rotate immediately.
 *
 * The session_name parameter is copied to the immediate session rotation
 * attributes.
 */
extern enum lttng_rotation_status lttng_rotation_immediate_attr_set_session_name(
		struct lttng_rotation_immediate_attr *attr,
		const char *session_name);

/*
 * Set the name of the session to rotate automatically.
 *
 * The session_name parameter is copied to the immediate session rotation
 * attributes.
 */
extern enum lttng_rotation_status lttng_rotation_schedule_attr_set_session_name(
		struct lttng_rotation_schedule_attr *attr,
		const char *session_name);

/*
 * Set the timer to periodically rotate the session (µs, -1ULL to disable).
 */
extern enum lttng_rotation_status lttng_rotation_schedule_attr_set_timer_period(
		struct lttng_rotation_schedule_attr *attr, uint64_t timer);

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
 * The path returned is owned by the rotation handle.
 *
 * Note that path will not be set in case of error, or if the session
 * rotation has expired.
 *
 * FIXME: Return an lttng_location object instead of a path.
 */
extern enum lttng_rotation_status lttng_rotation_handle_get_completed_archive_location(
		struct lttng_rotation_handle *rotation_handle,
		const char **path);

/*
 * Destroy an lttng_rotate_session handle.
 */
extern void lttng_rotation_handle_destroy(
		struct lttng_rotation_handle *rotation_handle);

/*
 * Rotate the output folder of the session
 *
 * On success, handle is allocated and can be used to monitor the progress
 * of the rotation with lttng_rotation_get_state(). The handle must be freed
 * by the caller with lttng_rotation_handle_destroy().
 *
 * Return 0 if the rotate action was successfully launched or a negative
 * LTTng error code on error.
 */
extern int lttng_rotate_session(struct lttng_rotation_immediate_attr *attr,
		struct lttng_rotation_handle **rotation_handle);

/*
 * Configure a session to rotate periodically or based on the size written.
 */
extern int lttng_rotation_set_schedule(
		struct lttng_rotation_schedule_attr *attr);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ROTATION_H */
