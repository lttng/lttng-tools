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

#ifndef LTTNG_ROTATION_H
#define LTTNG_ROTATION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return codes for lttng_rotation_handle_get_output_path.
 */
enum lttng_rotation_status {
	/*
	 * After starting a rotation.
	 */
	LTTNG_ROTATION_STATUS_STARTED = 0,
	/*
	 * When the rotation is complete.
	 */
	LTTNG_ROTATION_STATUS_COMPLETED = 1,
	/*
	 * If the handle does not match the last rotate command, we cannot
	 * retrieve the path for the chunk.
	 */
	LTTNG_ROTATION_STATUS_EXPIRED = 2,
	/*
	 * On error.
	 */
	LTTNG_ROTATION_STATUS_ERROR = 3,
	/*
	 * If no rotation occured during this session.
	 */
	LTTNG_ROTATION_STATUS_NO_ROTATION = 4,
};

/*
 * Input parameter to the lttng_rotate_session command.
 * The lttng_rotation_manual_attr object is opaque to the user. Use the helper
 * functions below to use it.
 */
struct lttng_rotation_manual_attr;

/*
 * Input parameter to the lttng_rotate_schedule command.
 * The lttng_rotation_schedule_attr object is opaque to the user. Use the helper
 * functions below to use it.
 */
struct lttng_rotation_schedule_attr;

/*
 * Handle used to check the progress of a rotation.
 * This object is opaque to the user. Use the helper functions below to use it.
 */
struct lttng_rotation_handle;

/*
 * lttng rotate session command inputs.
 */
/*
 * Return a newly allocated manual rotate session descriptor object or NULL on error.
 */
struct lttng_rotation_manual_attr *lttng_rotation_manual_attr_create(void);

/*
 * Return a newly allocated scheduled rotate session descriptor object or NULL on error.
 */
struct lttng_rotation_schedule_attr *lttng_rotation_schedule_attr_create(void);

/*
 * Free a given manual rotate session descriptor object.
 */
void lttng_rotation_manual_attr_destroy(struct lttng_rotation_manual_attr *attr);

/*
 * Free a given scheduled rotate session descriptor object.
 */
void lttng_rotation_schedule_attr_destroy(struct lttng_rotation_schedule_attr *attr);

/*
 * Set the name of the session to rotate manually.
 */
int lttng_rotation_manual_attr_set_session_name(
		struct lttng_rotation_manual_attr *attr, const char *session_name);

/*
 * Set the name of the session to rotate automatically.
 */
int lttng_rotation_schedule_attr_set_session_name(
		struct lttng_rotation_schedule_attr *attr, const char *session_name);

/*
 * Set the timer to periodically rotate the session (µs, -1ULL to disable).
 */
void lttng_rotation_schedule_attr_set_timer_period(
		struct lttng_rotation_schedule_attr *attr, uint64_t timer);

/*
 * lttng rotate session handle functions.
 */
/*
 * Get the status from a handle.
 */
enum lttng_rotation_status lttng_rotation_handle_get_status(
		struct lttng_rotation_handle *rotation_handle);

/*
 * If the rotation is complete, returns 0, allocate path and set
 * it to the path of the readable chunk, the caller is responsible to free it.
 * Otherwise return a negative value.
 */
int lttng_rotation_handle_get_output_path(
		struct lttng_rotation_handle *rotation_handle,
		char **path);

/*
 * Destroy a lttng_rotate_session handle allocated by lttng_rotate_session()
 */
void lttng_rotation_handle_destroy(
		struct lttng_rotation_handle *rotation_handle);

/*
 * Rotate the output folder of the session
 *
 * On success, handle is allocated and can be used to monitor the progress
 * of the rotation with lttng_rotation_is_pending(). The handle must be freed
 * by the caller with lttng_rotation_handle_destroy().
 *
 * Return 0 if the rotate action was successfully launched or a negative
 * LTTng error code on error.
 */
extern int lttng_rotate_session(struct lttng_rotation_manual_attr *attr,
		struct lttng_rotation_handle **rotation_handle);

/*
 * For a given rotation handle, this call checks if a session rotation is still in
 * progress or has completed.
 *
 * Return 0 if the rotation is complete, in this case, the output path can be
 * fetched with lttng_rotation_handle_get_output_path().
 * Return 1 if the rotate is still pending.
 * Return a negative LTTng error code on error (readable with lttng_strerror).
 */
extern int lttng_rotation_is_pending(struct lttng_rotation_handle *rotation_handle);

/*
 * Ask the session daemon where the data for this session is currently being
 * written to. If rotations occured during a session, this call is useful to
 * know the location of the last chunk.
 *
 * Return 0 and allocate chunk_path if rotations occured for this session, the
 * caller needs to free chunk_path.
 * Return 1 if no rotation occured during the session, chunk_path is left
 * unallocated.
 * Return -1 on error.
 */
extern int lttng_rotation_get_current_path(const char *session_name,
		char **chunk_path);

/*
 * Configure a session to rotate periodically or based on the size written.
 */
extern int lttng_rotation_set_schedule(struct lttng_rotation_schedule_attr *attr);


#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ROTATION_H */
