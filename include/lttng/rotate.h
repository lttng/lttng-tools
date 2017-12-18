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

#ifndef LTTNG_ROTATE_H
#define LTTNG_ROTATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return codes for lttng_rotate_session_get_output_path.
 */
enum lttng_rotate_status {
	/*
	 * After starting a rotation.
	 */
	LTTNG_ROTATE_STARTED = 0,
	/*
	 * When the rotation is complete.
	 */
	LTTNG_ROTATE_COMPLETED = 1,
	/*
	 * If the handle does not match the last rotate command, we cannot
	 * retrieve the path for the chunk.
	 */
	LTTNG_ROTATE_EXPIRED = 2,
	/*
	 * On error.
	 */
	LTTNG_ROTATE_ERROR = 3,
	/*
	 * If no rotation occured during this session.
	 */
	LTTNG_ROTATE_NO_ROTATION = 4,
};

/*
 * Input parameter to the lttng_rotate_session command.
 * The lttng_rotate_session_attr object is opaque to the user. Use the helper
 * functions below to use it.
 */
struct lttng_rotate_session_attr;

/*
 * Handle used to check the progress of a rotation.
 * This object is opaque to the user. Use the helper functions below to use it.
 */
struct lttng_rotate_session_handle;

/*
 * lttng rotate session command inputs.
 */
/*
 * Return a newly allocated rotate session attribute object or NULL on error.
 */
struct lttng_rotate_session_attr *lttng_rotate_session_attr_create(void);

/*
 * Free a given rotate ssession attribute object.
 */
void lttng_rotate_session_attr_destroy(struct lttng_rotate_session_attr *attr);

/*
 * Set the name of the session to rotate.
 */
int lttng_rotate_session_attr_set_session_name(
		struct lttng_rotate_session_attr *attr, const char *session_name);

/*
 * lttng rotate session handle functions.
 */
/*
 * Get the status from a handle.
 */
enum lttng_rotate_status lttng_rotate_session_get_status(
		struct lttng_rotate_session_handle *rotate_handle);

/*
 * If the rotation is complete, returns 0, allocate path and set
 * it to the path of the readable chunk, the caller is responsible to free it.
 * Otherwise return a negative value.
 */
int lttng_rotate_session_get_output_path(
		struct lttng_rotate_session_handle *rotate_handle,
		char **path);

/*
 * Destroy a lttng_rotate_session handle allocated by lttng_rotate_session()
 */
void lttng_rotate_session_handle_destroy(
		struct lttng_rotate_session_handle *rotate_handle);

/*
 * Rotate the output folder of the session
 *
 * On success, handle is allocated and can be used to monitor the progress
 * of the rotation with lttng_rotate_session_pending(). The handle must be freed
 * by the caller with lttng_rotate_session_handle_destroy().
 *
 * Return 0 if the rotate action was successfully launched or a negative
 * LTTng error code on error.
 */
extern int lttng_rotate_session(struct lttng_rotate_session_attr *attr,
		struct lttng_rotate_session_handle **rotate_handle);

/*
 * For a given session name, this call checks if a session rotation is still in
 * progress or has completed.
 *
 * Return 0 if the rotation is complete, in this case, the output path can be
 * fetched with lttng_rotate_session_get_output_path().
 * Return 1 if the rotate is still pending.
 * Return a negative LTTng error code on error (readable with lttng_strerror).
 */
extern int lttng_rotate_session_pending(
		struct lttng_rotate_session_handle *rotate_handle);

/*
 * Ask the sessiond where the data for this session is currently being written
 * to. If rotations occured during a session, this call is useful to know the
 * location of the last chunk.
 *
 * Return 0 and allocate chunk_path if rotations occured for this session, the
 * caller needs to free chunk_path.
 * Return 1 if no rotation occured during the session, chunk_path is left
 * unallocated.
 * Return -1 on error.
 */
extern int lttng_rotate_get_current_path(const char *session_name,
		char **chunk_path);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ROTATE_H */
