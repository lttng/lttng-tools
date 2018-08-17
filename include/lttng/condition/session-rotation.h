/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef LTTNG_CONDITION_SESSION_ROTATION_H
#define LTTNG_CONDITION_SESSION_ROTATION_H

#include <lttng/condition/evaluation.h>
#include <lttng/condition/condition.h>
#include <stdint.h>
#include <lttng/domain.h>
#include <lttng/location.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Session rotation conditions allow an action to be taken whenever a
 * session rotation is ongoing or completed.
 *
 * Session rotation conditions have the following properties:
 *   - the exact name of the session to be monitored for rotations
 *
 * Wildcards, regular expressions or other globbing mechanisms are not supported
 * in session rotation condition properties.
 */

/*
 * Create a newly allocated session rotation in progress condition.
 *
 * A session rotation ongoing condition evaluates to true whenever a rotation
 * is ongoing for a given session.
 *
 * Returns a new condition on success, NULL on failure. This condition must be
 * destroyed using lttng_condition_destroy().
 */
extern struct lttng_condition *
lttng_condition_session_rotation_ongoing_create(void);

/*
 * Create a newly allocated session rotation completion condition.
 *
 * A session rotation completed condition evaluates to true whenever a rotation
 * is completed for a given session. This condition is not evaluated on
 * subscription or registration of a trigger. This means that a trigger
 * using this condition will only fire when the next session rotation completes.
 * Previously completed rotations will have no effect.
 *
 * Returns a new condition on success, NULL on failure. This condition must be
 * destroyed using lttng_condition_destroy().
 */
 extern struct lttng_condition *
 lttng_condition_session_rotation_completed_create(void);

/*
 * Get the session name property of a session rotation condition.
 *
 * The caller does not assume the ownership of the returned session name. The
 * session name shall only only be used for the duration of the condition's
 * lifetime, or before a different session name is set.
 *
 * Returns LTTNG_CONDITION_STATUS_OK and a pointer to the condition's session
 * name on success, LTTNG_CONDITION_STATUS_INVALID if an invalid
 * parameter is passed, or LTTNG_CONDITION_STATUS_UNSET if a session name
 * was not set prior to this call.
 */
extern enum lttng_condition_status
lttng_condition_session_rotation_get_session_name(
		const struct lttng_condition *condition,
		const char **session_name);

/*
 * Set the session name property of a session rotation condition.
 *
 * The passed session name parameter will be copied to the condition.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success, LTTNG_CONDITION_STATUS_INVALID
 * if invalid paramenters are passed.
 */
extern enum lttng_condition_status
lttng_condition_session_rotation_set_session_name(
		struct lttng_condition *condition,
		const char *session_name);

/**
 * lttng_evaluation_session_rotation are specialised lttng_evaluations
 * which allow users to query a number of properties resulting from the
 * evaluation of a condition which evaluated to true.
 */

/*
 * Get the session rotation id property of a session rotation evaluation.
 *
 * Returns LTTNG_EVALUATION_STATUS_OK on success and the id of the session
 * rotation, or LTTNG_EVALUATION_STATUS_INVALID if an invalid parameter is
 * passed.
 */
extern enum lttng_evaluation_status
lttng_evaluation_session_rotation_get_id(
		const struct lttng_evaluation *evaluation, uint64_t *id);

/*
 * Get the session rotation location property of a session rotation completed
 * evaluation.
 *
 * The caller does not assume the ownership of the returned location. The
 * location shall only only be used for the duration of the evaluation's
 * lifetime.
 *
 * Returns LTTNG_EVALUATION_STATUS_OK and set location on success.
 * A NULL location may be returned if a rotation chunk's location
 * has expired.
 *
 * LTTNG_EVALUATION_STATUS_INVALID is returned if an invalid parameter is
 * passed.
 */
extern enum lttng_evaluation_status
lttng_evaluation_session_rotation_completed_get_location(
		const struct lttng_evaluation *evaluation,
		const struct lttng_trace_archive_location **location);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_SESSION_ROTATION_H */
