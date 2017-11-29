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

#ifndef LTTNG_CONDITION_SESSION_CONSUMED_SIZE_H
#define LTTNG_CONDITION_SESSION_CONSUMED_SIZE_H

#include <lttng/condition/evaluation.h>
#include <lttng/condition/condition.h>
#include <stdint.h>
#include <lttng/domain.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Session consumed size conditions allow an action to be taken whenever a
 * session's produced data size crosses a set threshold.
 *
 * These conditions are periodically evaluated against the current session
 * statistics. The period at which these conditions are evaluated is
 * governed by the channels' monitor timer.
 *
 * Session consumed size conditions have the following properties:
 *   - the exact name of the session to be monitored,
 *   - a total consumed size threshold, expressed in bytes.
 *
 * Wildcards, regular expressions or other globbing mechanisms are not supported
 * in session consumed size condition properties.
 */

/*
 * Create a newly allocated consumed session consumed size condition.
 *
 * A consumed session size condition evaluates to true whenever the sum of all
 * its channels' consumed data size is higher than a set threshold. The
 * consumed data sizes are free running counters.
 *
 * Returns a new condition on success, NULL on failure. This condition must be
 * destroyed using lttng_condition_destroy().
 */
extern struct lttng_condition *
lttng_condition_session_consumed_size_create(void);

/*
 * Get the threshold of a session consumed size condition.
 *
 * The session consumed size condition's threshold must have been defined as
 * an absolute value expressed in bytes in order for this call to succeed.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success and a threshold expressed in
 * bytes, LTTNG_CONDITION_STATUS_INVALID if an invalid parameter is passed, or
 * LTTNG_CONDITION_STATUS_UNSET if a threshold, expressed as an absolute size in
 * bytes, was not set prior to this call.
 */
extern enum lttng_condition_status
lttng_condition_session_consumed_size_get_threshold(
		const struct lttng_condition *condition,
	        uint64_t *consumed_threshold_bytes);

/*
 * Set the threshold of a session consumed size usage condition.
 *
 * Setting a threshold overrides any previously set threshold.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success, LTTNG_CONDITION_STATUS_INVALID
 * if invalid paramenters are passed.
 */
extern enum lttng_condition_status
lttng_condition_session_consumed_size_set_threshold(
		struct lttng_condition *condition,
	        uint64_t consumed_threshold_bytes);

/*
 * Get the session name property of a session consumed size condition.
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
lttng_condition_session_consumed_size_get_session_name(
		const struct lttng_condition *condition,
		const char **session_name);

/*
 * Set the session name property of a session consumed size condition.
 *
 * The passed session name parameter will be copied to the condition.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success, LTTNG_CONDITION_STATUS_INVALID
 * if invalid paramenters are passed.
 */
extern enum lttng_condition_status
lttng_condition_session_consumed_size_set_session_name(
		struct lttng_condition *condition,
		const char *session_name);

/**
 * lttng_evaluation_session_consumed_size are specialised lttng_evaluations
 * which allow users to query a number of properties resulting from the
 * evaluation of a condition which evaluated to true.
 */

/*
 * Get the session consumed property of a session consumed size evaluation.
 *
 * Returns LTTNG_EVALUATION_STATUS_OK on success and a threshold expressed in
 * bytes, or LTTNG_EVALUATION_STATUS_INVALID if an invalid parameter is passed.
 */
extern enum lttng_evaluation_status
lttng_evaluation_session_consumed_size_get_consumed_size(
		const struct lttng_evaluation *evaluation,
	        uint64_t *session_consumed);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_SESSION_CONSUMED_SIZE_H */
