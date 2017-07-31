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

#ifndef LTTNG_CONDITION_BUFFER_USAGE_H
#define LTTNG_CONDITION_BUFFER_USAGE_H

#include <lttng/condition/evaluation.h>
#include <lttng/condition/condition.h>
#include <stdint.h>
#include <lttng/domain.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_condition;
struct lttng_evaluation;

/**
 * Buffer usage conditions allows an action to be taken whenever a channel's
 * buffer usage crosses a set threshold.
 *
 * These conditions are periodically evaluated against the current buffer
 * usage statistics. The period at which these conditions are evaluated is
 * governed by the channels' monitor timer.
 *
 * Note that the use of these conditons does not imply any hysteresis-loop
 * mechanism. For instance, an upper-bound buffer usage condition set to 75%
 * will fire everytime the buffer usage goes from a value < 75% to a value that
 * is >= 75%. The evaluation result does not depend on any lower-bound condition
 * being reached before the condition is evaluated to true again.
 *
 * Buffer usage conditions have the following properties:
 *   - the exact name of the session in which the channel to be monitored is
 *     defined,
 *   - the domain of the channel to be monitored,
 *   - the exact name of the channel to be monitored,
 *   - a usage threshold, expressed either in bytes or as a fraction of total
 *     buffer capacity.
 *
 * Wildcards, regular expressions or other globbing mechanisms are not supported
 * in buffer usage condition properties.
 */

/*
 * Create a newly allocated lower-bound buffer usage condition.
 *
 * A lower-bound buffer usage condition evaluates to true whenever
 * a buffer's usage _crosses_ the bound that is defined as part of the
 * condition's properties from high to low. In other words, the condition only
 * evaluates to true when a buffer's usage transitions from a value higher than
 * the threshold defined in the condition to a value lower than the threshold
 * defined in the condition.
 *
 * Returns a new condition on success, NULL on failure. This condition must be
 * destroyed using lttng_condition_destroy().
 */
extern struct lttng_condition *
lttng_condition_buffer_usage_low_create(void);

/*
 * Create a newly allocated upper-bound buffer usage condition.
 *
 * An upper-bound buffer usage condition evaluates to true whenever
 * a buffer's usage _crosses_ the bound that is defined as part of the
 * condition's properties from low to high. In other words, the condition only
 * evaluates to true when a buffer's usage transitions from a value lower than
 * the threshold defined in the condition to a value higher than the threshold
 * defined in the condition.
 *
 * Returns a new condition on success, NULL on failure. This condition must be
 * destroyed using lttng_condition_destroy().
 */
extern struct lttng_condition *
lttng_condition_buffer_usage_high_create(void);

/*
 * Get the buffer usage threshold ratio of a buffer usage condition.
 *
 * The buffer usage condition's threshold must have been defined as a ratio in
 * order for this call to succeed.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success and a ratio contained by the
 * interval [0.0, 1.0]. LTTNG_CONDITION_STATUS_INVALID is returned if an invalid
 * parameter is passed, or LTTNG_CONDITION_STATUS_UNSET if a threshold,
 * expressed as a ratio of total buffer capacity, was not set prior to this
 * call.
 */
extern enum lttng_condition_status
lttng_condition_buffer_usage_get_threshold_ratio(
		const struct lttng_condition *condition,
	        double *threshold_ratio);

/*
 * Set the buffer usage threshold ratio of a buffer usage condition.
 *
 * The threshold ratio passed must be contained by the interval [0.0, 1.0] and
 * represents a ratio of the channel's buffer's capacity. Setting a threshold,
 * either as a ratio or as an absolute size in bytes will override any
 * previously set threshold.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success, LTTNG_CONDITION_STATUS_INVALID
 * if invalid paramenters are passed.
 */
extern enum lttng_condition_status
lttng_condition_buffer_usage_set_threshold_ratio(
		struct lttng_condition *condition,
	        double threshold_ratio);

/*
 * Get the buffer usage threshold of a buffer usage condition.
 *
 * The buffer usage condition's threshold must have been defined as an absolute
 * value expressed in bytes in order for this call to succeed.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success and a threshold expressed in
 * bytes, LTTNG_CONDITION_STATUS_INVALID if an invalid parameter is passed, or
 * LTTNG_CONDITION_STATUS_UNSET if a threshold, expressed as an absolute size in
 * bytes, was not set prior to this call.
 */
extern enum lttng_condition_status
lttng_condition_buffer_usage_get_threshold(
		const struct lttng_condition *condition,
	        uint64_t *threshold_bytes);

/*
 * Set the buffer usage threshold in bytes of a buffer usage condition.
 *
 * Setting a threshold, either as a ratio or as an absolute size in bytes
 * will override any previously set threshold.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success, LTTNG_CONDITION_STATUS_INVALID
 * if invalid paramenters are passed.
 */
extern enum lttng_condition_status
lttng_condition_buffer_usage_set_threshold(
		struct lttng_condition *condition,
	        uint64_t threshold_bytes);

/*
 * Get the session name property of a buffer usage condition.
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
lttng_condition_buffer_usage_get_session_name(
		const struct lttng_condition *condition,
		const char **session_name);

/*
 * Set the session name property of a buffer usage condition.
 *
 * The passed session name parameter will be copied to the condition.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success, LTTNG_CONDITION_STATUS_INVALID
 * if invalid paramenters are passed.
 */
extern enum lttng_condition_status
lttng_condition_buffer_usage_set_session_name(
		struct lttng_condition *condition,
		const char *session_name);

/*
 * Get the channel name property of a buffer usage condition.
 *
 * The caller does not assume the ownership of the returned channel name. The
 * channel name shall only only be used for the duration of the condition's
 * lifetime, or before a different channel name is set.
 *
 * Returns LTTNG_CONDITION_STATUS_OK and a pointer to the condition's channel
 * name on success, LTTNG_CONDITION_STATUS_INVALID if an invalid
 * parameter is passed, or LTTNG_CONDITION_STATUS_UNSET if a channel name
 * was not set prior to this call.
 */
extern enum lttng_condition_status
lttng_condition_buffer_usage_get_channel_name(
		const struct lttng_condition *condition,
		const char **channel_name);

/*
 * Set the channel name property of a buffer usage condition.
 *
 * The passed channel name parameter will be copied to the condition.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success, LTTNG_CONDITION_STATUS_INVALID
 * if invalid paramenters are passed.
 */
extern enum lttng_condition_status
lttng_condition_buffer_usage_set_channel_name(
		struct lttng_condition *condition,
		const char *channel_name);

/*
 * Get the domain type property of a buffer usage condition.
 *
 * Returns LTTNG_CONDITION_STATUS_OK and sets the domain type output parameter
 * on success, LTTNG_CONDITION_STATUS_INVALID if an invalid parameter is passed,
 * or LTTNG_CONDITION_STATUS_UNSET if a domain type was not set prior to this
 * call.
 */
extern enum lttng_condition_status
lttng_condition_buffer_usage_get_domain_type(
		const struct lttng_condition *condition,
		enum lttng_domain_type *type);

/*
 * Set the domain type property of a buffer usage condition.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success, LTTNG_CONDITION_STATUS_INVALID
 * if invalid paramenters are passed.
 */
extern enum lttng_condition_status
lttng_condition_buffer_usage_set_domain_type(
		struct lttng_condition *condition,
		enum lttng_domain_type type);


/**
 * lttng_evaluation_buffer_usage are specialised lttng_evaluations which
 * allow users to query a number of properties resulting from the evaluation
 * of a condition which evaluated to true.
 *
 * The evaluation of a buffer usage condition yields two different results:
 *   - the usage ratio of the channel buffers at the time of the evaluation,
 *   - the usage, in bytes, of the channel buffers at the time of evaluation.
 */

/*
 * Get the buffer usage ratio property of a buffer usage evaluation.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success and a threshold expressed as
 * as a ratio of the buffer's capacity, or LTTNG_CONDITION_STATUS_INVALID if
 * an invalid parameter is passed.
 */
extern enum lttng_evaluation_status
lttng_evaluation_buffer_usage_get_usage_ratio(
		const struct lttng_evaluation *evaluation,
		double *usage_ratio);

/*
 * Get the buffer usage property of a buffer usage evaluation.
 *
 * Returns LTTNG_CONDITION_STATUS_OK on success and a threshold expressed in
 * bytes, or LTTNG_CONDITION_STATUS_INVALID if an invalid parameter is passed.
 */
extern enum lttng_evaluation_status
lttng_evaluation_buffer_usage_get_usage(
		const struct lttng_evaluation *evaluation,
	        uint64_t *usage_bytes);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_BUFFER_USAGE_H */
