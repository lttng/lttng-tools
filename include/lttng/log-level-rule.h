/*
 * SPDX-FileCopyrightText: 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOG_LEVEL_RULE_H
#define LTTNG_LOG_LEVEL_RULE_H

#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_ll_rule
@{
*/

/*!
@struct lttng_log_level_rule

@brief
    Log level rule (opaque type).
*/
struct lttng_log_level_rule;

/*!
@brief
    Log level rule type.
*/
enum lttng_log_level_rule_type {
	/// Exact match.
	LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY = 0,

	/// "At least as severe as" match.
	LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS = 1,

	/// Unknown (error).
	LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN = -1,
};

/*!
@brief
    Return type of log level rule API functions.
*/
enum lttng_log_level_rule_status {
	/// Success.
	LTTNG_LOG_LEVEL_RULE_STATUS_OK = 0,

	/// Error.
	LTTNG_LOG_LEVEL_RULE_STATUS_ERROR = -1,

	/// Unsatisfied precondition.
	LTTNG_LOG_LEVEL_RULE_STATUS_INVALID = -3,
};

/*!
@brief
    Returns the type of the log level rule \lt_p{rule}.

@param[in] rule
    Log level rule of which to get the type.

@returns
    Type of \lt_p{rule}.

@pre
    @lt_pre_not_null{rule}
*/
LTTNG_EXPORT extern enum lttng_log_level_rule_type
lttng_log_level_rule_get_type(const struct lttng_log_level_rule *rule);

/*!
@brief
    Creates a log level rule for which a log level must match exactly
    \lt_p{level} to be satisfied.

@param[in] level
    @parblock
    Exact log level to match.

    You may use one of the enumerators of #lttng_loglevel,
    #lttng_loglevel_jul, #lttng_loglevel_log4j, #lttng_loglevel_log4j2,
    and #lttng_loglevel_python.
    @endparblock

@returns
    @parblock
    Exact match log level rule on success, or \c NULL on error.

    Destroy the returned log level rule with
    lttng_log_level_rule_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_log_level_rule *lttng_log_level_rule_exactly_create(int level);

/*!
@brief
    Sets \lt_p{*level} to the level of the exact match log level
    rule \lt_p{rule}.

@param[in] rule
    Exact match log level rule of which to get the level.
@param[out] level
    <strong>On success</strong>, this function sets \lt_p{*level}
    to the level of \lt_p{rule}.

@retval LTTNG_LOG_LEVEL_RULE_STATUS_OK
    Success.
@retval LTTNG_LOG_LEVEL_RULE_STATUS_ERROR
    Error.
@retval LTTNG_LOG_LEVEL_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY}
    @lt_pre_not_null{level}
*/
LTTNG_EXPORT extern enum lttng_log_level_rule_status
lttng_log_level_rule_exactly_get_level(const struct lttng_log_level_rule *rule, int *level);

/*!
@brief
    Creates a log level rule for which a log level must be at least
    as severe as \lt_p{level} to be satisfied.

@param[in] level
    @parblock
    Log level to compare to.

    You may use one of the enumerators of #lttng_loglevel,
    #lttng_loglevel_jul, #lttng_loglevel_log4j, #lttng_loglevel_log4j2,
    and #lttng_loglevel_python.
    @endparblock

@returns
    @parblock
    "At least as severe as" log level rule on success,
    or \c NULL on error.

    Destroy the returned log level rule with
    lttng_log_level_rule_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_log_level_rule *
lttng_log_level_rule_at_least_as_severe_as_create(int level);

/*!
@brief
    Sets \lt_p{*level} to the level of the "at least as severe as" log
    level rule \lt_p{rule}.

@param[in] rule
    "At least as severe as" log level rule of which to get the level.
@param[out] level
    <strong>On success</strong>, this function sets \lt_p{*level}
    to the level of \lt_p{rule}.

@retval LTTNG_LOG_LEVEL_RULE_STATUS_OK
    Success.
@retval LTTNG_LOG_LEVEL_RULE_STATUS_ERROR
    Error.
@retval LTTNG_LOG_LEVEL_RULE_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{rule}
    @lt_pre_has_type{rule,LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS}
    @lt_pre_not_null{level}
*/
LTTNG_EXPORT extern enum lttng_log_level_rule_status
lttng_log_level_rule_at_least_as_severe_as_get_level(const struct lttng_log_level_rule *rule,
						     int *level);

/*!
@brief
    Destroys the log level rule \lt_p{rule}.

@param[in] rule
    @parblock
    Log level rule to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_log_level_rule_destroy(struct lttng_log_level_rule *rule);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_LOG_LEVEL_RULE_H */
