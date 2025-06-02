/*
 * SPDX-FileCopyrightText: 2021 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_RATE_POLICY_H
#define LTTNG_RATE_POLICY_H

#include <lttng/lttng-export.h>

#include <inttypes.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_action_rate_policy
@{
*/

/*!
@struct lttng_rate_policy

@brief
    Trigger action rate policy (opaque type).
*/
struct lttng_rate_policy;

/*!
@brief
    Return type of trigger action rate policy API functions.
*/
enum lttng_rate_policy_status {
	/// Success.
	LTTNG_RATE_POLICY_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_RATE_POLICY_STATUS_INVALID = -3,

	/* Unused for the moment */
	LTTNG_RATE_POLICY_STATUS_ERROR = -1,
	LTTNG_RATE_POLICY_STATUS_UNKNOWN = -2,
	LTTNG_RATE_POLICY_STATUS_UNSET = -4,
	LTTNG_RATE_POLICY_STATUS_UNSUPPORTED = -5,
	LTTNG_RATE_POLICY_STATUS_PERMISSION_DENIED = -6,
};

/*!
@brief
    Trigger action rate policy type.

Get the type of a trigger action rate policy with
lttng_rate_policy_get_type().
*/
enum lttng_rate_policy_type {
	/// Every&nbsp;\lt_var{N} times.
	LTTNG_RATE_POLICY_TYPE_EVERY_N = 0,

	/// Once after&nbsp;\lt_var{N} times.
	LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N = 1,

	/// Unknown (error).
	LTTNG_RATE_POLICY_TYPE_UNKNOWN = -1,
};

/*!
@brief
    Returns the type of the trigger action rate policy
    \lt_p{policy}.

@param[in] policy
    Trigger action rate policy of which to get the type.

@returns
    Type of \lt_p{policy}.

@pre
    @lt_pre_not_null{policy}
*/
LTTNG_EXPORT extern enum lttng_rate_policy_type
lttng_rate_policy_get_type(const struct lttng_rate_policy *policy);

/*!
@brief
    Creates an “every&nbsp;\lt_var{N} times”
    trigger action rate policy, setting&nbsp;\lt_var{N} to
    \lt_p{n}.

@param[in] n
    Value of&nbsp;\lt_var{N}.

@returns
    @parblock
    Trigger action rate policy with the type
    #LTTNG_RATE_POLICY_TYPE_EVERY_N on success,
    or \c NULL on error.

    Destroy the returned rate policy with
    lttng_rate_policy_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_rate_policy *lttng_rate_policy_every_n_create(uint64_t n);

/*!
@brief
    Sets \lt_p{*n} to&nbsp;\lt_var{N} of the
    “every&nbsp;\lt_var{N} times” trigger action
    rate policy \lt_p{policy}.

@param[in] policy
    “Every&nbsp;\lt_var{N} times” trigger action rate policy of which to
    get&nbsp;\lt_var{N}.
@param[out] n
    <strong>On success</strong>, this function sets \lt_p{*n}
    to&nbsp;\lt_var{N}.

@retval #LTTNG_RATE_POLICY_STATUS_OK
    Success.
@retval #LTTNG_RATE_POLICY_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{policy}
    @lt_pre_has_type{policy,LTTNG_RATE_POLICY_TYPE_EVERY_N}
    @lt_pre_not_null{n}
*/
LTTNG_EXPORT extern enum lttng_rate_policy_status
lttng_rate_policy_every_n_get_interval(const struct lttng_rate_policy *policy, uint64_t *n);

/*!
@brief
    Creates a “once after&nbsp;\lt_var{N} times”
    trigger action rate policy, setting&nbsp;\lt_var{N} to
    \lt_p{n}.

@param[in] n
    Value of&nbsp;\lt_var{N}.

@returns
    @parblock
    Trigger action rate policy with the type
    #LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N on success,
    or \c NULL on error.

    Destroy the returned rate policy with
    lttng_rate_policy_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_rate_policy *lttng_rate_policy_once_after_n_create(uint64_t n);

/*!
@brief
    Sets \lt_p{*n} to&nbsp;\lt_var{N} of the
    “once after&nbsp;\lt_var{N} times” trigger action rate policy
    \lt_p{policy}.

@param[in] policy
    “Once after&nbsp;\lt_var{N} times” trigger action rate policy of
    which to get&nbsp;\lt_var{N}.
@param[out] n
    <strong>On success</strong>, this function sets \lt_p{*n}
    to&nbsp;\lt_var{N}.

@retval #LTTNG_RATE_POLICY_STATUS_OK
    Success.
@retval #LTTNG_RATE_POLICY_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{policy}
    @lt_pre_has_type{policy,LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N}
    @lt_pre_not_null{n}
*/
LTTNG_EXPORT extern enum lttng_rate_policy_status
lttng_rate_policy_once_after_n_get_threshold(const struct lttng_rate_policy *policy, uint64_t *n);

/*!
@brief
    Destroys the trigger action rate policy \lt_p{policy}.

@param[in] policy
    @parblock
    Trigger action rate policy to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_rate_policy_destroy(struct lttng_rate_policy *policy);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_rate_policy_H */
