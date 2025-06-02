/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_CONDITION_BUFFER_USAGE_H
#define LTTNG_CONDITION_BUFFER_USAGE_H

#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>
#include <lttng/domain.h>
#include <lttng/lttng-export.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_cond_buffer_usage
@{
*/

/*!
@brief
    Creates an initial “channel buffer usage becomes less than”
    trigger condition to execute
    an action when the ring buffer usage of a given \lt_obj_channel
    becomes less than some configured threshold.

On success, the returned trigger condition isn't valid yet; you must:

- Set a target \lt_obj_session name with
  lttng_condition_buffer_usage_set_session_name().

- Set a target \lt_obj_domain with
  lttng_condition_buffer_usage_set_domain_type().

- Set a target channel name with
  lttng_condition_buffer_usage_set_channel_name().

- Set a channel buffer usage threshold with
  lttng_condition_buffer_usage_set_threshold_ratio() or
  lttng_condition_buffer_usage_set_threshold().

@returns
    @parblock
    Trigger condition with the type
    #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW on success,
    or \c NULL on error.

    Destroy the returned trigger condition with
    lttng_condition_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_condition *lttng_condition_buffer_usage_low_create(void);

/*!
@brief
    Creates an initial “channel buffer usage becomes greater than”
    trigger condition to execute
    an action when the ring buffer usage of a given \lt_obj_channel
    becomes greater than some configured threshold.

On success, the returned trigger condition isn't valid yet; you must:

- Set a target \lt_obj_session name with
  lttng_condition_buffer_usage_set_session_name().

- Set a target \lt_obj_domain with
  lttng_condition_buffer_usage_set_domain_type().

- Set a target channel name with
  lttng_condition_buffer_usage_set_channel_name().

- Set a channel buffer usage threshold with
  lttng_condition_buffer_usage_set_threshold_ratio() or
  lttng_condition_buffer_usage_set_threshold().

@returns
    @parblock
    Trigger condition with the type
    #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH on success,
    or \c NULL on error.

    Destroy the returned trigger condition with
    lttng_condition_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_condition *lttng_condition_buffer_usage_high_create(void);

/*!
@brief
    Sets \lt_p{*threshold} to the \lt_obj_channel buffer usage ratio
    threshold of the “channel buffer usage becomes greater/less than”
    trigger condition \lt_p{condition}.

@param[in] condition
    “Channel buffer usage becomes greater/less than”
    trigger condition of which to get the
    channel buffer usage ratio threshold.
@param[out] threshold
    <strong>On success</strong>, this function sets \lt_p{*threshold}
    to the channel buffer usage ratio (between&nbsp;0 and&nbsp;1)
    threshold of \lt_p{condition}.

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_UNSET
    \lt_p{condition} has no channel buffer usage ratio threshold,
    although it may have a channel buffer usage size threshold (see
    lttng_condition_buffer_usage_get_threshold()).
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.
    @lt_pre_not_null{threshold}

@sa lttng_condition_buffer_usage_set_threshold_ratio() --
    Set the channel buffer usage ratio threshold of a
    “channel buffer usage becomes greater/less than” trigger condition.
@sa lttng_condition_buffer_usage_get_threshold() --
    Get the channel buffer usage size threshold of a
    “channel buffer usage becomes greater/less than” trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_get_threshold_ratio(const struct lttng_condition *condition,
						 double *threshold);

/*!
@brief
    Sets the \lt_obj_channel buffer usage ratio threshold of the
    “channel buffer usage becomes greater/less than”
    trigger condition \lt_p{condition} to \lt_p{threshold}.

This function overrides any current channel buffer usage threshold of
\lt_p{condition}.

@param[in] condition
    “Channel buffer usage becomes greater/less than” trigger
    condition of which to set the channel buffer usage ratio threshold.
@param[in] threshold
    Channel buffer usage ratio (between&nbsp;0 and&nbsp;1) threshold
    of \lt_p{condition}.

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.

@sa lttng_condition_buffer_usage_get_threshold_ratio() --
    Get the channel buffer usage ratio threshold of a
    “channel buffer usage becomes greater/less than” trigger condition.
@sa lttng_condition_buffer_usage_set_threshold() --
    Set the channel buffer usage size threshold of a
    “channel buffer usage becomes greater/less than” trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_set_threshold_ratio(struct lttng_condition *condition,
						 double threshold);

/*!
@brief
    Sets \lt_p{*threshold} to the channel buffer usage size
    (bytes) threshold of the
    “channel buffer usage becomes greater/less than”
    trigger condition \lt_p{condition}.

@param[in] condition
    “Channel buffer usage becomes greater/less than”
    trigger condition of which to get the channel buffer usage size
    threshold.
@param[out] threshold
    <strong>On success</strong>, this function sets \lt_p{*threshold}
    to the buffer usage size (bytes) threshold of \lt_p{condition}.

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_UNSET
    \lt_p{condition} has no channel buffer usage size threshold,
    although it may have a channel buffer usage ratio threshold (see
    lttng_condition_buffer_usage_get_threshold_ratio()).
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.
    @lt_pre_not_null{threshold}

@sa lttng_condition_buffer_usage_set_threshold() --
    Set the channel buffer usage size threshold of a
    “channel buffer usage becomes greater/less than” trigger condition.
@sa lttng_condition_buffer_usage_get_threshold_ratio() --
    Get the channel buffer usage ratio threshold of a
    “channel buffer usage becomes greater/less than” trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_get_threshold(const struct lttng_condition *condition,
					   uint64_t *threshold);

/*!
@brief
    Sets the \lt_obj_channel buffer usage size threshold of the
    “channel buffer usage becomes greater/less than”
    trigger condition \lt_p{condition} to \lt_p{threshold}.

This function overrides any current channel buffer usage threshold of
\lt_p{condition}.

@param[in] condition
    “Channel buffer usage becomes greater/less than” trigger
    condition of which to set the channel buffer usage size threshold.
@param[in] threshold
    Channel buffer usage size (bytes) threshold of \lt_p{condition}.

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.

@sa lttng_condition_buffer_usage_get_threshold() --
    Get the channel buffer usage size threshold of a
    “channel buffer usage becomes greater/less than” trigger condition.
@sa lttng_condition_buffer_usage_set_threshold_ratio() --
    Set the channel buffer usage ratio threshold of a
    “channel buffer usage becomes greater/less than” trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_set_threshold(struct lttng_condition *condition, uint64_t threshold);

/*!
@brief
    Sets \lt_p{*session_name} to the target \lt_obj_session name of the
    “channel buffer usage becomes greater/less than” trigger
    condition \lt_p{condition}.

@param[in] condition
    “Channel buffer usage becomes greater/less than” trigger
    condition of which to get the target recording session name.
@param[out] session_name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*session_name}
    to the target recording session name of \lt_p{condition}.

    \lt_p{condition} owns \lt_p{*session_name}.

    \lt_p{*session_name} remains valid until the next
    function call with \lt_p{condition}.
    @endparblock

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_UNSET
    \lt_p{condition} has no target recording session name.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.
    @lt_pre_not_null{session_name}

@sa lttng_condition_buffer_usage_set_session_name() --
    Set the target recording session name of a
    “channel buffer usage becomes greater/less than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_get_session_name(const struct lttng_condition *condition,
					      const char **session_name);

/*!
@brief
    Sets the target \lt_obj_session name of the
    “channel buffer usage becomes greater/less than”
    trigger condition \lt_p{condition} to \lt_p{session_name}.

@param[in] condition
    “Channel buffer usage becomes greater/less than” trigger
    condition of which to set the target recording session name.
@param[in] session_name
    Target recording session name of \lt_p{condition} (copied).

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.
    @lt_pre_not_null{session_name}

@sa lttng_condition_buffer_usage_get_session_name() --
    Get the target recording session name of a
    “channel buffer usage becomes greater/less than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_set_session_name(struct lttng_condition *condition,
					      const char *session_name);

/*!
@brief
    Sets \lt_p{*channel_name} to the target \lt_obj_channel name of the
    “channel buffer usage becomes greater/less than” trigger
    condition \lt_p{condition}.

@param[in] condition
    “Channel buffer usage becomes greater/less than” trigger
    condition of which to get the target channel name.
@param[out] channel_name
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*channel_name}
    to the target channel name of \lt_p{condition}.

    \lt_p{condition} owns \lt_p{*channel_name}.

    \lt_p{*channel_name} remains valid until the next
    function call with \lt_p{condition}.
    @endparblock

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_UNSET
    \lt_p{condition} has no target channel name.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.
    @lt_pre_not_null{channel_name}

@sa lttng_condition_buffer_usage_set_channel_name() --
    Set the target channel name of a
    “channel buffer usage becomes greater/less than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_get_channel_name(const struct lttng_condition *condition,
					      const char **channel_name);

/*!
@brief
    Sets the target \lt_obj_channel name of the
    “channel buffer usage becomes greater/less than”
    trigger condition \lt_p{condition} to \lt_p{channel_name}.

@param[in] condition
    “Channel buffer usage becomes greater/less than” trigger
    condition of which to set the target channel name.
@param[in] channel_name
    Target channel name of \lt_p{condition} (copied).

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.
    @lt_pre_not_null{channel_name}

@sa lttng_condition_buffer_usage_get_channel_name() --
    Get the target channel name of a
    “channel buffer usage becomes greater/less than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_set_channel_name(struct lttng_condition *condition,
					      const char *channel_name);

/*!
@brief
    Sets \lt_p{*domain} to the target \lt_obj_domain of the
    “channel buffer usage becomes greater/less than” trigger
    condition \lt_p{condition}.

@param[in] condition
    “Channel buffer usage becomes greater/less than” trigger
    condition of which to get the target tracing domain.
@param[out] domain
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*domain}
    to the target tracing domain of \lt_p{condition}.

    \lt_p{condition} owns \lt_p{*domain}.

    \lt_p{*domain} remains valid until the next
    function call with \lt_p{condition}.
    @endparblock

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_UNSET
    \lt_p{condition} has no target tracing domain.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.

@sa lttng_condition_buffer_usage_set_domain_type() --
    Set the target tracing domain of a
    “channel buffer usage becomes greater/less than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_get_domain_type(const struct lttng_condition *condition,
					     enum lttng_domain_type *domain);

/*!
@brief
    Sets the target \lt_obj_domain of the
    “channel buffer usage becomes greater/less than”
    trigger condition \lt_p{condition} to \lt_p{domain}.

@param[in] condition
    “Channel buffer usage becomes greater/less than” trigger
    condition of which to set the target tracing domain.
@param[in] domain
    Target tracing domain of \lt_p{condition}.

@retval #LTTNG_CONDITION_STATUS_OK
    Success.
@retval #LTTNG_CONDITION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{condition}
    - \lt_p{condition} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.
    @lt_pre_not_null{domain}

@sa lttng_condition_buffer_usage_get_domain_type() --
    Get the target tracing domain of a
    “channel buffer usage becomes greater/less than”
    trigger condition.
*/
LTTNG_EXPORT extern enum lttng_condition_status
lttng_condition_buffer_usage_set_domain_type(struct lttng_condition *condition,
					     enum lttng_domain_type domain);

/*!
@brief
    Sets \lt_p{*usage} to the captured \lt_obj_channel
    buffer usage ratio of the
    “channel buffer usage becomes greater/less than” trigger
    condition evaluation \lt_p{evaluation}.

@param[in] evaluation
    “Channel buffer usage becomes greater/less than” trigger
    condition evaluation of which to get the captured channel
    buffer usage ratio.
@param[out] usage
    <strong>On success</strong>, this function sets
    \lt_p{*usage} to the captured channel buffer usage ratio
    (between&nbsp;0 and&nbsp;1) of \lt_p{evaluation}.

@retval #LTTNG_EVALUATION_STATUS_OK
    Success.
@retval #LTTNG_EVALUATION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{evaluation}
    - \lt_p{evaluation} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.
    @lt_pre_not_null{usage}

@sa lttng_evaluation_buffer_usage_get_usage() --
    Get the captured channel buffer usage size of a
    “channel buffer usage becomes greater/less than” trigger
    condition evaluation.
*/
LTTNG_EXPORT extern enum lttng_evaluation_status
lttng_evaluation_buffer_usage_get_usage_ratio(const struct lttng_evaluation *evaluation,
					      double *usage);

/*!
@brief
    Sets \lt_p{*usage} to the captured \lt_obj_channel
    buffer usage size of the
    “channel buffer usage becomes greater/less than” trigger
    condition evaluation \lt_p{evaluation}.

@param[in] evaluation
    “Channel buffer usage becomes greater/less than” trigger
    condition evaluation of which to get the captured channel
    buffer usage size.
@param[out] usage
    <strong>On success</strong>, this function sets
    \lt_p{*usage} to the captured channel buffer usage size (bytes)
    of \lt_p{evaluation}.

@retval #LTTNG_EVALUATION_STATUS_OK
    Success.
@retval #LTTNG_EVALUATION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{evaluation}
    - \lt_p{evaluation} has the type
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH or
      #LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW.
    @lt_pre_not_null{usage}

@sa lttng_evaluation_buffer_usage_get_usage_ratio() --
    Get the captured channel buffer usage ratio of a
    “channel buffer usage becomes greater/less than” trigger
    condition evaluation.
*/
LTTNG_EXPORT extern enum lttng_evaluation_status
lttng_evaluation_buffer_usage_get_usage(const struct lttng_evaluation *evaluation, uint64_t *usage);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_CONDITION_BUFFER_USAGE_H */
