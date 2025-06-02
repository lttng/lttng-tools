/*
 * SPDX-FileCopyrightText: 2019 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_LIST_H
#define LTTNG_ACTION_LIST_H

#include <lttng/lttng-export.h>

struct lttng_action;

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_action_list
@{
*/

/*!
@brief
    Creates an empty trigger action list.

@returns
    @parblock
    Trigger action with the type
    #LTTNG_ACTION_TYPE_LIST on success, or \c NULL on error.

    Destroy the returned trigger action with lttng_action_destroy().
    @endparblock
*/
LTTNG_EXPORT extern struct lttng_action *lttng_action_list_create(void);

/*!
@brief
    Appends the trigger action \lt_p{action} to the action list
    \lt_p{action_list}.

@param[in] action_list
    Trigger action list to which to add the action \lt_p{action}.
@param[in] action
    Trigger action to add to \lt_p{action_list} (not moved).

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_ACTION_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{action_list}
    @lt_pre_has_type{action_list,LTTNG_ACTION_TYPE_LIST}
    @lt_pre_not_null{action}
    - \lt_p{action} doesn't recursively contain \lt_p{action_list}
      (no reference cycle).
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_list_add_action(struct lttng_action *action_list, struct lttng_action *action);

/*!
@brief
    Sets \lt_p{*count} to the number of trigger actions contained in
    the action list \lt_p{action_list}.

@param[in] action_list
    Trigger action list of which to
    get the number of contained actions.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count}
    to the number of trigger actions in \lt_p{action_list}.

@retval #LTTNG_ACTION_STATUS_OK
    Success.
@retval #LTTNG_ACTION_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{action_list}
    @lt_pre_has_type{action_list,LTTNG_ACTION_TYPE_LIST}
    @lt_pre_not_null{count}

@sa lttng_action_list_get_at_index() --
    Get a trigger action from an action list by index.
*/
LTTNG_EXPORT extern enum lttng_action_status
lttng_action_list_get_count(const struct lttng_action *action_list, unsigned int *count);

/*!
@brief
    Returns the trigger action of the trigger
    action list \lt_p{action_list} at the index \lt_p{index}.

@param[in] action_list
    Trigger action list of which to get
    the action at the index \lt_p{index}.
@param[in] index
    Index of the trigger action to get from \lt_p{action_list}.

@returns
    @parblock
    Trigger action of \lt_p{action_list} at the
    index \lt_p{index}, or \c NULL on error.

    \lt_p{action_list} owns the returned trigger action.

    The returned trigger action remains valid as long
    as \lt_p{action_list} exists.
    @endparblock

@pre
    @lt_pre_not_null{action_list}
    @lt_pre_has_type{action_list,LTTNG_ACTION_TYPE_LIST}
    - \lt_p{index} is less than the number of trigger actions
      (as returned by lttng_action_list_get_count())
      of \lt_p{action_list}.

@sa lttng_action_list_get_count() --
    Get the number of trigger actions of an action list.
*/
LTTNG_EXPORT extern const struct lttng_action *
lttng_action_list_get_at_index(const struct lttng_action *action_list, unsigned int index);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_LIST_H */
