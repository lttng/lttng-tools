/*
 * SPDX-FileCopyrightText: 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_EXPR_H
#define LTTNG_EVENT_EXPR_H

#include <lttng/lttng-export.h>

#include <stdbool.h>

struct lttng_event_expr;

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_ev_expr
@{
*/

/*!
@brief
    Event expression type.

Get the type of an event expression with
lttng_event_expr_get_type().
*/
enum lttng_event_expr_type {
	/// Payload field reference.
	LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD = 0,

	/// Statically-known context field reference.
	LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD = 1,

	/// Application-specific context field reference.
	LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD = 2,

	/// Array field element reference.
	LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT = 3,

	/// Unsatisfied precondition.
	LTTNG_EVENT_EXPR_TYPE_INVALID = -1,
};

/*!
@brief
    Return type of event expression API functions.
*/
enum lttng_event_expr_status {
	/// Success.
	LTTNG_EVENT_EXPR_STATUS_OK = 0,

	/// Unsatisfied precondition.
	LTTNG_EVENT_EXPR_STATUS_INVALID = -1,
};

/*!
@brief
    Returns the type of the event expression \lt_p{expr}.

@param[in] expr
    Event expression of which to get the type.

@returns
    Type of \lt_p{expr}.

@pre
    @lt_pre_not_null{expr}
*/
LTTNG_EXPORT extern enum lttng_event_expr_type
lttng_event_expr_get_type(const struct lttng_event_expr *expr);

/*!
@brief
    Creates an event payload field reference expression for the payload
    field named \lt_p{field_name}.

@param[in] field_name
    Name of the payload field to reference to (copied).

@returns
    Event payload field reference expression for the payload field named
    \lt_p{field_name}, or \c NULL on error.

@pre
    @lt_pre_not_null{field_name}
*/
LTTNG_EXPORT extern struct lttng_event_expr *
lttng_event_expr_event_payload_field_create(const char *field_name);

/*!
@brief
    Returns the name of the referenced payload field of the
    event payload field reference expression \lt_p{expr}.

@param[in] expr
    Event payload field reference expression of which to get the name of
    the referenced field.

@returns
    @parblock
    Name of the referenced field of \lt_p{expr}, or \c NULL on error.

    \lt_p{expr} owns the returned string.

    The returned string remains valid as long as \lt_p{expr} exists.
    @endparblock

@pre
    @lt_pre_not_null{expr}
    @lt_pre_has_type{expr,LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD}
*/
LTTNG_EXPORT extern const char *
lttng_event_expr_event_payload_field_get_name(const struct lttng_event_expr *expr);

/*!
@brief
    Creates a statically-known context field reference expression for
    the context field named \lt_p{field_name}.

@param[in] field_name
    @parblock
    Name of the statically-known context field to refer to (copied).

    Use one of the statically known names in the “Field name” column
    of the table of #lttng_event_context_type
    (that is, excluding the
    #LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER,
    #LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER,
    and #LTTNG_EVENT_CONTEXT_APP_CONTEXT rows).
    @endparblock

@returns
    Statically-known context field reference expression for the context
    field named \lt_p{field_name}, or \c NULL on error.

@pre
    @lt_pre_not_null{field_name}
    - \lt_p{field_name} is one of the names in the “Field name” column
      of the table of #lttng_event_context_type,
      excluding the #LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER,
      #LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER,
      and #LTTNG_EVENT_CONTEXT_APP_CONTEXT rows.
*/
LTTNG_EXPORT extern struct lttng_event_expr *
lttng_event_expr_channel_context_field_create(const char *field_name);

/*!
@brief
    Returns the name of the referenced context field of the
    statically-known context field reference expression \lt_p{expr}.

@param[in] expr
    Event payload field reference expression of which to get the name of
    the referenced field.

@returns
    @parblock
    Name of the referenced field of \lt_p{expr}, or \c NULL on error.

    \lt_p{expr} owns the returned string.

    The returned string remains valid as long as \lt_p{expr} exists.
    @endparblock

@pre
    @lt_pre_not_null{expr}
    @lt_pre_has_type{expr,LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD}
*/
LTTNG_EXPORT extern const char *
lttng_event_expr_channel_context_field_get_name(const struct lttng_event_expr *expr);

/*!
@brief
    Creates an application-specific context field reference expression
    for the application-specific context field provided by the provider
    named \lt_p{provider_name} and having the type named
    \lt_p{type_name}.

@param[in] provider_name
    Name of the provider of the application-specific context field
    to refer to (copied).
@param[in] type_name
    Name of the type of the application-specific context field
    to refer to (copied).

@returns
    Application-specific context field reference expression for the
    provider named \lt_p{provider_name} and the type named
    \lt_p{type_name}, or \c NULL on error.

@pre
    @lt_pre_not_null{provider_name}
    @lt_pre_not_null{type_name}
*/
LTTNG_EXPORT extern struct lttng_event_expr *
lttng_event_expr_app_specific_context_field_create(const char *provider_name,
						   const char *type_name);

/*!
@brief
    Returns the provider name of the referenced field of the
    application-specific context field reference expression \lt_p{expr}.

@param[in] expr
    Application-specific context field reference expression of which to
    get the provider name of the referenced field.

@returns
    @parblock
    Provider name of the referenced field of \lt_p{expr},
    or \c NULL on error.

    \lt_p{expr} owns the returned string.

    The returned string remains valid as long as \lt_p{expr} exists.
    @endparblock

@pre
    @lt_pre_not_null{expr}
    @lt_pre_has_type{expr,LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD}
*/
LTTNG_EXPORT extern const char *
lttng_event_expr_app_specific_context_field_get_provider_name(const struct lttng_event_expr *expr);

/*!
@brief
    Returns the type name of the referenced field of the
    application-specific context field reference expression \lt_p{expr}.

@param[in] expr
    Application-specific context field reference expression of which to
    get the type name of the referenced field.

@returns
    @parblock
    Type name of the referenced field of \lt_p{expr},
    or \c NULL on error.

    \lt_p{expr} owns the returned string.

    The returned string remains valid as long as \lt_p{expr} exists.
    @endparblock

@pre
    @lt_pre_not_null{expr}
    @lt_pre_has_type{expr,LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD}
*/
LTTNG_EXPORT extern const char *
lttng_event_expr_app_specific_context_field_get_type_name(const struct lttng_event_expr *expr);

/*!
@brief
    Creates an array field element reference expression
    for the parent array field referred by \lt_p{array_field_expr} and
    the index \lt_p{index}.

@param[in] array_field_expr
    @parblock
    Parent array field containing the field element to refer to.

    <strong>On success</strong>, the ownership of this expression is
    moved to the returned expression.
    @endparblock
@param[in] index
    Index of the field element to refer to
    within \lt_p{array_field_expr}.

@returns
    Array field element reference expression for the parent array field
    \lt_p{array_field_expr} and the index \lt_p{index}.

@pre
    @lt_pre_not_null{array_field_expr}
*/
LTTNG_EXPORT extern struct lttng_event_expr *
lttng_event_expr_array_field_element_create(struct lttng_event_expr *array_field_expr,
					    unsigned int index);

/*!
@brief
    Returns the parent array field expression of the
    array field element reference expression\lt_p{expr}.

@param[in] expr
    Array field element reference expression of which to
    get the parent array field expression.

@returns
    @parblock
    Parent array field expression of \lt_p{expr},
    or \c NULL on error.

    \lt_p{expr} owns the returned expression.

    The returned expression remains valid as long as \lt_p{expr} exists.
    @endparblock

@pre
    @lt_pre_not_null{expr}
    @lt_pre_has_type{expr,LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT}

@sa lttng_event_expr_array_field_element_get_index() --
    Get the index of an array field element reference expression.
*/
LTTNG_EXPORT extern const struct lttng_event_expr *
lttng_event_expr_array_field_element_get_parent_expr(const struct lttng_event_expr *expr);

/*!
@brief
    Sets \lt_p{*index} to the index of the
    array field element reference expression\lt_p{expr}.

@param[in] expr
    Array field element reference expression of which to
    get the index.
@param[out] index
    <strong>On success</strong>, this function sets \lt_p{*index}
    to the index of \lt_p{expr}.

@retval #LTTNG_EVENT_EXPR_STATUS_OK
    Success.
@retval #LTTNG_EVENT_EXPR_STATUS_INVALID
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{expr}
    @lt_pre_has_type{expr,LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT}
    @lt_pre_not_null{index}

@sa lttng_event_expr_array_field_element_get_parent_expr() --
    Get the parent array field expression of an
    array field element reference expression.
*/
LTTNG_EXPORT extern enum lttng_event_expr_status
lttng_event_expr_array_field_element_get_index(const struct lttng_event_expr *expr,
					       unsigned int *index);

/*!
@brief
    Returns whether or not the event expressions \lt_p{expr_a} and
    \lt_p{expr_b} are equal.

@param[in] expr_a
    @parblock
    Event expression to compare to \lt_p{expr_b}.

    May be \c NULL.
    @endparblock
@param[in] expr_b
    @parblock
    Event expression to compare to \lt_p{expr_a}.

    May be \c NULL.
    @endparblock

@returns
    \c true if \lt_p{expr_a} and \lt_p{expr_b} are equal.
*/
LTTNG_EXPORT extern bool lttng_event_expr_is_equal(const struct lttng_event_expr *expr_a,
						   const struct lttng_event_expr *expr_b);

/*!
@brief
    Destroys the event expression \lt_p{expr}.

@param[in] expr
    @parblock
    Event expression to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_event_expr_destroy(struct lttng_event_expr *expr);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_EXPR_H */
