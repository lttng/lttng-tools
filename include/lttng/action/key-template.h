/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_ACTION_KEY_TEMPLATE_H
#define LTTNG_ACTION_KEY_TEMPLATE_H

#include <lttng/lttng-export.h>

struct lttng_key_template;

#ifdef __cplusplus
extern "C" {
#endif

/*!
@addtogroup api_trigger_action_incr_map_val
@{
*/

/*!
@brief
    Return type of \ref api_trigger_action_incr_map_val_key_template "key template"
    API functions.
*/
enum lttng_key_template_status {
	/// Success.
	LTTNG_KEY_TEMPLATE_STATUS_OK = 0,

	/// Error.
	LTTNG_KEY_TEMPLATE_STATUS_ERROR = -1,

	/// Unsatisfied precondition.
	LTTNG_KEY_TEMPLATE_STATUS_INVALID = -3,
};

/*!
@brief
    Creates a \ref api_trigger_action_incr_map_val_key_template "key template"
    by parsing the template string \lt_p{str}.

The grammar of \lt_p{str} is fmtlib-like:

- Verbatim text outside of any \c {…} placeholder is preserved as-is.
- The placeholder <code>{event_name}</code> is, when LTTng executes
  the containing
  \ref api_trigger_action_incr_map_val "\"increment map value\" trigger action",
  replaced with the name of the matching event of the
  \ref api_trigger_cond_er_matches "\"event rule matches\" trigger condition".
- The placeholder <code>{provider_name}</code> is replaced with its
  provider name.
- A literal opening or closing curly brace must be doubled
  (<code>{{</code> renders as <code>{</code>; <code>}}</code> renders
  as <code>}</code>).

\lt_p{str} must be non-empty, must not end while a placeholder is
open, and must only reference the placeholder names listed above.

@param[in] str
    Template string to parse.

@returns
    @parblock
    Key template parsed from \lt_p{str} on success, or \c NULL if
    \lt_p{str} is unparseable, empty, or on memory error.

    Destroy the returned key template with
    lttng_key_template_destroy().
    @endparblock

@pre
    @lt_pre_not_null{str}

@sa lttng_key_template_to_string() --
    Render a key template back to its string form.
*/
LTTNG_EXPORT extern struct lttng_key_template *
lttng_key_template_create_from_string(const char *str);

/*!
@brief
    Renders the
    \ref api_trigger_action_incr_map_val_key_template "key template"
    \lt_p{tmpl} back to its template string form.

The returned string round-trips through
lttng_key_template_create_from_string(): parsing it yields a
key template equal to \lt_p{tmpl}.

@param[in] tmpl
    Key template to render.
@param[out] str
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*str} to a
    newly-allocated, NUL-terminated string holding the template
    string form of \lt_p{tmpl}.

    The caller owns \lt_p{*str} and must release it with \c free().
    @endparblock

@retval #LTTNG_KEY_TEMPLATE_STATUS_OK
    Success.
@retval #LTTNG_KEY_TEMPLATE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_KEY_TEMPLATE_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{tmpl}
    @lt_pre_not_null{str}

@sa lttng_key_template_create_from_string() --
    Parse a template string into a key template.
*/
LTTNG_EXPORT extern enum lttng_key_template_status
lttng_key_template_to_string(const struct lttng_key_template *tmpl, char **str);

/*!
@brief
    Destroys the
    \ref api_trigger_action_incr_map_val_key_template "key template"
    \lt_p{tmpl}.

@param[in] tmpl
    @parblock
    Key template to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_key_template_destroy(struct lttng_key_template *tmpl);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_KEY_TEMPLATE_H */
