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
    Return type of
    \ref api_trigger_action_incr_map_val_key_template "key template"
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
    from the template string \lt_p{template_string}.

The syntax of \lt_p{template_string} is similar to
<a href="https://fmt.dev/">{fmt}</a> and Python's
<a href="https://peps.python.org/pep-0498/">f-string</a>.

See the \ref api_trigger_action_incr_map_val_key_template "key template"
documentation for the grammar of \lt_p{template_string} and the available
placeholders.

@param[in] template_string
    Template string to parse.

@returns
    @parblock
    Key template parsed from \lt_p{template_string} on success, or \c NULL on
    memory error.

    Destroy the returned key template with
    lttng_key_template_destroy().
    @endparblock

@pre
    @lt_pre_not_null{template_string}
    - \lt_p{template_string} isn't empty.
    - \lt_p{template_string} doesn't end while a placeholder is open.
    - \lt_p{template_string} only references available placeholder names.

@sa lttng_key_template_to_string() --
    Render a key template back to its string form.
*/
LTTNG_EXPORT extern struct lttng_key_template *
lttng_key_template_create_from_string(const char *template_string);

/*!
@brief
    Renders the
    \ref api_trigger_action_incr_map_val_key_template "key template"
    \lt_p{key_template} back to its template string form.

The returned string round-trips through lttng_key_template_create_from_string():
parsing it yields a key template equivalent to \lt_p{key_template}. That being said,
the returned string isn't necessarily identical to the template string which
produced \lt_p{key_template}: this function renders each placeholder in a canonical
form. For example, an original <code>{&nbsp;event_name&nbsp;}</code> renders
back as <code>{event_name}</code>.

@param[in] key_template
    Key template to render.
@param[out] template_string
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*template_string} to a
    newly-allocated, NUL-terminated string holding the template
    string form of \lt_p{key_template}.

    The caller owns \lt_p{*template_string} and must release it with \c free().
    @endparblock

@retval #LTTNG_KEY_TEMPLATE_STATUS_OK
    Success.
@retval #LTTNG_KEY_TEMPLATE_STATUS_INVALID
    Unsatisfied precondition.
@retval #LTTNG_KEY_TEMPLATE_STATUS_ERROR
    Memory error.

@pre
    @lt_pre_not_null{key_template}
    @lt_pre_not_null{template_string}

@sa lttng_key_template_create_from_string() --
    Parse a template string into a key template.
*/
LTTNG_EXPORT extern enum lttng_key_template_status
lttng_key_template_to_string(const struct lttng_key_template *key_template, char **template_string);

/*!
@brief
    Destroys the
    \ref api_trigger_action_incr_map_val_key_template "key template"
    \lt_p{key_template}.

@param[in] key_template
    @parblock
    Key template to destroy.

    May be \c NULL.
    @endparblock
*/
LTTNG_EXPORT extern void lttng_key_template_destroy(struct lttng_key_template *key_template);

/// @}

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ACTION_KEY_TEMPLATE_H */
