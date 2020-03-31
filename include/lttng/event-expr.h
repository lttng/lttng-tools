/*
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_EXPR_H
#define LTTNG_EVENT_EXPR_H

#include <stdbool.h>

struct lttng_event_expr;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Types of an event expression.
 */
enum lttng_event_expr_type {
	/*
	 * Returned by lttng_event_expr_get_type() with an invalid
	 * parameter.
	 */
	LTTNG_EVENT_EXPR_TYPE_INVALID = -1,

	/*
	 * The named payload field of an event.
	 *
	 * Command-line expression example:
	 *
	 *     next_prio
	 */
	LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD = 0,

	/*
	 * The named per-channel context field of an event.
	 *
	 * Command-line expression example:
	 *
	 *     $ctx.vpid
	 */
	LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD = 1,

	/*
	 * The named application-specific context field of an event.
	 *
	 * Command-line expression example:
	 *
	 *     $app.iga:active-clients
	 */
	LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD = 2,

	/*
	 * The element of an array field.
	 *
	 * Command-line expression example:
	 *
	 *     my_field[4]
	 *     $ctx.some_context[5][1]
	 */
	LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT = 3,
};

/*
 * Event expression API status codes.
 */
enum lttng_event_expr_status {
	/*
	 * Invalid parameter.
	 */
	LTTNG_EVENT_EXPR_STATUS_INVALID = -1,

	/*
	 * Success.
	 */
	LTTNG_EVENT_EXPR_STATUS_OK = 0,
};

/*
 * Returns the type of the event expression `expr`, or
 * `LTTNG_EVENT_EXPR_TYPE_INVALID` if `expr` is `NULL`.
 */
extern enum lttng_event_expr_type lttng_event_expr_get_type(
		const struct lttng_event_expr *expr);

/*
 * Creates an event payload field expression for the payload field named
 * `field_name`.
 *
 * Returns `NULL` if:
 *
 * * There's a memory error.
 * * `field_name` is `NULL`.
 */
extern struct lttng_event_expr *lttng_event_expr_event_payload_field_create(
		const char *field_name);

/*
 * Returns the field name of the event payload field expression `expr`,
 * or `NULL` if:
 *
 * * `expr` is `NULL`.
 * * The type of `expr` is not
 *   `LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD`.
 */
extern const char *lttng_event_expr_event_payload_field_get_name(
		const struct lttng_event_expr *expr);

/*
 * Creates a per-channel context field expression for the per-channel
 * context field named `field_name`.
 *
 * Returns `NULL` if:
 *
 * * There's a memory error.
 * * `field_name` is `NULL`.
 */
extern struct lttng_event_expr *
lttng_event_expr_channel_context_field_create(const char *field_name);

/*
 * Returns the field name of the per-channel context field
 * expression `expr`, or `NULL` if:
 *
 * `expr` is `NULL`.
 * * The type of `expr` is not
 *   `LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD`.
 */
extern const char *lttng_event_expr_channel_context_field_get_name(
		const struct lttng_event_expr *expr);

/*
 * Creates an application-specific context field expression for the
 * application-specific context field provided by the provider named
 * `provider_name` and having the type named `type_name`.
 *
 * Returns `NULL` if:
 *
 * * There's a memory error.
 * * `provider_name` is `NULL`.
 * * `type_name` is `NULL`.
 */
extern struct lttng_event_expr *
lttng_event_expr_app_specific_context_field_create(
		const char *provider_name, const char *type_name);

/*
 * Returns the provider name of the application-specific context field
 * expression `expr`, or `NULL` if:
 *
 * * `expr` is `NULL`.
 * * The type of `expr` is not
 *   `LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD`.
 */
extern const char *
lttng_event_expr_app_specific_context_field_get_provider_name(
		const struct lttng_event_expr *expr);

/*
 * Returns the type name of the application-specific context field
 * expression `expr`, or `NULL` if:
 *
 * * `expr` is `NULL`.
 * * The type of `expr` is not
 *   `LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD`.
 */
extern const char *
lttng_event_expr_app_specific_context_field_get_type_name(
		const struct lttng_event_expr *expr);

/*
 * Creates an array field element expression for the parent array field
 * `array_field_expr` (transfering the ownership) and the index `index`.
 *
 * Returns `NULL` if:
 *
 * * There's a memory error.
 * * `array_field_expr` is `NULL`.
 * * `array_field_expr` is not a locator expression, that is, its type
 *   is not one of:
 *
 *    * `LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD`
 *    * `LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD`
 *    * `LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD`
 *    * `LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT`
 */
extern struct lttng_event_expr *lttng_event_expr_array_field_element_create(
		struct lttng_event_expr *array_field_expr,
		unsigned int index);

/*
 * Returns the parent array field expression of the array field element
 * expression `expr`, or `NULL` if:
 *
 * * `expr` is `NULL`.
 * * The type of `expr` is not
 *   `LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT`.
 */
extern const struct lttng_event_expr *
lttng_event_expr_array_field_element_get_parent_expr(
		const struct lttng_event_expr *expr);

/*
 * Sets `*index` to the index of the array field element expression
 * `expr`.
 *
 * Returns:
 *
 * `LTTNG_EVENT_EXPR_STATUS_OK`:
 *     Success.
 *
 * `LTTNG_EVENT_EXPR_STATUS_INVALID`:
 *     * `expr` is `NULL`.
 *     * The type of `expr` is not
 *       `LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT`.
 *     * `index` is `NULL`.
 */
extern enum lttng_event_expr_status
lttng_event_expr_array_field_element_get_index(
		const struct lttng_event_expr *expr, unsigned int *index);

/*
 * Returns whether or not the event expressions `expr_a` and `expr_b`
 * are equal.
 *
 * `expr_a` and `expr_b` can be `NULL`.
 */
extern bool lttng_event_expr_is_equal(const struct lttng_event_expr *expr_a,
		const struct lttng_event_expr *expr_b);

/*
 * Destroys the event expression `expr` if not `NULL`.
 */
extern void lttng_event_expr_destroy(struct lttng_event_expr *expr);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_EXPR_H */
