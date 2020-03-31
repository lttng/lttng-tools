/*
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_EXPR_INTERNAL_H
#define LTTNG_EVENT_EXPR_INTERNAL_H

#include <assert.h>
#include <lttng/event-expr.h>

struct lttng_event_expr {
	enum lttng_event_expr_type type;
};

/*
 * `LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD` and
 * `LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD`.
 */
struct lttng_event_expr_field {
	struct lttng_event_expr parent;
	char *name;
};

/* `LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD` */
struct lttng_event_expr_app_specific_context_field {
	struct lttng_event_expr parent;
	char *provider_name;
	char *type_name;
};

/* `LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT` */
struct lttng_event_expr_array_field_element {
	struct lttng_event_expr parent;

	/* Owned by this */
	struct lttng_event_expr *array_field_expr;

	unsigned int index;
};

/*
 * Returns whether or not `expr` is an l-value (locator value).
 */
static inline
bool lttng_event_expr_is_lvalue(const struct lttng_event_expr *expr)
{
	assert(expr);
	return expr->type == LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD ||
			expr->type == LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD ||
			expr->type == LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD ||
			expr->type == LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT;
}

#endif /* LTTNG_EVENT_EXPR_INTERNAL_H */
