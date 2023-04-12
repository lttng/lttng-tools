/*
 * Copyright (C) 2020 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_EXPR_INTERNAL_H
#define LTTNG_EVENT_EXPR_INTERNAL_H

#include <common/macros.hpp>

#include <lttng/event-expr.h>

struct lttng_bytecode;
struct mi_writer;

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
static inline bool lttng_event_expr_is_lvalue(const struct lttng_event_expr *expr)
{
	LTTNG_ASSERT(expr);
	return expr->type == LTTNG_EVENT_EXPR_TYPE_EVENT_PAYLOAD_FIELD ||
		expr->type == LTTNG_EVENT_EXPR_TYPE_CHANNEL_CONTEXT_FIELD ||
		expr->type == LTTNG_EVENT_EXPR_TYPE_APP_SPECIFIC_CONTEXT_FIELD ||
		expr->type == LTTNG_EVENT_EXPR_TYPE_ARRAY_FIELD_ELEMENT;
}

int lttng_event_expr_to_bytecode(const struct lttng_event_expr *expr,
				 struct lttng_bytecode **bytecode_out);

enum lttng_error_code lttng_event_expr_mi_serialize(const struct lttng_event_expr *expression,
						    struct mi_writer *writer);

#endif /* LTTNG_EVENT_EXPR_INTERNAL_H */
