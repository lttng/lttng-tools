/*
 * Copyright 2020 EfficiOS, Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <lttng/event-expr.h>
#include <common/event-expr-to-bytecode.h>
#include <common/bytecode/bytecode.h>
#include <tap/tap.h>

#define NR_TESTS 4

static
void test_event_payload_field(void)
{
	struct lttng_event_expr *event_expr;
	struct lttng_bytecode *bytecode = NULL;
	int ret;

	event_expr = lttng_event_expr_event_payload_field_create("tourlou");
	ret = lttng_event_expr_to_bytecode(event_expr, &bytecode);

	ok(ret == 0, "event payload field");

	lttng_event_expr_destroy(event_expr);
	free(bytecode);
}

static
void test_channel_context_field(void)
{
	struct lttng_event_expr *event_expr;
	struct lttng_bytecode *bytecode = NULL;
	int ret;

	event_expr = lttng_event_expr_channel_context_field_create("tourlou");
	ret = lttng_event_expr_to_bytecode(event_expr, &bytecode);

	ok(ret == 0, "channel context field");

	lttng_event_expr_destroy(event_expr);
	free(bytecode);
}

static
void test_app_specific_context_field(void)
{
	struct lttng_event_expr *event_expr;
	struct lttng_bytecode *bytecode = NULL;
	int ret;

	event_expr = lttng_event_expr_app_specific_context_field_create("Bob", "Leponge");
	ret = lttng_event_expr_to_bytecode(event_expr, &bytecode);

	ok(ret == 0, "app-specific context field");

	lttng_event_expr_destroy(event_expr);
	free(bytecode);
}

static
void test_array_field_element(void)
{
	struct lttng_event_expr *event_expr;
	struct lttng_bytecode *bytecode = NULL;
	int ret;

	event_expr = lttng_event_expr_event_payload_field_create("allo");
	event_expr = lttng_event_expr_array_field_element_create(event_expr, 168);
	ret = lttng_event_expr_to_bytecode(event_expr, &bytecode);

	ok(ret == 0, "array field element");

	lttng_event_expr_destroy(event_expr);
	free(bytecode);
}

int main(void)
{
	plan_tests(NR_TESTS);

	test_event_payload_field();
	test_channel_context_field();
	test_app_specific_context_field();
	test_array_field_element();

	return exit_status();
}
