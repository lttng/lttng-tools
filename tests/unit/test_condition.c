/*
 * test_condition.c
 *
 * Unit tests for the condition API.
 *
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <lttng/event.h>
#include <lttng/event-rule/tracepoint.h>
#include <lttng/condition/condition-internal.h>
#include <lttng/condition/on-event.h>
#include <lttng/domain.h>
#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 13

static
void test_condition_event_rule(void)
{
	int ret, i;
	struct lttng_event_rule *tracepoint = NULL;
	const struct lttng_event_rule *tracepoint_tmp = NULL;
	enum lttng_event_rule_status status;
	struct lttng_condition *condition = NULL;
	struct lttng_condition *condition_from_buffer = NULL;
	enum lttng_condition_status condition_status;
	const char *pattern="my_event_*";
	const char *filter="msg_id == 23 && size >= 2048";
	const char *exclusions[] = { "my_event_test1", "my_event_test2", "my_event_test3" };
	struct lttng_payload buffer;

	lttng_payload_init(&buffer);

	tracepoint = lttng_event_rule_tracepoint_create(LTTNG_DOMAIN_UST);
	ok(tracepoint, "tracepoint UST_DOMAIN");

	status = lttng_event_rule_tracepoint_set_pattern(tracepoint, pattern);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "Setting pattern");

	status = lttng_event_rule_tracepoint_set_filter(tracepoint, filter);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "Setting filter");

	status = lttng_event_rule_tracepoint_set_log_level_range_lower_bound(
			tracepoint, LTTNG_LOGLEVEL_WARNING);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "Setting log level range");

	for (i = 0; i < 3; i++) {
		status = lttng_event_rule_tracepoint_add_exclusion(
				tracepoint, exclusions[i]);
		ok(status == LTTNG_EVENT_RULE_STATUS_OK,
				"Setting exclusion pattern");
	}

	condition = lttng_condition_on_event_create(tracepoint);
	ok(condition, "Created condition");

	condition_status = lttng_condition_on_event_get_rule(
			condition, &tracepoint_tmp);
	ok(condition_status == LTTNG_CONDITION_STATUS_OK,
			"Getting event rule from event rule condition");
	ok(tracepoint == tracepoint_tmp, "lttng_condition_event_rule_get_rule provides a reference to the original rule");

	ret = lttng_condition_serialize(condition, &buffer);
	ok(ret == 0, "Condition serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(&buffer, 0, -1);

		(void) lttng_condition_create_from_payload(
				&view, &condition_from_buffer);
	}

	ok(condition_from_buffer, "Condition created from payload is non-null");

	ok(lttng_condition_is_equal(condition, condition_from_buffer),
			"Serialized and de-serialized conditions are equal");

	lttng_payload_reset(&buffer);
	lttng_event_rule_destroy(tracepoint);
	lttng_condition_destroy(condition);
	lttng_condition_destroy(condition_from_buffer);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_condition_event_rule();
	return exit_status();
}
