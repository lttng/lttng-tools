/*
 * test_condition.c
 *
 * Unit tests for the condition API.
 *
 * SPDX-FileCopyrightText: 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/buffer-view.hpp>
#include <common/dynamic-buffer.hpp>

#include <lttng/condition/condition-internal.hpp>
#include <lttng/condition/event-rule-matches-internal.hpp>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/domain.h>
#include <lttng/event-rule/user-tracepoint.h>
#include <lttng/event.h>
#include <lttng/log-level-rule.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <tap/tap.h>
#include <unistd.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 13

static void test_condition_event_rule()
{
	int ret, i;
	struct lttng_event_rule *tracepoint = nullptr;
	const struct lttng_event_rule *tracepoint_tmp = nullptr;
	enum lttng_event_rule_status status;
	struct lttng_condition *condition = nullptr;
	struct lttng_condition *condition_from_buffer = nullptr;
	enum lttng_condition_status condition_status;
	const char *pattern = "my_event_*";
	const char *filter = "msg_id == 23 && size >= 2048";
	const char *exclusions[] = { "my_event_test1", "my_event_test2", "my_event_test3" };
	struct lttng_log_level_rule *log_level_rule_at_least_as_severe = nullptr;
	struct lttng_payload buffer;

	lttng_payload_init(&buffer);

	/* Create log level rule. */
	log_level_rule_at_least_as_severe =
		lttng_log_level_rule_at_least_as_severe_as_create(LTTNG_LOGLEVEL_WARNING);
	LTTNG_ASSERT(log_level_rule_at_least_as_severe);

	tracepoint = lttng_event_rule_user_tracepoint_create();
	ok(tracepoint, "user tracepoint");

	status = lttng_event_rule_user_tracepoint_set_name_pattern(tracepoint, pattern);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "Setting pattern");

	status = lttng_event_rule_user_tracepoint_set_filter(tracepoint, filter);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "Setting filter");

	status = lttng_event_rule_user_tracepoint_set_log_level_rule(
		tracepoint, log_level_rule_at_least_as_severe);
	ok(status == LTTNG_EVENT_RULE_STATUS_OK, "Setting log level range");

	for (i = 0; i < 3; i++) {
		status = lttng_event_rule_user_tracepoint_add_name_pattern_exclusion(tracepoint,
										     exclusions[i]);
		ok(status == LTTNG_EVENT_RULE_STATUS_OK, "Setting exclusion pattern");
	}

	condition = lttng_condition_event_rule_matches_create(tracepoint);
	ok(condition, "Created condition");

	condition_status = lttng_condition_event_rule_matches_get_rule(condition, &tracepoint_tmp);
	ok(condition_status == LTTNG_CONDITION_STATUS_OK,
	   "Getting event rule from event rule condition");
	ok(tracepoint == tracepoint_tmp,
	   "lttng_condition_event_rule_get_rule provides a reference to the original rule");

	ret = lttng_condition_serialize(condition, &buffer);
	ok(ret == 0, "Condition serialized");

	{
		struct lttng_payload_view view = lttng_payload_view_from_payload(&buffer, 0, -1);

		(void) lttng_condition_create_from_payload(&view, &condition_from_buffer);
	}

	ok(condition_from_buffer, "Condition created from payload is non-null");

	ok(lttng_condition_is_equal(condition, condition_from_buffer),
	   "Serialized and de-serialized conditions are equal");

	lttng_payload_reset(&buffer);
	lttng_event_rule_destroy(tracepoint);
	lttng_condition_destroy(condition);
	lttng_condition_destroy(condition_from_buffer);
	lttng_log_level_rule_destroy(log_level_rule_at_least_as_severe);
}

int main()
{
	plan_tests(NUM_TESTS);
	test_condition_event_rule();
	return exit_status();
}
