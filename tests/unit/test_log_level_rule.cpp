/*
 * Unit tests for the log level rule API.
 *
 * Copyright (C) 2020 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <common/payload-view.h>
#include <common/payload.h>
#include <lttng/log-level-rule-internal.h>
#include <lttng/log-level-rule.h>

/* For error.h. */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 29

static void test_log_level_rule_error(void)
{
	int level = 9000;
	struct lttng_log_level_rule *exactly =
			lttng_log_level_rule_exactly_create(level);
	struct lttng_log_level_rule *at_least_as_severe =
			lttng_log_level_rule_at_least_as_severe_as_create(
					level);

	ok(lttng_log_level_rule_get_type(NULL) == LTTNG_LOG_LEVEL_RULE_TYPE_UNKNOWN, "Get type on invalid pointer");

	ok(lttng_log_level_rule_exactly_get_level(NULL, NULL) == LTTNG_LOG_LEVEL_RULE_STATUS_INVALID, "lttng_log_level_rule_exactly_get_level (NULL, NULL) returns invalid");
	ok(lttng_log_level_rule_exactly_get_level(exactly, NULL) == LTTNG_LOG_LEVEL_RULE_STATUS_INVALID, "lttng_log_level_rule_exactly_get_level (valid, NULL) returns invalid");
	ok(lttng_log_level_rule_exactly_get_level(NULL, &level) == LTTNG_LOG_LEVEL_RULE_STATUS_INVALID, "lttng_log_level_rule_exactly_get_level (NULL, valid) returns invalid");

	ok(lttng_log_level_rule_at_least_as_severe_as_get_level(NULL, NULL) == LTTNG_LOG_LEVEL_RULE_STATUS_INVALID, "lttng_log_level_rule_at_least_as_severe_as_get_level (NULL, NULL) returns invalid");
	ok(lttng_log_level_rule_at_least_as_severe_as_get_level(exactly, NULL) == LTTNG_LOG_LEVEL_RULE_STATUS_INVALID, "lttng_log_level_rule_at_least_as_severe_as_get_level (valid, NULL) returns invalid");
	ok(lttng_log_level_rule_at_least_as_severe_as_get_level(NULL, &level) == LTTNG_LOG_LEVEL_RULE_STATUS_INVALID, "lttng_log_level_rule_at_least_as_severe_as_get_level (NULL, valid) returns invalid");

	lttng_log_level_rule_destroy(exactly);
	lttng_log_level_rule_destroy(at_least_as_severe);
}

static
void test_log_level_rule_serialize_deserialize(const struct lttng_log_level_rule *rule)
{
	struct lttng_log_level_rule *log_level_rule_from_buffer = NULL;
	struct lttng_payload payload;

	lttng_payload_init(&payload);

	ok(lttng_log_level_rule_serialize(rule, &payload) == 0, "Serializing.");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);

		ok(lttng_log_level_rule_create_from_payload(
				&view, &log_level_rule_from_buffer) > 0,
				"Deserializing.");
	}

	ok(lttng_log_level_rule_is_equal(rule, log_level_rule_from_buffer), "Serialized and from buffer are equal");

	lttng_log_level_rule_destroy(log_level_rule_from_buffer);
}

static
void test_log_level_rule_is_equal_exactly(void)
{
	int level = 9000, no_eq_level = 420;
	struct lttng_log_level_rule *a, *b, *different_level, *different_type;

	/* Identical log level rules. */
	a = lttng_log_level_rule_exactly_create(level);
	b = lttng_log_level_rule_exactly_create(level);

	/* Different level, same type. */
	different_level = lttng_log_level_rule_exactly_create(no_eq_level);

	/* Different type. */
	different_type = lttng_log_level_rule_at_least_as_severe_as_create(level);

	LTTNG_ASSERT(a && b && different_level && different_type);

	ok(lttng_log_level_rule_is_equal(a, a), "Same object is equal");
	ok(lttng_log_level_rule_is_equal(a, b), "Object a and b are equal");
	ok(!lttng_log_level_rule_is_equal(a, different_level), " Object of different levels are not equal");
	ok(!lttng_log_level_rule_is_equal(a, different_type), " Object of different types are not equal");

	lttng_log_level_rule_destroy(a);
	lttng_log_level_rule_destroy(b);
	lttng_log_level_rule_destroy(different_level);
	lttng_log_level_rule_destroy(different_type);
}

static
void test_log_level_rule_is_equal_at_least_as_severe_as(void)
{
	int level = 9000, no_eq_level = 420;
	struct lttng_log_level_rule *a, *b, *different_level, *different_type;

	/* Identical log level rules. */
	a = lttng_log_level_rule_at_least_as_severe_as_create(level);
	b = lttng_log_level_rule_at_least_as_severe_as_create(level);

	/* Different level, same type. */
	different_level = lttng_log_level_rule_at_least_as_severe_as_create(no_eq_level);

	/* Different type. */
	different_type = lttng_log_level_rule_exactly_create(level);

	LTTNG_ASSERT(a && b && different_level && different_type);

	ok(lttng_log_level_rule_is_equal(a, a), "Same object is equal");
	ok(lttng_log_level_rule_is_equal(a, b), "Object a and b are equal");
	ok(!lttng_log_level_rule_is_equal(a, different_level), " Object of different levels are not equal");
	ok(!lttng_log_level_rule_is_equal(a, different_type), " Object of different types are not equal");

	lttng_log_level_rule_destroy(a);
	lttng_log_level_rule_destroy(b);
	lttng_log_level_rule_destroy(different_level);
	lttng_log_level_rule_destroy(different_type);
}

static void test_log_level_rule_exactly(void)
{
	int level = 9000;
	int _level;
	struct lttng_log_level_rule *exactly = NULL;
	enum lttng_log_level_rule_status status;

	exactly = lttng_log_level_rule_exactly_create(level);

	ok(exactly, "Log level exactly allocated");
	ok(lttng_log_level_rule_get_type(exactly) ==
					LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY,
			"Log level rule exactly type");

	status = lttng_log_level_rule_exactly_get_level(exactly, &_level);
	ok(status == LTTNG_LOG_LEVEL_RULE_STATUS_OK, "Get the level");
	ok(_level == level, "Level property is valid");

	test_log_level_rule_is_equal_exactly();
	test_log_level_rule_serialize_deserialize(exactly);
	lttng_log_level_rule_destroy(exactly);
}

static void test_log_level_rule_at_least_as_severe_as(void)
{
	int level = 9000;
	int _level;
	struct lttng_log_level_rule *at_least_as_severe_as = NULL;
	enum lttng_log_level_rule_status status;

	at_least_as_severe_as = lttng_log_level_rule_at_least_as_severe_as_create(level);

	ok(at_least_as_severe_as, "Log level at_least_as_severe_as allocated");
	ok(lttng_log_level_rule_get_type(at_least_as_severe_as) ==
					LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS,
			"Log level rule at_least_as_severe_as type");

	status = lttng_log_level_rule_at_least_as_severe_as_get_level(at_least_as_severe_as, &_level);
	ok(status == LTTNG_LOG_LEVEL_RULE_STATUS_OK, "Get the level");
	ok(_level == level, "Level property is valid");

	test_log_level_rule_is_equal_at_least_as_severe_as();
	test_log_level_rule_serialize_deserialize(at_least_as_severe_as);
	lttng_log_level_rule_destroy(at_least_as_severe_as);
}

int main(void)
{
	plan_tests(NUM_TESTS);
	test_log_level_rule_exactly();
	test_log_level_rule_at_least_as_severe_as();
	test_log_level_rule_error();
	return exit_status();
}
