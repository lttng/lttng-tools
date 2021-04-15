/*
 * Unit tests for the rate policy object API.
 *
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <common/payload-view.h>
#include <common/payload.h>
#include <lttng/action/rate-policy-internal.h>
#include <lttng/action/rate-policy.h>

/* For error.h. */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 42

static void test_rate_policy_every_n(void)
{
	enum lttng_rate_policy_status status;
	struct lttng_rate_policy *policy_a = NULL; /* Interval of 100. */
	struct lttng_rate_policy *policy_b = NULL; /* Interval of 100 */
	struct lttng_rate_policy *policy_c = NULL; /* Interval of 1 */
	struct lttng_rate_policy *policy_from_buffer = NULL;
	uint64_t interval_a_b = 100;
	uint64_t interval_c = 1;
	uint64_t interval_query = 0;
	struct lttng_payload payload;

	lttng_payload_init(&payload);

	policy_a = lttng_rate_policy_every_n_create(interval_a_b);
	policy_b = lttng_rate_policy_every_n_create(interval_a_b);
	policy_c = lttng_rate_policy_every_n_create(interval_c);
	ok(policy_a != NULL,
			"Rate policy every n A created: interval: %" PRIu64,
			interval_a_b);
	ok(policy_b != NULL,
			"Rate policy every n B created: interval: %" PRIu64,
			interval_a_b);
	ok(policy_c != NULL,
			"Rate policy every n C created: interval: %" PRIu64,
			interval_c);

	ok(LTTNG_RATE_POLICY_TYPE_EVERY_N ==
					lttng_rate_policy_get_type(policy_a),
			"Type is LTTNG_RATE_POLICY_TYPE_EVERY_N");

	/* Getter tests */
	status = lttng_rate_policy_every_n_get_interval(NULL, NULL);
	ok(status == LTTNG_RATE_POLICY_STATUS_INVALID,
			"Get interval returns INVALID");

	status = lttng_rate_policy_every_n_get_interval(NULL, &interval_query);
	ok(status == LTTNG_RATE_POLICY_STATUS_INVALID,
			"Get interval returns INVALID");

	status = lttng_rate_policy_every_n_get_interval(policy_a, NULL);
	ok(status == LTTNG_RATE_POLICY_STATUS_INVALID,
			"Get interval returns INVALID");

	status = lttng_rate_policy_every_n_get_interval(
			policy_a, &interval_query);
	ok(status == LTTNG_RATE_POLICY_STATUS_OK &&
					interval_query == interval_a_b,
			" Getting interval A");

	status = lttng_rate_policy_every_n_get_interval(
			policy_b, &interval_query);
	ok(status == LTTNG_RATE_POLICY_STATUS_OK &&
					interval_query == interval_a_b,
			" Getting interval B");

	status = lttng_rate_policy_every_n_get_interval(
			policy_c, &interval_query);
	ok(status == LTTNG_RATE_POLICY_STATUS_OK &&
					interval_query == interval_c,
			" Getting interval C");

	/* is_equal tests */
	/* TODO: this is the behaviour introduced by the
	 * lttng_condition_is_equal back in 2017 do we want to fix this and
	 * return true if both are NULL?
	 */
	ok(false == lttng_rate_policy_is_equal(NULL, NULL),
			"is equal (NULL,NULL)");
	ok(false == lttng_rate_policy_is_equal(policy_a, NULL),
			"is equal (object, NULL)");
	ok(false == lttng_rate_policy_is_equal(NULL, policy_a),
			" is equal (NULL, object)");
	ok(true == lttng_rate_policy_is_equal(policy_a, policy_a),
			"is equal (object A, object A)");

	ok(true == lttng_rate_policy_is_equal(policy_a, policy_b),
			"is equal (object A, object B");
	ok(true == lttng_rate_policy_is_equal(policy_b, policy_a),
			"is equal (object B, object A");

	ok(false == lttng_rate_policy_is_equal(policy_a, policy_c),
			"is equal (object A, object C)");
	ok(false == lttng_rate_policy_is_equal(policy_c, policy_a),
			"is equal (object C, object A)");

	/* Serialization and create_from buffer. */
	ok(lttng_rate_policy_serialize(policy_a, &payload) == 0, "Serializing");
	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);

		ok(lttng_rate_policy_create_from_payload(
				   &view, &policy_from_buffer) > 0 &&
						policy_from_buffer != NULL,
				"Deserializing");
	}

	ok(lttng_rate_policy_is_equal(policy_a, policy_from_buffer),
			"serialized and from buffer are equal");

	lttng_rate_policy_destroy(policy_a);
	lttng_rate_policy_destroy(policy_b);
	lttng_rate_policy_destroy(policy_c);
	lttng_payload_reset(&payload);
}

static void test_rate_policy_once_after_n(void)
{
	enum lttng_rate_policy_status status;
	struct lttng_rate_policy *policy_a = NULL; /* Threshold of 100. */
	struct lttng_rate_policy *policy_b = NULL; /* threshold of 100 */
	struct lttng_rate_policy *policy_c = NULL; /* threshold of 1 */
	struct lttng_rate_policy *policy_from_buffer = NULL;
	uint64_t threshold_a_b = 100;
	uint64_t threshold_c = 1;
	uint64_t threshold_query = 0;
	struct lttng_payload payload;

	lttng_payload_init(&payload);

	policy_a = lttng_rate_policy_once_after_n_create(threshold_a_b);
	policy_b = lttng_rate_policy_once_after_n_create(threshold_a_b);
	policy_c = lttng_rate_policy_once_after_n_create(threshold_c);
	ok(policy_a != NULL,
			"Rate policy every n A created: threshold: %" PRIu64,
			threshold_a_b);
	ok(policy_b != NULL,
			"Rate policy every n B created: threshold: %" PRIu64,
			threshold_a_b);
	ok(policy_c != NULL,
			"Rate policy every n C created: threshold: %" PRIu64,
			threshold_c);

	ok(LTTNG_RATE_POLICY_TYPE_ONCE_AFTER_N ==
					lttng_rate_policy_get_type(policy_a),
			"Type is LTTNG_RATE_POLICY_TYPE_once_after_n");

	/* Getter tests */
	status = lttng_rate_policy_once_after_n_get_threshold(NULL, NULL);
	ok(status == LTTNG_RATE_POLICY_STATUS_INVALID,
			"Get threshold returns INVALID");

	status = lttng_rate_policy_once_after_n_get_threshold(
			NULL, &threshold_query);
	ok(status == LTTNG_RATE_POLICY_STATUS_INVALID,
			"Get threshold returns INVALID");

	status = lttng_rate_policy_once_after_n_get_threshold(policy_a, NULL);
	ok(status == LTTNG_RATE_POLICY_STATUS_INVALID,
			"Get threshold returns INVALID");

	status = lttng_rate_policy_once_after_n_get_threshold(
			policy_a, &threshold_query);
	ok(status == LTTNG_RATE_POLICY_STATUS_OK &&
					threshold_query == threshold_a_b,
			" Getting threshold A");

	status = lttng_rate_policy_once_after_n_get_threshold(
			policy_b, &threshold_query);
	ok(status == LTTNG_RATE_POLICY_STATUS_OK &&
					threshold_query == threshold_a_b,
			" Getting threshold B");

	status = lttng_rate_policy_once_after_n_get_threshold(
			policy_c, &threshold_query);
	ok(status == LTTNG_RATE_POLICY_STATUS_OK &&
					threshold_query == threshold_c,
			" Getting threshold C");

	/* is_equal tests */
	/* TODO: this is the behaviour introduced by the
	 * lttng_condition_is_equal back in 2017 do we want to fix this and
	 * return true if both are NULL?
	 */
	ok(false == lttng_rate_policy_is_equal(NULL, NULL),
			"is equal (NULL,NULL)");
	ok(false == lttng_rate_policy_is_equal(policy_a, NULL),
			"is equal (object, NULL)");
	ok(false == lttng_rate_policy_is_equal(NULL, policy_a),
			" is equal (NULL, object)");
	ok(true == lttng_rate_policy_is_equal(policy_a, policy_a),
			"is equal (object A, object A)");

	ok(true == lttng_rate_policy_is_equal(policy_a, policy_b),
			"is equal (object A, object B");
	ok(true == lttng_rate_policy_is_equal(policy_b, policy_a),
			"is equal (object B, object A");

	ok(false == lttng_rate_policy_is_equal(policy_a, policy_c),
			"is equal (object A, object C)");
	ok(false == lttng_rate_policy_is_equal(policy_c, policy_a),
			"is equal (object C, object A)");

	/* Serialization and create_from buffer. */
	ok(lttng_rate_policy_serialize(policy_a, &payload) == 0, "Serializing");
	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);

		ok(lttng_rate_policy_create_from_payload(
				   &view, &policy_from_buffer) > 0 &&
						policy_from_buffer != NULL,
				"Deserializing");
	}

	ok(lttng_rate_policy_is_equal(policy_a, policy_from_buffer),
			"serialized and from buffer are equal");

	lttng_rate_policy_destroy(policy_a);
	lttng_rate_policy_destroy(policy_b);
	lttng_rate_policy_destroy(policy_c);
	lttng_payload_reset(&payload);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_rate_policy_every_n();
	test_rate_policy_once_after_n();
	return exit_status();
}
