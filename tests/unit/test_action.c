/*
 * test_action.c
 *
 * Unit tests for the notification API.
 *
 * Copyright (C) 2017 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: MIT
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
#include <lttng/action/action-internal.h>
#include <lttng/action/action.h>
#include <lttng/action/firing-policy-internal.h>
#include <lttng/action/firing-policy.h>
#include <lttng/action/notify.h>
#include <lttng/action/rotate-session.h>
#include <lttng/action/start-session.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 34

static void test_action_notify(void)
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *notify_action = NULL,
			    *notify_action_from_buffer = NULL;
	struct lttng_firing_policy *policy = NULL, *default_policy;
	struct lttng_payload payload;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_firing_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_firing_policy_every_n_create(1);

	assert(policy && default_policy);

	notify_action = lttng_action_notify_create();
	ok(notify_action, "Create notify action");
	ok(lttng_action_get_type(notify_action) == LTTNG_ACTION_TYPE_NOTIFY,
			"Action has type LTTNG_ACTION_TYPE_NOTIFY");

	/* Validate the default policy for a notify action. */
	{
		const struct lttng_firing_policy *cur_policy = NULL;
		status = lttng_action_notify_get_firing_policy(
				notify_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_firing_policy_is_equal(
								default_policy,
								cur_policy),
				"Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_notify_set_firing_policy(notify_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set firing policy");

	/* Validate the custom policy for a notify action. */
	{
		const struct lttng_firing_policy *cur_policy = NULL;
		status = lttng_action_notify_get_firing_policy(
				notify_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_firing_policy_is_equal(
								policy,
								cur_policy),
				"Notify action policy get");
	}

	ret = lttng_action_serialize(notify_action, &payload);
	ok(ret == 0, "Action notify serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		(void) lttng_action_create_from_payload(
				&view, &notify_action_from_buffer);
	}
	ok(notify_action_from_buffer,
			"Notify action created from payload is non-null");

	ok(lttng_action_is_equal(notify_action, notify_action_from_buffer),
			"Serialized and de-serialized notify action are equal");

	lttng_firing_policy_destroy(default_policy);
	lttng_firing_policy_destroy(policy);
	lttng_action_destroy(notify_action);
	lttng_action_destroy(notify_action_from_buffer);
	lttng_payload_reset(&payload);
}

static void test_action_rotate_session(void)
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *rotate_session_action = NULL,
			    *rotate_session_action_from_buffer = NULL;
	struct lttng_firing_policy *policy = NULL, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_firing_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_firing_policy_every_n_create(1);

	assert(policy && default_policy);

	rotate_session_action = lttng_action_rotate_session_create();
	ok(rotate_session_action, "Create rotate_session action");
	ok(lttng_action_get_type(rotate_session_action) ==
					LTTNG_ACTION_TYPE_ROTATE_SESSION,
			"Action has type LTTNG_ACTION_TYPE_ROTATE_SESSION");

	/* Session name setter. */
	status = lttng_action_rotate_session_set_session_name(NULL, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,NULL) expect invalid");
	status = lttng_action_rotate_session_set_session_name(
			rotate_session_action, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (object,NULL) expect invalid");
	status = lttng_action_rotate_session_set_session_name(
			NULL, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_rotate_session_set_session_name(
			rotate_session_action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_rotate_session_get_session_name(
			rotate_session_action, &get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK &&
					!strcmp(session_name, get_session_name),
			"Get session name, expected `%s` got `%s`",
			session_name, get_session_name);

	/* Validate the default policy for a rotate_session action. */
	{
		const struct lttng_firing_policy *cur_policy = NULL;
		status = lttng_action_rotate_session_get_firing_policy(
				rotate_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_firing_policy_is_equal(
								default_policy,
								cur_policy),
				"Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_rotate_session_set_firing_policy(
			rotate_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set firing policy");

	/* Validate the custom policy for a rotate_session action. */
	{
		const struct lttng_firing_policy *cur_policy = NULL;
		status = lttng_action_rotate_session_get_firing_policy(
				rotate_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_firing_policy_is_equal(
								policy,
								cur_policy),
				"rotate_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(rotate_session_action, &payload);
	ok(ret == 0, "Action rotate_session serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		(void) lttng_action_create_from_payload(
				&view, &rotate_session_action_from_buffer);
	}
	ok(rotate_session_action_from_buffer,
			"rotate_session action created from payload is non-null");

	ok(lttng_action_is_equal(rotate_session_action,
			   rotate_session_action_from_buffer),
			"Serialized and de-serialized rotate_session action are equal");

	lttng_firing_policy_destroy(default_policy);
	lttng_firing_policy_destroy(policy);
	lttng_action_destroy(rotate_session_action);
	lttng_action_destroy(rotate_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

static void test_action_start_session(void)
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *start_session_action = NULL,
			    *start_session_action_from_buffer = NULL;
	struct lttng_firing_policy *policy = NULL, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_firing_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_firing_policy_every_n_create(1);

	assert(policy && default_policy);

	start_session_action = lttng_action_start_session_create();
	ok(start_session_action, "Create start_session action");
	ok(lttng_action_get_type(start_session_action) ==
					LTTNG_ACTION_TYPE_START_SESSION,
			"Action has type LTTNG_ACTION_TYPE_START_SESSION");

	/* Session name setter. */
	status = lttng_action_start_session_set_session_name(NULL, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,NULL) expect invalid");
	status = lttng_action_start_session_set_session_name(
			start_session_action, NULL);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (object,NULL) expect invalid");
	status = lttng_action_start_session_set_session_name(
			NULL, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
			"Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_start_session_set_session_name(
			start_session_action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_start_session_get_session_name(
			start_session_action, &get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK &&
					!strcmp(session_name, get_session_name),
			"Get session name, expected `%s` got `%s`",
			session_name, get_session_name);

	/* Validate the default policy for a start_session action. */
	{
		const struct lttng_firing_policy *cur_policy = NULL;
		status = lttng_action_start_session_get_firing_policy(
				start_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_firing_policy_is_equal(
								default_policy,
								cur_policy),
				"Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_start_session_set_firing_policy(
			start_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set firing policy");

	/* Validate the custom policy for a start_session action. */
	{
		const struct lttng_firing_policy *cur_policy = NULL;
		status = lttng_action_start_session_get_firing_policy(
				start_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
						lttng_firing_policy_is_equal(
								policy,
								cur_policy),
				"start_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(start_session_action, &payload);
	ok(ret == 0, "Action start_session serialized");

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
						&payload, 0, -1);
		(void) lttng_action_create_from_payload(
				&view, &start_session_action_from_buffer);
	}
	ok(start_session_action_from_buffer,
			"start_session action created from payload is non-null");

	ok(lttng_action_is_equal(start_session_action,
			   start_session_action_from_buffer),
			"Serialized and de-serialized start_session action are equal");

	lttng_firing_policy_destroy(default_policy);
	lttng_firing_policy_destroy(policy);
	lttng_action_destroy(start_session_action);
	lttng_action_destroy(start_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_action_notify();
	test_action_rotate_session();
	test_action_start_session();
	return exit_status();
}
