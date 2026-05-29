/*
 * test_action.c
 *
 * Unit tests for the notification API.
 *
 * SPDX-FileCopyrightText: 2017 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <common/error.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/action/action-internal.hpp>
#include <lttng/action/action.h>
#include <lttng/action/increment-map-value.h>
#include <lttng/action/key-template.h>
#include <lttng/action/list-internal.hpp>
#include <lttng/action/notify.h>
#include <lttng/action/rate-policy-internal.hpp>
#include <lttng/action/rate-policy.h>
#include <lttng/action/rotate-session.h>
#include <lttng/action/snapshot-session.h>
#include <lttng/action/start-session.h>
#include <lttng/action/stop-session.h>

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <tap/tap.h>
#include <unistd.h>

/* For error.h */
bool lttng_opt_is_tui = true;
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 102

namespace {
void test_action_notify()
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *notify_action = nullptr, *notify_action_from_buffer = nullptr;
	struct lttng_rate_policy *policy = nullptr, *default_policy;
	struct lttng_payload payload;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	LTTNG_ASSERT(policy && default_policy);

	notify_action = lttng_action_notify_create();
	ok(notify_action, "Create notify action");
	ok(lttng_action_get_type(notify_action) == LTTNG_ACTION_TYPE_NOTIFY,
	   "Action has type LTTNG_ACTION_TYPE_NOTIFY");

	/* Validate the default policy for a notify action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status = lttng_action_notify_get_rate_policy(notify_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(default_policy, cur_policy),
		   "Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_notify_set_rate_policy(notify_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a notify action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status = lttng_action_notify_get_rate_policy(notify_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(policy, cur_policy),
		   "Notify action policy get");
	}

	ret = lttng_action_serialize(notify_action, &payload);
	ok(ret == 0, "Action notify serialized");

	{
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);
		(void) lttng_action_create_from_payload(&view, &notify_action_from_buffer);
	}
	ok(notify_action_from_buffer, "Notify action created from payload is non-null");

	ok(lttng_action_is_equal(notify_action, notify_action_from_buffer),
	   "Serialized and de-serialized notify action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(notify_action);
	lttng_action_destroy(notify_action_from_buffer);
	lttng_payload_reset(&payload);
}

void test_action_list()
{
	int ret, action_idx;
	struct lttng_action *list_action = nullptr, *list_action_from_buffer = nullptr,
			    *stop_session_action = nullptr, *notify_action = nullptr,
			    *start_session_action = nullptr;
	struct lttng_payload payload;

	lttng_payload_init(&payload);

	list_action = lttng_action_list_create();
	ok(list_action, "Create list action");
	ok(lttng_action_get_type(list_action) == LTTNG_ACTION_TYPE_LIST,
	   "Action has type LTTNG_ACTION_TYPE_LIST");

	start_session_action = lttng_action_start_session_create();
	(void) lttng_action_start_session_set_session_name(start_session_action, "une-session");

	stop_session_action = lttng_action_stop_session_create();
	(void) lttng_action_stop_session_set_session_name(stop_session_action, "une-autre-session");
	notify_action = lttng_action_notify_create();

	lttng_action_list_add_action(list_action, start_session_action);
	lttng_action_list_add_action(list_action, stop_session_action);
	lttng_action_list_add_action(list_action, notify_action);

	ret = lttng_action_serialize(list_action, &payload);
	ok(ret == 0, "Action list serialized");

	{
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);
		(void) lttng_action_create_from_payload(&view, &list_action_from_buffer);
	}
	ok(list_action_from_buffer, "Notify action created from payload is non-null");

	ok(lttng_action_is_equal(list_action, list_action_from_buffer),
	   "Serialized and de-serialized list action are equal");

	action_idx = 0;
	for (auto action : lttng::ctl::const_action_list_view(list_action)) {
		const lttng_action_type inner_action_type = lttng_action_get_type(action);
		switch (action_idx) {
		case 0:
			ok(inner_action_type == LTTNG_ACTION_TYPE_START_SESSION,
			   "First inner action of action list is `start-session` action");
			break;
		case 1:
			ok(inner_action_type == LTTNG_ACTION_TYPE_STOP_SESSION,
			   "Second inner action of action list is `stop-session` action");
			break;
		case 2:
			ok(inner_action_type == LTTNG_ACTION_TYPE_NOTIFY,
			   "Third inner action of action list is `notify` action");
			break;
		}
		action_idx++;
	}

	action_idx = 0;
	for (auto action : lttng::ctl::action_list_view(list_action)) {
		const lttng_action_type inner_action_type = lttng_action_get_type(action);
		switch (action_idx) {
		case 0:
			ok(inner_action_type == LTTNG_ACTION_TYPE_START_SESSION,
			   "First inner action of action list is `start-session` action");
			break;
		case 1:
			ok(inner_action_type == LTTNG_ACTION_TYPE_STOP_SESSION,
			   "Second inner action of action list is `stop-session` action");
			break;
		case 2:
			ok(inner_action_type == LTTNG_ACTION_TYPE_NOTIFY,
			   "Third inner action of action list is `notify` action");
			break;
		}
		action_idx++;
	}

	lttng_action_destroy(list_action);
	lttng_action_destroy(list_action_from_buffer);
	lttng_action_destroy(start_session_action);
	lttng_action_destroy(stop_session_action);
	lttng_action_destroy(notify_action);
	lttng_payload_reset(&payload);
}

void test_action_rotate_session()
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *rotate_session_action = nullptr,
			    *rotate_session_action_from_buffer = nullptr;
	struct lttng_rate_policy *policy = nullptr, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	LTTNG_ASSERT(policy && default_policy);

	rotate_session_action = lttng_action_rotate_session_create();
	ok(rotate_session_action, "Create rotate_session action");
	ok(lttng_action_get_type(rotate_session_action) == LTTNG_ACTION_TYPE_ROTATE_SESSION,
	   "Action has type LTTNG_ACTION_TYPE_ROTATE_SESSION");

	/* Session name setter. */
	status = lttng_action_rotate_session_set_session_name(nullptr, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (NULL,NULL) expect invalid");
	status = lttng_action_rotate_session_set_session_name(rotate_session_action, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (object,NULL) expect invalid");
	status = lttng_action_rotate_session_set_session_name(nullptr, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_rotate_session_set_session_name(rotate_session_action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_rotate_session_get_session_name(rotate_session_action,
							      &get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK && !strcmp(session_name, get_session_name),
	   "Get session name, expected `%s` got `%s`",
	   session_name,
	   get_session_name);

	/* Validate the default policy for a rotate_session action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status = lttng_action_rotate_session_get_rate_policy(rotate_session_action,
								     &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(default_policy, cur_policy),
		   "Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_rotate_session_set_rate_policy(rotate_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a rotate_session action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status = lttng_action_rotate_session_get_rate_policy(rotate_session_action,
								     &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(policy, cur_policy),
		   "rotate_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(rotate_session_action, &payload);
	ok(ret == 0, "Action rotate_session serialized");

	{
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);
		(void) lttng_action_create_from_payload(&view, &rotate_session_action_from_buffer);
	}
	ok(rotate_session_action_from_buffer,
	   "rotate_session action created from payload is non-null");

	ok(lttng_action_is_equal(rotate_session_action, rotate_session_action_from_buffer),
	   "Serialized and de-serialized rotate_session action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(rotate_session_action);
	lttng_action_destroy(rotate_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

void test_action_start_session()
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *start_session_action = nullptr,
			    *start_session_action_from_buffer = nullptr;
	struct lttng_rate_policy *policy = nullptr, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	LTTNG_ASSERT(policy && default_policy);

	start_session_action = lttng_action_start_session_create();
	ok(start_session_action, "Create start_session action");
	ok(lttng_action_get_type(start_session_action) == LTTNG_ACTION_TYPE_START_SESSION,
	   "Action has type LTTNG_ACTION_TYPE_START_SESSION");

	/* Session name setter. */
	status = lttng_action_start_session_set_session_name(nullptr, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (NULL,NULL) expect invalid");
	status = lttng_action_start_session_set_session_name(start_session_action, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (object,NULL) expect invalid");
	status = lttng_action_start_session_set_session_name(nullptr, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_start_session_set_session_name(start_session_action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_start_session_get_session_name(start_session_action,
							     &get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK && !strcmp(session_name, get_session_name),
	   "Get session name, expected `%s` got `%s`",
	   session_name,
	   get_session_name);

	/* Validate the default policy for a start_session action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status = lttng_action_start_session_get_rate_policy(start_session_action,
								    &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(default_policy, cur_policy),
		   "Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_start_session_set_rate_policy(start_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a start_session action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status = lttng_action_start_session_get_rate_policy(start_session_action,
								    &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(policy, cur_policy),
		   "start_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(start_session_action, &payload);
	ok(ret == 0, "Action start_session serialized");

	{
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);
		(void) lttng_action_create_from_payload(&view, &start_session_action_from_buffer);
	}
	ok(start_session_action_from_buffer,
	   "start_session action created from payload is non-null");

	ok(lttng_action_is_equal(start_session_action, start_session_action_from_buffer),
	   "Serialized and de-serialized start_session action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(start_session_action);
	lttng_action_destroy(start_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

void test_action_stop_session()
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *stop_session_action = nullptr,
			    *stop_session_action_from_buffer = nullptr;
	struct lttng_rate_policy *policy = nullptr, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	LTTNG_ASSERT(policy && default_policy);

	stop_session_action = lttng_action_stop_session_create();
	ok(stop_session_action, "Create stop_session action");
	ok(lttng_action_get_type(stop_session_action) == LTTNG_ACTION_TYPE_STOP_SESSION,
	   "Action has type LTTNG_ACTION_TYPE_STOP_SESSION");

	/* Session name setter. */
	status = lttng_action_stop_session_set_session_name(nullptr, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (NULL,NULL) expect invalid");
	status = lttng_action_stop_session_set_session_name(stop_session_action, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (object,NULL) expect invalid");
	status = lttng_action_stop_session_set_session_name(nullptr, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_stop_session_set_session_name(stop_session_action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_stop_session_get_session_name(stop_session_action, &get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK && !strcmp(session_name, get_session_name),
	   "Get session name, expected `%s` got `%s`",
	   session_name,
	   get_session_name);

	/* Validate the default policy for a stop_session action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status =
			lttng_action_stop_session_get_rate_policy(stop_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(default_policy, cur_policy),
		   "Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_stop_session_set_rate_policy(stop_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a stop_session action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status =
			lttng_action_stop_session_get_rate_policy(stop_session_action, &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(policy, cur_policy),
		   "stop_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(stop_session_action, &payload);
	ok(ret == 0, "Action stop_session serialized");

	{
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);
		(void) lttng_action_create_from_payload(&view, &stop_session_action_from_buffer);
	}
	ok(stop_session_action_from_buffer, "stop_session action created from payload is non-null");

	ok(lttng_action_is_equal(stop_session_action, stop_session_action_from_buffer),
	   "Serialized and de-serialized stop_session action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(stop_session_action);
	lttng_action_destroy(stop_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

void test_action_snapshot_session()
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *snapshot_session_action = nullptr,
			    *snapshot_session_action_from_buffer = nullptr;
	struct lttng_rate_policy *policy = nullptr, *default_policy;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *get_session_name;

	lttng_payload_init(&payload);

	/* To set. */
	policy = lttng_rate_policy_every_n_create(100);
	/* For comparison. */
	default_policy = lttng_rate_policy_every_n_create(1);

	LTTNG_ASSERT(policy && default_policy);

	snapshot_session_action = lttng_action_snapshot_session_create();
	ok(snapshot_session_action, "Create snapshot_session action");
	ok(lttng_action_get_type(snapshot_session_action) == LTTNG_ACTION_TYPE_SNAPSHOT_SESSION,
	   "Action has type LTTNG_ACTION_TYPE_SNAPSHOT_SESSION");

	/* Session name setter. */
	status = lttng_action_snapshot_session_set_session_name(nullptr, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (NULL,NULL) expect invalid");
	status = lttng_action_snapshot_session_set_session_name(snapshot_session_action, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (object,NULL) expect invalid");
	status = lttng_action_snapshot_session_set_session_name(nullptr, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set session name (NULL,object) expect invalid");

	/* Set the session name */
	status = lttng_action_snapshot_session_set_session_name(snapshot_session_action,
								session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set session name");

	status = lttng_action_snapshot_session_get_session_name(snapshot_session_action,
								&get_session_name);
	ok(status == LTTNG_ACTION_STATUS_OK && !strcmp(session_name, get_session_name),
	   "Get session name, expected `%s` got `%s`",
	   session_name,
	   get_session_name);

	/* Validate the default policy for a snapshot_session action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status = lttng_action_snapshot_session_get_rate_policy(snapshot_session_action,
								       &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(default_policy, cur_policy),
		   "Default policy is every n=1");
	}

	/* Set a custom policy. */
	status = lttng_action_snapshot_session_set_rate_policy(snapshot_session_action, policy);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set rate policy");

	/* Validate the custom policy for a snapshot_session action. */
	{
		const struct lttng_rate_policy *cur_policy = nullptr;
		status = lttng_action_snapshot_session_get_rate_policy(snapshot_session_action,
								       &cur_policy);
		ok(status == LTTNG_ACTION_STATUS_OK &&
			   lttng_rate_policy_is_equal(policy, cur_policy),
		   "snapshot_session action policy get");
	}

	/* Ser/des tests. */
	ret = lttng_action_serialize(snapshot_session_action, &payload);
	ok(ret == 0, "Action snapshot_session serialized");

	{
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);
		(void) lttng_action_create_from_payload(&view,
							&snapshot_session_action_from_buffer);
	}
	ok(snapshot_session_action_from_buffer,
	   "snapshot_session action created from payload is non-null");

	ok(lttng_action_is_equal(snapshot_session_action, snapshot_session_action_from_buffer),
	   "Serialized and de-serialized snapshot_session action are equal");

	lttng_rate_policy_destroy(default_policy);
	lttng_rate_policy_destroy(policy);
	lttng_action_destroy(snapshot_session_action);
	lttng_action_destroy(snapshot_session_action_from_buffer);
	lttng_payload_reset(&payload);
}

void test_action_increment_map_value()
{
	int ret;
	enum lttng_action_status status;
	struct lttng_action *action = nullptr, *action_from_buffer = nullptr;
	struct lttng_payload payload;
	const char *session_name = "my_session_name";
	const char *channel_name = "my_map_channel";
	const char *key_template_str = "hits-{provider_name}:{event_name}";
	const char *got = nullptr;
	struct lttng_key_template *key_template = nullptr;
	const struct lttng_key_template *got_template = nullptr;

	lttng_payload_init(&payload);

	action = lttng_action_increment_map_value_create();
	ok(action, "Create increment_map_value action");
	ok(lttng_action_get_type(action) == LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE,
	   "Action has type LTTNG_ACTION_TYPE_INCREMENT_MAP_VALUE");

	/* Action without any mandatory field must not validate. */
	ok(!lttng_action_validate(action),
	   "increment_map_value action does not validate before mandatory fields are set");

	/* Target session name setter precondition checks. */
	status = lttng_action_increment_map_value_set_target_session_name(nullptr, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
	   "Set target session name (NULL,NULL) expect invalid");
	status = lttng_action_increment_map_value_set_target_session_name(action, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
	   "Set target session name (object,NULL) expect invalid");
	status = lttng_action_increment_map_value_set_target_session_name(nullptr, session_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
	   "Set target session name (NULL,object) expect invalid");

	status = lttng_action_increment_map_value_set_target_session_name(action, session_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set target session name");

	status = lttng_action_increment_map_value_get_target_session_name(action, &got);
	ok(status == LTTNG_ACTION_STATUS_OK && got && !strcmp(session_name, got),
	   "Get target session name, expected `%s` got `%s`",
	   session_name,
	   got ? got : "(null)");

	/* Target channel name setter precondition checks. */
	status = lttng_action_increment_map_value_set_target_channel_name(nullptr, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
	   "Set target channel name (NULL,NULL) expect invalid");
	status = lttng_action_increment_map_value_set_target_channel_name(action, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
	   "Set target channel name (object,NULL) expect invalid");
	status = lttng_action_increment_map_value_set_target_channel_name(nullptr, channel_name);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
	   "Set target channel name (NULL,object) expect invalid");

	status = lttng_action_increment_map_value_set_target_channel_name(action, channel_name);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set target channel name");

	status = lttng_action_increment_map_value_get_target_channel_name(action, &got);
	ok(status == LTTNG_ACTION_STATUS_OK && got && !strcmp(channel_name, got),
	   "Get target channel name, expected `%s` got `%s`",
	   channel_name,
	   got ? got : "(null)");

	/* The action still misses a key template. */
	ok(!lttng_action_validate(action),
	   "increment_map_value action does not validate without a key template");

	/*
	 * Build the template the action will use. The key template parser and
	 * renderer are exercised standalone in test_action_key_template.
	 */
	key_template = lttng_key_template_create_from_string(key_template_str);
	ok(key_template, "Parse key template `%s`", key_template_str);

	/* Key template setter precondition checks. */
	status = lttng_action_increment_map_value_set_key_template(nullptr, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set key template (NULL,NULL) expect invalid");
	status = lttng_action_increment_map_value_set_key_template(action, nullptr);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set key template (object,NULL) expect invalid");
	status = lttng_action_increment_map_value_set_key_template(nullptr, key_template);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set key template (NULL,object) expect invalid");

	status = lttng_action_increment_map_value_set_key_template(action, key_template);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set key template");

	/*
	 * The action holds a copy: destroying the caller's template must not
	 * affect the action's stored template.
	 */
	lttng_key_template_destroy(key_template);
	key_template = nullptr;

	status = lttng_action_increment_map_value_get_key_template(action, &got_template);
	ok(status == LTTNG_ACTION_STATUS_OK && got_template != nullptr,
	   "Get key template returns non-null after set");

	{
		char *got_str = nullptr;

		(void) lttng_key_template_to_string(got_template, &got_str);
		ok(got_str && strcmp(got_str, key_template_str) == 0,
		   "Get key template renders back to `%s`, got `%s`",
		   key_template_str,
		   got_str ? got_str : "(null)");
		free(got_str);
	}

	/*
	 * Everything but the target map channel type is set: the action must
	 * still fail to validate, proving the channel type is mandatory.
	 */
	ok(!lttng_action_validate(action),
	   "increment_map_value action does not validate without a target channel type");

	{
		enum lttng_map_channel_type got_type = LTTNG_MAP_CHANNEL_TYPE_KERNEL;
		ok(lttng_action_increment_map_value_get_target_channel_type(action, &got_type) ==
			   LTTNG_ACTION_STATUS_UNSET,
		   "Get target channel type before set returns UNSET");
	}

	/* Target channel type setter precondition checks. */
	status = lttng_action_increment_map_value_set_target_channel_type(
		nullptr, LTTNG_MAP_CHANNEL_TYPE_KERNEL);
	ok(status == LTTNG_ACTION_STATUS_INVALID, "Set target channel type (NULL) expect invalid");
	status = lttng_action_increment_map_value_set_target_channel_type(
		action, (enum lttng_map_channel_type) 42);
	ok(status == LTTNG_ACTION_STATUS_INVALID,
	   "Set target channel type out of range expect invalid");

	status = lttng_action_increment_map_value_set_target_channel_type(
		action, LTTNG_MAP_CHANNEL_TYPE_USER);
	ok(status == LTTNG_ACTION_STATUS_OK, "Set target channel type");

	{
		enum lttng_map_channel_type got_type = LTTNG_MAP_CHANNEL_TYPE_KERNEL;
		status =
			lttng_action_increment_map_value_get_target_channel_type(action, &got_type);
		ok(status == LTTNG_ACTION_STATUS_OK && got_type == LTTNG_MAP_CHANNEL_TYPE_USER,
		   "Get target channel type returns the type that was set");
	}

	/* Validation: all mandatory fields are now set. */
	ok(lttng_action_validate(action),
	   "increment_map_value action validates with all mandatory fields set");

	/* Serialize / deserialize / equality round-trip. */
	ret = lttng_action_serialize(action, &payload);
	ok(ret == 0, "Action increment_map_value serialized");

	{
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);
		(void) lttng_action_create_from_payload(&view, &action_from_buffer);
	}
	ok(action_from_buffer, "increment_map_value action created from payload is non-null");

	ok(lttng_action_is_equal(action, action_from_buffer),
	   "Serialized and de-serialized increment_map_value action are equal");

	lttng_action_destroy(action);
	lttng_action_destroy(action_from_buffer);
	lttng_payload_reset(&payload);
}

int _main()
{
	plan_tests(NUM_TESTS);
	test_action_notify();
	test_action_list();
	test_action_rotate_session();
	test_action_start_session();
	test_action_stop_session();
	test_action_snapshot_session();
	test_action_increment_map_value();
	return exit_status();
}
} /* namespace */

int main()
{
	try {
		return _main();
	} catch (const std::exception& e) {
		ERR_FMT("Unhandled exception caught by action unit test: {}", e.what());
		abort();
	}
}
