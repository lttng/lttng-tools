/*
 * Copyright (C) 2021 Simon Marchi <simon.marchi@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

/* Utility to register some triggers, for test purposes. */

#include <common/filter/filter-ast.h>
#include <common/macros.h>
#include <lttng/lttng.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

static void register_trigger(const char *trigger_name,
		struct lttng_condition *condition,
		struct lttng_action *action)
{
	struct lttng_trigger *trigger;
	enum lttng_trigger_status trigger_status;
	int ret;

	trigger = lttng_trigger_create(condition, action);
	trigger_status = lttng_trigger_set_name(trigger, trigger_name);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);
	ret = lttng_register_trigger(trigger);
	assert(ret == 0);
}

/*
 * Register a trigger with the given condition and an action group containing a
 * single notify action.
 */
static void register_trigger_action_group_notify(
		const char *trigger_name, struct lttng_condition *condition)
{
	struct lttng_action *action_notify;
	struct lttng_action *action_group;
	enum lttng_action_status action_status;

	action_group = lttng_action_group_create();
	action_notify = lttng_action_notify_create();
	action_status = lttng_action_group_add_action(
			action_group, action_notify);
	assert(action_status == LTTNG_ACTION_STATUS_OK);

	register_trigger(trigger_name, condition, action_group);
}

static struct lttng_condition *create_session_consumed_size_condition(
		const char *session_name, uint64_t threshold)
{
	struct lttng_condition *condition;
	enum lttng_condition_status condition_status;

	condition = lttng_condition_session_consumed_size_create();
	condition_status =
			lttng_condition_session_consumed_size_set_session_name(
					condition, session_name);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);
	condition_status = lttng_condition_session_consumed_size_set_threshold(
			condition, threshold);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	return condition;
}

static void test_session_consumed_size_condition(void)
{
	register_trigger_action_group_notify(
			"trigger-with-session-consumed-size-condition",
			create_session_consumed_size_condition(
					"the-session-name", 1234));
}

static void fill_buffer_usage_condition(struct lttng_condition *condition,
		const char *session_name,
		const char *channel_name,
		enum lttng_domain_type domain_type)
{
	enum lttng_condition_status condition_status;

	condition_status = lttng_condition_buffer_usage_set_session_name(
			condition, session_name);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);
	condition_status = lttng_condition_buffer_usage_set_channel_name(
			condition, channel_name);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);
	condition_status = lttng_condition_buffer_usage_set_domain_type(
			condition, domain_type);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);
}

static void fill_buffer_usage_bytes_condition(struct lttng_condition *condition,
		const char *session_name,
		const char *channel_name,
		enum lttng_domain_type domain_type,
		uint64_t threshold)
{
	enum lttng_condition_status condition_status;

	fill_buffer_usage_condition(
			condition, session_name, channel_name, domain_type);
	condition_status = lttng_condition_buffer_usage_set_threshold(
			condition, threshold);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);
}

static void fill_buffer_usage_ratio_condition(struct lttng_condition *condition,
		const char *session_name,
		const char *channel_name,
		enum lttng_domain_type domain_type,
		double ratio)
{
	enum lttng_condition_status condition_status;

	fill_buffer_usage_condition(
			condition, session_name, channel_name, domain_type);
	condition_status = lttng_condition_buffer_usage_set_threshold_ratio(
			condition, ratio);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);
}

static struct lttng_condition *create_buffer_usage_high_bytes_condition(
		const char *session_name,
		const char *channel_name,
		enum lttng_domain_type domain_type,
		uint64_t threshold)
{
	struct lttng_condition *condition;

	condition = lttng_condition_buffer_usage_high_create();
	fill_buffer_usage_bytes_condition(condition, session_name, channel_name,
			domain_type, threshold);

	return condition;
}

static struct lttng_condition *create_buffer_usage_low_bytes_condition(
		const char *session_name,
		const char *channel_name,
		enum lttng_domain_type domain_type,
		uint64_t threshold)
{
	struct lttng_condition *condition;

	condition = lttng_condition_buffer_usage_low_create();
	fill_buffer_usage_bytes_condition(condition, session_name, channel_name,
			domain_type, threshold);

	return condition;
}

static struct lttng_condition *create_buffer_usage_high_ratio_condition(
		const char *session_name,
		const char *channel_name,
		enum lttng_domain_type domain_type,
		double ratio)
{
	struct lttng_condition *condition;

	condition = lttng_condition_buffer_usage_high_create();
	fill_buffer_usage_ratio_condition(condition, session_name, channel_name,
			domain_type, ratio);

	return condition;
}

static struct lttng_condition *create_buffer_usage_low_ratio_condition(
		const char *session_name,
		const char *channel_name,
		enum lttng_domain_type domain_type,
		double ratio)
{
	struct lttng_condition *condition;

	condition = lttng_condition_buffer_usage_low_create();
	fill_buffer_usage_ratio_condition(condition, session_name, channel_name,
			domain_type, ratio);

	return condition;
}

static void test_buffer_usage_conditions(void)
{
	register_trigger_action_group_notify(
			"trigger-with-buffer-usage-high-bytes-condition",
			create_buffer_usage_high_bytes_condition(
					"the-session-name", "the-channel-name",
					LTTNG_DOMAIN_UST, 1234));

	register_trigger_action_group_notify(
			"trigger-with-buffer-usage-low-bytes-condition",
			create_buffer_usage_low_bytes_condition(
					"the-session-name", "the-channel-name",
					LTTNG_DOMAIN_UST, 2345));

	register_trigger_action_group_notify(
			"trigger-with-buffer-usage-high-ratio-condition",
			create_buffer_usage_high_ratio_condition(
					"the-session-name", "the-channel-name",
					LTTNG_DOMAIN_UST, 0.25));

	register_trigger_action_group_notify(
			"trigger-with-buffer-usage-low-ratio-condition",
			create_buffer_usage_low_ratio_condition(
					"the-session-name", "the-channel-name",
					LTTNG_DOMAIN_UST, 0.4));
}

static void fill_session_rotation_condition(
		struct lttng_condition *condition, const char *session_name)
{
	enum lttng_condition_status condition_status;

	condition_status = lttng_condition_session_rotation_set_session_name(
			condition, session_name);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);
}

static struct lttng_condition *create_session_rotation_ongoing_condition(
		const char *session_name)
{
	struct lttng_condition *condition;

	condition = lttng_condition_session_rotation_ongoing_create();

	fill_session_rotation_condition(condition, session_name);

	return condition;
}

static struct lttng_condition *create_session_rotation_completed_condition(
		const char *session_name)
{
	struct lttng_condition *condition;

	condition = lttng_condition_session_rotation_completed_create();

	fill_session_rotation_condition(condition, session_name);

	return condition;
}

static void test_session_rotation_conditions(void)
{
	register_trigger_action_group_notify(
			"trigger-with-session-rotation-ongoing-condition",
			create_session_rotation_ongoing_condition(
					"the-session-name"));

	register_trigger_action_group_notify(
			"trigger-with-session-rotation-completed-condition",
			create_session_rotation_completed_condition(
					"the-session-name"));
}

static struct {
	const char *name;
	void (*callback)(void);
} tests[] = {
		{
				"test_session_consumed_size_condition",
				test_session_consumed_size_condition,
		},
		{"test_buffer_usage_conditions", test_buffer_usage_conditions},
		{"test_session_rotation_conditions",
				test_session_rotation_conditions},
};

static void show_known_tests(void)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		fprintf(stderr, " - %s\n", tests[i].name);
	}
}

int main(int argc, char **argv)
{
	const char *test;
	size_t i;
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <test>\n", argv[0]);
		fprintf(stderr, "\n");
		fprintf(stderr, "Test must be one of:\n");
		show_known_tests();
		goto error;
	}

	test = argv[1];

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		if (strcmp(tests[i].name, test) == 0) {
			break;
		}
	}

	if (i == ARRAY_SIZE(tests)) {
		fprintf(stderr, "Unrecognized test `%s`\n", test);
		fprintf(stderr, "\n");
		fprintf(stderr, "Known tests:\n");
		show_known_tests();
		goto error;
	}

	tests[i].callback();

	ret = 0;
	goto end;

error:
	ret = 1;

end:
	return ret;
}
