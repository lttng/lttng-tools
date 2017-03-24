/*
 * test_notification.c
 *
 * Unit tests for the notification API.
 *
 * Copyright (C) 2017 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <lttng/action/action.h>
#include <lttng/action/notify.h>
#include <lttng/condition/buffer-usage.h>
#include <lttng/condition/condition.h>
#include <lttng/domain.h>
#include <lttng/notification/notification.h>
#include <lttng/trigger/trigger.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 182

void test_condition_buffer_usage(struct lttng_condition *buffer_usage_condition)
{
	enum lttng_condition_status status = LTTNG_CONDITION_STATUS_OK;
	const char *session_name = NULL;
	const char *channel_name = NULL;
	enum lttng_domain_type domain_type;
	/* Start at a non zero value to validate initialization */
	double threshold_ratio;
	uint64_t threshold_bytes;

	assert(buffer_usage_condition);

	diag("Validating initialization");
	status = lttng_condition_buffer_usage_get_threshold_ratio(buffer_usage_condition, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Threshold ratio is unset");

	status = lttng_condition_buffer_usage_get_threshold(buffer_usage_condition, &threshold_bytes);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Threshold byte is unset");

	status = lttng_condition_buffer_usage_get_session_name(buffer_usage_condition, &session_name);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Session name is unset");
	ok(!session_name, "Session name is null");

	status = lttng_condition_buffer_usage_get_channel_name(buffer_usage_condition, &channel_name);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Channel name is unset");
	ok(!session_name, "Channel name is null");

	status = lttng_condition_buffer_usage_get_domain_type(buffer_usage_condition, &domain_type);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Domain name is unset");

	diag("Testing session name set/get");
	status = lttng_condition_buffer_usage_set_session_name(NULL, "Test");
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set null condition on set session name");
	status = lttng_condition_buffer_usage_get_session_name(NULL, &session_name);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Get session name with null condition");
	ok(!session_name, "Session name is null");
	status = lttng_condition_buffer_usage_get_session_name(buffer_usage_condition, &session_name);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Session name is unset");
	ok(!session_name, "Session name is null");

	status = lttng_condition_buffer_usage_set_session_name(buffer_usage_condition, NULL);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set null session name");
	status = lttng_condition_buffer_usage_get_session_name(buffer_usage_condition, &session_name);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Session name is unset");
	ok(!session_name, "Session name is null");

	status = lttng_condition_buffer_usage_set_session_name(buffer_usage_condition, "");
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set empty session name");
	status = lttng_condition_buffer_usage_get_session_name(buffer_usage_condition, &session_name);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Session name is unset");
	ok(!session_name, "Session name is null");

	status = lttng_condition_buffer_usage_set_session_name(buffer_usage_condition, "session420");
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set session name session420");
	status = lttng_condition_buffer_usage_get_session_name(buffer_usage_condition, &session_name);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Session name is set");
	ok(session_name, "Session name has a value");
	ok(strcmp("session420", session_name) == 0, "Session name is %s", "session420");

	/*
	 * Test second set on session_name. Test invalid set and validate that
	 * the value is still the previous good one.
	 */

	status = lttng_condition_buffer_usage_set_session_name(buffer_usage_condition, "");
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set session name to empty");
	status = lttng_condition_buffer_usage_get_session_name(buffer_usage_condition, &session_name);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Session name is still set");
	ok(session_name, "Session name has a value");
	ok(strcmp("session420", session_name) == 0, "Session is still name is %s", "session420");

	diag("Testing channel name set/get");
	status = lttng_condition_buffer_usage_set_channel_name(NULL, "Test");
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set null condition on set channel name");
	status = lttng_condition_buffer_usage_get_channel_name(NULL, &channel_name);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Get channel name with null condition");
	status = lttng_condition_buffer_usage_get_channel_name(buffer_usage_condition, &channel_name);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Channel name is unset");
	ok(!channel_name, "Channel name is null");

	status = lttng_condition_buffer_usage_set_channel_name(buffer_usage_condition, NULL);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set null channel name");
	status = lttng_condition_buffer_usage_get_channel_name(buffer_usage_condition, &channel_name);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Channel name is unset");
	ok(!channel_name, "Channel name is null");

	status = lttng_condition_buffer_usage_set_channel_name(buffer_usage_condition, "");
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set empty channel name");
	status = lttng_condition_buffer_usage_get_channel_name(buffer_usage_condition, &channel_name);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Channel name is unset");
	ok(!channel_name, "Channel name is null");

	status = lttng_condition_buffer_usage_set_channel_name(buffer_usage_condition, "channel420");
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set channel name channel420");
	status = lttng_condition_buffer_usage_get_channel_name(buffer_usage_condition, &channel_name);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Channel name is set");
	ok(channel_name, "Channel name has a value");
	ok(strcmp("channel420", channel_name) == 0, "Channel name is %s", "channel420");

	/*
	 * Test second set on channel_name. Test invalid set and validate that
	 * the value is still the previous good one.
	 */

	status = lttng_condition_buffer_usage_set_channel_name(buffer_usage_condition, "");
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set channel name to empty");
	status = lttng_condition_buffer_usage_get_channel_name(buffer_usage_condition, &channel_name);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Channel name is still set");
	ok(channel_name, "Channel name has a value");
	ok(strcmp("channel420", channel_name) == 0, "Channel is still name is %s", "channel420");

	diag("Testing threshold ratio set/get");
	status = lttng_condition_buffer_usage_set_threshold_ratio(NULL, 0.420);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set threshold ratio with null condition");
	status = lttng_condition_buffer_usage_get_threshold_ratio(NULL, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Get threshold ratio with null condition");
	status = lttng_condition_buffer_usage_get_threshold_ratio(buffer_usage_condition, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Threshold ratio is unset");

	status = lttng_condition_buffer_usage_set_threshold_ratio(buffer_usage_condition, -100.0);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set threshold ratio < 0");
	status = lttng_condition_buffer_usage_get_threshold_ratio(buffer_usage_condition, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Threshold ratio is unset");

	status = lttng_condition_buffer_usage_set_threshold_ratio(buffer_usage_condition, 200.0);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set Threshold ratio > 1");
	status = lttng_condition_buffer_usage_get_threshold_ratio(buffer_usage_condition, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Threshold ratio is unset");

	status = lttng_condition_buffer_usage_set_threshold_ratio(buffer_usage_condition, 1.0);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set threshold ratio == 1.0");
	status = lttng_condition_buffer_usage_get_threshold_ratio(buffer_usage_condition, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Threshold ratio is set");
	ok(threshold_ratio == 1.0, "Threshold ratio is 1.0");

	status = lttng_condition_buffer_usage_set_threshold_ratio(buffer_usage_condition, 0.0);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set threshold ratio == 0.0");
	status = lttng_condition_buffer_usage_get_threshold_ratio(buffer_usage_condition, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Threshold ratio is set");
	ok(threshold_ratio == 0.0, "Threshold ratio is 0.0");

	status = lttng_condition_buffer_usage_set_threshold_ratio(buffer_usage_condition, 0.420);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set threshold ratio == 0.420");
	status = lttng_condition_buffer_usage_get_threshold_ratio(buffer_usage_condition, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Threshold ratio is set");
	ok(threshold_ratio == 0.420, "Threshold ratio is 0.420");

	diag("Testing threshold bytes set/get");
	status = lttng_condition_buffer_usage_set_threshold(NULL, 100000);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set threshold with null condition");
	status = lttng_condition_buffer_usage_get_threshold(NULL, &threshold_bytes);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Get threshold value with null condition ");
	status = lttng_condition_buffer_usage_get_threshold(buffer_usage_condition, &threshold_bytes);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Threshold is unset");

	status = lttng_condition_buffer_usage_set_threshold(buffer_usage_condition, 100000);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set threshold > 0");
	status = lttng_condition_buffer_usage_get_threshold(buffer_usage_condition, &threshold_bytes);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Threshold is set");
	ok(threshold_bytes == 100000, "Threshold is %" PRIu64 , 100000);

	status = lttng_condition_buffer_usage_set_threshold(buffer_usage_condition, UINT64_MAX);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set threshold UINT64_MAX");
	status = lttng_condition_buffer_usage_get_threshold(buffer_usage_condition, &threshold_bytes);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Threshold is set");
	ok(threshold_bytes == UINT64_MAX, "Threshold is UINT64_MAX");

	status = lttng_condition_buffer_usage_set_threshold(buffer_usage_condition, 0);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set threshold  == 0");
	status = lttng_condition_buffer_usage_get_threshold(buffer_usage_condition, &threshold_bytes);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Threshold is set");
	ok(threshold_bytes == 0, "Threshold is %d", 0);

	/*
	 * Test value of threshold ration, since we overwrote it with a byte
	 * threshold. Make sure it gets squashed.
	 */
	diag("Testing interaction between byte and ratio thresholds");

	threshold_ratio = -1.0;
	status = lttng_condition_buffer_usage_get_threshold_ratio(buffer_usage_condition, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Threshold ratio is unset");
	ok(threshold_ratio == -1.0, "Threshold ratio is untouched");

	/* Set a ratio to validate that the byte threshold is now unset */
	status = lttng_condition_buffer_usage_set_threshold_ratio(buffer_usage_condition, 0.420);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set threshold ratio == 0.420");
	status = lttng_condition_buffer_usage_get_threshold_ratio(buffer_usage_condition, &threshold_ratio);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Threshold ratio is set");
	ok(threshold_ratio == 0.420, "Threshold ratio is 0.420");

	threshold_bytes = 420;
	status = lttng_condition_buffer_usage_get_threshold(buffer_usage_condition, &threshold_bytes);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Threshold is unset");
	ok(threshold_bytes == 420, "Threshold is untouched");

	diag("Testing domain type set/get");
	status = lttng_condition_buffer_usage_set_domain_type(NULL, LTTNG_DOMAIN_UST);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set domain type with null condition");
	status = lttng_condition_buffer_usage_get_domain_type(NULL, &domain_type);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Get domain type with null condition");

	status = lttng_condition_buffer_usage_set_domain_type(buffer_usage_condition, LTTNG_DOMAIN_NONE);
	ok(status == LTTNG_CONDITION_STATUS_INVALID, "Set domain type as LTTNG_DOMAIN_NONE");
	status = lttng_condition_buffer_usage_get_domain_type(buffer_usage_condition, &domain_type);
	ok(status == LTTNG_CONDITION_STATUS_UNSET, "Domain type is unset");

	status = lttng_condition_buffer_usage_set_domain_type(buffer_usage_condition, LTTNG_DOMAIN_UST);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Set domain type as LTTNG_DOMAIN_UST");
	status = lttng_condition_buffer_usage_get_domain_type(buffer_usage_condition, &domain_type);
	ok(status == LTTNG_CONDITION_STATUS_OK, "Domain type is set");
	ok(domain_type == LTTNG_DOMAIN_UST, "Domain type is LTTNG_DOMAIN_UST");
}


void test_condition_buffer_usage_low(void)
{
	struct lttng_condition *buffer_usage_low = NULL;

	diag("Testing lttng_condition_buffer_usage_low_create");
	buffer_usage_low = lttng_condition_buffer_usage_low_create();
	ok(buffer_usage_low, "Condition allocated");

	ok(lttng_condition_get_type(buffer_usage_low) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW, "Condition is of type \"low buffer usage\"");

	test_condition_buffer_usage(buffer_usage_low);

	lttng_condition_destroy(buffer_usage_low);
}

void test_condition_buffer_usage_high(void)
{
	struct lttng_condition *buffer_usage_high = NULL;

	diag("Testing lttng_condition_buffer_usage_high_create");
	buffer_usage_high = lttng_condition_buffer_usage_high_create();
	ok(buffer_usage_high, "High buffer usage condition allocated");

	ok(lttng_condition_get_type(buffer_usage_high) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH, "Condition is of type \"high buffer usage\"");

	test_condition_buffer_usage(buffer_usage_high);

	lttng_condition_destroy(buffer_usage_high);
}

void test_action(void)
{
	struct lttng_action *notify_action = NULL;

	notify_action = lttng_action_notify_create();
	ok(notify_action, "Create notify action");
	ok(lttng_action_get_type(notify_action) == LTTNG_ACTION_TYPE_NOTIFY, "Action has type LTTNG_ACTION_TYPE_NOTIFY");
	lttng_action_destroy(notify_action);
}

void test_trigger(void)
{
	struct lttng_action *notify_action = NULL;
	struct lttng_condition *buffer_usage_high = NULL;
	struct lttng_trigger *trigger = NULL;

	notify_action = lttng_action_notify_create();
	buffer_usage_high = lttng_condition_buffer_usage_high_create();

	trigger = lttng_trigger_create(NULL, NULL);
	ok(!trigger, "lttng_trigger_create(NULL, NULL) returns null");
	trigger = lttng_trigger_create(buffer_usage_high, NULL);
	ok(!trigger, "lttng_trigger_create(NON-NULL, NULL) returns null");
	trigger = lttng_trigger_create(NULL, notify_action);
	ok(!trigger, "lttng_trigger_create(NULL, NON-NULL) returns null");

	trigger = lttng_trigger_create(buffer_usage_high, notify_action);
	ok(trigger, "lttng_trigger_create(NON-NULL, NON-NULL) returns an object");

	lttng_action_destroy(notify_action);
	lttng_condition_destroy(buffer_usage_high);
	lttng_trigger_destroy(trigger);
}


int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_condition_buffer_usage_low();
	test_condition_buffer_usage_high();
	test_action();
	test_trigger();
	return exit_status();
}
