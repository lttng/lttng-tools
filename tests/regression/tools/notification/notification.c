/*
 * notification.c
 *
 * Tests suite for LTTng notification API
 *
 * Copyright (C) 2017 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>

#include <common/compat/errno.h>
#include <lttng/action/action.h>
#include <lttng/action/notify.h>
#include <lttng/condition/buffer-usage.h>
#include <lttng/condition/condition.h>
#include <lttng/condition/evaluation.h>
#include <lttng/domain.h>
#include <lttng/endpoint.h>
#include <lttng/lttng-error.h>
#include <lttng/notification/channel.h>
#include <lttng/notification/notification.h>
#include <lttng/trigger/trigger.h>
#include <lttng/lttng.h>

#include <tap/tap.h>

#define NUM_TESTS 104

int nb_args = 0;
int named_pipe_args_start = 0;
pid_t app_pid = 0;
const char *app_state_file = NULL;

static
void wait_on_file(const char *path, bool file_exist)
{
	if (!path) {
		return;
	}
	for (;;) {
		int ret;
		struct stat buf;

		ret = stat(path, &buf);
		if (ret == -1 && errno == ENOENT) {
			if (file_exist) {
				/*
				 * The file does not exist. wait a bit and
				 * continue looping until it does.
				 */
				(void) poll(NULL, 0, 10);
				continue;
			}

			/*
			 * File does not exist and the exit condition we want.
			 * Break from the loop and return.
			 */
			break;
		}
		if (ret) {
			perror("stat");
			exit(EXIT_FAILURE);
		}
		/*
		 * stat() returned 0, so the file exists. break now only if
		 * that's the exit condition we want.
		 */
		if (file_exist) {
			break;
		}
	}
}

static
int write_pipe(const char *path, uint8_t data)
{
	int ret = 0;
	int fd = 0;

	fd = open(path, O_WRONLY | O_NONBLOCK);
	if (fd < 0) {
		perror("Could not open consumer control named pipe");
		goto end;
	}

	ret = write(fd, &data , sizeof(data));
	if (ret < 1) {
		perror("Named pipe write failed");
		if (close(fd)) {
			perror("Named pipe close failed");
		}
		ret = -1;
		goto end;
	}

	ret = close(fd);
	if (ret < 0) {
		perror("Name pipe closing failed");
		ret = -1;
		goto end;
	}
end:
	return ret;
}

static
int stop_consumer(const char **argv)
{
	int ret = 0, i;

	for (i = named_pipe_args_start; i < nb_args; i++) {
		ret = write_pipe(argv[i], 49);
	}
	return ret;
}

static
int resume_consumer(const char **argv)
{
	int ret = 0, i;

	for (i = named_pipe_args_start; i < nb_args; i++) {
		ret = write_pipe(argv[i], 0);
	}
	return ret;
}

static
int suspend_application(void)
{
	int ret;
	struct stat buf;

	if (!stat(app_state_file, &buf)) {
		fail("App is already in a suspended state.");
		ret = -1;
		goto error;
	}

	/*
	 * Send SIGUSR1 to application instructing it to bypass tracepoint.
	 */
	assert(app_pid > 1);

	ret = kill(app_pid, SIGUSR1);
	if (ret) {
		fail("SIGUSR1 failed. errno %d", errno);
		ret = -1;
		goto error;
	}

	wait_on_file(app_state_file, true);

error:
	return ret;

}

static
int resume_application(void)
{
	int ret;
	struct stat buf;

	ret = stat(app_state_file, &buf);
	if (ret == -1 && errno == ENOENT) {
		fail("State file does not exist");
		goto error;
	}
	if (ret) {
		perror("stat");
		goto error;
	}

	assert(app_pid > 1);

	ret = kill(app_pid, SIGUSR1);
	if (ret) {
		fail("SIGUSR1 failed. errno %d", errno);
		ret = -1;
		goto error;
	}

	wait_on_file(app_state_file, false);

error:
	return ret;

}


static
void test_triggers_buffer_usage_condition(const char *session_name,
		const char *channel_name,
		enum lttng_domain_type domain_type,
		enum lttng_condition_type condition_type)
{
	unsigned int test_vector_size = 5, i;
	enum lttng_condition_status condition_status;
	struct lttng_action *action;

	/* Set-up */
	action = lttng_action_notify_create();
	if (!action) {
		fail("Setup error on action creation");
		goto end;
	}

	/* Test lttng_register_trigger with null value */
	ok(lttng_register_trigger(NULL) == -LTTNG_ERR_INVALID, "Registering a NULL trigger fails as expected");

	/* Test: register a trigger */

	for (i = 0; i < pow(2,test_vector_size); i++) {
		int loop_ret = 0;
		char *test_tuple_string = NULL;
		unsigned int mask_position = 0;
		bool session_name_set = false;
		bool channel_name_set = false;
		bool threshold_ratio_set = false;
		bool threshold_byte_set = false;
		bool domain_type_set = false;

		struct lttng_trigger *trigger = NULL;
		struct lttng_condition *condition = NULL;

		/* Create base condition */
		switch (condition_type) {
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
			condition = lttng_condition_buffer_usage_low_create();
			break;
		case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
			condition = lttng_condition_buffer_usage_high_create();
			break;
		default:
			loop_ret = 1;
			goto loop_end;
		}

		if (!condition) {
			loop_ret = 1;
			goto loop_end;

		}

		/* Prepare the condition for trigger registration test */

		/* Set session name */
		if ((1 << mask_position) & i) {
			condition_status = lttng_condition_buffer_usage_set_session_name(
					condition, session_name);
			if (condition_status != LTTNG_CONDITION_STATUS_OK) {
				loop_ret = 1;
				goto loop_end;
			}
			session_name_set = true;
		}
		mask_position++;

		/* Set channel name */
		if ((1 << mask_position) & i) {
			condition_status = lttng_condition_buffer_usage_set_channel_name(
					condition, channel_name);
			if (condition_status != LTTNG_CONDITION_STATUS_OK) {
				loop_ret = 1;
				goto loop_end;
			}
			channel_name_set = true;
		}
		mask_position++;

		/* Set threshold ratio */
		if ((1 << mask_position) & i) {
			condition_status = lttng_condition_buffer_usage_set_threshold_ratio(
					condition, 0.0);
			if (condition_status != LTTNG_CONDITION_STATUS_OK) {
				loop_ret = 1;
				goto loop_end;
			}
			threshold_ratio_set = true;
		}
		mask_position++;

		/* Set threshold byte */
		if ((1 << mask_position) & i) {
			condition_status = lttng_condition_buffer_usage_set_threshold(
					condition, 0);
			if (condition_status != LTTNG_CONDITION_STATUS_OK) {
				loop_ret = 1;
				goto loop_end;
			}
			threshold_byte_set = true;
		}
		mask_position++;

		/* Set domain type */
		if ((1 << mask_position) & i) {
			condition_status = lttng_condition_buffer_usage_set_domain_type(
					condition, LTTNG_DOMAIN_UST);
			if (condition_status != LTTNG_CONDITION_STATUS_OK) {
				loop_ret = 1;
				goto loop_end;
			}
			domain_type_set = true;
		}

		/* Safety check */
		if (mask_position != test_vector_size -1) {
			assert("Logic error for test vector generation");
		}

		loop_ret = asprintf(&test_tuple_string, "session name %s, channel name %s, threshold ratio %s, threshold byte %s, domain type %s",
				session_name_set ? "set" : "unset",
				channel_name_set ? "set" : "unset",
				threshold_ratio_set ? "set" : "unset",
				threshold_byte_set ? "set" : "unset",
				domain_type_set? "set" : "unset");
		if (!test_tuple_string || loop_ret < 0) {
			loop_ret = 1;
			goto loop_end;
		}

		/* Create trigger */
		trigger = lttng_trigger_create(condition, action);
		if (!trigger) {
			loop_ret = 1;
			goto loop_end;
		}

		loop_ret = lttng_register_trigger(trigger);

loop_end:
		if (loop_ret == 1) {
			fail("Setup error occurred for tuple: %s", test_tuple_string);
			goto loop_cleanup;
		}

		/* This combination happens three times */
		if (session_name_set && channel_name_set
				&& (threshold_ratio_set || threshold_byte_set)
				&& domain_type_set) {
			ok(loop_ret == 0, "Trigger is registered: %s", test_tuple_string);

			/*
			 * Test that a trigger cannot be registered
			 * multiple time.
			 */
			loop_ret = lttng_register_trigger(trigger);
			ok(loop_ret == -LTTNG_ERR_TRIGGER_EXISTS, "Re-register trigger fails as expected: %s", test_tuple_string);

			/* Test that a trigger can be unregistered */
			loop_ret = lttng_unregister_trigger(trigger);
			ok(loop_ret == 0, "Unregister trigger: %s", test_tuple_string);

			/*
			 * Test that unregistration of a non-previously
			 * registered trigger fail.
			 */
			loop_ret = lttng_unregister_trigger(trigger);
			ok(loop_ret == -LTTNG_ERR_TRIGGER_NOT_FOUND, "Unregister of a non-registered trigger fails as expected: %s", test_tuple_string);
		} else {
			ok(loop_ret == -LTTNG_ERR_INVALID_TRIGGER, "Trigger is invalid as expected and cannot be registered: %s", test_tuple_string);
		}

loop_cleanup:
		free(test_tuple_string);
		lttng_trigger_destroy(trigger);
		lttng_condition_destroy(condition);
	}

end:
	lttng_action_destroy(action);
}

static
void wait_data_pending(const char *session_name)
{
	int ret;

	do {
		ret = lttng_data_pending(session_name);
		assert(ret >= 0);
	} while (ret != 0);
}

static
int setup_buffer_usage_condition(struct lttng_condition *condition,
		const char *condition_name,
		const char *session_name,
		const char *channel_name,
		const enum lttng_domain_type domain_type)
{
	enum lttng_condition_status condition_status;
	int ret = 0;

	condition_status = lttng_condition_buffer_usage_set_session_name(
			condition, session_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Failed to set session name on creation of condition `%s`",
				condition_name);
		ret = -1;
		goto end;
	}

	condition_status = lttng_condition_buffer_usage_set_channel_name(
			condition, channel_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Failed to set channel name on creation of condition `%s`",
				condition_name);
		ret = -1;
		goto end;
	}

	condition_status = lttng_condition_buffer_usage_set_domain_type(
			condition, domain_type);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Failed to set domain type on creation of condition `%s`",
				condition_name);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
void test_invalid_channel_subscription(
		const enum lttng_domain_type domain_type)
{
	enum lttng_condition_status condition_status;
	enum lttng_notification_channel_status nc_status;
	struct lttng_condition *dummy_condition = NULL;
	struct lttng_condition *dummy_invalid_condition = NULL;
	struct lttng_notification_channel *notification_channel = NULL;
	int ret = 0;

	notification_channel = lttng_notification_channel_create(
			lttng_session_daemon_notification_endpoint);
	ok(notification_channel, "Notification channel object creation");
	if (!notification_channel) {
		goto end;
	}

	/*
	 * Create a dummy, empty (thus invalid) condition to test error paths.
	 */
	dummy_invalid_condition = lttng_condition_buffer_usage_low_create();
	if (!dummy_invalid_condition) {
		fail("Setup error on condition creation");
		goto end;
	}

	/*
	 * Test subscription and unsubscription of an invalid condition to/from
	 * a channel.
	 */
	nc_status = lttng_notification_channel_subscribe(
			notification_channel, dummy_invalid_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID,
			"Subscribing to an invalid condition");

	nc_status = lttng_notification_channel_unsubscribe(
			notification_channel, dummy_invalid_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID,
			"Unsubscribing from an invalid condition");

	/* Create a valid dummy condition with a ratio of 0.5 */
	dummy_condition = lttng_condition_buffer_usage_low_create();
	if (!dummy_condition) {
		fail("Setup error on dummy_condition creation");
		goto end;
	}

	condition_status = lttng_condition_buffer_usage_set_threshold_ratio(
			dummy_condition, 0.5);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on condition creation");
		goto end;
	}

	ret = setup_buffer_usage_condition(dummy_condition, "dummy_condition",
			"dummy_session", "dummy_channel", domain_type);
	if (ret) {
		fail("Setup error on dummy condition creation");
		goto end;
	}

	/*
	 * Test subscription and unsubscription to/from a channel with invalid
	 * parameters.
	 */
	nc_status = lttng_notification_channel_subscribe(NULL, NULL);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID,
			"Notification channel subscription is invalid: NULL, NULL");

	nc_status = lttng_notification_channel_subscribe(
			notification_channel, NULL);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID,
			"Notification channel subscription is invalid: NON-NULL, NULL");

	nc_status = lttng_notification_channel_subscribe(NULL, dummy_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID,
			"Notification channel subscription is invalid: NULL, NON-NULL");

	nc_status = lttng_notification_channel_unsubscribe(
			notification_channel, dummy_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_UNKNOWN_CONDITION,
			"Unsubscribing from a valid unknown condition");

end:
	lttng_notification_channel_destroy(notification_channel);
	lttng_condition_destroy(dummy_invalid_condition);
	lttng_condition_destroy(dummy_condition);
	return;
}

enum buffer_usage_type {
	BUFFER_USAGE_TYPE_LOW,
	BUFFER_USAGE_TYPE_HIGH,
};

static int register_buffer_usage_notify_trigger(const char *session_name,
		const char *channel_name,
		const enum lttng_domain_type domain_type,
		enum buffer_usage_type buffer_usage_type,
		double ratio,
		struct lttng_condition **condition,
		struct lttng_action **action,
		struct lttng_trigger **trigger)
{
	enum lttng_condition_status condition_status;
	struct lttng_action *tmp_action = NULL;
	struct lttng_condition *tmp_condition = NULL;
	struct lttng_trigger *tmp_trigger = NULL;
	int ret = 0;

	/* Set-up */
	tmp_action = lttng_action_notify_create();
	if (!action) {
		fail("Setup error on action creation");
		ret = -1;
		goto error;
	}

	if (buffer_usage_type == BUFFER_USAGE_TYPE_LOW) {
		tmp_condition = lttng_condition_buffer_usage_low_create();
	} else {
		tmp_condition = lttng_condition_buffer_usage_high_create();
	}

	if (!tmp_condition) {
		fail("Setup error on condition creation");
		ret = -1;
		goto error;
	}

	/* Set the buffer usage threashold */
	condition_status = lttng_condition_buffer_usage_set_threshold_ratio(
			tmp_condition, ratio);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on condition creation");
		ret = -1;
		goto error;
	}

	ret = setup_buffer_usage_condition(tmp_condition, "condition_name",
			session_name, channel_name, domain_type);
	if (ret) {
		fail("Setup error on condition creation");
		ret = -1;
		goto error;
	}

	/* Register the trigger for condition. */
	tmp_trigger = lttng_trigger_create(tmp_condition, tmp_action);
	if (!tmp_trigger) {
		fail("Setup error on trigger creation");
		ret = -1;
		goto error;
	}

	ret = lttng_register_trigger(tmp_trigger);
	if (ret) {
		fail("Setup error on trigger registration");
		ret = -1;
		goto error;
	}

	*condition = tmp_condition;
	*trigger = tmp_trigger;
	*action = tmp_action;
	goto end;

error:
	lttng_action_destroy(tmp_action);
	lttng_condition_destroy(tmp_condition);
	lttng_trigger_destroy(tmp_trigger);

end:
	return ret;
}

static void test_subscription_twice(const char *session_name,
		const char *channel_name,
		const enum lttng_domain_type domain_type)
{
	int ret = 0;
	enum lttng_notification_channel_status nc_status;

	struct lttng_action *action = NULL;
	struct lttng_notification_channel *notification_channel = NULL;
	struct lttng_trigger *trigger = NULL;

	struct lttng_condition *condition = NULL;

	ret = register_buffer_usage_notify_trigger(session_name, channel_name,
			domain_type, BUFFER_USAGE_TYPE_LOW, 0.99, &condition,
			&action, &trigger);
	if (ret) {
		fail("Setup error on trigger registration");
		goto end;
	}

	/* Begin testing. */
	notification_channel = lttng_notification_channel_create(
			lttng_session_daemon_notification_endpoint);
	ok(notification_channel, "Notification channel object creation");
	if (!notification_channel) {
		goto end;
	}

	/* Subscribe a valid condition. */
	nc_status = lttng_notification_channel_subscribe(
			notification_channel, condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
			"Subscribe to condition");

	/* Subscribing again should fail. */
	nc_status = lttng_notification_channel_subscribe(
			notification_channel, condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_ALREADY_SUBSCRIBED,
			"Subscribe to a condition for which subscription was already done");

end:
	lttng_unregister_trigger(trigger);
	lttng_trigger_destroy(trigger);
	lttng_notification_channel_destroy(notification_channel);
	lttng_action_destroy(action);
	lttng_condition_destroy(condition);
}

static void test_buffer_usage_notification_channel(const char *session_name,
		const char *channel_name,
		const enum lttng_domain_type domain_type,
		const char **argv)
{
	int ret = 0;
	enum lttng_notification_channel_status nc_status;

	struct lttng_action *low_action = NULL;
	struct lttng_action *high_action = NULL;
	struct lttng_notification *notification = NULL;
	struct lttng_notification_channel *notification_channel = NULL;
	struct lttng_trigger *low_trigger = NULL;
	struct lttng_trigger *high_trigger = NULL;

	struct lttng_condition *low_condition = NULL;
	struct lttng_condition *high_condition = NULL;

	const double low_ratio = 0.0;
	const double high_ratio = 0.90;

	ret = register_buffer_usage_notify_trigger(session_name, channel_name,
			domain_type, BUFFER_USAGE_TYPE_LOW, low_ratio,
			&low_condition, &low_action, &low_trigger);
	if (ret) {
		fail("Setup error on low trigger registration");
		goto end;
	}

	ret = register_buffer_usage_notify_trigger(session_name, channel_name,
			domain_type, BUFFER_USAGE_TYPE_HIGH, high_ratio,
			&high_condition, &high_action, &high_trigger);
	if (ret) {
		fail("Setup error on high trigger registration");
		goto end;
	}

	/* Begin testing */
	notification_channel = lttng_notification_channel_create(
			lttng_session_daemon_notification_endpoint);
	ok(notification_channel, "Notification channel object creation");
	if (!notification_channel) {
		goto end;
	}

	/* Subscribe a valid low condition */
	nc_status = lttng_notification_channel_subscribe(
			notification_channel, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
			"Subscribe to low condition");

	/* Subscribe a valid high condition */
	nc_status = lttng_notification_channel_subscribe(
			notification_channel, high_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
			"Subscribe to high condition");

	resume_application();

	/* Wait for notification to happen */
	stop_consumer(argv);
	lttng_start_tracing(session_name);

	/* Wait for high notification */
	do {
		nc_status = lttng_notification_channel_get_next_notification(
				notification_channel, &notification);
	} while (nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK && notification &&
					lttng_condition_get_type(lttng_notification_get_condition(
							notification)) ==
							LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH,
			"High notification received after intermediary communication");
	lttng_notification_destroy(notification);
	notification = NULL;

	suspend_application();
	lttng_stop_tracing_no_wait(session_name);
	resume_consumer(argv);
	wait_data_pending(session_name);

	/*
	 * Test that communication still work even if there is notification
	 * waiting for consumption.
	 */

	nc_status = lttng_notification_channel_unsubscribe(
			notification_channel, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
			"Unsubscribe with pending notification");

	nc_status = lttng_notification_channel_subscribe(
			notification_channel, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
			"Subscribe with pending notification");

	do {
		nc_status = lttng_notification_channel_get_next_notification(
				notification_channel, &notification);
	} while (nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK && notification &&
					lttng_condition_get_type(lttng_notification_get_condition(
							notification)) ==
							LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW,
			"Low notification received after intermediary communication");
	lttng_notification_destroy(notification);
	notification = NULL;

	/* Stop consumer to force a high notification */
	stop_consumer(argv);
	resume_application();
	lttng_start_tracing(session_name);

	do {
		nc_status = lttng_notification_channel_get_next_notification(
				notification_channel, &notification);
	} while (nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK && notification &&
					lttng_condition_get_type(lttng_notification_get_condition(
							notification)) ==
							LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH,
			"High notification received after intermediary communication");
	lttng_notification_destroy(notification);
	notification = NULL;

	suspend_application();
	lttng_stop_tracing_no_wait(session_name);
	resume_consumer(argv);
	wait_data_pending(session_name);

	do {
		nc_status = lttng_notification_channel_get_next_notification(
				notification_channel, &notification);
	} while (nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK && notification &&
					lttng_condition_get_type(lttng_notification_get_condition(
							notification)) ==
							LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW,
			"Low notification received after re-subscription");
	lttng_notification_destroy(notification);
	notification = NULL;

	stop_consumer(argv);
	resume_application();
	/* Stop consumer to force a high notification */
	lttng_start_tracing(session_name);

	do {
		nc_status = lttng_notification_channel_get_next_notification(
				notification_channel, &notification);
	} while (nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INTERRUPTED);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK && notification &&
					lttng_condition_get_type(lttng_notification_get_condition(
							notification)) ==
							LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH,
			"High notification");
	lttng_notification_destroy(notification);
	notification = NULL;

	suspend_application();

	/* Resume consumer to allow event consumption */
	lttng_stop_tracing_no_wait(session_name);
	resume_consumer(argv);
	wait_data_pending(session_name);

	nc_status = lttng_notification_channel_unsubscribe(
			notification_channel, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
			"Unsubscribe low condition with pending notification");

	nc_status = lttng_notification_channel_unsubscribe(
			notification_channel, high_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK,
			"Unsubscribe high condition with pending notification");

end:
	lttng_notification_channel_destroy(notification_channel);
	lttng_trigger_destroy(low_trigger);
	lttng_trigger_destroy(high_trigger);
	lttng_action_destroy(low_action);
	lttng_action_destroy(high_action);
	lttng_condition_destroy(low_condition);
	lttng_condition_destroy(high_condition);
}

int main(int argc, const char *argv[])
{
	const char *session_name = NULL;
	const char *channel_name = NULL;
	const char *domain_type_string = NULL;
	enum lttng_domain_type domain_type = LTTNG_DOMAIN_NONE;

	plan_tests(NUM_TESTS);

	/* Argument 6 and upward are named pipe location for consumerd control */
	named_pipe_args_start = 6;

	if (argc < 7) {
		fail("Missing parameter for tests to run %d", argc);
		goto error;
	}

	nb_args = argc;

	domain_type_string = argv[1];
	session_name = argv[2];
	channel_name = argv[3];
	app_pid = (pid_t) atoi(argv[4]);
	app_state_file = argv[5];

	if (!strcmp("LTTNG_DOMAIN_UST", domain_type_string)) {
		domain_type = LTTNG_DOMAIN_UST;
	}
	if (!strcmp("LTTNG_DOMAIN_KERNEL", domain_type_string)) {
		domain_type = LTTNG_DOMAIN_KERNEL;
	}
	if (domain_type == LTTNG_DOMAIN_NONE) {
		fail("Unknown domain type");
		goto error;
	}

	/*
	 * Test cases are responsible for resuming the app when needed and
	 * making sure it's suspended when returning.
	 */
	suspend_application();

	diag("Test trigger for domain %s with buffer_usage_low condition", domain_type_string);
	test_triggers_buffer_usage_condition(session_name, channel_name, domain_type, LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW);
	diag("Test trigger for domain %s with buffer_usage_high condition", domain_type_string);
	test_triggers_buffer_usage_condition(session_name, channel_name, domain_type, LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH);

	/* Basic error path check. */
	test_invalid_channel_subscription(domain_type);
	test_subscription_twice(session_name, channel_name, domain_type);

	diag("Test buffer usage notification channel api for domain %s", domain_type_string);
	test_buffer_usage_notification_channel(session_name, channel_name, domain_type, argv);
error:
	return exit_status();
}

