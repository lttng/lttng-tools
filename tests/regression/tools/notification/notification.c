/*
 * notification.c
 *
 * Tests suite for LTTng notification API
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
#include <errno.h>
#include <poll.h>

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

#include <tap/tap.h>

#define NUM_TESTS 104

int nb_args = 0;
int named_pipe_args_start = 0;
pid_t app_pid = -1;
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
				(void) poll(NULL, 0, 10);	/* 10 ms delay */
				continue;			/* retry */
			}
			break; /* File does not exist */
		}
		if (ret) {
			perror("stat");
			exit(EXIT_FAILURE);
		}
		break;	/* found */
	}
}

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

int stop_consumer(const char **argv)
{
	int ret = 0;
	for (int i = named_pipe_args_start; i < nb_args; i++) {
		ret = write_pipe(argv[i], 49);
	}
	return ret;
}

int resume_consumer(const char **argv)
{
	int ret = 0;
	for (int i = named_pipe_args_start; i < nb_args; i++) {
		ret = write_pipe(argv[i], 0);
	}
	return ret;
}

int suspend_application()
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

int resume_application()
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


void test_triggers_buffer_usage_condition(const char *session_name,
		const char *channel_name,
		enum lttng_domain_type domain_type,
		enum lttng_condition_type condition_type)
{
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
	unsigned int test_vector_size = 5;
	for (unsigned int  i = 0; i < pow(2,test_vector_size); i++) {
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

		loop_ret = asprintf(&test_tuple_string, "session name %s, channel name  %s, threshold ratio %s, threshold byte %s, domain type %s",
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
			ok(loop_ret == -LTTNG_ERR_TRIGGER_NOT_FOUND, "Unregister of a non-registerd  trigger fails as expected: %s", test_tuple_string);
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

void test_notification_channel(const char *session_name, const char *channel_name, const enum lttng_domain_type domain_type, const char **argv)
{
	int ret = 0;
	enum lttng_condition_status condition_status;
	enum lttng_notification_channel_status nc_status;

	struct lttng_action *action = NULL;
	struct lttng_notification *notification = NULL;
	struct lttng_notification_channel *notification_channel = NULL;
	struct lttng_trigger *trigger = NULL;

	struct lttng_condition *low_condition = NULL;
	struct lttng_condition *high_condition = NULL;
	struct lttng_condition *dummy_invalid_condition = NULL;
	struct lttng_condition *dummy_condition = NULL;

	double low_ratio = 0.0;
	double high_ratio = 0.99;

	/* Set-up */
	action = lttng_action_notify_create();
	if (!action) {
		fail("Setup error on action creation");
		goto end;
	}

	/* Create a dummy, empty condition for later test */
	dummy_invalid_condition = lttng_condition_buffer_usage_low_create();
	if (!dummy_invalid_condition) {
		fail("Setup error on condition creation");
		goto end;
	}

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

	condition_status = lttng_condition_buffer_usage_set_session_name(
			dummy_condition, session_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on dummy_condition creation");
		goto end;
	}
	condition_status = lttng_condition_buffer_usage_set_channel_name(
			dummy_condition, channel_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on dummy_condition creation");
		goto end;
	}
	condition_status = lttng_condition_buffer_usage_set_domain_type(
			dummy_condition, domain_type);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on dummy_condition creation");
		goto end;
	}

	/* Register a low condition with a ratio */
	low_condition = lttng_condition_buffer_usage_low_create();
	if (!low_condition) {
		fail("Setup error on low_condition creation");
		goto end;
	}
	condition_status = lttng_condition_buffer_usage_set_threshold_ratio(
			low_condition, low_ratio);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on low_condition creation");
		goto end;
	}

	condition_status = lttng_condition_buffer_usage_set_session_name(
			low_condition, session_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on low_condition creation");
		goto end;
	}
	condition_status = lttng_condition_buffer_usage_set_channel_name(
			low_condition, channel_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on low_condition creation");
		goto end;
	}
	condition_status = lttng_condition_buffer_usage_set_domain_type(
			low_condition, domain_type);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on low_condition creation");
		goto end;

	}

	/* Register a high condition with a ratio */
	high_condition = lttng_condition_buffer_usage_high_create();
	if (!high_condition) {
		fail("Setup error on high_condition creation");
		goto end;
	}

	condition_status = lttng_condition_buffer_usage_set_threshold_ratio(
			high_condition, high_ratio);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on high_condition creation");
		goto end;
	}

	condition_status = lttng_condition_buffer_usage_set_session_name(
			high_condition, session_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on high_condition creation");
		goto end;
	}
	condition_status = lttng_condition_buffer_usage_set_channel_name(
			high_condition, channel_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on high_condition creation");
		goto end;
	}
	condition_status = lttng_condition_buffer_usage_set_domain_type(
			high_condition, domain_type);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		fail("Setup error on high_condition creation");
		goto end;
	}

	/* Register the triggers for low and high condition */
	trigger = lttng_trigger_create(low_condition, action);
	if (!trigger) {
		fail("Setup error on low trigger creation");
		goto end;
	}

	ret = lttng_register_trigger(trigger);
	if (ret) {
		fail("Setup error on low trigger registration");
		goto end;
	}

	lttng_trigger_destroy(trigger);
	trigger = NULL;

	trigger = lttng_trigger_create(high_condition, action);
	if (!trigger) {
		fail("Setup error on high trigger creation");
		goto end;
	}

	ret = lttng_register_trigger(trigger);
	if (ret) {
		fail("Setup error on high trigger registration");
		goto end;
	}

	/* Begin testing */
	notification_channel = lttng_notification_channel_create(lttng_session_daemon_notification_endpoint);
	ok(notification_channel, "Notification channel object creation");
	if (!notification_channel) {
		goto end;
	}

	/* Basic error path check */
	nc_status = lttng_notification_channel_subscribe(NULL, NULL);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID, "Notification channel subscription is invalid: NULL, NULL");

	nc_status = lttng_notification_channel_subscribe(notification_channel, NULL);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID, "Notification channel subscription is invalid: NON-NULL, NULL");

	nc_status = lttng_notification_channel_subscribe(NULL, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID, "Notification channel subscription is invalid: NULL, NON-NULL");

	nc_status = lttng_notification_channel_subscribe(notification_channel, dummy_invalid_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID, "Subscribing to an invalid condition");

	nc_status = lttng_notification_channel_unsubscribe(notification_channel, dummy_invalid_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_INVALID, "Unsubscribing to an invalid condition");

	nc_status = lttng_notification_channel_unsubscribe(notification_channel, dummy_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_UNKNOWN_CONDITION, "Unsubscribing to an valid unknown condition");

	/* Subscribe a valid low condition */
	nc_status = lttng_notification_channel_subscribe(notification_channel, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK, "Subscribe to condition");

	/* Subscribe a valid high condition */
	nc_status = lttng_notification_channel_subscribe(notification_channel, high_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK, "Subscribe to condition");

	nc_status = lttng_notification_channel_subscribe(notification_channel, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_ALREADY_SUBSCRIBED, "Subscribe to a condition for which subscription was already done");

	nc_status = lttng_notification_channel_subscribe(notification_channel, high_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_ALREADY_SUBSCRIBED, "Subscribe to a condition for which subscription was already done");

	/* Wait for notification to happen */
	stop_consumer(argv);
	lttng_start_tracing(session_name);

	/* Wait for high notification */
	nc_status = lttng_notification_channel_get_next_notification(notification_channel, &notification);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK
			&& notification
			&& lttng_condition_get_type(lttng_notification_get_condition(notification)) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH,
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

	nc_status = lttng_notification_channel_unsubscribe(notification_channel, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK, "Unsubscribe with pending notification");

	nc_status = lttng_notification_channel_subscribe(notification_channel, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK, "subscribe with pending notification");

	nc_status = lttng_notification_channel_get_next_notification(notification_channel, &notification);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK
			&& notification
			&& lttng_condition_get_type(lttng_notification_get_condition(notification)) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW,
			"Low notification received after intermediary communication");
	lttng_notification_destroy(notification);
	notification = NULL;

	/* Stop consumer to force a high notification */
	stop_consumer(argv);
	resume_application();
	lttng_start_tracing(session_name);

	nc_status = lttng_notification_channel_get_next_notification(notification_channel, &notification);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK && notification &&
			lttng_condition_get_type(lttng_notification_get_condition(notification)) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH,
			"High notification received after intermediary communication");
	lttng_notification_destroy(notification);
	notification = NULL;

	suspend_application();
	lttng_stop_tracing_no_wait(session_name);
	resume_consumer(argv);
	wait_data_pending(session_name);

	nc_status = lttng_notification_channel_get_next_notification(notification_channel, &notification);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK && notification &&
			lttng_condition_get_type(lttng_notification_get_condition(notification)) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW,
			"Low notification received after re-subscription");
	lttng_notification_destroy(notification);
	notification = NULL;

	stop_consumer(argv);
	resume_application();
	/* Stop consumer to force a high notification */
	lttng_start_tracing(session_name);

	nc_status = lttng_notification_channel_get_next_notification(notification_channel, &notification);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK && notification &&
			lttng_condition_get_type(lttng_notification_get_condition(notification)) == LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH,
			"High notification");
	lttng_notification_destroy(notification);
	notification = NULL;

	/* Resume consumer to allow event consumption */
	suspend_application();
	lttng_stop_tracing_no_wait(session_name);
	resume_consumer(argv);
	wait_data_pending(session_name);

	nc_status = lttng_notification_channel_unsubscribe(notification_channel, low_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK, "Unsubscribe low condition with pending notification");
	nc_status = lttng_notification_channel_unsubscribe(notification_channel, high_condition);
	ok(nc_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK, "Unsubscribe high condition with pending notification");

end:
	lttng_notification_channel_destroy(notification_channel);
	lttng_trigger_destroy(trigger);
	lttng_action_destroy(action);
	lttng_condition_destroy(low_condition);
	lttng_condition_destroy(high_condition);
	lttng_condition_destroy(dummy_invalid_condition);
	lttng_condition_destroy(dummy_condition);
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

	diag("Test trigger for domain %s with buffer_usage_low condition", domain_type_string);
	test_triggers_buffer_usage_condition(session_name, channel_name, domain_type, LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW);
	diag("Test trigger for domain %s with buffer_usage_high condition", domain_type_string);
	test_triggers_buffer_usage_condition(session_name, channel_name, domain_type, LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH);

	diag("Test notification channel api for domain %s", domain_type_string);
	test_notification_channel(session_name, channel_name, domain_type, argv);
error:
	return exit_status();
}

