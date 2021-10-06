/*
 * trigger_name.c
 *
 * Test that hidden triggers are not visible to liblttng-ctl.
 *
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <tap/tap.h>

#include <common/macros.h>
#include <lttng/lttng.h>

#define TEST_COUNT 1

#define TEST_SESSION_NAME "test_session"
#define TEST_CHANNEL_NAME "test_channel"

static
int get_registered_triggers_count(void)
{
	int ret;
	enum lttng_error_code ret_code;
	enum lttng_trigger_status trigger_status;
	struct lttng_triggers *triggers = NULL;
	unsigned int trigger_count;

	ret_code = lttng_list_triggers(&triggers);
	if (ret_code != LTTNG_OK) {
		fail("Failed to list triggers");
		ret = -1;
		goto end;
	}

	trigger_status = lttng_triggers_get_count(triggers, &trigger_count);
	if (trigger_status != LTTNG_TRIGGER_STATUS_OK) {
		fail("Failed to get count of triggers returned by listing");
		ret = -1;
		goto end;
	}

	ret = (int) trigger_count;

end:
	lttng_triggers_destroy(triggers);
	return ret;
}

static
int setup_session_with_size_rotation_schedule(const char *session_output_path)
{
	int ret;
	struct lttng_session_descriptor *session_desriptor = NULL;
	enum lttng_error_code ret_code;
	struct lttng_handle ust_channel_handle = {
		.session_name = TEST_SESSION_NAME,
		.domain.type = LTTNG_DOMAIN_UST,
		.domain.buf_type = LTTNG_BUFFER_PER_UID,
	};
	struct lttng_channel channel_cfg = {
		.name = TEST_CHANNEL_NAME,
		.enabled = 1,
		.attr.overwrite = -1,
		.attr.subbuf_size = sysconf(_SC_PAGE_SIZE) * 8,
		.attr.num_subbuf = 8,
		.attr.output = LTTNG_EVENT_MMAP,
	};
	enum lttng_rotation_status rotation_status;
	struct lttng_rotation_schedule *rotation_schedule = NULL;

	session_desriptor = lttng_session_descriptor_local_create(
			TEST_SESSION_NAME, session_output_path);
	if (!session_desriptor) {
		fail("Failed to create session descriptor for session `%s`",
				TEST_SESSION_NAME);
		ret = -1;
		goto end;
	}

	ret_code = lttng_create_session_ext(session_desriptor);
	if (ret_code != LTTNG_OK) {
		fail("Failed to create session `%s`: %s", TEST_SESSION_NAME,
				lttng_strerror(-ret_code));
		ret = -1;
		goto end;
	}

	ret = lttng_enable_channel(&ust_channel_handle, &channel_cfg);
	if (ret) {
		fail("Failed to enable channel `%s`: %s", TEST_CHANNEL_NAME,
				lttng_strerror(ret));
		ret = -1;
		goto end;
	}

	ret = lttng_start_tracing(TEST_SESSION_NAME);
	if (ret) {
		fail("Failed to start session `%s`: %s", TEST_SESSION_NAME,
				lttng_strerror(ret));
		ret = -1;
		goto end;
	}

	rotation_schedule = lttng_rotation_schedule_size_threshold_create();
	if (!rotation_schedule) {
		fail("Failed to create rotation schedule descriptor");
		ret = -1;
		goto end;
	}

	/*
	 * The rotation schedule size threshold doesn't matter; no event rules
	 * were specified so the session consumed size should not grow over
	 * time.
	 */
	rotation_status = lttng_rotation_schedule_size_threshold_set_threshold(
			rotation_schedule, sysconf(_SC_PAGE_SIZE) * 4096);
	if (rotation_status != LTTNG_ROTATION_STATUS_OK) {
		fail("Failed to set size threshold of session rotation schedule");
		ret = -1;
		goto end;
	}

	rotation_status = lttng_session_add_rotation_schedule(
			TEST_SESSION_NAME, rotation_schedule);
	if (rotation_status != LTTNG_ROTATION_STATUS_OK) {
		fail("Failed to set size-based rotation schedule on session `%s`",
				TEST_SESSION_NAME);
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	lttng_session_descriptor_destroy(session_desriptor);
	lttng_rotation_schedule_destroy(rotation_schedule);
	return ret;
}

int main(int argc, const char **argv)
{
	int ret;

	if (argc != 2) {
		fail("Missing trace path");
		goto end;
	}

	plan_tests(TEST_COUNT);

	if (get_registered_triggers_count() != 0) {
		fail("Session daemon already has registered triggers, bailing out");
		goto end;
	}

	ret = setup_session_with_size_rotation_schedule(argv[1]);
	if (ret) {
		goto end;
	}

	ok(get_registered_triggers_count() == 0,
			"No triggers visible while session has an enabled size-based rotation schedule");

	ret = lttng_destroy_session(TEST_SESSION_NAME);
	if (ret) {
		fail("Failed to destroy session `%s`", TEST_SESSION_NAME);
		goto end;
	}
end:
	return exit_status();
}
