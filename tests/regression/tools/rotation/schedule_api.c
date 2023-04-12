/*
 * schedule_api.c
 *
 * Unit tests for the session rotation schedule API
 *
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <lttng/lttng.h>

#include <stdbool.h>
#include <stddef.h>
#include <tap/tap.h>

#define NUM_TESTS 26

#define SIZE_THRESHOLD_BYTES 1024
#define PERIODIC_TIME_US     1000000

const char *session_name;

static bool schedules_equal(const struct lttng_rotation_schedule *a,
			    const struct lttng_rotation_schedule *b)
{
	bool equal = false;
	enum lttng_rotation_schedule_type a_type, b_type;
	uint64_t a_value, b_value;
	enum lttng_rotation_status status;

	a_type = lttng_rotation_schedule_get_type(a);
	b_type = lttng_rotation_schedule_get_type(b);
	if (a_type != b_type) {
		diag("Schedules are not of the same type (%i != %i)", a_type, b_type);
		goto end;
	}

	switch (a_type) {
	case LTTNG_ROTATION_SCHEDULE_TYPE_SIZE_THRESHOLD:
	{
		status = lttng_rotation_schedule_size_threshold_get_threshold(a, &a_value);
		if (status != LTTNG_ROTATION_STATUS_OK) {
			diag("Failed to retrieve size threshold of schedule 'a'");
			goto end;
		}
		status = lttng_rotation_schedule_size_threshold_get_threshold(b, &b_value);
		if (status != LTTNG_ROTATION_STATUS_OK) {
			diag("Failed to retrieve size threshold of schedule 'b'");
			goto end;
		}
		break;
	}
	case LTTNG_ROTATION_SCHEDULE_TYPE_PERIODIC:
	{
		status = lttng_rotation_schedule_periodic_get_period(a, &a_value);
		if (status != LTTNG_ROTATION_STATUS_OK) {
			diag("Failed to retrieve period of schedule 'a'");
			goto end;
		}
		status = lttng_rotation_schedule_periodic_get_period(b, &b_value);
		if (status != LTTNG_ROTATION_STATUS_OK) {
			diag("Failed to retrieve period of schedule 'b'");
			goto end;
		}
		break;
	}
	default:
		diag("Unexpected schedule type: %i", a_type);
		goto end;
	}

	equal = a_value == b_value;
	if (!equal) {
		diag("Schedules have different values");
	}
end:
	return equal;
}

static void test_add_null_session(void)
{
	enum lttng_rotation_status status;
	struct lttng_rotation_schedule *size_schedule = NULL;

	size_schedule = lttng_rotation_schedule_size_threshold_create();

	status = lttng_session_add_rotation_schedule(NULL, size_schedule);
	ok(status == LTTNG_ROTATION_STATUS_INVALID,
	   "NULL session name rejected by lttng_session_add_rotation_schedule()");
	lttng_rotation_schedule_destroy(size_schedule);
}

static void test_add_null_schedule(void)
{
	enum lttng_rotation_status status;

	status = lttng_session_add_rotation_schedule(session_name, NULL);
	ok(status == LTTNG_ROTATION_STATUS_INVALID,
	   "NULL schedule rejected by lttng_session_add_rotation_schedule()");
}

static void test_add_uninitialized_schedule(void)
{
	enum lttng_rotation_status status;
	struct lttng_rotation_schedule *size_schedule = NULL, *periodic_schedule = NULL;

	size_schedule = lttng_rotation_schedule_size_threshold_create();
	ok(size_schedule, "Created a size threshold session rotation schedule");

	status = lttng_session_add_rotation_schedule(session_name, size_schedule);
	ok(status == LTTNG_ROTATION_STATUS_INVALID,
	   "Uninitialized size schedule rejected by lttng_session_add_rotation_schedule()");

	periodic_schedule = lttng_rotation_schedule_periodic_create();
	ok(periodic_schedule, "Created a periodic session rotation schedule");

	status = lttng_session_add_rotation_schedule(session_name, periodic_schedule);
	ok(status == LTTNG_ROTATION_STATUS_INVALID,
	   "Uninitialized periodic schedule rejected by lttng_session_add_rotation_schedule()");

	lttng_rotation_schedule_destroy(size_schedule);
	lttng_rotation_schedule_destroy(periodic_schedule);
}

static void test_remove_null_session(void)
{
	enum lttng_rotation_status status;
	struct lttng_rotation_schedule *size_schedule = NULL;

	size_schedule = lttng_rotation_schedule_size_threshold_create();

	status = lttng_session_remove_rotation_schedule(NULL, size_schedule);
	ok(status == LTTNG_ROTATION_STATUS_INVALID,
	   "NULL session name rejected by lttng_session_remove_rotation_schedule()");
	lttng_rotation_schedule_destroy(size_schedule);
}

static void test_remove_null_schedule(void)
{
	enum lttng_rotation_status status;

	status = lttng_session_remove_rotation_schedule(session_name, NULL);
	ok(status == LTTNG_ROTATION_STATUS_INVALID,
	   "NULL schedule rejected by lttng_session_remove_rotation_schedule()");
}

static void test_remove_uninitialized_schedule(void)
{
	enum lttng_rotation_status status;
	struct lttng_rotation_schedule *size_schedule = NULL, *periodic_schedule = NULL;

	size_schedule = lttng_rotation_schedule_size_threshold_create();
	status = lttng_session_remove_rotation_schedule(session_name, size_schedule);
	ok(status == LTTNG_ROTATION_STATUS_INVALID,
	   "Uninitialized size schedule rejected by lttng_session_remove_rotation_schedule()");

	periodic_schedule = lttng_rotation_schedule_periodic_create();
	status = lttng_session_remove_rotation_schedule(session_name, periodic_schedule);
	ok(status == LTTNG_ROTATION_STATUS_INVALID,
	   "Uninitialized periodic schedule rejected by lttng_session_remove_rotation_schedule()");

	lttng_rotation_schedule_destroy(size_schedule);
	lttng_rotation_schedule_destroy(periodic_schedule);
}

static void test_uninitialized_schedule_get(void)
{
	uint64_t value;
	enum lttng_rotation_status status;
	struct lttng_rotation_schedule *size_schedule = NULL, *periodic_schedule = NULL;

	size_schedule = lttng_rotation_schedule_size_threshold_create();
	periodic_schedule = lttng_rotation_schedule_periodic_create();

	status = lttng_rotation_schedule_size_threshold_get_threshold(size_schedule, &value);
	ok(status == LTTNG_ROTATION_STATUS_UNAVAILABLE,
	   "Getter on size threshold rotation schedule returns LTTNG_ROTATION_STATUS_UNAVAILABLE by default");
	status = lttng_rotation_schedule_periodic_get_period(periodic_schedule, &value);
	ok(status == LTTNG_ROTATION_STATUS_UNAVAILABLE,
	   "Getter on periodic rotation schedule returns LTTNG_ROTATION_STATUS_UNAVAILABLE by default");

	lttng_rotation_schedule_destroy(size_schedule);
	lttng_rotation_schedule_destroy(periodic_schedule);
}

static void test_add_list_remove_schedule(const struct lttng_rotation_schedule *original_schedule)
{
	int ret;
	unsigned int schedules_count = 0;
	enum lttng_rotation_status status;
	const struct lttng_rotation_schedule *list_schedule;
	struct lttng_rotation_schedules *list_schedules;

	status = lttng_session_add_rotation_schedule(session_name, original_schedule);
	ok(status == LTTNG_ROTATION_STATUS_OK,
	   "Add a rotation schedule to session \'%s\'",
	   session_name);

	ret = lttng_session_list_rotation_schedules(session_name, &list_schedules);
	ok(ret == LTTNG_OK && list_schedules,
	   "List rotation schedules of session \'%s\'",
	   session_name);

	status = lttng_rotation_schedules_get_count(list_schedules, &schedules_count);
	ok(status == LTTNG_ROTATION_STATUS_OK && schedules_count == 1,
	   "Listing returned 1 rotation schedule");

	list_schedule = lttng_rotation_schedules_get_at_index(list_schedules, 0);
	ok(list_schedule, "Obtain the first schedule of a schedules list");

	ok(schedules_equal(original_schedule, list_schedule),
	   "Schedule returned by the listing is equal to the reference schedule that was added");

	status = lttng_session_remove_rotation_schedule(session_name, list_schedule);
	ok(status == LTTNG_ROTATION_STATUS_OK,
	   "Remove rotation schedule returned by the schedules listing");
	lttng_rotation_schedules_destroy(list_schedules);

	(void) lttng_session_list_rotation_schedules(session_name, &list_schedules);
	status = lttng_rotation_schedules_get_count(list_schedules, &schedules_count);
	ok(status == LTTNG_ROTATION_STATUS_OK && schedules_count == 0,
	   "Listing returned 0 rotation schedules after removal");
	lttng_rotation_schedules_destroy(list_schedules);
}

static void test_add_list_remove_size_schedule(void)
{
	struct lttng_rotation_schedule *size_schedule;

	diag("Add, list, and remove a size threshold rotation schedule");
	size_schedule = lttng_rotation_schedule_size_threshold_create();
	(void) lttng_rotation_schedule_size_threshold_set_threshold(size_schedule,
								    SIZE_THRESHOLD_BYTES);
	test_add_list_remove_schedule(size_schedule);
	lttng_rotation_schedule_destroy(size_schedule);
}

static void test_add_list_remove_periodic_schedule(void)
{
	struct lttng_rotation_schedule *periodic_schedule;

	diag("Add, list, and remove a periodic rotation schedule");
	periodic_schedule = lttng_rotation_schedule_periodic_create();
	(void) lttng_rotation_schedule_periodic_set_period(periodic_schedule, PERIODIC_TIME_US);
	test_add_list_remove_schedule(periodic_schedule);
	lttng_rotation_schedule_destroy(periodic_schedule);
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);

	if (argc < 2) {
		diag("Usage: schedule_api SESSION_NAME");
		goto end;
	}

	session_name = argv[1];

	diag("Argument validation");
	test_add_null_session();
	test_add_null_schedule();
	test_add_uninitialized_schedule();
	test_remove_null_session();
	test_remove_null_schedule();
	test_remove_uninitialized_schedule();
	test_uninitialized_schedule_get();

	test_add_list_remove_size_schedule();
	test_add_list_remove_periodic_schedule();
end:
	return exit_status();
}
