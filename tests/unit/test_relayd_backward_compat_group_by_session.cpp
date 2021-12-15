/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tap/tap.h>

#include <common/time.hpp>

#include "backward-compatibility-group-by.hpp"

/* Number of TAP tests in this file */
#define NUM_TESTS_PER_TEST 1

struct test {
	const char *stream_path;
	const char *session_name;
	const char *hostname;
	const char *creation_time;
	const char *extra_path;
	const char *leftover;
	bool is_valid;
};

int lttng_opt_quiet;
int lttng_opt_mi;
int lttng_opt_verbose;

struct test tests[] = {
		/* Default name session streaming. */
		{"hostname/auto-20190918-164429/ust/uid/1000/64-bit",
				"auto-20190918-164429", "hostname",
				"20190918-164429", "", "ust/uid/1000/64-bit",
				true},
		/* Custom default name session */
		{"hostname/custom_auto-20190319-120000/ust/uid/1000/64-bit",
				"custom_auto-20190319-120000", "hostname",
				"20190319-120000", "", "ust/uid/1000/64-bit",
				true},
		/* Named session streaming */
		{"hostname/test-20190918-164709/ust/uid/1000/64-bit", "test",
				"hostname", "20190918-164709", "",
				"ust/uid/1000/64-bit", true},
		/* Default session snapshot streaming */
		{"hostname//snapshot-1-20190918-164829-0/ust//uid/1000/64-bit",
				"my_session", "hostname", "", "",
				"snapshot-1-20190918-164829-0/ust//uid/1000/64-bit",
				true},
		/* Named session snapshot streaming */
		{"hostname//snapshot-1-20190918-175919-0/ust//uid/1000/64-bit",
				"my_session", "hostname", "", "",
				"snapshot-1-20190918-175919-0/ust//uid/1000/64-bit",
				true},
		/* Default name session, live */
		{"hostname//auto-20190918-171641/ust/uid/1000/64-bit",
				"auto-20190918-171641", "hostname",
				"20190918-171641", "", "ust/uid/1000/64-bit",
				true},
		/* Named session, live */
		{"hostname//test-20190918-180333//ust/uid/1000/64-bit",
				"test-20190918-180333", "hostname",
				"20190918-180333", "", "/ust/uid/1000/64-bit",
				true},
		/* Default name session, streaming & live , extra path */
		{"hostname/extra/path/ust/uid/1000/64-bit",
				"auto-20190919-122110", "hostname",
				"20190919-122110", "extra",
				"path/ust/uid/1000/64-bit", true},
		/* Named session, live, extra path */
		{"hostname/extra/path/ust/uid/1000/64-bit", "test", "hostname",
				"", "extra", "path/ust/uid/1000/64-bit", true},
		/* Named session, snapshot, extra path */
		{"hostname/extra/path/snapshot-1-20190919-140702-0/ust//uid/1000/64-bit",
				"test", "hostname", "", "extra",
				"path/snapshot-1-20190919-140702-0/ust//uid/1000/64-bit",
				true},
		/* Corner cases*/
		/* Named session with valid datetime in it */
		/* Default name session, extra path with session name in it*/
		{"hostname/test-20190319-120000-20190918-180921/ust/uid/1000/64-bit",
				"test-20190319-120000", "hostname",
				"20190918-180921", "", "ust/uid/1000/64-bit",
				true},
		/* Empty path */
		{"", "test", "", "", "", "", false},
		/* Path without second token */
		{"hostname", "test", "hostname", "", "", "", false},
		/* No leftover */
		{"hostname/test", "test", "hostname", "", "", "", true},
		/* Path with ession name but no datetime */
		{"hostname/test/ust/uid/1000/64-bit", "test", "hostname", "",
				"", "ust/uid/1000/64-bit", true},
};

static char *craft_expected(struct test *test, time_t relay_session_creation_time)
{
	int ret;
	char *result = NULL;
	char relay_session_creation_datetime[DATETIME_STR_LEN];

	ret = time_to_datetime_str(relay_session_creation_time,
			relay_session_creation_datetime,
			sizeof(relay_session_creation_datetime));
	if (ret < 0) {
		result = NULL;
		goto end;
	}

	ret = asprintf(&result, "%s/%s-%s/%s%s%s", test->session_name,
			test->hostname,
			test->creation_time[0] == '\0' ?
					relay_session_creation_datetime :
					test->creation_time,
			test->extra_path,
			test->extra_path[0] != '\0' ? "/" : "", test->leftover);
	if (ret < 0) {
		result = NULL;
		goto end;
	}
end:
	return result;
}

int main(void)
{
	int i;
	int num_test = sizeof(tests) / sizeof(struct test);
	const time_t test_time = time(NULL);

	plan_tests(NUM_TESTS_PER_TEST * num_test);
	diag("Backward compatibility utils for lttng-relayd --group-by-session");

	if (test_time == (time_t) -1) {
		perror("Failed to sample time");
		return exit_status();
	}

	for (i = 0; i < num_test; i++) {
		char *expected = NULL;
		char *result = NULL;

		expected = craft_expected(&tests[i], test_time);
		if (!expected) {
			fprintf(stderr, "Failed to craft expected output\n");
			goto loop;
		}

		result = backward_compat_group_by_session(tests[i].stream_path,
				tests[i].session_name, test_time);
		if (!result && tests[i].is_valid) {
			fprintf(stderr, "Failed to get result\n");
			goto loop;
		} else if (!result && tests[i].is_valid == false) {
			pass("Returned null as expected");
			goto loop;
		}

		ok(strncmp(expected, result, strlen(expected)) == 0,
				"In: %s, out: %s, expected: %s",
				tests[i].stream_path, result, expected);
	loop:
		free(expected);
		free(result);
	}
	return exit_status();
}
