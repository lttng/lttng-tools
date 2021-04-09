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

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

#define NUM_TESTS 2

static void test_action_notify(void)
{
	struct lttng_action *notify_action = NULL;

	notify_action = lttng_action_notify_create();
	ok(notify_action, "Create notify action");
	ok(lttng_action_get_type(notify_action) == LTTNG_ACTION_TYPE_NOTIFY,
			"Action has type LTTNG_ACTION_TYPE_NOTIFY");
	lttng_action_destroy(notify_action);
}

int main(int argc, const char *argv[])
{
	plan_tests(NUM_TESTS);
	test_action_notify();
	return exit_status();
}
