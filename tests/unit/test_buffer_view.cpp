/*
 * Copyright (C) 2020 EfficiOS, inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */


#include <common/buffer-view.hpp>
#include <tap/tap.h>

static const int TEST_COUNT = 5;

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

static void test_contains_string(void)
{
	const char buf[] = {'A', 'l', 'l', 'o', '\0'};
	struct lttng_buffer_view view = lttng_buffer_view_init(buf, 0, 5);
	struct lttng_buffer_view view_minus_one =
			lttng_buffer_view_init(buf, 0, 4);

	ok1(!lttng_buffer_view_contains_string(&view, buf, 4));
	ok1(lttng_buffer_view_contains_string(&view, buf, 5));
	ok1(!lttng_buffer_view_contains_string(&view, buf, 6));

	ok1(!lttng_buffer_view_contains_string(&view_minus_one, buf, 4));
	ok1(!lttng_buffer_view_contains_string(&view_minus_one, buf, 5));
}

int main(void)
{
	plan_tests(TEST_COUNT);

	test_contains_string();

	return exit_status();
}
