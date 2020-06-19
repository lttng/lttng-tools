/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/payload.h>
#include <common/payload-view.h>
#include <tap/tap.h>

static const int TEST_COUNT = 5;

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

static void test_fd_push_pop_order(void)
{
	int ret, i;
	struct lttng_payload payload;

	lttng_payload_init(&payload);

	diag("Validating fd push/pop order");
	for (i = 0; i < 3; i++) {
		ret = lttng_payload_push_fd(&payload, i);
		if (ret) {
			break;
		}
	}
	ok(ret == 0, "Added three file descriptors to an lttng_payload");

	{
		bool fail_pop = false;
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
					&payload, 0, -1);

		for (i = 0; i < 3; i++) {
			ret = lttng_payload_view_pop_fd(&view);
			fail_pop |= ret != i;
		}

		ok(!fail_pop, "File descriptors are popped from a payload view in the order of insertion");
	}

	lttng_payload_reset(&payload);
}

static void test_fd_push_pop_imbalance(void)
{
	int ret, i;
	struct lttng_payload payload;
	const char * const test_description = "Error reported when popping more file descriptors than were pushed";

	lttng_payload_init(&payload);

	diag("Validating fd pop imbalance");
	for (i = 0; i < 10; i++) {
		ret = lttng_payload_push_fd(&payload, i);
		if (ret) {
			break;
		}
	}

	{
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
					&payload, 0, -1);

		for (i = 0; i < 10; i++) {
			ret = lttng_payload_view_pop_fd(&view);
			if (ret == -1) {
				goto fail;
			}
		}

		ret = lttng_payload_view_pop_fd(&view);
		ok(ret == -1, test_description);
	}

	lttng_payload_reset(&payload);
	return;
fail:
	fail(test_description);
	lttng_payload_reset(&payload);
}

static void test_fd_pop_fd_root_views(void)
{
	int ret, i;
	const int fd = 42;
	struct lttng_payload payload;
	const char * const test_description = "Same file descriptor returned when popping from different top-level views";

	lttng_payload_init(&payload);

	diag("Validating root view fd pop behaviour");
	ret = lttng_payload_push_fd(&payload, fd);
	if (ret) {
		goto fail;
	}

	for (i = 0; i < 5; i++) {
		struct lttng_payload_view view =
				lttng_payload_view_from_payload(
					&payload, 0, -1);

		ret = lttng_payload_view_pop_fd(&view);
		if (ret != fd) {
			goto fail;
		}
	}

	lttng_payload_reset(&payload);
	pass(test_description);
	return;
fail:
	lttng_payload_reset(&payload);
	fail(test_description);
}

static void test_fd_pop_fd_descendant_views(void)
{
	int ret;
	const int fd1 = 42, fd2 = 1837;
	struct lttng_payload payload;
	const char * const test_description = "Different file descriptors returned when popping from descendant views";

	lttng_payload_init(&payload);

	diag("Validating descendant view fd pop behaviour");
	ret = lttng_payload_push_fd(&payload, fd1);
	if (ret) {
		goto fail;
	}

	ret = lttng_payload_push_fd(&payload, fd2);
	if (ret) {
		goto fail;
	}

	{
		struct lttng_payload_view view1 =
				lttng_payload_view_from_payload(
					&payload, 0, -1);
		struct lttng_payload_view view2 =
			lttng_payload_view_from_view(
				&view1, 0, -1);

		ret = lttng_payload_view_pop_fd(&view1);
		if (ret != fd1) {
			goto fail;
		}

		ret = lttng_payload_view_pop_fd(&view2);
		if (ret != fd2) {
			goto fail;
		}
	}

	lttng_payload_reset(&payload);
	pass(test_description);
	return;
fail:
	lttng_payload_reset(&payload);
	fail(test_description);
}

int main(void)
{
	plan_tests(TEST_COUNT);

	test_fd_push_pop_order();
	test_fd_push_pop_imbalance();
	test_fd_pop_fd_root_views();
	test_fd_pop_fd_descendant_views();

	return exit_status();
}
