/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <fcntl.h>
#include <tap/tap.h>
#include <unistd.h>

static const int TEST_COUNT = 5;

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

static void test_fd_push_pop_order()
{
	int ret, i;
	struct lttng_payload payload;
	int fds[3];

	lttng_payload_init(&payload);

	diag("Validating fd push/pop order");
	for (i = 0; i < 3; i++) {
		int fd = fcntl(STDOUT_FILENO, F_DUPFD, 0);
		struct fd_handle *handle;

		LTTNG_ASSERT(fd >= 0);
		fds[i] = fd;

		handle = fd_handle_create(fd);
		LTTNG_ASSERT(handle);

		ret = lttng_payload_push_fd_handle(&payload, handle);
		fd_handle_put(handle);
		if (ret) {
			break;
		}
	}

	ok(ret == 0, "Added three file descriptors to an lttng_payload");

	{
		bool fail_pop = false;
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);

		for (i = 0; i < 3; i++) {
			struct fd_handle *handle = lttng_payload_view_pop_fd_handle(&view);

			fail_pop |= fd_handle_get_fd(handle) != fds[i];
			fd_handle_put(handle);
		}

		ok(!fail_pop,
		   "File descriptors are popped from a payload view in the order of insertion");
	}

	lttng_payload_reset(&payload);
}

static void test_fd_push_pop_imbalance()
{
	int ret, i;
	struct lttng_payload payload;
	const char *const test_description =
		"Error reported when popping more file descriptors than were pushed";

	lttng_payload_init(&payload);

	diag("Validating fd pop imbalance");
	for (i = 0; i < 10; i++) {
		struct fd_handle *handle;
		int fd = fcntl(STDOUT_FILENO, F_DUPFD, 0);

		LTTNG_ASSERT(fd >= 0);

		handle = fd_handle_create(fd);
		LTTNG_ASSERT(handle);

		ret = lttng_payload_push_fd_handle(&payload, handle);
		fd_handle_put(handle);
		if (ret) {
			break;
		}
	}

	{
		struct fd_handle *handle;
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);

		for (i = 0; i < 10; i++) {
			handle = lttng_payload_view_pop_fd_handle(&view);
			fd_handle_put(handle);
			if (!handle) {
				goto fail;
			}
		}

		handle = lttng_payload_view_pop_fd_handle(&view);
		ok(!handle, "%s", test_description);
		fd_handle_put(handle);
	}

	lttng_payload_reset(&payload);
	return;
fail:
	fail("%s", test_description);
	lttng_payload_reset(&payload);
}

static void test_fd_pop_fd_root_views()
{
	int ret, i;
	int fd = fcntl(STDOUT_FILENO, F_DUPFD, 0);
	struct fd_handle *handle;
	struct lttng_payload payload;
	const char *const test_description =
		"Same file descriptor returned when popping from different top-level views";

	LTTNG_ASSERT(fd >= 0);
	handle = fd_handle_create(fd);
	LTTNG_ASSERT(handle);

	lttng_payload_init(&payload);

	diag("Validating root view fd pop behaviour");
	ret = lttng_payload_push_fd_handle(&payload, handle);
	if (ret) {
		goto fail;
	}

	for (i = 0; i < 5; i++) {
		int view_fd;
		struct fd_handle *view_handle;
		struct lttng_payload_view view = lttng_payload_view_from_payload(&payload, 0, -1);

		view_handle = lttng_payload_view_pop_fd_handle(&view);
		if (!view_handle) {
			goto fail;
		}

		view_fd = fd_handle_get_fd(view_handle);
		fd_handle_put(view_handle);
		if (view_fd != fd || view_handle != handle) {
			goto fail;
		}
	}

	lttng_payload_reset(&payload);
	pass("%s", test_description);
	fd_handle_put(handle);
	return;
fail:
	lttng_payload_reset(&payload);
	fail("%s", test_description);
	fd_handle_put(handle);
}

static void test_fd_pop_fd_descendant_views()
{
	int ret;
	const int fd1 = 42, fd2 = 1837;
	struct fd_handle *handle1 = fd_handle_create(fd1);
	struct fd_handle *handle2 = fd_handle_create(fd2);
	struct fd_handle *view_handle1 = nullptr, *view_handle2 = nullptr;
	struct lttng_payload payload;
	const char *const test_description =
		"Different file descriptors returned when popping from descendant views";

	lttng_payload_init(&payload);
	LTTNG_ASSERT(handle1);
	LTTNG_ASSERT(handle2);

	diag("Validating descendant view fd pop behaviour");
	ret = lttng_payload_push_fd_handle(&payload, handle1);
	if (ret) {
		goto fail;
	}

	ret = lttng_payload_push_fd_handle(&payload, handle2);
	if (ret) {
		goto fail;
	}

	{
		struct lttng_payload_view view1 = lttng_payload_view_from_payload(&payload, 0, -1);
		struct lttng_payload_view view2 = lttng_payload_view_from_view(&view1, 0, -1);

		view_handle1 = lttng_payload_view_pop_fd_handle(&view1);
		if (!view_handle1 || fd_handle_get_fd(view_handle1) != fd1) {
			goto fail;
		}

		view_handle2 = lttng_payload_view_pop_fd_handle(&view2);
		if (!view_handle2 || fd_handle_get_fd(view_handle2) != fd2) {
			goto fail;
		}
	}

	lttng_payload_reset(&payload);
	pass("%s", test_description);
	fd_handle_put(handle1);
	fd_handle_put(handle2);
	fd_handle_put(view_handle1);
	fd_handle_put(view_handle2);
	return;
fail:
	lttng_payload_reset(&payload);
	fail("%s", test_description);
	fd_handle_put(handle1);
	fd_handle_put(handle2);
	fd_handle_put(view_handle1);
	fd_handle_put(view_handle2);
}

int main()
{
	plan_tests(TEST_COUNT);

	test_fd_push_pop_order();
	test_fd_push_pop_imbalance();
	test_fd_pop_fd_root_views();
	test_fd_pop_fd_descendant_views();

	return exit_status();
}
