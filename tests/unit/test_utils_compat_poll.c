/*
 * test_utils_compat_poll.c
 *
 * Unit tests for the compatibility layer of poll/epoll API.
 *
 * Copyright (C) 2019 Yannick Lamarre <ylamarre@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <tap/tap.h>

#include <common/compat/poll.h>
#include <common/readwrite.h>
#include <common/pipe.h>
#include <common/dynamic-array.h>

/* Verification without trashing test order in the child process */
#define childok(e, test, ...) do { \
	if (!(e)) { \
		diag(test, ## __VA_ARGS__); \
		_exit(EXIT_FAILURE); \
	} \
} while(0)

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

/*
 * Non-zero 8-bits arbitrary value below 0x7f to ensure no sign extension
 * occurs. Used to verify that the value is properly propagated through the
 * pipe.
 */
#define MAGIC_VALUE ((char) 0x5A)

#ifdef HAVE_EPOLL
#define NUM_TESTS 48
#else
#define NUM_TESTS 47
#endif

#ifdef HAVE_EPOLL
#if defined(HAVE_EPOLL_CREATE1) && defined(EPOLL_CLOEXEC)
#define CLOE_VALUE EPOLL_CLOEXEC
#else
#define CLOE_VALUE FD_CLOEXEC
#endif

static
void test_epoll_compat(void)
{
	/*
	 * Type conversion present to disable warning of anonymous enum from
	 * compiler.
	 */
	ok((int) LTTNG_CLOEXEC == (int) CLOE_VALUE, "epoll's CLOEXEC value");
}
#endif

static void test_alloc(void)
{
	struct lttng_poll_event poll_events;

	lttng_poll_init(&poll_events);

	/* Null pointer */
	ok(lttng_poll_create(NULL, 1, 0) != 0, "Create over NULL pointer fails");
	/* Size 0 */
	ok(lttng_poll_create(&poll_events, 0, 0) != 0, "Create with size 0 fails");
	/* without CLOEXEC */
	ok(lttng_poll_create(&poll_events, 1, 0) == 0, "Create valid poll set succeeds");
	/*
	 * lttng_poll_event structure untested due to incompatibility across
	 * sublayers. lttng_poll_clean cannot be tested. There is no success
	 * criteria. Verify set's max size cases.
	 */
	lttng_poll_clean(&poll_events);
}

/* Tests stuff related to what would be handled with epoll_ctl. */
static void test_add_del(void)
{
	struct lttng_poll_event poll_events;

	lttng_poll_init(&poll_events);
	ok(lttng_poll_add(NULL, 1, LPOLLIN) != 0, "Adding to NULL set fails");
	ok(lttng_poll_add(&poll_events, 1, LPOLLIN) != 0, "Adding to uninitialized structure fails");
	ok(lttng_poll_add(&poll_events, -1, LPOLLIN) != 0, "Adding invalid FD fails");

	ok(lttng_poll_create(&poll_events, 1, 0) == 0, "Create a poll set succeeds");
	ok(LTTNG_POLL_GETNB(&poll_events) == 0, "Set created empty");

	ok(lttng_poll_add(NULL, 1, LPOLLIN) != 0, "Adding to NULL set fails");
	ok(LTTNG_POLL_GETNB(&poll_events) == 0, "Set still empty");
	ok(lttng_poll_add(&poll_events, -1, LPOLLIN) != 0, "Adding invalid FD fails");
	ok(LTTNG_POLL_GETNB(&poll_events) == 0, "Set still empty");

	ok(lttng_poll_add(&poll_events, 1, LPOLLIN) == 0, "Adding valid FD succeeds");
	ok(LTTNG_POLL_GETNB(&poll_events) == 1, "Nb of elements incremented");

	ok(lttng_poll_del(NULL, 1) != 0, "Removing from NULL set fails");
	ok(LTTNG_POLL_GETNB(&poll_events) == 1, "Number of FD in set unchanged");

	ok(lttng_poll_del(&poll_events, -1) != 0, "Removing from negative FD fails");
	ok(LTTNG_POLL_GETNB(&poll_events) == 1, "Number of FD in set unchanged");

	ok(lttng_poll_del(&poll_events, 2) == 0, "Removing invalid FD still succeeds");
	ok(LTTNG_POLL_GETNB(&poll_events) == 1, "Number of elements unchanged");

	ok(lttng_poll_del(&poll_events, 1) == 0, "Removing valid FD succeeds");
	ok(LTTNG_POLL_GETNB(&poll_events) == 0, "Nb of elements decremented");

	ok(lttng_poll_del(&poll_events, 1) != 0, "Removing from empty set fails");
	ok(LTTNG_POLL_GETNB(&poll_events) == 0, "Nb of elements unchanged");

	lttng_poll_clean(&poll_events);
}

static void test_mod_wait(void)
{
	struct lttng_poll_event poll_events;
	struct lttng_poll_event cpoll_events;
	int hupfd[2];
	int infd[2];
	pid_t cpid;
	char rbuf = 0, tbuf = MAGIC_VALUE;
	int wstatus;

	lttng_poll_init(&poll_events);
	lttng_poll_init(&cpoll_events);

	ok(pipe(hupfd) != -1, "pipe function succeeds");
	ok(pipe(infd) != -1, "pipe function succeeds");

	cpid = fork();
	if (cpid == 0) {
		childok(lttng_poll_create(&cpoll_events, 1, 0) == 0, "Create valid poll set succeeds");
		childok(lttng_poll_mod(NULL, infd[0], LPOLLIN) == -1, "lttng_poll_mod with invalid input returns an error");
		childok(lttng_poll_mod(&cpoll_events, infd[0], LPOLLIN) == -1, "lttng_poll_mod with invalid input returns an error");
		childok(lttng_poll_add(&cpoll_events, infd[0], LPOLLHUP) == 0, "Add valid FD succeeds");
		childok(lttng_poll_mod(&cpoll_events, -1, LPOLLIN) == -1, "lttng_poll_mod with invalid input returns an error");
		childok(lttng_poll_mod(&cpoll_events, hupfd[0], LPOLLIN) == 0, "lttng_poll_mod on unincluded FD goes on");
		childok(lttng_poll_mod(&cpoll_events, infd[0], LPOLLIN) == 0, "Modify event type succeeds");
		childok(close(infd[1]) == 0, "Close valid FD succeeds");
		childok(lttng_poll_wait(&cpoll_events, -1) == 1, "Wait on close times out");
		childok(lttng_read(infd[0], &rbuf, 1) == 1, "Data is present in the pipe");
		childok(rbuf == MAGIC_VALUE, "Received data is consistent with transmitted data");
		childok(lttng_poll_del(&cpoll_events, infd[0]) == 0, "Removing valid FD succeeds");
		childok(close(infd[0]) == 0, "Close valid FD succeeds");
		childok(close(hupfd[0]) == 0, "Close valid FD succeeds");
		childok(close(hupfd[1]) == 0, "Close valid FD succeeds");
		lttng_poll_clean(&cpoll_events);
		_exit(EXIT_SUCCESS);
	} else {
		ok(close(hupfd[1]) == 0, "Close valid FD succeeds");
		ok(close(infd[0]) == 0, "Close valid FD succeeds");

		ok(lttng_poll_wait(NULL, -1) == -1, "lttng_poll_wait call with invalid input returns error");

		ok(lttng_poll_create(&poll_events, 1, 0) == 0, "Create valid poll set succeeds");
		ok(lttng_poll_wait(&poll_events, -1) == -1, "lttng_poll_wait call with invalid input returns error");
		ok(lttng_poll_add(&poll_events, hupfd[0], LPOLLHUP) == 0, "Add valid FD succeeds");
		ok(lttng_write(infd[1], &tbuf, 1) == 1, "Write to pipe succeeds");
		ok(lttng_poll_wait(&poll_events, -1) == 1, "Wakes up on one event");
		ok(lttng_poll_del(&poll_events, hupfd[0]) == 0, "Removing valid FD succeeds");
		ok(close(hupfd[0]) == 0, "Close valid FD succeeds");
		ok(close(infd[1]) == 0, "Close valid FD succeeds");
		lttng_poll_clean(&poll_events);
		ok(waitpid(cpid, &wstatus, 0) == cpid, "Wait for child exit");
		ok(WIFEXITED(wstatus) == 1, "Child process exited");
		ok(WEXITSTATUS(wstatus) == EXIT_SUCCESS, "Child process exited with EXIT_SUCCESS");
	}
}

static void destroy_pipe(void *pipe)
{
	lttng_pipe_destroy(pipe);
}

static int run_active_set_combination(unsigned int fd_count,
		unsigned int active_fds_mask)
{
	int ret = 0;
	unsigned int i;
	const unsigned int active_fds_count = __builtin_popcount(active_fds_mask);
	struct lttng_poll_event poll_events;
	struct lttng_dynamic_pointer_array pipes;
	struct lttng_pipe *pipe = NULL;

	lttng_poll_init(&poll_events);
	lttng_dynamic_pointer_array_init(&pipes, destroy_pipe);

	ret = lttng_poll_create(&poll_events, fd_count, 0);
	if (ret) {
		diag("Failed to create poll set for %u file descriptors",
				fd_count);
		goto end;
	}

	for (i = 0; i < fd_count; i++) {
		pipe = lttng_pipe_open(0);

		if (!pipe) {
			diag("Failed to allocate pipe");
			ret = -1;
			goto end;
		}

		ret = lttng_poll_add(&poll_events, lttng_pipe_get_readfd(pipe),
				LPOLLIN);
		if (ret) {
			diag("Failed to add file descriptor to poll set");
			ret = -1;
			goto end;
		}

		ret = lttng_dynamic_pointer_array_add_pointer(&pipes, pipe);
		if (ret) {
			diag("Failed to add pipe to pipes array");
			ret = -1;
			goto end;
		}

		/* Ownership transferred to the pointer array. */
		pipe = NULL;
	}

	/* Write one byte for all active fds that should be active. */
	for (i = 0; i < fd_count; i++) {
		struct lttng_pipe *borrowed_pipe;

		/* Should this fd be made active? */
		if (!(active_fds_mask & (1 << i))) {
			continue;
		}

		borrowed_pipe = lttng_dynamic_pointer_array_get_pointer(
				&pipes, i);

		ret = lttng_pipe_write(
				borrowed_pipe, &(char){'a'}, sizeof(char));
		if (ret != sizeof(char)) {
			diag("Failed to write to pipe");
			ret = -1;
			goto end;
		}
	}

	ret = lttng_poll_wait(&poll_events, 0);
	if (ret != active_fds_count) {
		diag("lttng_poll_wait returned %d, expected %u active file descriptors",
				ret, active_fds_count);
		ret = -1;
		goto end;
	} else {
		/* Success! */
		ret = 0;
	}

end:
	lttng_dynamic_pointer_array_reset(&pipes);
	lttng_poll_clean(&poll_events);
	lttng_pipe_destroy(pipe);
	return ret;
}

static void test_active_set_combinations(unsigned int fd_count)
{
	unsigned int i, all_active_mask = 0;

	/* Do you really want to test more than 4,294,967,295 combinations? */
	assert(fd_count <= 32);

	for (i = 0; i < fd_count; i++) {
		all_active_mask |= (1 << i);
	}

	for (i = 0; i <= all_active_mask; i++) {
		const int ret = run_active_set_combination(fd_count, i);

		if (ret) {
			goto fail;
		}
	}

	pass("Test all combinations of active file descriptors for %u file descriptors", fd_count);
	return;
fail:
	fail("Test all combinations of active file descriptors for %u file descriptors", fd_count);
}

static void test_func_def(void)
{
#ifdef LTTNG_POLL_GETFD
#define PASS_GETFD 1
#else
#define PASS_GETFD 0
#endif

#ifdef LTTNG_POLL_GETEV
#define PASS_GETEV 1
#else
#define PASS_GETEV 0
#endif

#ifdef LTTNG_POLL_GETSZ
#define PASS_GETSZ 1
#else
#define PASS_GETSZ 0
#endif

#ifdef LTTNG_POLL_GET_PREV_FD
#define PASS_GET_PREV_FD 1
#else
#define PASS_GET_PREV_FD 0
#endif

	ok(lttng_poll_reset == lttng_poll_reset, "lttng_poll_reset is defined");
	ok(lttng_poll_init == lttng_poll_init , "lttng_poll_init is defined");
	ok(PASS_GETFD, "GETFD is defined");
	ok(PASS_GETEV, "GETEV is defined");
	ok(PASS_GETSZ, "GETSZ is defined");
	ok(PASS_GET_PREV_FD, "GET_PREV_FD is defined");
}

int main(void)
{
	plan_tests(NUM_TESTS);
#ifdef HAVE_EPOLL
	test_epoll_compat();
#endif
	test_func_def();
	test_alloc();
	test_add_del();
	test_mod_wait();
	test_active_set_combinations(8);
	return exit_status();
}
