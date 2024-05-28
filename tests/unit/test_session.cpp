/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>

#include <bin/lttng-sessiond/health-sessiond.hpp>
#include <bin/lttng-sessiond/session.hpp>
#include <bin/lttng-sessiond/thread.hpp>
#include <bin/lttng-sessiond/ust-app.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <tap/tap.h>
#include <time.h>
#include <unistd.h>
#include <urcu.h>

#define SESSION1 "test1"

#define MAX_SESSIONS	  10000
#define RANDOM_STRING_LEN 11

/* Number of TAP tests in this file */
#define NUM_TESTS 11

static struct ltt_session_list *session_list;

static const char alphanum[] = "0123456789"
			       "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			       "abcdefghijklmnopqrstuvwxyz";
static char random_string[RANDOM_STRING_LEN];

/*
 * Return random string of 10 characters.
 * Not thread-safe.
 */
static char *get_random_string()
{
	int i;

	for (i = 0; i < RANDOM_STRING_LEN - 1; i++) {
		random_string[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	random_string[RANDOM_STRING_LEN - 1] = '\0';

	return random_string;
}

/*
 * Return 0 if session name is found, else -1
 */
static int find_session_name(const char *name)
{
	struct ltt_session *iter;

	cds_list_for_each_entry (iter, &session_list->head, list) {
		if (strcmp(iter->name, name) == 0) {
			return 0;
		}
	}

	return -1;
}

static int session_list_count()
{
	int count = 0;
	struct ltt_session *iter;

	cds_list_for_each_entry (iter, &session_list->head, list) {
		count++;
	}
	return count;
}

/*
 * Empty session list manually.
 */
static void empty_session_list()
{
	struct ltt_session *iter, *tmp;

	const auto list_lock = lttng::sessiond::lock_session_list();
	cds_list_for_each_entry_safe (iter, tmp, &session_list->head, list) {
		session_destroy(iter);
	}

	/* Session list must be 0 */
	LTTNG_ASSERT(!session_list_count());
}

/*
 * Test creation of 1 session
 */
static int create_one_session(const char *name)
{
	int ret;
	enum lttng_error_code ret_code;
	struct ltt_session *session = nullptr;

	const auto list_lock = lttng::sessiond::lock_session_list();
	ret_code = session_create(name, geteuid(), getegid(), &session);
	session_put(session);
	if (ret_code == LTTNG_OK) {
		/* Validate */
		ret = find_session_name(name);
		if (ret < 0) {
			/* Session not found by name */
			printf("session not found after creation\n");
			ret = -1;
		} else {
			/* Success */
			ret = 0;
		}
	} else {
		if (ret_code == LTTNG_ERR_EXIST_SESS) {
			printf("(session already exists) ");
		}
		ret = -1;
	}

	return ret;
}

/*
 * Test deletion of 1 session
 */
static int destroy_one_session(ltt_session::ref session)
{
	int ret;
	char session_name[NAME_MAX];

	strncpy(session_name, session->name, sizeof(session_name));
	session_name[sizeof(session_name) - 1] = '\0';

	/* Reference of the session list. */
	ltt_session *weak_session_ptr = &session.get();
	{
		/* Drop the reference that stems from the look-up. */
		const ltt_session::ref reference_to_drop = std::move(session);
	}

	session_destroy(weak_session_ptr);

	ret = find_session_name(session_name);
	if (ret < 0) {
		/* Success, -1 means that the sesion is NOT found */
		ret = 0;
	} else {
		/* Fail */
		ret = -1;
	}

	return ret;
}

/*
 * This test is supposed to fail at the second create call. If so, return 0 for
 * test success, else -1.
 */
static int two_session_same_name()
{
	const auto ret = create_one_session(SESSION1);
	if (ret < 0) {
		/* Fail */
		return -1;
	}

	/*
	 * Mind the order of the declaration of list_lock vs session:
	 * the session list lock must always be released _after_ the release of
	 * a session's reference (the destruction of a ref/locked_ref) to ensure
	 * since the reference's release may unpublish the session from the list of
	 * sessions.
	 */
	const auto list_lock = lttng::sessiond::lock_session_list();
	try {
		const auto session = ltt_session::find_session(SESSION1);
		/* Success */
		return 0;
	} catch (const lttng::sessiond::exceptions::session_not_found_error& ex) {
		/* Fail */
		return -1;
	}
}

static void test_session_list()
{
	session_list = session_get_list();
	ok(session_list != nullptr, "Session list: not NULL");
}

static void test_create_one_session()
{
	ok(create_one_session(SESSION1) == 0, "Create session: %s", SESSION1);
}

static void test_validate_session()
{
	/*
	 * Mind the order of the declaration of list_lock vs session:
	 * the session list lock must always be released _after_ the release of
	 * a session's reference (the destruction of a ref/locked_ref) to ensure
	 * since the reference's release may unpublish the session from the list of
	 * sessions.
	 */
	const auto list_lock = lttng::sessiond::lock_session_list();

	try {
		const auto session = ltt_session::find_session(SESSION1);
		pass("Validating session: session found");

		ok(session->kernel_session == nullptr && strlen(session->name),
		   "Validating session: basic sanity check");

		session->lock();
		session->unlock();
	} catch (const lttng::sessiond::exceptions::session_not_found_error& ex) {
		fail("Validating session: session found");
		skip(1, "Skipping session validation check as session was not found");
	}
}

static void test_destroy_session()
{
	/*
	 * Mind the order of the declaration of list_lock vs session:
	 * the session list lock must always be released _after_ the release of
	 * a session's reference (the destruction of a ref/locked_ref) to ensure
	 * since the reference's release may unpublish the session from the list of
	 * sessions.
	 */
	const auto list_lock = lttng::sessiond::lock_session_list();

	try {
		auto session = ltt_session::find_session(SESSION1);

		pass("Destroying session: session found");

		ok(destroy_one_session(std::move(session)) == 0,
		   "Destroying session: %s destroyed",
		   SESSION1);

	} catch (const lttng::sessiond::exceptions::session_not_found_error& ex) {
		fail("Destroying session: session found");
		skip(1, "Skipping session destruction as it was not found");
	}
}

static void test_duplicate_session()
{
	ok(two_session_same_name() == 0, "Duplicate session creation");
}

static void test_session_name_generation()
{
	struct ltt_session *session = nullptr;
	enum lttng_error_code ret_code;
	const char *expected_session_name_prefix = DEFAULT_SESSION_NAME;

	const auto list_lock = lttng::sessiond::lock_session_list();

	ret_code = session_create(nullptr, geteuid(), getegid(), &session);
	ok(ret_code == LTTNG_OK, "Create session with a NULL name (auto-generate a name)");
	if (!session) {
		skip(1, "Skipping session name generation tests as session_create() failed.");
		goto end;
	}
	diag("Automatically-generated session name: %s", *session->name ? session->name : "ERROR");
	ok(*session->name &&
		   !strncmp(expected_session_name_prefix,
			    session->name,
			    sizeof(DEFAULT_SESSION_NAME) - 1),
	   "Auto-generated session name starts with %s",
	   DEFAULT_SESSION_NAME);
end:
	session_put(session);
}

static void test_large_session_number()
{
	int ret, i, failed = 0;
	struct ltt_session *iter, *tmp;

	for (i = 0; i < MAX_SESSIONS; i++) {
		char *tmp_name = get_random_string();
		ret = create_one_session(tmp_name);
		if (ret < 0) {
			diag("session %d (name: %s) creation failed", i, tmp_name);
			++failed;
		}
	}

	ok(failed == 0, "Large sessions number: created %u sessions", MAX_SESSIONS);

	failed = 0;

	const auto list_lock = lttng::sessiond::lock_session_list();
	for (i = 0; i < MAX_SESSIONS; i++) {
		cds_list_for_each_entry_safe (iter, tmp, &session_list->head, list) {
			ret = destroy_one_session([iter]() {
				session_get(iter);
				return ltt_session::ref(*iter);
			}());

			if (ret < 0) {
				diag("session %d destroy failed", i);
				++failed;
			}
		}
	}

	ok(failed == 0 && session_list_count() == 0,
	   "Large sessions number: destroyed %u sessions",
	   MAX_SESSIONS);
}

int main()
{
	plan_tests(NUM_TESTS);

	the_health_sessiond = health_app_create(NR_HEALTH_SESSIOND_TYPES);

	diag("Sessions unit tests");

	rcu_register_thread();

	test_session_list();

	test_create_one_session();

	test_validate_session();

	test_destroy_session();

	test_duplicate_session();

	empty_session_list();

	test_session_name_generation();

	test_large_session_number();

	rcu_unregister_thread();
	lttng_thread_list_shutdown_orphans();

	return exit_status();
}
