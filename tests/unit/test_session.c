/*
 * Copyright (c)  2011 David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <urcu.h>

#include <tap/tap.h>

#include <bin/lttng-sessiond/session.h>
#include <bin/lttng-sessiond/ust-app.h>
#include <bin/lttng-sessiond/ht-cleanup.h>
#include <bin/lttng-sessiond/health-sessiond.h>
#include <bin/lttng-sessiond/thread.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/common.h>

#define SESSION1 "test1"

#define MAX_SESSIONS 10000
#define RANDOM_STRING_LEN	11

/* Number of TAP tests in this file */
#define NUM_TESTS 11

struct health_app *health_sessiond;
static struct ltt_session_list *session_list;

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 0;
int lttng_opt_mi;

int ust_consumerd32_fd;
int ust_consumerd64_fd;

static const char alphanum[] =
	"0123456789"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";
static char random_string[RANDOM_STRING_LEN];

/*
 * Return random string of 10 characters.
 * Not thread-safe.
 */
static char *get_random_string(void)
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
static int find_session_name(char *name)
{
	struct ltt_session *iter;

	cds_list_for_each_entry(iter, &session_list->head, list) {
		if (strcmp(iter->name, name) == 0) {
			return 0;
		}
	}

	return -1;
}

static int session_list_count(void)
{
	int count = 0;
	struct ltt_session *iter;

	cds_list_for_each_entry(iter, &session_list->head, list) {
		count++;
	}
	return count;
}

/*
 * Empty session list manually.
 */
static void empty_session_list(void)
{
	struct ltt_session *iter, *tmp;

	session_lock_list();
	cds_list_for_each_entry_safe(iter, tmp, &session_list->head, list) {
		session_destroy(iter);
	}
	session_unlock_list();

	/* Session list must be 0 */
	assert(!session_list_count());
}

/*
 * Test creation of 1 session
 */
static int create_one_session(char *name)
{
	int ret;
	enum lttng_error_code ret_code;
	struct ltt_session *session = NULL;

	session_lock_list();
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

	session_unlock_list();
	return ret;
}

/*
 * Test deletion of 1 session
 */
static int destroy_one_session(struct ltt_session *session)
{
	int ret;
	char session_name[NAME_MAX];

	strncpy(session_name, session->name, sizeof(session_name));
	session_name[sizeof(session_name) - 1] = '\0';

	session_destroy(session);
	session_put(session);

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
static int two_session_same_name(void)
{
	int ret;
	struct ltt_session *sess;

	ret = create_one_session(SESSION1);
	if (ret < 0) {
		/* Fail */
		ret = -1;
		goto end;
	}

	session_lock_list();
	sess = session_find_by_name(SESSION1);
	if (sess) {
		/* Success */
		session_put(sess);
		session_unlock_list();
		ret = 0;
		goto end_unlock;
	} else {
		/* Fail */
		ret = -1;
		goto end_unlock;
	}
end_unlock:
	session_unlock_list();
end:
	return ret;
}

void test_session_list(void)
{
	session_list = session_get_list();
	ok(session_list != NULL, "Session list: not NULL");
}

void test_create_one_session(void)
{
	ok(create_one_session(SESSION1) == 0,
	   "Create session: %s",
	   SESSION1);
}

void test_validate_session(void)
{
	struct ltt_session *tmp;

	session_lock_list();
	tmp = session_find_by_name(SESSION1);

	ok(tmp != NULL,
	   "Validating session: session found");

	if (tmp) {
		ok(tmp->kernel_session == NULL &&
		   strlen(tmp->name),
		   "Validating session: basic sanity check");
	} else {
		skip(1, "Skipping session validation check as session was not found");
		goto end;
	}

	session_lock(tmp);
	session_unlock(tmp);
	session_put(tmp);
end:
	session_unlock_list();
}

void test_destroy_session(void)
{
	struct ltt_session *tmp;

	session_lock_list();
	tmp = session_find_by_name(SESSION1);

	ok(tmp != NULL,
	   "Destroying session: session found");

	if (tmp) {
		ok(destroy_one_session(tmp) == 0,
		   "Destroying session: %s destroyed",
		   SESSION1);
	} else {
		skip(1, "Skipping session destruction as it was not found");
	}
	session_unlock_list();
}

void test_duplicate_session(void)
{
	ok(two_session_same_name() == 0,
	   "Duplicate session creation");
}

void test_session_name_generation(void)
{
	struct ltt_session *session = NULL;
	enum lttng_error_code ret_code;
	const char *expected_session_name_prefix = DEFAULT_SESSION_NAME;

	session_lock_list();
	ret_code = session_create(NULL, geteuid(), getegid(), &session);
	ok(ret_code == LTTNG_OK,
		"Create session with a NULL name (auto-generate a name)");
	if (!session) {
		skip(1, "Skipping session name generation tests as session_create() failed.");
		goto end;
	}
	diag("Automatically-generated session name: %s", *session->name ?
		session->name : "ERROR");
	ok(*session->name && !strncmp(expected_session_name_prefix, session->name,
			sizeof(DEFAULT_SESSION_NAME) - 1),
			"Auto-generated session name starts with %s",
			DEFAULT_SESSION_NAME);
end:
	session_put(session);
	session_unlock_list();
}

void test_large_session_number(void)
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

	ok(failed == 0,
	   "Large sessions number: created %u sessions",
	   MAX_SESSIONS);

	failed = 0;

	session_lock_list();
	for (i = 0; i < MAX_SESSIONS; i++) {
		cds_list_for_each_entry_safe(iter, tmp, &session_list->head, list) {
			assert(session_get(iter));
			ret = destroy_one_session(iter);
			if (ret < 0) {
				diag("session %d destroy failed", i);
				++failed;
			}
		}
	}
	session_unlock_list();

	ok(failed == 0 && session_list_count() == 0,
	   "Large sessions number: destroyed %u sessions",
	   MAX_SESSIONS);
}

int main(int argc, char **argv)
{
	struct lttng_thread *ht_cleanup_thread;

	plan_tests(NUM_TESTS);

	health_sessiond = health_app_create(NR_HEALTH_SESSIOND_TYPES);
	ht_cleanup_thread = launch_ht_cleanup_thread();
	assert(ht_cleanup_thread);
	lttng_thread_put(ht_cleanup_thread);

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
