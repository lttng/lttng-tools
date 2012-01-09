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

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#include <lttng-sessiond-comm.h>

#include <lttng-sessiond/session.h>
#include "utils.h"

#define SESSION1 "test1"

/* This path will NEVER be created in this test */
#define PATH1 "/tmp/.test-junk-lttng"

#define MAX_SESSIONS 10000

/*
 * String of 263 caracters. NAME_MAX + "OVERFLOW". If OVERFLOW appears in the
 * session name, we have a problem.
 *
 * NAME_MAX = 255
 */
#define OVERFLOW_SESSION_NAME \
	"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" \
	"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" \
	"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" \
	"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabc"  \
	"OVERFLOW"

static struct ltt_session_list *session_list;

/* For lttngerr.h */
int opt_quiet = 1;
int opt_verbose = 0;

static const char alphanum[] =
	"0123456789"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz";

/*
 * Return random string of 10 characters.
 */
static char *get_random_string(void)
{
	int i;
	char *str = malloc(11);

	for (i = 0; i < 10; i++) {
		str[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	str[10] = '\0';

	return str;
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

/*
 * Empty session list manually.
 */
static void empty_session_list(void)
{
	struct ltt_session *iter, *tmp;

	cds_list_for_each_entry_safe(iter, tmp, &session_list->head, list) {
		cds_list_del(&iter->list);
		session_list->count--;
		free(iter);
	}

	/* Session list must be 0 */
	assert(!session_list->count);
}

/*
 * Test creation of 1 session
 */
static int create_one_session(char *name, char *path)
{
	int ret;

	ret = session_create(name, path, geteuid(), getegid());
	if (ret == LTTCOMM_OK) {
		/* Validate */
		ret = find_session_name(name);
		if (ret < 0) {
			/* Session not found by name */
			printf("session not found after creation\n");
			return -1;
		} else {
			/* Success */
			return 0;
		}
	} else {
		if (ret == LTTCOMM_EXIST_SESS) {
			printf("(session already exists) ");
		}
		return -1;
	}

	return 0;
}

/*
 * Test deletion of 1 session
 */
static int destroy_one_session(struct ltt_session *session)
{
	int ret;

	ret = session_destroy(session);

	if (ret == LTTCOMM_OK) {
		/* Validate */
		if (session == NULL) {
			return 0;
		}
		ret = find_session_name(session->name);
		if (ret < 0) {
			/* Success, -1 means that the sesion is NOT found */
			return 0;
		} else {
			/* Fail */
			return -1;
		}
	}

	return 0;
}

static int fuzzing_create_args(void)
{
	int ret;

	ret = create_one_session(NULL, NULL);
	if (ret > 0) {
		printf("Session created with (null),(null)\n");
		return -1;
	}

	ret = create_one_session(NULL, PATH1);
	if (ret > 0) {
		printf("Session created with (null), %s)\n", PATH1);
		return -1;
	}

	ret = create_one_session(SESSION1, NULL);
	if (ret > 0) {
		printf("Session created with %s, (null)\n", SESSION1);
		return -1;
	}

	/* Session list must be 0 */
	assert(!session_list->count);

	return 0;
}

static int fuzzing_destroy_args(void)
{
	int ret;

	ret = destroy_one_session(NULL);
	if (ret > 0) {
		printf("Session destroyed with (null)\n");
		return -1;
	}

	/* Session list must be 0 */
	assert(!session_list->count);

	return 0;
}

/*
 * This test is supposed to fail at the second create call. If so, return 0 for
 * test success, else -1.
 */
static int two_session_same_name(void)
{
	int ret;

	ret = create_one_session(SESSION1, PATH1);
	if (ret < 0) {
		/* Fail */
		return -1;
	}

	ret = create_one_session(SESSION1, PATH1);
	if (ret < 0) {
		/* Success */
		return 0;
	}

	/* Fail */
	return -1;
}

int main(int argc, char **argv)
{
	int ret, i;
	char *tmp_name;
	struct ltt_session *iter, *tmp;

	srand(time(NULL));

	printf("\nTesting Sessions:\n-----------\n");

	session_list = session_get_list();
	if (session_list == NULL) {
		return -1;
	}

	printf("Create 1 session %s: ", SESSION1);
	fflush(stdout);
	ret = create_one_session(SESSION1, PATH1);
	if (ret < 0) {
		return -1;
	}
	PRINT_OK();

	printf("Validating created session %s: ", SESSION1);
	fflush(stdout);
	tmp = session_find_by_name(SESSION1);
	if (tmp == NULL) {
		return -1;
	}
	/* Basic init session values */
	assert(tmp->kernel_session == NULL);
	assert(strlen(tmp->path));
	assert(strlen(tmp->name));
	session_lock(tmp);
	session_unlock(tmp);

	PRINT_OK();

	printf("Destroy 1 session %s: ", SESSION1);
	fflush(stdout);
	ret = destroy_one_session(tmp);
	if (ret < 0) {
		return -1;
	}
	PRINT_OK();

	printf("Two session with same name: ");
	fflush(stdout);
	ret = two_session_same_name();
	if (ret < 0) {
		return -1;
	}
	PRINT_OK();

	empty_session_list();

	printf("Fuzzing create_session arguments: ");
	fflush(stdout);
	ret = fuzzing_create_args();
	if (ret < 0) {
		return -1;
	}
	PRINT_OK();

	printf("Fuzzing destroy_session argument: ");
	fflush(stdout);
	ret = fuzzing_destroy_args();
	if (ret < 0) {
		return -1;
	}
	PRINT_OK();

	printf("Creating %d sessions: ", MAX_SESSIONS);
	fflush(stdout);
	for (i = 0; i < MAX_SESSIONS; i++) {
		tmp_name = get_random_string();
		ret = create_one_session(tmp_name, PATH1);
		if (ret < 0) {
			printf("session %d (name: %s) creation failed\n", i, tmp_name);
			return -1;
		}
		free(tmp_name);
	}
	PRINT_OK();

	printf("Destroying %d sessions: ", MAX_SESSIONS);
	fflush(stdout);
	for (i = 0; i < MAX_SESSIONS; i++) {
		cds_list_for_each_entry_safe(iter, tmp, &session_list->head, list) {
			ret = destroy_one_session(iter);
			if (ret < 0) {
				printf("session %d (name: %s) creation failed\n", i, iter->name);
				return -1;
			}
		}
	}
	PRINT_OK();

	/* Session list must be 0 */
	assert(!session_list->count);

	/* Success */
	return 0;
}
