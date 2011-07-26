/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <urcu/list.h>

#include "lttngerr.h"
#include "session.h"

/*
 * NOTES:
 *
 * No ltt_session.lock is taken here because those data structure are widely
 * spread across the lttng-tools code base so before caling functions below
 * that can read/write a session, the caller MUST acquire the session lock
 * using lock_session() and unlock_session().
 */

/*
 * Init tracing session list.
 *
 * Please see session.h for more explanation and correct usage of the list.
 */
static struct ltt_session_list ltt_session_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_session_list.head),
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.count = 0,
};

/*
 *  add_session_list
 *
 *  Add a ltt_session structure to the global list.
 *
 *  The caller MUST acquire the session list lock before.
 */
static void add_session_list(struct ltt_session *ls)
{
	cds_list_add(&ls->list, &ltt_session_list.head);
	ltt_session_list.count++;
}

/*
 *  del_session_list
 *
 *  Delete a ltt_session structure to the global list.
 *
 *  The caller MUST acquire the session list lock before.
 */
static void del_session_list(struct ltt_session *ls)
{
	cds_list_del(&ls->list);
	/* Sanity check */
	if (ltt_session_list.count > 0) {
		ltt_session_list.count--;
	}
}

/*
 *  get_session_list
 *
 *  Return a pointer to the session list.
 */
struct ltt_session_list *get_session_list(void)
{
	return &ltt_session_list;
}

/*
 * Acquire session list lock
 */
void lock_session_list(void)
{
	pthread_mutex_lock(&ltt_session_list.lock);
}

/*
 * Release session list lock
 */
void unlock_session_list(void)
{
	pthread_mutex_unlock(&ltt_session_list.lock);
}

/*
 * Acquire session lock
 */
void lock_session(struct ltt_session *session)
{
	pthread_mutex_lock(&session->lock);
}

/*
 * Release session lock
 */
void unlock_session(struct ltt_session *session)
{
	pthread_mutex_unlock(&session->lock);
}

/*
 * 	find_session_by_name
 *
 * 	Return a ltt_session structure ptr that matches name.
 * 	If no session found, NULL is returned.
 */
struct ltt_session *find_session_by_name(char *name)
{
	int found = 0;
	struct ltt_session *iter;

	lock_session_list();
	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		if (strncmp(iter->name, name, strlen(name)) == 0) {
			found = 1;
			break;
		}
	}
	unlock_session_list();

	if (!found) {
		iter = NULL;
	}

	return iter;
}

/*
 * 	destroy_session
 *
 *  Delete session from the session list and free the memory.
 *
 *  Return -1 if no session is found.  On success, return 1;
 */
int destroy_session(char *name)
{
	int found = -1;
	struct ltt_session *iter, *tmp;

	lock_session_list();
	cds_list_for_each_entry_safe(iter, tmp, &ltt_session_list.head, list) {
		if (strcmp(iter->name, name) == 0) {
			DBG("Destroying session %s", iter->name);
			del_session_list(iter);
			free(iter->name);
			free(iter->path);
			pthread_mutex_destroy(&iter->lock);
			free(iter);
			found = 1;
			break;
		}
	}
	unlock_session_list();

	return found;
}

/*
 * 	create_session
 *
 * 	Create a brand new session and add it to the session list.
 */
int create_session(char *name, char *path)
{
	int ret;
	char date_time[NAME_MAX];
	struct ltt_session *new_session;
	time_t rawtime;
	struct tm *timeinfo;

	new_session = find_session_by_name(name);
	if (new_session != NULL) {
		ret = -EEXIST;
		goto error_exist;
	}

	/* Allocate session data structure */
	new_session = malloc(sizeof(struct ltt_session));
	if (new_session == NULL) {
		perror("malloc");
		ret = -ENOMEM;
		goto error_malloc;
	}

	/* Define session name */
	if (name != NULL) {
		if (asprintf(&new_session->name, "%s", name) < 0) {
			ret = -ENOMEM;
			goto error_asprintf;
		}
	} else {
		ERR("No session name given");
		ret = -1;
		goto error;
	}

	/* Define session system path */
	if (path != NULL) {
		if (strstr(name, "auto-") == NULL) {
			time(&rawtime);
			timeinfo = localtime(&rawtime);
			strftime(date_time, sizeof(date_time), "-%Y%m%d-%H%M%S", timeinfo);
		} else {
			date_time[0] = '\0';
		}

		if (asprintf(&new_session->path, "%s/%s%s", path, name, date_time) < 0) {
			ret = -ENOMEM;
			goto error_asprintf;
		}
	} else {
		ERR("No session path given");
		ret = -1;
		goto error;
	}

	/* Init kernel session */
	new_session->kernel_session = NULL;

	/* Init list */
	CDS_INIT_LIST_HEAD(&new_session->ust_traces);

	/* Set trace list counter */
	new_session->ust_trace_count = 0;

	/* Add new session to the session list */
	lock_session_list();
	add_session_list(new_session);
	unlock_session_list();

	/* Init lock */
	pthread_mutex_init(&new_session->lock, NULL);

	DBG("Tracing session %s created in %s", new_session->name, new_session->path);

	return 0;

error:
error_asprintf:
	if (new_session != NULL) {
		free(new_session);
	}

error_exist:
error_malloc:
	return ret;
}
