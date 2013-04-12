/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <urcu.h>

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "session.h"

/*
 * NOTES:
 *
 * No ltt_session.lock is taken here because those data structure are widely
 * spread across the lttng-tools code base so before caling functions below
 * that can read/write a session, the caller MUST acquire the session lock
 * using session_lock() and session_unlock().
 */

/*
 * Init tracing session list.
 *
 * Please see session.h for more explanation and correct usage of the list.
 */
static struct ltt_session_list ltt_session_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_session_list.head),
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.next_uuid = 0,
};

/*
 * Add a ltt_session structure to the global list.
 *
 * The caller MUST acquire the session list lock before.
 * Returns the unique identifier for the session.
 */
static unsigned int add_session_list(struct ltt_session *ls)
{
	assert(ls);

	cds_list_add(&ls->list, &ltt_session_list.head);
	return ltt_session_list.next_uuid++;
}

/*
 * Delete a ltt_session structure to the global list.
 *
 * The caller MUST acquire the session list lock before.
 */
static void del_session_list(struct ltt_session *ls)
{
	assert(ls);

	cds_list_del(&ls->list);
}

/*
 * Return a pointer to the session list.
 */
struct ltt_session_list *session_get_list(void)
{
	return &ltt_session_list;
}

/*
 * Acquire session list lock
 */
void session_lock_list(void)
{
	pthread_mutex_lock(&ltt_session_list.lock);
}

/*
 * Release session list lock
 */
void session_unlock_list(void)
{
	pthread_mutex_unlock(&ltt_session_list.lock);
}

/*
 * Acquire session lock
 */
void session_lock(struct ltt_session *session)
{
	assert(session);

	pthread_mutex_lock(&session->lock);
}

/*
 * Release session lock
 */
void session_unlock(struct ltt_session *session)
{
	assert(session);

	pthread_mutex_unlock(&session->lock);
}

/*
 * Return a ltt_session structure ptr that matches name. If no session found,
 * NULL is returned. This must be called with the session lock held using
 * session_lock_list and session_unlock_list.
 */
struct ltt_session *session_find_by_name(char *name)
{
	struct ltt_session *iter;

	assert(name);

	DBG2("Trying to find session by name %s", name);

	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		if (strncmp(iter->name, name, NAME_MAX) == 0) {
			goto found;
		}
	}

	iter = NULL;

found:
	return iter;
}

/*
 * Delete session from the session list and free the memory.
 *
 * Return -1 if no session is found.  On success, return 1;
 */
int session_destroy(struct ltt_session *session)
{
	/* Safety check */
	assert(session);

	DBG("Destroying session %s", session->name);
	del_session_list(session);
	pthread_mutex_destroy(&session->lock);

	rcu_read_lock();
	consumer_destroy_output(session->consumer);
	rcu_read_unlock();
	free(session);

	return LTTNG_OK;
}

/*
 * Create a brand new session and add it to the session list.
 */
int session_create(char *name, uid_t uid, gid_t gid)
{
	int ret;
	struct ltt_session *new_session;

	/* Allocate session data structure */
	new_session = zmalloc(sizeof(struct ltt_session));
	if (new_session == NULL) {
		PERROR("zmalloc");
		ret = LTTNG_ERR_FATAL;
		goto error_malloc;
	}

	/* Define session name */
	if (name != NULL) {
		if (snprintf(new_session->name, NAME_MAX, "%s", name) < 0) {
			ret = LTTNG_ERR_FATAL;
			goto error_asprintf;
		}
	} else {
		ERR("No session name given");
		ret = LTTNG_ERR_FATAL;
		goto error;
	}

	/* Init kernel session */
	new_session->kernel_session = NULL;
	new_session->ust_session = NULL;

	/* Init lock */
	pthread_mutex_init(&new_session->lock, NULL);

	new_session->uid = uid;
	new_session->gid = gid;

	/* Add new session to the session list */
	session_lock_list();
	new_session->id = add_session_list(new_session);
	session_unlock_list();

	/*
	 * Consumer is let to NULL since the create_session_uri command will set it
	 * up and, if valid, assign it to the session.
	 */

	DBG("Tracing session %s created with ID %u by UID %d GID %d", name,
			new_session->id, new_session->uid, new_session->gid);

	return LTTNG_OK;

error:
error_asprintf:
	free(new_session);

error_malloc:
	return ret;
}

/*
 * Check if the UID or GID match the session. Root user has access to all
 * sessions.
 */
int session_access_ok(struct ltt_session *session, uid_t uid, gid_t gid)
{
	assert(session);

	if (uid != session->uid && gid != session->gid && uid != 0) {
		return 0;
	} else {
		return 1;
	}
}
