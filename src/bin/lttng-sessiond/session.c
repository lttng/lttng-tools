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

#define _LGPL_SOURCE
#include <limits.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <urcu.h>
#include <dirent.h>
#include <sys/types.h>

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "session.h"
#include "utils.h"

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

/* These characters are forbidden in a session name. Used by validate_name. */
static const char *forbidden_name_chars = "/";

/* Global hash table to keep the sessions, indexed by id. */
static struct lttng_ht *ltt_sessions_ht_by_id = NULL;

/*
 * Validate the session name for forbidden characters.
 *
 * Return 0 on success else -1 meaning a forbidden char. has been found.
 */
static int validate_name(const char *name)
{
	int ret;
	char *tok, *tmp_name;

	assert(name);

	tmp_name = strdup(name);
	if (!tmp_name) {
		/* ENOMEM here. */
		ret = -1;
		goto error;
	}

	tok = strpbrk(tmp_name, forbidden_name_chars);
	if (tok) {
		DBG("Session name %s contains a forbidden character", name);
		/* Forbidden character has been found. */
		ret = -1;
		goto error;
	}
	ret = 0;

error:
	free(tmp_name);
	return ret;
}

/*
 * Add a ltt_session structure to the global list.
 *
 * The caller MUST acquire the session list lock before.
 * Returns the unique identifier for the session.
 */
static uint64_t add_session_list(struct ltt_session *ls)
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
 * Allocate the ltt_sessions_ht_by_id HT.
 *
 * The session list lock must be held.
 */
int ltt_sessions_ht_alloc(void)
{
	int ret = 0;

	DBG("Allocating ltt_sessions_ht_by_id");
	ltt_sessions_ht_by_id = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!ltt_sessions_ht_by_id) {
		ret = -1;
		ERR("Failed to allocate ltt_sessions_ht_by_id");
		goto end;
	}
end:
	return ret;
}

/*
 * Destroy the ltt_sessions_ht_by_id HT.
 *
 * The session list lock must be held.
 */
static void ltt_sessions_ht_destroy(void)
{
	if (!ltt_sessions_ht_by_id) {
		return;
	}
	ht_cleanup_push(ltt_sessions_ht_by_id);
	ltt_sessions_ht_by_id = NULL;
}

/*
 * Add a ltt_session to the ltt_sessions_ht_by_id.
 * If unallocated, the ltt_sessions_ht_by_id HT is allocated.
 * The session list lock must be held.
 */
static void add_session_ht(struct ltt_session *ls)
{
	int ret;

	assert(ls);

	if (!ltt_sessions_ht_by_id) {
		ret = ltt_sessions_ht_alloc();
		if (ret) {
			ERR("Error allocating the sessions HT");
			goto end;
		}
	}
	lttng_ht_node_init_u64(&ls->node, ls->id);
	lttng_ht_add_unique_u64(ltt_sessions_ht_by_id, &ls->node);

end:
	return;
}

/*
 * Test if ltt_sessions_ht_by_id is empty.
 * Return 1 if empty, 0 if not empty.
 * The session list lock must be held.
 */
static int ltt_sessions_ht_empty(void)
{
	int ret;

	if (!ltt_sessions_ht_by_id) {
		ret = 1;
		goto end;
	}

	ret = lttng_ht_get_count(ltt_sessions_ht_by_id) ? 0 : 1;
end:
	return ret;
}

/*
 * Remove a ltt_session from the ltt_sessions_ht_by_id.
 * If empty, the ltt_sessions_ht_by_id HT is freed.
 * The session list lock must be held.
 */
static void del_session_ht(struct ltt_session *ls)
{
	struct lttng_ht_iter iter;
	int ret;

	assert(ls);
	assert(ltt_sessions_ht_by_id);

	iter.iter.node = &ls->node.node;
	ret = lttng_ht_del(ltt_sessions_ht_by_id, &iter);
	assert(!ret);

	if (ltt_sessions_ht_empty()) {
		DBG("Empty ltt_sessions_ht_by_id, destroying it");
		ltt_sessions_ht_destroy();
	}
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
 * NULL is returned. This must be called with the session list lock held using
 * session_lock_list and session_unlock_list.
 */
struct ltt_session *session_find_by_name(const char *name)
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
 * Return an ltt_session that matches the id. If no session is found,
 * NULL is returned. This must be called with rcu_read_lock and
 * session list lock held (to guarantee the lifetime of the session).
 */
struct ltt_session *session_find_by_id(uint64_t id)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct ltt_session *ls;

	if (!ltt_sessions_ht_by_id) {
		goto end;
	}

	lttng_ht_lookup(ltt_sessions_ht_by_id, &id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node == NULL) {
		goto end;
	}
	ls = caa_container_of(node, struct ltt_session, node);

	DBG3("Session %" PRIu64 " found by id.", id);
	return ls;

end:
	DBG3("Session %" PRIu64 " NOT found by id", id);
	return NULL;
}

/*
 * Delete session from the session list and free the memory.
 *
 * Return -1 if no session is found.  On success, return 1;
 * Should *NOT* be called with RCU read-side lock held.
 */
int session_destroy(struct ltt_session *session)
{
	/* Safety check */
	assert(session);

	DBG("Destroying session %s", session->name);
	del_session_list(session);
	pthread_mutex_destroy(&session->lock);
	del_session_ht(session);

	consumer_output_put(session->consumer);
	snapshot_destroy(&session->snapshot);
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

	ret = validate_name(name);
	if (ret < 0) {
		ret = LTTNG_ERR_SESSION_INVALID_CHAR;
		goto error;
	}

	ret = gethostname(new_session->hostname, sizeof(new_session->hostname));
	if (ret < 0) {
		if (errno == ENAMETOOLONG) {
			new_session->hostname[sizeof(new_session->hostname) - 1] = '\0';
		} else {
			ret = LTTNG_ERR_FATAL;
			goto error;
		}
	}

	/* Init kernel session */
	new_session->kernel_session = NULL;
	new_session->ust_session = NULL;

	/* Init lock */
	pthread_mutex_init(&new_session->lock, NULL);

	new_session->uid = uid;
	new_session->gid = gid;

	ret = snapshot_init(&new_session->snapshot);
	if (ret < 0) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	/* Add new session to the session list */
	session_lock_list();
	new_session->id = add_session_list(new_session);
	/*
	 * Add the new session to the ltt_sessions_ht_by_id.
	 * No ownership is taken by the hash table; it is merely
	 * a wrapper around the session list used for faster access
	 * by session id.
	 */
	add_session_ht(new_session);
	session_unlock_list();

	/*
	 * Consumer is let to NULL since the create_session_uri command will set it
	 * up and, if valid, assign it to the session.
	 */
	DBG("Tracing session %s created with ID %" PRIu64 " by UID %d GID %d",
			name, new_session->id, new_session->uid, new_session->gid);

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
