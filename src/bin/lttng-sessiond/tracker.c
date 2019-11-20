/*
 * Copyright (C) 2018 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

#include "tracker.h"
#include <common/defaults.h>
#include <common/error.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <lttng/lttng-error.h>
#include <lttng/tracker-internal.h>

#define FALLBACK_USER_BUFLEN 16384
#define FALLBACK_GROUP_BUFLEN 16384

struct lttng_tracker_list *lttng_tracker_list_create(void)
{
	struct lttng_tracker_list *t;

	t = zmalloc(sizeof(*t));
	if (!t) {
		return NULL;
	}
	t->ht = cds_lfht_new(DEFAULT_HT_SIZE, 1, 0,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!t->ht) {
		goto error;
	}
	CDS_INIT_LIST_HEAD(&t->list_head);
	t->state = LTTNG_TRACK_ALL;
	return t;

error:
	free(t);
	return NULL;
}

static int match_tracker_key(struct cds_lfht_node *node, const void *key)
{
	const struct lttng_tracker_id *tracker_key = key;
	struct lttng_tracker_list_node *tracker_node;

	tracker_node = caa_container_of(
			node, struct lttng_tracker_list_node, ht_node);

	return lttng_tracker_id_is_equal(tracker_node->id, tracker_key);
}

static unsigned long hash_tracker_key(
		const struct lttng_tracker_id *tracker_key)
{
	unsigned long key_hash = 0;
	int value;
	const char *string;
	enum lttng_tracker_id_type type;

	/* We do not care for invalid state during hash computation */
	type = lttng_tracker_id_get_type(tracker_key);
	(void) lttng_tracker_id_get_value(tracker_key, &value);
	(void) lttng_tracker_id_get_string(tracker_key, &string);

	switch (type) {
	case LTTNG_ID_ALL:
		break;
	case LTTNG_ID_VALUE:
		key_hash ^= hash_key_ulong(
				(void *) (unsigned long) value, lttng_ht_seed);
		break;
	case LTTNG_ID_STRING:
		key_hash ^= hash_key_str(string, lttng_ht_seed);
		break;
	case LTTNG_ID_UNKNOWN:
		break;
	}
	key_hash ^= hash_key_ulong(
			(void *) (unsigned long) type, lttng_ht_seed);
	return key_hash;
}

static struct lttng_tracker_id **lttng_tracker_list_lookup(
		const struct lttng_tracker_list *tracker_list,
		const struct lttng_tracker_id *key)
{
	struct lttng_tracker_list_node *list_node;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(tracker_list->ht, hash_tracker_key(key),
			match_tracker_key, key, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		return NULL;
	}
	list_node = caa_container_of(
			node, struct lttng_tracker_list_node, ht_node);
	return &list_node->id;
}

static void destroy_list_node_rcu(struct rcu_head *head)
{
	struct lttng_tracker_list_node *n = caa_container_of(
			head, struct lttng_tracker_list_node, rcu_head);

	lttng_tracker_id_destroy(n->id);
	free(n);
}

static void _lttng_tracker_list_remove(struct lttng_tracker_list *tracker_list,
		struct lttng_tracker_list_node *n)
{
	cds_list_del(&n->list_node);

	rcu_read_lock();
	cds_lfht_del(tracker_list->ht, &n->ht_node);
	rcu_read_unlock();

	call_rcu(&n->rcu_head, destroy_list_node_rcu);
}

static void lttng_tracker_list_reset(struct lttng_tracker_list *tracker_list)
{
	struct lttng_tracker_list_node *n, *t;

	cds_list_for_each_entry_safe (
			n, t, &tracker_list->list_head, list_node) {
		_lttng_tracker_list_remove(tracker_list, n);
	}
	tracker_list->state = LTTNG_TRACK_ALL;
}

/* Protected by session mutex held by caller. */
int lttng_tracker_list_add(struct lttng_tracker_list *tracker_list,
		const struct lttng_tracker_id *_id)
{
	struct lttng_tracker_id **id;
	struct lttng_tracker_list_node *n = NULL;
	int ret;

	if (lttng_tracker_id_get_type(_id) == LTTNG_ID_ALL) {
		/* Track all, so remove each individual item. */
		lttng_tracker_list_reset(tracker_list);
		ret = LTTNG_OK;
		goto error;
	}
	rcu_read_lock();
	id = lttng_tracker_list_lookup(tracker_list, _id);
	/*
	 * It is okay to release the RCU read lock here since id is only checked
	 * for != NULL and not dereferenced.
	 */
	rcu_read_unlock();
	if (id) {
		ret = LTTNG_ERR_ID_TRACKED;
		goto error;
	}
	n = zmalloc(sizeof(*n));
	if (!n) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	n->id = lttng_tracker_id_duplicate(_id);
	if (!n->id) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	cds_list_add_tail(&n->list_node, &tracker_list->list_head);
	tracker_list->state = LTTNG_TRACK_LIST;

	rcu_read_lock();
	cds_lfht_add(tracker_list->ht, hash_tracker_key(n->id), &n->ht_node);
	rcu_read_unlock();

	return LTTNG_OK;

error:
	free(n);
	return ret;
}

/*
 * Lookup and remove.
 * Protected by session mutex held by caller.
 */
int lttng_tracker_list_remove(struct lttng_tracker_list *tracker_list,
		const struct lttng_tracker_id *_id)
{
	enum lttng_error_code ret = LTTNG_OK;
	struct lttng_tracker_id **id;
	struct lttng_tracker_list_node *n;

	if (lttng_tracker_id_get_type(_id) == LTTNG_ID_ALL) {
		/* Untrack all. */
		lttng_tracker_list_reset(tracker_list);
		/* Set state to "track none". */
		tracker_list->state = LTTNG_TRACK_NONE;
		goto end;
	}

	rcu_read_lock();
	id = lttng_tracker_list_lookup(tracker_list, _id);
	if (!id) {
		ret = LTTNG_ERR_ID_NOT_TRACKED;
		goto rcu_unlock;
	}

	n = caa_container_of(id, struct lttng_tracker_list_node, id);
	_lttng_tracker_list_remove(tracker_list, n);

rcu_unlock:
	rcu_read_unlock();
end:
	return ret;
}

void lttng_tracker_list_destroy(struct lttng_tracker_list *tracker_list)
{
	if (!tracker_list) {
		return;
	}
	lttng_tracker_list_reset(tracker_list);
	cds_lfht_destroy(tracker_list->ht, NULL);
	free(tracker_list);
}

static int lttng_lookup_user(const char *username, int *result)
{
	struct passwd p, *pres;
	int ret, retval = LTTNG_OK;
	char *buf = NULL;
	ssize_t buflen;

	buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (buflen < 0) {
		buflen = FALLBACK_USER_BUFLEN;
	}
	buf = zmalloc(buflen);
	if (!buf) {
		retval = LTTNG_ERR_NOMEM;
		goto end;
	}
	for (;;) {
		ret = getpwnam_r(username, &p, buf, buflen, &pres);
		switch (ret) {
		case EINTR:
			continue;
		case ERANGE:
			buflen *= 2;
			free(buf);
			buf = zmalloc(buflen);
			if (!buf) {
				retval = LTTNG_ERR_NOMEM;
				goto end;
			}
			continue;
		default:
			goto end_loop;
		}
	}
end_loop:

	switch (ret) {
	case 0:
		if (pres == NULL) {
			retval = LTTNG_ERR_USER_NOT_FOUND;
		} else {
			*result = (int) p.pw_uid;
			DBG("Lookup of tracker UID/VUID: name '%s' maps to id %d.",
					username, *result);
			retval = LTTNG_OK;
		}
		break;
	case ENOENT:
	case ESRCH:
	case EBADF:
	case EPERM:
		retval = LTTNG_ERR_USER_NOT_FOUND;
		break;
	default:
		retval = LTTNG_ERR_NOMEM;
	}
end:
	free(buf);
	return retval;
}

static int lttng_lookup_group(const char *groupname, int *result)
{
	struct group g, *gres;
	int ret, retval = LTTNG_OK;
	char *buf = NULL;
	ssize_t buflen;

	buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (buflen < 0) {
		buflen = FALLBACK_GROUP_BUFLEN;
	}
	buf = zmalloc(buflen);
	if (!buf) {
		retval = LTTNG_ERR_NOMEM;
		goto end;
	}
	for (;;) {
		ret = getgrnam_r(groupname, &g, buf, buflen, &gres);
		switch (ret) {
		case EINTR:
			continue;
		case ERANGE:
			buflen *= 2;
			free(buf);
			buf = zmalloc(buflen);
			if (!buf) {
				retval = LTTNG_ERR_NOMEM;
				goto end;
			}
			continue;
		default:
			goto end_loop;
		}
	}
end_loop:

	switch (ret) {
	case 0:
		if (gres == NULL) {
			retval = LTTNG_ERR_GROUP_NOT_FOUND;
		} else {
			*result = (int) g.gr_gid;
			DBG("Lookup of tracker GID/GUID: name '%s' maps to id %d.",
					groupname, *result);
			retval = LTTNG_OK;
		}
		break;
	case ENOENT:
	case ESRCH:
	case EBADF:
	case EPERM:
		retval = LTTNG_ERR_GROUP_NOT_FOUND;
		break;
	default:
		retval = LTTNG_ERR_NOMEM;
	}
end:
	free(buf);
	return retval;
}

int lttng_tracker_id_lookup_string(enum lttng_tracker_type tracker_type,
		const struct lttng_tracker_id *id,
		int *result)
{
	enum lttng_tracker_id_status status;
	int value;
	const char *string;

	switch (lttng_tracker_id_get_type(id)) {
	case LTTNG_ID_ALL:
		*result = -1;
		return LTTNG_OK;
	case LTTNG_ID_VALUE:
		status = lttng_tracker_id_get_value(id, &value);
		if (status != LTTNG_TRACKER_ID_STATUS_OK) {
			return LTTNG_ERR_INVALID;
		}
		*result = id->value;
		return LTTNG_OK;
	case LTTNG_ID_STRING:
		status = lttng_tracker_id_get_string(id, &string);
		if (status != LTTNG_TRACKER_ID_STATUS_OK) {
			return LTTNG_ERR_INVALID;
		}
		switch (tracker_type) {
		case LTTNG_TRACKER_PID:
		case LTTNG_TRACKER_VPID:
			ERR("Lookup of tracker PID/VPID by name unsupported.");
			return LTTNG_ERR_INVALID;
		case LTTNG_TRACKER_UID:
		case LTTNG_TRACKER_VUID:
			DBG("Lookup of tracker UID/VUID by name.");
			return lttng_lookup_user(string, result);
		case LTTNG_TRACKER_GID:
		case LTTNG_TRACKER_VGID:
			DBG("Lookup of tracker GID/VGID by name.");
			return lttng_lookup_group(string, result);
		default:
			return LTTNG_ERR_INVALID;
		}
		break;
	default:
		return LTTNG_ERR_INVALID;
	}
}

/*
 * Protected by session mutex held by caller.
 * On success, _ids and the ids it contains must be freed by the caller.
 */
int lttng_tracker_id_get_list(const struct lttng_tracker_list *tracker_list,
		struct lttng_tracker_ids **_ids)
{
	int retval = LTTNG_OK, ret;
	struct lttng_tracker_list_node *n;
	ssize_t count = 0, i = 0;
	struct lttng_tracker_ids *ids = NULL;
	struct lttng_tracker_id *id;
	enum lttng_tracker_id_status status;

	switch (tracker_list->state) {
	case LTTNG_TRACK_LIST:
		cds_list_for_each_entry (
				n, &tracker_list->list_head, list_node) {
			count++;
		}
		ids = lttng_tracker_ids_create(count);
		if (ids == NULL) {
			PERROR("Failed to allocate tracked ID list");
			retval = -LTTNG_ERR_NOMEM;
			goto end;
		}
		cds_list_for_each_entry (
				n, &tracker_list->list_head, list_node) {
			id = lttng_tracker_ids_get_pointer_of_index(ids, i);
			if (!id) {
				retval = -LTTNG_ERR_INVALID;
				goto error;
			}

			ret = lttng_tracker_id_copy(id, n->id);
			if (ret) {
				retval = -LTTNG_ERR_NOMEM;
				goto error;
			}
			i++;
		}
		break;
	case LTTNG_TRACK_ALL:

		ids = lttng_tracker_ids_create(1);
		if (ids == NULL) {
			PERROR("Failed to allocate tracked ID list");
			retval = -LTTNG_ERR_NOMEM;
			goto end;
		}

		id = lttng_tracker_ids_get_pointer_of_index(ids, 0);
		status = lttng_tracker_id_set_all(id);
		if (status != LTTNG_TRACKER_ID_STATUS_OK) {
			ERR("Invalid tracker id for track all");
			retval = -LTTNG_ERR_INVALID;
			goto error;
		}
		break;
	case LTTNG_TRACK_NONE:
		/* No ids track, so we return 0 element collection. */
		ids = lttng_tracker_ids_create(0);
		if (ids == NULL) {
			PERROR("alloc list ids");
			retval = -LTTNG_ERR_NOMEM;
			goto end;
		}
		break;
	}
	*_ids = ids;

end:
	return retval;

error:
	lttng_tracker_ids_destroy(ids);
	return retval;
}

int lttng_tracker_id_set_list(struct lttng_tracker_list *tracker_list,
		const struct lttng_tracker_ids *ids)
{
	size_t i, count;
	const struct lttng_tracker_id *id;

	assert(tracker_list);
	assert(ids);

	lttng_tracker_list_reset(tracker_list);
	count = lttng_tracker_ids_get_count(ids);

	if (count == 0) {
		/* Set state to "track none". */
		tracker_list->state = LTTNG_TRACK_NONE;
		return LTTNG_OK;
	}

	if (count == 1) {
		id = lttng_tracker_ids_get_at_index(ids, 0);
		if (lttng_tracker_id_get_type(id) == LTTNG_ID_ALL) {
			/* Track all. */
			return LTTNG_OK;
		}
	}

	for (i = 0; i < count; i++) {
		int ret;
		id = lttng_tracker_ids_get_at_index(ids, i);
		ret = lttng_tracker_list_add(tracker_list, id);
		if (ret != LTTNG_OK) {
			return ret;
		}
	}
	return LTTNG_OK;
}
