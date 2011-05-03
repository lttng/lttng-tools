/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>

#include "lttngerr.h"
#include "session.h"

/* Variables */
static unsigned int session_count;

/* Static internal function */
static void add_session_list(struct ltt_session *ls);
static void del_session_list(struct ltt_session *ls);

/* Init session's list */
static struct ltt_session_list ltt_session_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_session_list.head),
};

/*
 *  get_session_count
 *
 *  Return session_count
 */
unsigned int get_session_count(void)
{
	return session_count;
}

/*
 *  add_session_list
 *
 *  Add a ltt_session structure to the global list.
 */
static void add_session_list(struct ltt_session *ls)
{
	cds_list_add(&ls->list, &ltt_session_list.head);
	session_count++;
}

/*
 *  del_session_list
 *
 *  Delete a ltt_session structure to the global list.
 */
static void del_session_list(struct ltt_session *ls)
{
	cds_list_del(&ls->list);
	/* Sanity check */
	if (session_count != 0) {
		session_count--;
	}
}

/*
 * 	find_session_by_uuid
 *
 * 	Return a ltt_session structure ptr that matches the uuid.
 */
struct ltt_session *find_session_by_uuid(uuid_t session_id)
{
	int found = 0;
	struct ltt_session *iter;

	/* Sanity check for NULL session_id */
	if (uuid_is_null(session_id)) {
		goto end;
	}

	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		if (uuid_compare(iter->uuid, session_id) == 0) {
			found = 1;
			break;
		}
	}

end:
	if (!found) {
		iter = NULL;
	}
	return iter;
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

	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		if (strncmp(iter->name, name, strlen(name)) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) {
		iter = NULL;
	}

	return iter;
}

/*
 * 	destroy_session
 *
 *  Delete session from the global session list
 *  and free the memory.
 *
 *  Return -1 if no session is found.
 *  On success, return 1;
 */
int destroy_session(uuid_t *uuid)
{
	int found = -1;
	struct ltt_session *iter;

	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		if (uuid_compare(iter->uuid, *uuid) == 0) {
			DBG("Destroying session %s", iter->name);
			del_session_list(iter);
			free(iter);
			found = 1;
			break;
		}
	}

	return found;
}

/*
 * 	create_session
 *
 * 	Create a brand new session and add it to the
 * 	global session list.
 */
int create_session(char *name, uuid_t *session_id)
{
	struct ltt_session *new_session;

	DBG("Creating session %s", name);

	new_session = find_session_by_name(name);
	if (new_session != NULL) {
		goto error;
	}

	/* Allocate session data structure */
	new_session = malloc(sizeof(struct ltt_session));
	if (new_session == NULL) {
		perror("malloc");
		goto error_mem;
	}

	if (name != NULL) {
		if (asprintf(&new_session->name, "%s", name) < 0) {
			goto error_mem;
		}
	} else {
		/* Generate session name based on the session count */
		if (asprintf(&new_session->name, "%s%d", "lttng-", session_count) < 0) {
			goto error_mem;
		}
	}

	/* UUID generation */
	uuid_generate(new_session->uuid);
	uuid_copy(*session_id, new_session->uuid);

	/* Set consumer (identifier) to 0. This means that there is
	 * NO consumer attach to that session yet.
	 */
	new_session->ust_consumer = 0;
	new_session->kernel_consumer = 0;

	/* Init list */
	CDS_INIT_LIST_HEAD(&new_session->ust_traces);
	CDS_INIT_LIST_HEAD(&new_session->kernel_traces);

	/* Set trace list counter */
	new_session->ust_trace_count = 0;
	new_session->kern_trace_count = 0;

	/* Add new session to the global session list */
	add_session_list(new_session);

	return 0;

error:
	return -1;

error_mem:
	return -ENOMEM;
}

/*
 *  get_lttng_session
 *
 *  Iterate over the global session list and
 *  fill the lttng_session array.
 */
void get_lttng_session(struct lttng_session *lt)
{
	int i = 0;
	struct ltt_session *iter;
	struct lttng_session lsess;

	DBG("Getting all available session");

	/* Iterate over session list and append data after
	 * the control struct in the buffer.
	 */
	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		/* Copy name and uuid */
		uuid_unparse(iter->uuid, lsess.uuid);
		strncpy(lsess.name, iter->name, sizeof(lsess.name));
		lsess.name[sizeof(lsess.name) - 1] = '\0';
		memcpy(&lt[i], &lsess, sizeof(lsess));
		i++;
		/* Reset struct for next pass */
		memset(&lsess, 0, sizeof(lsess));
	}
}

