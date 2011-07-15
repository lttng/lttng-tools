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
#include <time.h>
#include <urcu/list.h>

#include "lttngerr.h"
#include "session.h"

/* Variables */
static unsigned int session_count;

/* Static internal function */
static void add_session_list(struct ltt_session *ls);
static void del_session_list(struct ltt_session *ls);

/* Init global session list */
struct ltt_session_list ltt_session_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_session_list.head),
};

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
int destroy_session(char *name)
{
	int found = -1;
	struct ltt_session *iter;

	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		if (strcmp(iter->name, name) == 0) {
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
 * 	Create a brand new session and add it to the global session list.
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

	/*
	 * Set consumer (identifier) to 0. This means that there is
	 * NO consumer attach to that session yet.
	 */
	new_session->ust_consumer = 0;

	/* Init kernel session */
	new_session->kernel_session = NULL;

	/* Init list */
	CDS_INIT_LIST_HEAD(&new_session->ust_traces);

	/* Set trace list counter */
	new_session->ust_trace_count = 0;

	/* Add new session to the global session list */
	add_session_list(new_session);

	DBG("Tracing session %s created in %s", name, new_session->path);

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

/*
 *  get_lttng_session
 *
 *  Iterate over the global session list and fill the lttng_session array.
 */
void get_lttng_session(struct lttng_session *sessions)
{
	int i = 0;
	struct ltt_session *iter;
	struct lttng_session lsess;

	DBG("Getting all available session");

	/* Iterate over session list and append data after
	 * the control struct in the buffer.
	 */
	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		strncpy(lsess.path, iter->path, sizeof(lsess.path));
		lsess.path[sizeof(lsess.path) - 1] = '\0';
		strncpy(lsess.name, iter->name, sizeof(lsess.name));
		lsess.name[sizeof(lsess.name) - 1] = '\0';
		memcpy(&sessions[i], &lsess, sizeof(lsess));
		i++;
		/* Reset struct for next pass */
		memset(&lsess, 0, sizeof(lsess));
	}
}

