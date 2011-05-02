/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <urcu/list.h>

#include "lttngerr.h"
#include "traceable-app.h"

/* Number of element for the list below. */
static unsigned int traceable_app_count;

/* Init ust traceabl application's list */
struct ltt_traceable_app_list ltt_traceable_app_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_traceable_app_list.head),
};

/* List mutex */
pthread_mutex_t ltt_traceable_app_list_mutex;

/* Internal function */
static void add_traceable_app(struct ltt_traceable_app *lta);
static void del_traceable_app(struct ltt_traceable_app *lta);

/*
 *  add_traceable_app
 *
 *  Add a traceable application structure to the global
 *  list protected by a mutex.
 */
static void add_traceable_app(struct ltt_traceable_app *lta)
{
	pthread_mutex_lock(&ltt_traceable_app_list_mutex);
	cds_list_add(&lta->list, &ltt_traceable_app_list.head);
	traceable_app_count++;
	pthread_mutex_unlock(&ltt_traceable_app_list_mutex);
}

/*
 *  del_traceable_app
 *
 *  Delete a traceable application structure from the
 *  global list protected by a mutex.
 */
static void del_traceable_app(struct ltt_traceable_app *lta)
{
	pthread_mutex_lock(&ltt_traceable_app_list_mutex);
	cds_list_del(&lta->list);
	/* Sanity check */
	if (traceable_app_count != 0) {
		traceable_app_count--;
	}
	pthread_mutex_unlock(&ltt_traceable_app_list_mutex);
}

/*
 *  register_traceable_app
 *
 *  Using pid and uid (of the app), allocate
 *  a new ltt_traceable_app struct and add it
 *  to the global traceable app list.
 *
 *  On success, return 0, else return malloc ENOMEM.
 */
int register_traceable_app(pid_t pid, uid_t uid)
{
	struct ltt_traceable_app *lta;

	lta = malloc(sizeof(struct ltt_traceable_app));
	if (lta == NULL) {
		perror("malloc");
		return -ENOMEM;
	}

	lta->uid = uid;
	lta->pid = pid;
	add_traceable_app(lta);
	DBG("Application %d registered with UID %d", pid, uid);

	return 0;
}

/*
 *  unregister_traceable_app
 *
 *  Unregister app by removing it from the global
 *  traceable app list and freeing the data struct.
 */
void unregister_traceable_app(pid_t pid)
{
	struct ltt_traceable_app *lta;

	lta = find_app_by_pid(pid);
	if (lta != NULL) {
		del_traceable_app(lta);
		free(lta);
		DBG("PID %d unregistered", pid);
	}
}

/*
 *  get_app_count
 *
 *  Return traceable_app_count
 */
unsigned int get_app_count(void)
{
	return traceable_app_count;
}

/*
 *  find_app_by_pid
 *
 *  Iterate over the traceable apps list and
 *  return a pointer or NULL if not found.
 */
struct ltt_traceable_app *find_app_by_pid(pid_t pid)
{
	struct ltt_traceable_app *iter;

	pthread_mutex_lock(&ltt_traceable_app_list_mutex);
	cds_list_for_each_entry(iter, &ltt_traceable_app_list.head, list) {
		if (iter->pid == pid) {
			pthread_mutex_unlock(&ltt_traceable_app_list_mutex);
			/* Found */
			return iter;
		}
	}
	pthread_mutex_unlock(&ltt_traceable_app_list_mutex);

	return NULL;
}

/*
 * 	get_app_list_pids
 *
 *  List traceable user-space application and fill an
 *  array of pids.
 */
void get_app_list_pids(pid_t *pids)
{
	int i = 0;
	struct ltt_traceable_app *iter;

	/* Protected by a mutex here because the threads manage_client
	 * and manage_apps can access this list.
	 */
	pthread_mutex_lock(&ltt_traceable_app_list_mutex);
	cds_list_for_each_entry(iter, &ltt_traceable_app_list.head, list) {
		pids[i] = iter->pid;
		i++;
	}
	pthread_mutex_unlock(&ltt_traceable_app_list_mutex);
}
