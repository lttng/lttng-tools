/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lttngerr.h>

#include "traceable-app.h"

/* Init ust traceabl application's list */
static struct ltt_traceable_app_list ltt_traceable_app_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_traceable_app_list.head),
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.count = 0,
};

/*
 * Add a traceable application structure to the global list.
 */
static void add_traceable_app(struct ltt_traceable_app *lta)
{
	cds_list_add(&lta->list, &ltt_traceable_app_list.head);
	ltt_traceable_app_list.count++;
}

/*
 * Delete a traceable application structure from the global list.
 */
static void del_traceable_app(struct ltt_traceable_app *lta)
{
	cds_list_del(&lta->list);
	/* Sanity check */
	if (ltt_traceable_app_list.count > 0) {
		ltt_traceable_app_list.count--;
	}
}

/*
 * Return pointer to traceable apps list.
 */
struct ltt_traceable_app_list *get_traceable_apps_list(void)
{
	return &ltt_traceable_app_list;
}

/*
 * Acquire traceable apps list lock.
 */
void lock_apps_list(void)
{
	pthread_mutex_lock(&ltt_traceable_app_list.lock);
}

/*
 * Release traceable apps list lock.
 */
void unlock_apps_list(void)
{
	pthread_mutex_unlock(&ltt_traceable_app_list.lock);
}

/*
 * Iterate over the traceable apps list and return a pointer or NULL if not
 * found.
 */
static struct ltt_traceable_app *find_app_by_sock(int sock)
{
	struct ltt_traceable_app *iter;

	cds_list_for_each_entry(iter, &ltt_traceable_app_list.head, list) {
		if (iter->sock == sock) {
			/* Found */
			return iter;
		}
	}

	return NULL;
}

/*
 * Iterate over the traceable apps list and return a pointer or NULL if not
 * found.
 */
struct ltt_traceable_app *traceable_app_get_by_pid(pid_t pid)
{
	struct ltt_traceable_app *iter;

	cds_list_for_each_entry(iter, &ltt_traceable_app_list.head, list) {
		if (iter->pid == pid) {
			/* Found */
			return iter;
		}
	}

	return NULL;
}

/*
 * Using pid and uid (of the app), allocate a new ltt_traceable_app struct and
 * add it to the global traceable app list.
 *
 * On success, return 0, else return malloc ENOMEM.
 */
int register_traceable_app(struct ust_register_msg *msg, int sock)
{
	struct ltt_traceable_app *lta;

	lta = malloc(sizeof(struct ltt_traceable_app));
	if (lta == NULL) {
		perror("malloc");
		return -ENOMEM;
	}

	lta->uid = msg->uid;
	lta->gid = msg->gid;
	lta->pid = msg->pid;
	lta->ppid = msg->ppid;
	lta->v_major = msg->major;
	lta->v_minor = msg->minor;
	lta->sock = sock;
	strncpy(lta->name, msg->name, sizeof(lta->name));
	lta->name[16] = '\0';

	lock_apps_list();
	add_traceable_app(lta);
	unlock_apps_list();

	DBG("App registered with pid:%d ppid:%d uid:%d gid:%d sock:%d name:%s"
			" (version %d.%d)", lta->pid, lta->ppid, lta->uid, lta->gid,
			lta->sock, lta->name, lta->v_major, lta->v_minor);

	return 0;
}

/*
 * Unregister app by removing it from the global traceable app list and freeing
 * the data struct.
 *
 * The socket is already closed at this point so no close to sock.
 */
void unregister_traceable_app(int sock)
{
	struct ltt_traceable_app *lta;

	lock_apps_list();
	lta = find_app_by_sock(sock);
	if (lta) {
		DBG("PID %d unregistered with sock %d", lta->pid, sock);
		close(lta->sock);
		del_traceable_app(lta);
		free(lta);
	}
	unlock_apps_list();
}

/*
 * Return traceable_app_count
 */
unsigned int get_app_count(void)
{
	unsigned int count;

	lock_apps_list();
	count = ltt_traceable_app_list.count;
	unlock_apps_list();

	return count;
}

/*
 * Free and clean all traceable apps of the global list.
 */
void clean_traceable_apps_list(void)
{
	struct ltt_traceable_app *iter, *tmp;

	/*
	 * Don't acquire list lock here. This function should be called from
	 * cleanup() functions meaning that the program will exit.
	 */
	cds_list_for_each_entry_safe(iter, tmp, &ltt_traceable_app_list.head, list) {
		close(iter->sock);
		free(iter);
	}
}
