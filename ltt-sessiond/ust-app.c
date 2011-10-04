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

#include "ust-app.h"

#include "benchmark.h"

/* Init ust traceable application's list */
static struct ust_app_list ust_app_list = {
	.head = CDS_LIST_HEAD_INIT(ust_app_list.head),
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.count = 0,
};

/*
 * Add a traceable application structure to the global list.
 */
static void add_app_to_list(struct ust_app *lta)
{
	cds_list_add(&lta->list, &ust_app_list.head);
	ust_app_list.count++;
}

/*
 * Delete a traceable application structure from the global list.
 */
static void del_app_from_list(struct ust_app *lta)
{
	struct ltt_ust_channel *chan;

	cds_list_del(&lta->list);
	/* Sanity check */
	if (ust_app_list.count > 0) {
		ust_app_list.count--;
	}

	cds_list_for_each_entry(chan, &lta->channels.head, list) {
		trace_ust_destroy_channel(chan);
	}
}

/*
 * Iterate over the traceable apps list and return a pointer or NULL if not
 * found.
 */
static struct ust_app *find_app_by_sock(int sock)
{
	struct ust_app *iter;

	cds_list_for_each_entry(iter, &ust_app_list.head, list) {
		if (iter->sock == sock) {
			/* Found */
			return iter;
		}
	}

	return NULL;
}

/*
 * Return pointer to traceable apps list.
 */
struct ust_app_list *ust_app_get_list(void)
{
	return &ust_app_list;
}

/*
 * Acquire traceable apps list lock.
 */
void ust_app_lock_list(void)
{
	pthread_mutex_lock(&ust_app_list.lock);
}

/*
 * Release traceable apps list lock.
 */
void ust_app_unlock_list(void)
{
	pthread_mutex_unlock(&ust_app_list.lock);
}

/*
 * Iterate over the traceable apps list and return a pointer or NULL if not
 * found.
 */
struct ust_app *ust_app_get_by_pid(pid_t pid)
{
	struct ust_app *iter;

	cds_list_for_each_entry(iter, &ust_app_list.head, list) {
		if (iter->pid == pid) {
			/* Found */
			DBG2("Found traceable app by pid %d", pid);
			return iter;
		}
	}

	DBG2("Traceable app with pid %d not found", pid);

	return NULL;
}

/*
 * Using pid and uid (of the app), allocate a new ust_app struct and
 * add it to the global traceable app list.
 *
 * On success, return 0, else return malloc ENOMEM.
 */
int ust_app_register(struct ust_register_msg *msg, int sock)
{
	struct ust_app *lta;

	lta = malloc(sizeof(struct ust_app));
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
	CDS_INIT_LIST_HEAD(&lta->channels.head);

	ust_app_lock_list();
	add_app_to_list(lta);
	ust_app_unlock_list();

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
void ust_app_unregister(int sock)
{
	struct ust_app *lta;

	tracepoint(ust_unregister_start);

	ust_app_lock_list();
	lta = find_app_by_sock(sock);
	if (lta) {
		DBG("PID %d unregistered with sock %d", lta->pid, sock);
		del_app_from_list(lta);
		close(lta->sock);
		free(lta);
	}
	ust_app_unlock_list();

	tracepoint(ust_unregister_stop);
}

/*
 * Return traceable_app_count
 */
unsigned int ust_app_list_count(void)
{
	unsigned int count;

	ust_app_lock_list();
	count = ust_app_list.count;
	ust_app_unlock_list();

	return count;
}

/*
 * Free and clean all traceable apps of the global list.
 */
void ust_app_clean_list(void)
{
	struct ust_app *iter, *tmp;

	/*
	 * Don't acquire list lock here. This function should be called from
	 * cleanup() functions meaning that the program will exit.
	 */
	cds_list_for_each_entry_safe(iter, tmp, &ust_app_list.head, list) {
		del_app_from_list(iter);
		close(iter->sock);
		free(iter);
	}
}
