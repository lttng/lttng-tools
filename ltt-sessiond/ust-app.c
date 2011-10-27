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

#include "hashtable.h"
#include "ust-app.h"
#include "../hashtable/hash.h"

/*
 * Delete a traceable application structure from the global list.
 */
static void delete_ust_app(struct ust_app *lta)
{
	int ret;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	rcu_read_lock();

	hashtable_get_first(lta->channels, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		ret = hashtable_del(lta->channels, &iter);
		if (!ret) {
			trace_ust_destroy_channel(
					caa_container_of(node, struct ltt_ust_channel, node));
		}
		hashtable_get_next(lta->channels, &iter);
	}

	free(lta->channels);
	close(lta->key.sock);

	/* Remove from apps hash table */
	node = hashtable_lookup(ust_app_ht,
			(void *) ((unsigned long) lta->key.pid), sizeof(void *), &iter);
	if (node == NULL) {
		ERR("UST app pid %d not found in hash table", lta->key.pid);
	} else {
		ret = hashtable_del(ust_app_ht, &iter);
		if (ret) {
			ERR("UST app unable to delete app %d from hash table",
					lta->key.pid);
		} else {
			DBG2("UST app pid %d deleted", lta->key.pid);
		}
	}

	/* Remove from key hash table */
	node = hashtable_lookup(ust_app_sock_key_map,
			(void *) ((unsigned long) lta->key.sock), sizeof(void *), &iter);
	if (node == NULL) {
		ERR("UST app key %d not found in key hash table", lta->key.sock);
	} else {
		ret = hashtable_del(ust_app_sock_key_map, &iter);
		if (ret) {
			ERR("UST app unable to delete app sock %d from key hash table",
					lta->key.sock);
		} else {
			DBG2("UST app pair sock %d key %d deleted",
					lta->key.sock, lta->key.pid);
		}
	}

	free(lta);

	rcu_read_unlock();
}

/*
 * URCU intermediate call to delete an UST app.
 */
static void delete_ust_app_rcu(struct rcu_head *head)
{
	struct cds_lfht_node *node =
		caa_container_of(head, struct cds_lfht_node, head);
	struct ust_app *app =
		caa_container_of(node, struct ust_app, node);

	delete_ust_app(app);
}

/*
 * Find an ust_app using the sock and return it.
 */
static struct ust_app *find_app_by_sock(int sock)
{
	struct cds_lfht_node *node;
	struct ust_app_key *key;
	struct cds_lfht_iter iter;
	//struct ust_app *app;

	rcu_read_lock();

	node = hashtable_lookup(ust_app_sock_key_map,
			(void *)((unsigned long) sock), sizeof(void *), &iter);
	if (node == NULL) {
		DBG2("UST app find by sock %d key not found", sock);
		rcu_read_unlock();
		goto error;
	}

	key = caa_container_of(node, struct ust_app_key, node);

	node = hashtable_lookup(ust_app_ht,
			(void *)((unsigned long) key->pid), sizeof(void *), &iter);
	if (node == NULL) {
		DBG2("UST app find by sock %d not found", sock);
		rcu_read_unlock();
		goto error;
	}
	rcu_read_unlock();

	return caa_container_of(node, struct ust_app, node);

error:
	return NULL;
}

/*
 * Return pointer to traceable apps list.
 */
struct cds_lfht *ust_app_get_ht(void)
{
	return ust_app_ht;
}

/*
 * Return ust app pointer or NULL if not found.
 */
struct ust_app *ust_app_find_by_pid(pid_t pid)
{
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	rcu_read_lock();
	node = hashtable_lookup(ust_app_ht,
			(void *)((unsigned long) pid), sizeof(void *), &iter);
	if (node == NULL) {
		rcu_read_unlock();
		DBG2("UST app no found with pid %d", pid);
		goto error;
	}
	rcu_read_unlock();

	DBG2("Found UST app by pid %d", pid);

	return caa_container_of(node, struct ust_app, node);

error:
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
	lta->key.pid = msg->pid;
	lta->ppid = msg->ppid;
	lta->v_major = msg->major;
	lta->v_minor = msg->minor;
	lta->key.sock = sock;
	strncpy(lta->name, msg->name, sizeof(lta->name));
	lta->name[16] = '\0';
	hashtable_node_init(&lta->node, (void *)((unsigned long)lta->key.pid),
			sizeof(void *));
	lta->channels = hashtable_new_str(0);

	/* Set sock key map */
	hashtable_node_init(&lta->key.node, (void *)((unsigned long)lta->key.sock),
			sizeof(void *));

	rcu_read_lock();
	hashtable_add_unique(ust_app_ht, &lta->node);
	hashtable_add_unique(ust_app_sock_key_map, &lta->key.node);
	rcu_read_unlock();

	DBG("App registered with pid:%d ppid:%d uid:%d gid:%d sock:%d name:%s"
			" (version %d.%d)", lta->key.pid, lta->ppid, lta->uid, lta->gid,
			lta->key.sock, lta->name, lta->v_major, lta->v_minor);

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

	DBG2("UST app unregistering sock %d", sock);

	lta = find_app_by_sock(sock);
	if (lta) {
		DBG("PID %d unregistering with sock %d", lta->key.pid, sock);
		/* FIXME: Better use a call_rcu here ? */
		delete_ust_app(lta);
	}
}

/*
 * Return traceable_app_count
 */
unsigned long ust_app_list_count(void)
{
	unsigned long count;

	rcu_read_lock();
	count = hashtable_get_count(ust_app_ht);
	rcu_read_unlock();

	return count;
}

/*
 * Free and clean all traceable apps of the global list.
 */
void ust_app_clean_list(void)
{
	int ret;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	DBG2("UST app clean hash table");

	rcu_read_lock();

	hashtable_get_first(ust_app_ht, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		ret = hashtable_del(ust_app_ht, &iter);
		if (!ret) {
			call_rcu(&node->head, delete_ust_app_rcu);
		}
		hashtable_get_next(ust_app_ht, &iter);
	}

	rcu_read_unlock();
}

/*
 * Init UST app hash table.
 */
void ust_app_ht_alloc(void)
{
	ust_app_ht = hashtable_new(0);
	ust_app_sock_key_map = hashtable_new(0);
}
