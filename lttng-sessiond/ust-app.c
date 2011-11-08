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
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <lttngerr.h>
#include <lttng-share.h>

#include "hashtable.h"
#include "ust-app.h"
#include "../hashtable/hash.h"
#include "ust-ctl.h"
#include "ust-consumer.h"

/*
 * Delete a traceable application structure from the global list.
 */
static void delete_ust_app(struct ust_app *lta)
{
	int ret;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	rcu_read_lock();

	/* TODO: clean session hashtable */
	free(lta->sessions);
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
 * Find an ust_app using the sock and return it. RCU read side lock must be
 * held before calling this helper function.
 */
static struct ust_app *find_app_by_sock(int sock)
{
	struct cds_lfht_node *node;
	struct ust_app_key *key;
	struct cds_lfht_iter iter;

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
		PERROR("malloc");
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

	/* Session hashtable */
	lta->sessions = hashtable_new(0);

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
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	rcu_read_lock();
	lta = find_app_by_sock(sock);
	if (lta == NULL) {
		ERR("Unregister app sock %d not found!", sock);
		goto error;
	}

	DBG("PID %d unregistering with sock %d", lta->key.pid, sock);

	/* Get the node reference for a call_rcu */
	node = hashtable_lookup(ust_app_ht,
			(void *)((unsigned long) lta->key.pid), sizeof(void *), &iter);
	if (node == NULL) {
		ERR("Unable to find app sock %d by pid %d", sock, lta->key.pid);
		goto error;
	}

	call_rcu(&node->head, delete_ust_app_rcu);

error:
	rcu_read_unlock();
	return;
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

/*
 * Alloc new UST app session.
 */
static struct ust_app_session *alloc_ust_app_session(void)
{
	struct ust_app_session *ua_sess;

	/* Init most of the default value by allocating and zeroing */
	ua_sess = zmalloc(sizeof(struct ust_app_session));
	if (ua_sess == NULL) {
		PERROR("malloc");
		goto error;
	}

	ua_sess->handle = -1;
	ua_sess->channels = hashtable_new_str(0);

	return ua_sess;

error:
	return NULL;
}

/*
 * Alloc new UST app channel.
 */
static struct ust_app_channel *alloc_ust_app_channel(char *name)
{
	struct ust_app_channel *ua_chan;

	/* Init most of the default value by allocating and zeroing */
	ua_chan = zmalloc(sizeof(struct ust_app_channel));
	if (ua_chan == NULL) {
		PERROR("malloc");
		goto error;
	}

	strncpy(ua_chan->name, name, sizeof(ua_chan->name));
	ua_chan->name[sizeof(ua_chan->name) - 1] = '\0';
	ua_chan->handle = -1;
	ua_chan->ctx = hashtable_new(0);
	CDS_INIT_LIST_HEAD(&ua_chan->streams.head);
	ua_chan->events = hashtable_new_str(0);
	hashtable_node_init(&ua_chan->node, (void *) ua_chan->name,
			strlen(ua_chan->name));

	DBG3("UST app channel %s allocated", ua_chan->name);

	return ua_chan;

error:
	return NULL;
}

/*
 * Alloc new UST app event.
 */
static struct ust_app_event *alloc_ust_app_event(char *name)
{
	struct ust_app_event *ua_event;

	/* Init most of the default value by allocating and zeroing */
	ua_event = zmalloc(sizeof(struct ust_app_event));
	if (ua_event == NULL) {
		PERROR("malloc");
		goto error;
	}

	strncpy(ua_event->name, name, sizeof(ua_event->name));
	ua_event->name[sizeof(ua_event->name) - 1] = '\0';
	ua_event->ctx = hashtable_new(0);
	hashtable_node_init(&ua_event->node, (void *) ua_event->name,
			strlen(ua_event->name));

	DBG3("UST app event %s allocated", ua_event->name);

	return ua_event;

error:
	return NULL;
}

static void shadow_copy_event(struct ust_app_event *ua_event,
		struct ltt_ust_event *uevent)
{
	strncpy(ua_event->name, uevent->attr.name, sizeof(ua_event->name));
	ua_event->name[sizeof(ua_event->name) - 1] = '\0';

	/* TODO: support copy context */
}

static void shadow_copy_channel(struct ust_app_channel *ua_chan,
		struct ltt_ust_channel *uchan)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node, *ua_event_node;
	struct ltt_ust_event *uevent;
	struct ust_app_event *ua_event;

	DBG2("Shadow copy of UST app channel %s", ua_chan->name);

	strncpy(ua_chan->name, uchan->name, sizeof(ua_chan->name));
	ua_chan->name[sizeof(ua_chan->name) - 1] = '\0';

	/* TODO: support copy context */

	/* Copy all events from ltt ust channel to ust app channel */
	hashtable_get_first(uchan->events, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		uevent = caa_container_of(node, struct ltt_ust_event, node);

		ua_event_node = hashtable_lookup(ua_chan->events,
				(void *) uevent->attr.name, strlen(uevent->attr.name), &iter);
		if (ua_event_node == NULL) {
			DBG2("UST event %s not found on shadow copy channel",
					uevent->attr.name);
			ua_event = alloc_ust_app_event(uevent->attr.name);
			if (ua_event == NULL) {
				goto next;
			}
			shadow_copy_event(ua_event, uevent);
			hashtable_add_unique(ua_chan->events, &ua_event->node);
		}

next:
		/* Get next UST events */
		hashtable_get_next(uchan->events, &iter);
	}

	DBG3("Shadow copy channel done");
}

static void shadow_copy_session(struct ust_app_session *ua_sess,
		struct ltt_ust_session *usess)
{
	struct cds_lfht_node *node, *ua_chan_node;
	struct cds_lfht_iter iter;
	struct ltt_ust_channel *uchan;
	struct ust_app_channel *ua_chan;

	DBG2("Shadow copy of session handle %d", ua_sess->handle);

	ua_sess->uid = usess->uid;

	/* TODO: support all UST domain */

	/* Iterate over all channels in global domain. */
	hashtable_get_first(usess->domain_global.channels, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		uchan = caa_container_of(node, struct ltt_ust_channel, node);

		ua_chan_node = hashtable_lookup(ua_sess->channels,
				(void *)uchan->name, strlen(uchan->name), &iter);
		if (ua_chan_node == NULL) {
			DBG2("Channel %s not found on shadow session copy, creating it",
					uchan->name);
			ua_chan = alloc_ust_app_channel(uchan->name);
			if (ua_chan == NULL) {
				/* malloc failed... continuing */
				goto next;
			}

			shadow_copy_channel(ua_chan, uchan);
			hashtable_add_unique(ua_sess->channels, &ua_chan->node);
		}

next:
		/* Next item in hash table */
		hashtable_get_next(usess->domain_global.channels, &iter);
	}
}

/*
 * Return ust app session from the app session hashtable using the UST session
 * uid.
 */
static struct ust_app_session *lookup_session_by_app(
		struct ltt_ust_session *usess, struct ust_app *app)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	/* Get right UST app session from app */
	node = hashtable_lookup(app->sessions,
			(void *) ((unsigned long) usess->uid), sizeof(void *), &iter);
	if (node == NULL) {
		goto error;
	}

	return caa_container_of(node, struct ust_app_session, node);

error:
	return NULL;
}

/*
 * Create a UST session onto the tracer of app and add it the session
 * hashtable.
 *
 * Return ust app session or NULL on error.
 */
static struct ust_app_session *create_ust_app_session(
		struct ltt_ust_session *usess, struct ust_app *app)
{
	int ret;
	struct ust_app_session *ua_sess;

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == NULL) {
		DBG2("UST app pid: %d session uid %d not found, creating it",
				app->key.pid, usess->uid);
		ua_sess = alloc_ust_app_session();
		if (ua_sess == NULL) {
			/* Only malloc can failed so something is really wrong */
			goto error;
		}
		shadow_copy_session(ua_sess, usess);
	}

	if (ua_sess->handle == -1) {
		ret = ustctl_create_session(app->key.sock);
		if (ret < 0) {
			ERR("Error creating session for app pid %d, sock %d",
					app->key.pid, app->key.sock);
			/* TODO: free() ua_sess */
			goto error;
		}

		DBG2("UST app ustctl create session handle %d", ret);
		ua_sess->handle = ret;

		/* Add ust app session to app's HT */
		hashtable_node_init(&ua_sess->node,
				(void *)((unsigned long) ua_sess->uid), sizeof(void *));
		hashtable_add_unique(app->sessions, &ua_sess->node);

		DBG2("UST app session created successfully with handle %d", ret);
	}

	return ua_sess;

error:
	return NULL;
}

static struct ust_app_channel *create_ust_app_channel(
		struct ust_app_session *ua_sess, struct ltt_ust_channel *uchan,
		struct ust_app *app)
{
	int ret = 0;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ua_chan_node;
	struct ust_app_channel *ua_chan;

	/* Lookup channel in the ust app session */
	ua_chan_node = hashtable_lookup(ua_sess->channels,
			(void *)uchan->name, strlen(uchan->name), &iter);
	if (ua_chan_node == NULL) {
		DBG2("Unable to find channel %s in ust session uid %u",
				uchan->name, ua_sess->uid);
		ua_chan = alloc_ust_app_channel(uchan->name);
		if (ua_chan == NULL) {
			goto error;
		}
		shadow_copy_channel(ua_chan, uchan);
		hashtable_add_unique(ua_sess->channels, &ua_chan->node);
	} else {
		ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);
	}

	/* TODO: remove cast and use lttng-ust-abi.h */
	ret = ustctl_create_channel(app->key.sock, ua_sess->handle,
			(struct lttng_ust_channel_attr *)&uchan->attr, &ua_chan->obj);
	if (ret < 0) {
		DBG("Error creating channel %s for app (pid: %d, sock: %d) "
				"and session handle %d with ret %d",
				ua_chan->name, app->key.pid, app->key.sock,
				ua_sess->handle, ret);
		goto error;
	}

	ua_chan->handle = ua_chan->obj->handle;
	ua_chan->attr.shm_fd = ua_chan->obj->shm_fd;
	ua_chan->attr.wait_fd = ua_chan->obj->wait_fd;
	ua_chan->attr.memory_map_size = ua_chan->obj->memory_map_size;

	DBG2("Channel %s UST create successfully for pid:%d and sock:%d",
			ua_chan->name, app->key.pid, app->key.sock);

	return ua_chan;

error:
	return NULL;
}

static struct ust_app_event *create_ust_app_event(
		struct ust_app_session *ua_sess, struct ust_app_channel *ua_chan,
		struct ltt_ust_event *uevent, struct ust_app *app)
{
	int ret;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ua_event_node;
	struct ust_app_event *ua_event;

	/* Get event node */
	ua_event_node = hashtable_lookup(ua_chan->events,
			(void *)uevent->attr.name, strlen(uevent->attr.name), &iter);
	if (ua_event_node == NULL) {
		DBG2("UST app event %s not found, creating it", uevent->attr.name);
		/* Does not exist so create one */
		ua_event = alloc_ust_app_event(uevent->attr.name);
		if (ua_event == NULL) {
			/* Only malloc can failed so something is really wrong */
			goto error;
		}
		shadow_copy_event(ua_event, uevent);

		hashtable_add_unique(ua_chan->events, &ua_event->node);
	} else {
		ua_event = caa_container_of(ua_event_node, struct ust_app_event, node);
	}

	/* Create UST event on tracer */
	ret = ustctl_create_event(app->key.sock, &uevent->attr, ua_chan->obj,
			&ua_event->obj);
	if (ret < 0) {
		ERR("Error ustctl create event %s for app pid: %d with ret %d",
				uevent->attr.name, app->key.pid, ret);
		/* TODO: free() ua_event */
		goto error;
	}
	ua_event->handle = ua_event->obj->handle;
	ua_event->enabled = 1;


	DBG2("Event %s UST create successfully for pid:%d", uevent->attr.name,
			app->key.pid);

	return ua_event;

error:
	return NULL;
}

static int create_ust_app_metadata(struct ust_app_session *ua_sess,
		char *pathname, struct ust_app *app)
{
	int ret = 0;
	struct lttng_ust_channel_attr uattr;

	if (ua_sess->metadata == NULL) {
		/* Allocate UST metadata */
		ua_sess->metadata = trace_ust_create_metadata(pathname);
		if (ua_sess->metadata == NULL) {
			ERR("UST app session %d creating metadata failed",
					ua_sess->handle);
			goto error;
		}

		uattr.overwrite = ua_sess->metadata->attr.overwrite;
		uattr.subbuf_size = ua_sess->metadata->attr.subbuf_size;
		uattr.num_subbuf = ua_sess->metadata->attr.num_subbuf;
		uattr.switch_timer_interval =
			ua_sess->metadata->attr.switch_timer_interval;
		uattr.read_timer_interval =
			ua_sess->metadata->attr.read_timer_interval;
		uattr.output = ua_sess->metadata->attr.output;

		/* UST tracer metadata creation */
		ret = ustctl_open_metadata(app->key.sock, ua_sess->handle, &uattr,
				&ua_sess->metadata->obj);
		if (ret < 0) {
			ERR("UST app open metadata failed for app pid:%d",
					app->key.pid);
			goto error;
		}

		DBG2("UST metadata opened for app pid %d", app->key.pid);
	}

	/* Open UST metadata stream */
	if (ua_sess->metadata->stream_obj == NULL) {
		ret = ustctl_create_stream(app->key.sock, ua_sess->metadata->obj,
				&ua_sess->metadata->stream_obj);
		if (ret < 0) {
			ERR("UST create metadata stream failed");
			goto error;
		}

		ret = snprintf(ua_sess->metadata->pathname, PATH_MAX, "%s/%s-%d",
				pathname, app->name, app->key.pid);
		if (ret < 0) {
			PERROR("asprintf UST create stream");
			goto error;
		}

		ret = mkdir(ua_sess->metadata->pathname, S_IRWXU | S_IRWXG);
		if (ret < 0) {
			PERROR("mkdir UST metadata");
			goto error;
		}

		ret = snprintf(ua_sess->metadata->pathname, PATH_MAX, "%s/%s-%d/metadata",
				pathname, app->name, app->key.pid);
		if (ret < 0) {
			PERROR("asprintf UST create stream");
			goto error;
		}

		DBG2("UST metadata stream object created for app pid %d",
				app->key.pid);
	}

	return 0;

error:
	return -1;
}

/*
 * Add channel to all ust app session.
 */
int ust_app_add_channel_all(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	int ret = 0;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;

	if (usess == NULL || uchan == NULL) {
		ERR("Adding UST global channel to NULL values");
		ret = -1;
		goto error;
	}

	DBG2("UST app adding channel %s to global domain for session uid %d",
			uchan->name, usess->uid);

	rcu_read_lock();

	/* For every UST applications registered */
	hashtable_get_first(ust_app_ht, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		app = caa_container_of(node, struct ust_app, node);

		/* Create session on the tracer side and add it to app session HT */
		ua_sess = create_ust_app_session(usess, app);
		if (ret < 0) {
			goto next;
		}

		/* Create channel onto application */
		ua_chan = create_ust_app_channel(ua_sess, uchan, app);
		if (ua_chan == NULL) {
			goto next;
		}

next:
		/* Next applications */
		hashtable_get_next(ust_app_ht, &iter);
	}
	rcu_read_unlock();

error:
	return ret;
}

int ust_app_add_event_all(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent)
{
	int ret = 0;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node, *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;

	DBG2("UST app adding event %s to global domain for session uid %d",
			uevent->attr.name, usess->uid);

	rcu_read_lock();

	/* For all registered applications */
	hashtable_get_first(ust_app_ht, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		app = caa_container_of(node, struct ust_app, node);

		/* Create session on the tracer side and add it to app session HT */
		ua_sess = create_ust_app_session(usess, app);
		if (ret < 0) {
			goto next;
		}

		/* Lookup channel in the ust app session */
		ua_chan_node = hashtable_lookup(ua_sess->channels,
				(void *)uchan->name, strlen(uchan->name), &iter);
		if (ua_chan_node == NULL) {
			ERR("Channel %s not found in session uid %d. Skipping",
					uchan->name, usess->uid);
			goto next;
		}
		ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);

		ua_event = create_ust_app_event(ua_sess, ua_chan, uevent, app);
		if (ua_event == NULL) {
			goto next;
		}

next:
		/* Next applications */
		hashtable_get_next(ust_app_ht, &iter);
	}
	rcu_read_unlock();

	return ret;
}

int ust_app_start_trace(struct ltt_ust_session *usess, struct ust_app *app)
{
	int ret = 0;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;

	DBG("Starting tracing for ust app pid %d", app->key.pid);

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == NULL) {
		/* Only malloc can failed so something is really wrong */
		goto error;
	}

	ret = create_ust_app_metadata(ua_sess, usess->pathname, app);
	if (ret < 0) {
		goto error;
	}

	/* For each channel */
	hashtable_get_first(ua_sess->channels, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		ua_chan = caa_container_of(node, struct ust_app_channel, node);

		/* Create all streams */
		while (1) {
			struct ltt_ust_stream *ustream;

			ustream = zmalloc(sizeof(*ustream));
			if (ustream == NULL) {
				PERROR("zmalloc ust stream");
				continue;
			}

			ret = ustctl_create_stream(app->key.sock, ua_chan->obj,
					&ustream->obj);
			if (ret < 0) {
				/* Got all streams */
				break;
			}
			ustream->handle = ustream->obj->handle;

			/* Order is important */
			cds_list_add_tail(&ustream->list, &ua_chan->streams.head);
			ret = snprintf(ustream->pathname, PATH_MAX, "%s/%s-%d/%s_%u",
					usess->pathname, app->name, app->key.pid,
					ua_chan->name, ua_chan->streams.count++);
			if (ret < 0) {
				PERROR("asprintf UST create stream");
				continue;
			}
			DBG2("UST stream %d ready at %s", ua_chan->streams.count,
					ustream->pathname);
		}

		/* Next applications */
		hashtable_get_next(ua_sess->channels, &iter);
	}

	/* Setup UST consumer socket and send fds to it */
	ret = ust_consumer_send_session(usess->consumer_fd, ua_sess);
	if (ret < 0) {
		goto error;
	}

	/* This start the UST tracing */
	ret = ustctl_start_session(app->key.sock, ua_sess->handle);
	if (ret < 0) {
		ERR("Error starting tracing for app pid: %d", app->key.pid);
		goto error;
	}

	/* Quiescent wait after starting trace */
	ustctl_wait_quiescent(app->key.sock);

	return 0;

error:
	return -1;
}

int ust_app_start_trace_all(struct ltt_ust_session *usess)
{
	int ret = 0;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct ust_app *app;

	DBG("Starting all UST traces");

	rcu_read_lock();
	hashtable_get_first(ust_app_ht, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		app = caa_container_of(node, struct ust_app, node);

		ret = ust_app_start_trace(usess, app);
		if (ret < 0) {
			goto next;
		}

next:
		/* Next applications */
		hashtable_get_next(ust_app_ht, &iter);
	}
	rcu_read_unlock();

	return 0;
}

void ust_app_global_update(struct ltt_ust_session *usess, int sock)
{
	int ret = 0;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;
	struct ltt_ust_channel *uchan;
	struct ltt_ust_event *uevent;

	rcu_read_lock();

	if (usess == NULL) {
		DBG2("No UST session on global update. Returning");
		goto error;
	}

	DBG2("UST app global update for app sock %d for session uid %d", sock,
			usess->uid);

	app = find_app_by_sock(sock);
	if (app == NULL) {
		ERR("Failed to update app sock %d", sock);
		goto error;
	}

	ua_sess = create_ust_app_session(usess, app);
	if (ua_sess == NULL) {
		goto error;
	}

	hashtable_get_first(usess->domain_global.channels, &iter);
	while ((node = hashtable_iter_get_node(&iter)) != NULL) {
		uchan = caa_container_of(node, struct ltt_ust_channel, node);

		ua_chan = create_ust_app_channel(ua_sess, uchan, app);
		if (ua_chan == NULL) {
			goto next_chan;
		}

		hashtable_get_first(uchan->events, &iter);
		while ((node = hashtable_iter_get_node(&iter)) != NULL) {
			uevent = caa_container_of(node, struct ltt_ust_event, node);

			ua_event = create_ust_app_event(ua_sess, ua_chan, uevent, app);
			if (ua_event == NULL) {
				goto next_event;
			}

next_event:
			hashtable_get_next(uchan->events, &iter);
		}

next_chan:
		/* Next item in hash table */
		hashtable_get_next(usess->domain_global.channels, &iter);
	}

	if (usess->start_trace) {
		ret = ust_app_start_trace(usess, app);
		if (ret < 0) {
			goto error;
		}

		DBG2("UST trace started for app pid %d", app->key.pid);
	}

error:
	rcu_read_unlock();
	return;
}
