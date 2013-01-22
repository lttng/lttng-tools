/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
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
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <urcu/compiler.h>
#include <lttng/ust-error.h>

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "fd-limit.h"
#include "health.h"
#include "ust-app.h"
#include "ust-consumer.h"
#include "ust-ctl.h"

/*
 * Match function for the hash table lookup.
 *
 * It matches an ust app event based on three attributes which are the event
 * name, the filter bytecode and the loglevel.
 */
static int ht_match_ust_app_event(struct cds_lfht_node *node, const void *_key)
{
	struct ust_app_event *event;
	const struct ust_app_ht_key *key;

	assert(node);
	assert(_key);

	event = caa_container_of(node, struct ust_app_event, node.node);
	key = _key;

	/* Match the 3 elements of the key: name, filter and loglevel. */

	/* Event name */
	if (strncmp(event->attr.name, key->name, sizeof(event->attr.name)) != 0) {
		goto no_match;
	}

	/* Event loglevel. */
	if (event->attr.loglevel != key->loglevel) {
		if (event->attr.loglevel_type == LTTNG_UST_LOGLEVEL_ALL
				&& key->loglevel == 0 && event->attr.loglevel == -1) {
			/*
			 * Match is accepted. This is because on event creation, the
			 * loglevel is set to -1 if the event loglevel type is ALL so 0 and
			 * -1 are accepted for this loglevel type since 0 is the one set by
			 * the API when receiving an enable event.
			 */
		} else {
			goto no_match;
		}
	}

	/* One of the filters is NULL, fail. */
	if ((key->filter && !event->filter) || (!key->filter && event->filter)) {
		goto no_match;
	}

	if (key->filter && event->filter) {
		/* Both filters exists, check length followed by the bytecode. */
		if (event->filter->len != key->filter->len ||
				memcmp(event->filter->data, key->filter->data,
					event->filter->len) != 0) {
			goto no_match;
		}
	}

	/* Match. */
	return 1;

no_match:
	return 0;
}

/*
 * Unique add of an ust app event in the given ht. This uses the custom
 * ht_match_ust_app_event match function and the event name as hash.
 */
static void add_unique_ust_app_event(struct lttng_ht *ht,
		struct ust_app_event *event)
{
	struct cds_lfht_node *node_ptr;
	struct ust_app_ht_key key;

	assert(ht);
	assert(ht->ht);
	assert(event);

	key.name = event->attr.name;
	key.filter = event->filter;
	key.loglevel = event->attr.loglevel;

	node_ptr = cds_lfht_add_unique(ht->ht,
			ht->hash_fct(event->node.key, lttng_ht_seed),
			ht_match_ust_app_event, &key, &event->node.node);
	assert(node_ptr == &event->node.node);
}

/*
 * Delete ust context safely. RCU read lock must be held before calling
 * this function.
 */
static
void delete_ust_app_ctx(int sock, struct ust_app_ctx *ua_ctx)
{
	if (ua_ctx->obj) {
		ustctl_release_object(sock, ua_ctx->obj);
		free(ua_ctx->obj);
	}
	free(ua_ctx);
}

/*
 * Delete ust app event safely. RCU read lock must be held before calling
 * this function.
 */
static
void delete_ust_app_event(int sock, struct ust_app_event *ua_event)
{
	free(ua_event->filter);

	if (ua_event->obj != NULL) {
		ustctl_release_object(sock, ua_event->obj);
		free(ua_event->obj);
	}
	free(ua_event);
}

/*
 * Delete ust app stream safely. RCU read lock must be held before calling
 * this function.
 */
static
void delete_ust_app_stream(int sock, struct ust_app_stream *stream)
{
	if (stream->obj) {
		ustctl_release_object(sock, stream->obj);
		lttng_fd_put(LTTNG_FD_APPS, 2);
		free(stream->obj);
	}
	free(stream);
}

/*
 * Delete ust app channel safely. RCU read lock must be held before calling
 * this function.
 */
static
void delete_ust_app_channel(int sock, struct ust_app_channel *ua_chan)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ust_app_event *ua_event;
	struct ust_app_ctx *ua_ctx;
	struct ust_app_stream *stream, *stmp;

	/* Wipe stream */
	cds_list_for_each_entry_safe(stream, stmp, &ua_chan->streams.head, list) {
		cds_list_del(&stream->list);
		delete_ust_app_stream(sock, stream);
	}

	/* Wipe context */
	cds_lfht_for_each_entry(ua_chan->ctx->ht, &iter.iter, ua_ctx, node.node) {
		ret = lttng_ht_del(ua_chan->ctx, &iter);
		assert(!ret);
		delete_ust_app_ctx(sock, ua_ctx);
	}
	lttng_ht_destroy(ua_chan->ctx);

	/* Wipe events */
	cds_lfht_for_each_entry(ua_chan->events->ht, &iter.iter, ua_event,
			node.node) {
		ret = lttng_ht_del(ua_chan->events, &iter);
		assert(!ret);
		delete_ust_app_event(sock, ua_event);
	}
	lttng_ht_destroy(ua_chan->events);

	if (ua_chan->obj != NULL) {
		ustctl_release_object(sock, ua_chan->obj);
		lttng_fd_put(LTTNG_FD_APPS, 2);
		free(ua_chan->obj);
	}
	free(ua_chan);
}

/*
 * Delete ust app session safely. RCU read lock must be held before calling
 * this function.
 */
static
void delete_ust_app_session(int sock, struct ust_app_session *ua_sess)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ust_app_channel *ua_chan;

	if (ua_sess->metadata) {
		if (ua_sess->metadata->stream_obj) {
			ustctl_release_object(sock, ua_sess->metadata->stream_obj);
			lttng_fd_put(LTTNG_FD_APPS, 2);
			free(ua_sess->metadata->stream_obj);
		}
		if (ua_sess->metadata->obj) {
			ustctl_release_object(sock, ua_sess->metadata->obj);
			lttng_fd_put(LTTNG_FD_APPS, 2);
			free(ua_sess->metadata->obj);
		}
		trace_ust_destroy_metadata(ua_sess->metadata);
	}

	cds_lfht_for_each_entry(ua_sess->channels->ht, &iter.iter, ua_chan,
			node.node) {
		ret = lttng_ht_del(ua_sess->channels, &iter);
		assert(!ret);
		delete_ust_app_channel(sock, ua_chan);
	}
	lttng_ht_destroy(ua_sess->channels);

	if (ua_sess->handle != -1) {
		ustctl_release_handle(sock, ua_sess->handle);
	}
	free(ua_sess);
}

/*
 * Delete a traceable application structure from the global list. Never call
 * this function outside of a call_rcu call.
 */
static
void delete_ust_app(struct ust_app *app)
{
	int ret, sock;
	struct ust_app_session *ua_sess, *tmp_ua_sess;

	rcu_read_lock();

	/* Delete ust app sessions info */
	sock = app->sock;
	app->sock = -1;

	lttng_ht_destroy(app->sessions);

	/* Wipe sessions */
	cds_list_for_each_entry_safe(ua_sess, tmp_ua_sess, &app->teardown_head,
			teardown_node) {
		/* Free every object in the session and the session. */
		delete_ust_app_session(sock, ua_sess);
	}

	/*
	 * Wait until we have deleted the application from the sock hash table
	 * before closing this socket, otherwise an application could re-use the
	 * socket ID and race with the teardown, using the same hash table entry.
	 *
	 * It's OK to leave the close in call_rcu. We want it to stay unique for
	 * all RCU readers that could run concurrently with unregister app,
	 * therefore we _need_ to only close that socket after a grace period. So
	 * it should stay in this RCU callback.
	 *
	 * This close() is a very important step of the synchronization model so
	 * every modification to this function must be carefully reviewed.
	 */
	ret = close(sock);
	if (ret) {
		PERROR("close");
	}
	lttng_fd_put(LTTNG_FD_APPS, 1);

	DBG2("UST app pid %d deleted", app->pid);
	free(app);

	rcu_read_unlock();
}

/*
 * URCU intermediate call to delete an UST app.
 */
static
void delete_ust_app_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct ust_app *app =
		caa_container_of(node, struct ust_app, pid_n);

	DBG3("Call RCU deleting app PID %d", app->pid);
	delete_ust_app(app);
}

/*
 * Alloc new UST app session.
 */
static
struct ust_app_session *alloc_ust_app_session(void)
{
	struct ust_app_session *ua_sess;

	/* Init most of the default value by allocating and zeroing */
	ua_sess = zmalloc(sizeof(struct ust_app_session));
	if (ua_sess == NULL) {
		PERROR("malloc");
		goto error;
	}

	ua_sess->handle = -1;
	ua_sess->channels = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);

	return ua_sess;

error:
	return NULL;
}

/*
 * Alloc new UST app channel.
 */
static
struct ust_app_channel *alloc_ust_app_channel(char *name,
		struct lttng_ust_channel *attr)
{
	struct ust_app_channel *ua_chan;

	/* Init most of the default value by allocating and zeroing */
	ua_chan = zmalloc(sizeof(struct ust_app_channel));
	if (ua_chan == NULL) {
		PERROR("malloc");
		goto error;
	}

	/* Setup channel name */
	strncpy(ua_chan->name, name, sizeof(ua_chan->name));
	ua_chan->name[sizeof(ua_chan->name) - 1] = '\0';

	ua_chan->enabled = 1;
	ua_chan->handle = -1;
	ua_chan->ctx = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	ua_chan->events = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	lttng_ht_node_init_str(&ua_chan->node, ua_chan->name);

	CDS_INIT_LIST_HEAD(&ua_chan->streams.head);

	/* Copy attributes */
	if (attr) {
		/* Translate from lttng_ust_channel to lttng_ust_channel_attr.*/
		ua_chan->attr.subbuf_size = attr->subbuf_size;
		ua_chan->attr.num_subbuf = attr->num_subbuf;
		ua_chan->attr.overwrite = attr->overwrite;
		ua_chan->attr.switch_timer_interval = attr->switch_timer_interval;
		ua_chan->attr.read_timer_interval = attr->read_timer_interval;
		ua_chan->attr.output = attr->output;
	}

	DBG3("UST app channel %s allocated", ua_chan->name);

	return ua_chan;

error:
	return NULL;
}

/*
 * Allocate and initialize a UST app stream.
 *
 * Return newly allocated stream pointer or NULL on error.
 */
static struct ust_app_stream *alloc_ust_app_stream(void)
{
	struct ust_app_stream *stream = NULL;

	stream = zmalloc(sizeof(*stream));
	if (stream == NULL) {
		PERROR("zmalloc ust app stream");
		goto error;
	}

	/* Zero could be a valid value for a handle so flag it to -1. */
	stream->handle = -1;

error:
	return stream;
}

/*
 * Alloc new UST app event.
 */
static
struct ust_app_event *alloc_ust_app_event(char *name,
		struct lttng_ust_event *attr)
{
	struct ust_app_event *ua_event;

	/* Init most of the default value by allocating and zeroing */
	ua_event = zmalloc(sizeof(struct ust_app_event));
	if (ua_event == NULL) {
		PERROR("malloc");
		goto error;
	}

	ua_event->enabled = 1;
	strncpy(ua_event->name, name, sizeof(ua_event->name));
	ua_event->name[sizeof(ua_event->name) - 1] = '\0';
	lttng_ht_node_init_str(&ua_event->node, ua_event->name);

	/* Copy attributes */
	if (attr) {
		memcpy(&ua_event->attr, attr, sizeof(ua_event->attr));
	}

	DBG3("UST app event %s allocated", ua_event->name);

	return ua_event;

error:
	return NULL;
}

/*
 * Alloc new UST app context.
 */
static
struct ust_app_ctx *alloc_ust_app_ctx(struct lttng_ust_context *uctx)
{
	struct ust_app_ctx *ua_ctx;

	ua_ctx = zmalloc(sizeof(struct ust_app_ctx));
	if (ua_ctx == NULL) {
		goto error;
	}

	if (uctx) {
		memcpy(&ua_ctx->ctx, uctx, sizeof(ua_ctx->ctx));
	}

	DBG3("UST app context %d allocated", ua_ctx->ctx.ctx);

error:
	return ua_ctx;
}

/*
 * Allocate a filter and copy the given original filter.
 *
 * Return allocated filter or NULL on error.
 */
static struct lttng_ust_filter_bytecode *alloc_copy_ust_app_filter(
		struct lttng_ust_filter_bytecode *orig_f)
{
	struct lttng_ust_filter_bytecode *filter = NULL;

	/* Copy filter bytecode */
	filter = zmalloc(sizeof(*filter) + orig_f->len);
	if (!filter) {
		PERROR("zmalloc alloc ust app filter");
		goto error;
	}

	memcpy(filter, orig_f, sizeof(*filter) + orig_f->len);

error:
	return filter;
}

/*
 * Find an ust_app using the sock and return it. RCU read side lock must be
 * held before calling this helper function.
 */
static
struct ust_app *find_app_by_sock(int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	lttng_ht_lookup(ust_app_ht_by_sock, (void *)((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == NULL) {
		DBG2("UST app find by sock %d not found", sock);
		goto error;
	}

	return caa_container_of(node, struct ust_app, sock_n);

error:
	return NULL;
}

/*
 * Lookup for an ust app event based on event name, filter bytecode and the
 * event loglevel.
 *
 * Return an ust_app_event object or NULL on error.
 */
static struct ust_app_event *find_ust_app_event(struct lttng_ht *ht,
		char *name, struct lttng_ust_filter_bytecode *filter, int loglevel)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *node;
	struct ust_app_event *event = NULL;
	struct ust_app_ht_key key;

	assert(name);
	assert(ht);

	/* Setup key for event lookup. */
	key.name = name;
	key.filter = filter;
	key.loglevel = loglevel;

	/* Lookup using the event name as hash and a custom match fct. */
	cds_lfht_lookup(ht->ht, ht->hash_fct((void *) name, lttng_ht_seed),
			ht_match_ust_app_event, &key, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		goto end;
	}

	event = caa_container_of(node, struct ust_app_event, node);

end:
	return event;
}

/*
 * Create the channel context on the tracer.
 */
static
int create_ust_channel_context(struct ust_app_channel *ua_chan,
		struct ust_app_ctx *ua_ctx, struct ust_app *app)
{
	int ret;

	health_code_update(&health_thread_cmd);

	ret = ustctl_add_context(app->sock, &ua_ctx->ctx,
			ua_chan->obj, &ua_ctx->obj);
	if (ret < 0) {
		goto error;
	}

	ua_ctx->handle = ua_ctx->obj->handle;

	DBG2("UST app context created successfully for channel %s", ua_chan->name);

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Set the filter on the tracer.
 */
static
int set_ust_event_filter(struct ust_app_event *ua_event,
		struct ust_app *app)
{
	int ret;

	health_code_update(&health_thread_cmd);

	if (!ua_event->filter) {
		ret = 0;
		goto error;
	}

	ret = ustctl_set_filter(app->sock, ua_event->filter,
			ua_event->obj);
	if (ret < 0) {
		goto error;
	}

	DBG2("UST filter set successfully for event %s", ua_event->name);

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Disable the specified event on to UST tracer for the UST session.
 */
static int disable_ust_event(struct ust_app *app,
		struct ust_app_session *ua_sess, struct ust_app_event *ua_event)
{
	int ret;

	health_code_update(&health_thread_cmd);

	ret = ustctl_disable(app->sock, ua_event->obj);
	if (ret < 0) {
		ERR("UST app event %s disable failed for app (pid: %d) "
				"and session handle %d with ret %d",
				ua_event->attr.name, app->pid, ua_sess->handle, ret);
		goto error;
	}

	DBG2("UST app event %s disabled successfully for app (pid: %d)",
			ua_event->attr.name, app->pid);

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Disable the specified channel on to UST tracer for the UST session.
 */
static int disable_ust_channel(struct ust_app *app,
		struct ust_app_session *ua_sess, struct ust_app_channel *ua_chan)
{
	int ret;

	health_code_update(&health_thread_cmd);

	ret = ustctl_disable(app->sock, ua_chan->obj);
	if (ret < 0) {
		ERR("UST app channel %s disable failed for app (pid: %d) "
				"and session handle %d with ret %d",
				ua_chan->name, app->pid, ua_sess->handle, ret);
		goto error;
	}

	DBG2("UST app channel %s disabled successfully for app (pid: %d)",
			ua_chan->name, app->pid);

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Enable the specified channel on to UST tracer for the UST session.
 */
static int enable_ust_channel(struct ust_app *app,
		struct ust_app_session *ua_sess, struct ust_app_channel *ua_chan)
{
	int ret;

	health_code_update(&health_thread_cmd);

	ret = ustctl_enable(app->sock, ua_chan->obj);
	if (ret < 0) {
		ERR("UST app channel %s enable failed for app (pid: %d) "
				"and session handle %d with ret %d",
				ua_chan->name, app->pid, ua_sess->handle, ret);
		goto error;
	}

	ua_chan->enabled = 1;

	DBG2("UST app channel %s enabled successfully for app (pid: %d)",
			ua_chan->name, app->pid);

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Enable the specified event on to UST tracer for the UST session.
 */
static int enable_ust_event(struct ust_app *app,
		struct ust_app_session *ua_sess, struct ust_app_event *ua_event)
{
	int ret;

	health_code_update(&health_thread_cmd);

	ret = ustctl_enable(app->sock, ua_event->obj);
	if (ret < 0) {
		ERR("UST app event %s enable failed for app (pid: %d) "
				"and session handle %d with ret %d",
				ua_event->attr.name, app->pid, ua_sess->handle, ret);
		goto error;
	}

	DBG2("UST app event %s enabled successfully for app (pid: %d)",
			ua_event->attr.name, app->pid);

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Open metadata onto the UST tracer for a UST session.
 */
static int open_ust_metadata(struct ust_app *app,
		struct ust_app_session *ua_sess)
{
	int ret;
	struct lttng_ust_channel_attr uattr;

	health_code_update(&health_thread_cmd);

	uattr.overwrite = ua_sess->metadata->attr.overwrite;
	uattr.subbuf_size = ua_sess->metadata->attr.subbuf_size;
	uattr.num_subbuf = ua_sess->metadata->attr.num_subbuf;
	uattr.switch_timer_interval =
		ua_sess->metadata->attr.switch_timer_interval;
	uattr.read_timer_interval =
		ua_sess->metadata->attr.read_timer_interval;
	uattr.output = ua_sess->metadata->attr.output;

	/* We are going to receive 2 fds, we need to reserve them. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 2);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon metadata open");
		goto error;
	}
	/* UST tracer metadata creation */
	ret = ustctl_open_metadata(app->sock, ua_sess->handle, &uattr,
			&ua_sess->metadata->obj);
	if (ret < 0) {
		ERR("UST app open metadata failed for app pid:%d with ret %d",
				app->pid, ret);
		goto error;
	}

	ua_sess->metadata->handle = ua_sess->metadata->obj->handle;

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Create metadata stream onto the UST tracer for a given session.
 */
static int create_ust_metadata_stream(struct ust_app *app,
		struct ust_app_session *ua_sess)
{
	int ret;

	health_code_update(&health_thread_cmd);

	/* We are going to receive 2 fds, we need to reserve them. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 2);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon metadata stream create");
		goto error;
	}
	ret = ustctl_create_stream(app->sock, ua_sess->metadata->obj,
			&ua_sess->metadata->stream_obj);
	if (ret < 0) {
		lttng_fd_put(LTTNG_FD_APPS, 2);
		ERR("UST create metadata stream failed");
		goto error;
	}

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Create stream onto the UST tracer for a given channel.
 *
 * Return -ENOENT if no more stream is available for this channel.
 * On success, return 0.
 * On error, return a negative value.
 */
static int create_ust_stream(struct ust_app *app,
		struct ust_app_channel *ua_chan, struct ust_app_stream *stream)
{
	int ret;

	assert(app);
	assert(ua_chan);
	assert(ua_chan->obj);
	assert(stream);

	health_code_update(&health_thread_cmd);

	/* We are going to receive 2 fds, we need to reserve them. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 2);
	if (ret < 0) {
		ERR("Exhausted number of available FD on stream creation");
		/* Just to make sure we never return -ENOENT. */
		ret = -1;
		goto error;
	}

	/*
	 * Set the stream name before creating it. On error, we don't have to
	 * delete it on the tracer side.
	 */
	ret = snprintf(stream->name, sizeof(stream->name), "%s_%u",
			ua_chan->name, ua_chan->streams.count);
	if (ret < 0) {
		/* Without the stream name we can't continue using it. */
		PERROR("snprintf UST create stream");
		/* Just to make sure we never return -ENOENT. */
		ret = -1;
		goto error;
	}

	ret = ustctl_create_stream(app->sock, ua_chan->obj, &stream->obj);
	if (ret < 0) {
		lttng_fd_put(LTTNG_FD_APPS, 2);
		/* Indicates that there is no more stream for that channel. */
		if (ret != -LTTNG_UST_ERR_NOENT) {
			ERR("UST create metadata stream failed (ret: %d)", ret);
		}
		goto error;
	}

	/* Set stream handle with the returned value. */
	stream->handle = stream->obj->handle;

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Create the specified channel onto the UST tracer for a UST session.
 */
static int create_ust_channel(struct ust_app *app,
		struct ust_app_session *ua_sess, struct ust_app_channel *ua_chan)
{
	int ret;

	health_code_update(&health_thread_cmd);

	/* We are going to receive 2 fds, we need to reserve them. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 2);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon create channel");
		goto error;
	}

	health_code_update(&health_thread_cmd);

	ret = ustctl_create_channel(app->sock, ua_sess->handle, &ua_chan->attr,
			&ua_chan->obj);
	if (ret < 0) {
		ERR("Creating channel %s for app (pid: %d, sock: %d) "
				"and session handle %d with ret %d",
				ua_chan->name, app->pid, app->sock,
				ua_sess->handle, ret);
		lttng_fd_put(LTTNG_FD_APPS, 2);
		goto error;
	}

	ua_chan->handle = ua_chan->obj->handle;

	DBG2("UST app channel %s created successfully for pid:%d and sock:%d",
			ua_chan->name, app->pid, app->sock);

	health_code_update(&health_thread_cmd);

	/* If channel is not enabled, disable it on the tracer */
	if (!ua_chan->enabled) {
		ret = disable_ust_channel(app, ua_sess, ua_chan);
		if (ret < 0) {
			goto error;
		}
	}

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Create the specified event onto the UST tracer for a UST session.
 */
static
int create_ust_event(struct ust_app *app, struct ust_app_session *ua_sess,
		struct ust_app_channel *ua_chan, struct ust_app_event *ua_event)
{
	int ret = 0;

	health_code_update(&health_thread_cmd);

	/* Create UST event on tracer */
	ret = ustctl_create_event(app->sock, &ua_event->attr, ua_chan->obj,
			&ua_event->obj);
	if (ret < 0) {
		ERR("Error ustctl create event %s for app pid: %d with ret %d",
				ua_event->attr.name, app->pid, ret);
		goto error;
	}

	ua_event->handle = ua_event->obj->handle;

	DBG2("UST app event %s created successfully for pid:%d",
			ua_event->attr.name, app->pid);

	health_code_update(&health_thread_cmd);

	/* Set filter if one is present. */
	if (ua_event->filter) {
		ret = set_ust_event_filter(ua_event, app);
		if (ret < 0) {
			goto error;
		}
	}

	/* If event not enabled, disable it on the tracer */
	if (ua_event->enabled == 0) {
		ret = disable_ust_event(app, ua_sess, ua_event);
		if (ret < 0) {
			/*
			 * If we hit an EPERM, something is wrong with our disable call. If
			 * we get an EEXIST, there is a problem on the tracer side since we
			 * just created it.
			 */
			switch (ret) {
			case -LTTNG_UST_ERR_PERM:
				/* Code flow problem */
				assert(0);
			case -LTTNG_UST_ERR_EXIST:
				/* It's OK for our use case. */
				ret = 0;
				break;
			default:
				break;
			}
			goto error;
		}
	}

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Copy data between an UST app event and a LTT event.
 */
static void shadow_copy_event(struct ust_app_event *ua_event,
		struct ltt_ust_event *uevent)
{
	strncpy(ua_event->name, uevent->attr.name, sizeof(ua_event->name));
	ua_event->name[sizeof(ua_event->name) - 1] = '\0';

	ua_event->enabled = uevent->enabled;

	/* Copy event attributes */
	memcpy(&ua_event->attr, &uevent->attr, sizeof(ua_event->attr));

	/* Copy filter bytecode */
	if (uevent->filter) {
		ua_event->filter = alloc_copy_ust_app_filter(uevent->filter);
		/* Filter might be NULL here in case of ENONEM. */
	}
}

/*
 * Copy data between an UST app channel and a LTT channel.
 */
static void shadow_copy_channel(struct ust_app_channel *ua_chan,
		struct ltt_ust_channel *uchan)
{
	struct lttng_ht_iter iter;
	struct ltt_ust_event *uevent;
	struct ltt_ust_context *uctx;
	struct ust_app_event *ua_event;
	struct ust_app_ctx *ua_ctx;

	DBG2("UST app shadow copy of channel %s started", ua_chan->name);

	strncpy(ua_chan->name, uchan->name, sizeof(ua_chan->name));
	ua_chan->name[sizeof(ua_chan->name) - 1] = '\0';
	/* Copy event attributes */
	memcpy(&ua_chan->attr, &uchan->attr, sizeof(ua_chan->attr));

	ua_chan->enabled = uchan->enabled;

	cds_lfht_for_each_entry(uchan->ctx->ht, &iter.iter, uctx, node.node) {
		ua_ctx = alloc_ust_app_ctx(&uctx->ctx);
		if (ua_ctx == NULL) {
			continue;
		}
		lttng_ht_node_init_ulong(&ua_ctx->node,
				(unsigned long) ua_ctx->ctx.ctx);
		lttng_ht_add_unique_ulong(ua_chan->ctx, &ua_ctx->node);
	}

	/* Copy all events from ltt ust channel to ust app channel */
	cds_lfht_for_each_entry(uchan->events->ht, &iter.iter, uevent, node.node) {
		ua_event = find_ust_app_event(ua_chan->events, uevent->attr.name,
				uevent->filter, uevent->attr.loglevel);
		if (ua_event == NULL) {
			DBG2("UST event %s not found on shadow copy channel",
					uevent->attr.name);
			ua_event = alloc_ust_app_event(uevent->attr.name, &uevent->attr);
			if (ua_event == NULL) {
				continue;
			}
			shadow_copy_event(ua_event, uevent);
			add_unique_ust_app_event(ua_chan->events, ua_event);
		}
	}

	DBG3("UST app shadow copy of channel %s done", ua_chan->name);
}

/*
 * Copy data between a UST app session and a regular LTT session.
 */
static void shadow_copy_session(struct ust_app_session *ua_sess,
		struct ltt_ust_session *usess, struct ust_app *app)
{
	struct lttng_ht_node_str *ua_chan_node;
	struct lttng_ht_iter iter;
	struct ltt_ust_channel *uchan;
	struct ust_app_channel *ua_chan;
	time_t rawtime;
	struct tm *timeinfo;
	char datetime[16];
	int ret;

	/* Get date and time for unique app path */
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);

	DBG2("Shadow copy of session handle %d", ua_sess->handle);

	ua_sess->id = usess->id;
	ua_sess->uid = usess->uid;
	ua_sess->gid = usess->gid;

	ret = snprintf(ua_sess->path, PATH_MAX, "%s-%d-%s/", app->name, app->pid,
			datetime);
	if (ret < 0) {
		PERROR("asprintf UST shadow copy session");
		/* TODO: We cannot return an error from here.. */
		assert(0);
	}

	/* TODO: support all UST domain */

	/* Iterate over all channels in global domain. */
	cds_lfht_for_each_entry(usess->domain_global.channels->ht, &iter.iter,
			uchan, node.node) {
		struct lttng_ht_iter uiter;

		lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &uiter);
		ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
		if (ua_chan_node != NULL) {
			/* Session exist. Contiuing. */
			continue;
		}

		DBG2("Channel %s not found on shadow session copy, creating it",
				uchan->name);
		ua_chan = alloc_ust_app_channel(uchan->name, &uchan->attr);
		if (ua_chan == NULL) {
			/* malloc failed FIXME: Might want to do handle ENOMEM .. */
			continue;
		}

		shadow_copy_channel(ua_chan, uchan);
		lttng_ht_add_unique_str(ua_sess->channels, &ua_chan->node);
	}
}

/*
 * Lookup sesison wrapper.
 */
static
void __lookup_session_by_app(struct ltt_ust_session *usess,
			struct ust_app *app, struct lttng_ht_iter *iter)
{
	/* Get right UST app session from app */
	lttng_ht_lookup(app->sessions, (void *)((unsigned long) usess->id), iter);
}

/*
 * Return ust app session from the app session hashtable using the UST session
 * id.
 */
static struct ust_app_session *lookup_session_by_app(
		struct ltt_ust_session *usess, struct ust_app *app)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;

	__lookup_session_by_app(usess, app, &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == NULL) {
		goto error;
	}

	return caa_container_of(node, struct ust_app_session, node);

error:
	return NULL;
}

/*
 * Create a session on the tracer side for the given app.
 *
 * On success, ua_sess_ptr is populated with the session pointer or else left
 * untouched. If the session was created, is_created is set to 1. On error,
 * it's left untouched. Note that ua_sess_ptr is mandatory but is_created can
 * be NULL.
 *
 * Returns 0 on success or else a negative code which is either -ENOMEM or
 * -ENOTCONN which is the default code if the ustctl_create_session fails.
 */
static int create_ust_app_session(struct ltt_ust_session *usess,
		struct ust_app *app, struct ust_app_session **ua_sess_ptr,
		int *is_created)
{
	int ret, created = 0;
	struct ust_app_session *ua_sess;

	assert(usess);
	assert(app);
	assert(ua_sess_ptr);

	health_code_update(&health_thread_cmd);

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == NULL) {
		DBG2("UST app pid: %d session id %d not found, creating it",
				app->pid, usess->id);
		ua_sess = alloc_ust_app_session();
		if (ua_sess == NULL) {
			/* Only malloc can failed so something is really wrong */
			ret = -ENOMEM;
			goto error;
		}
		shadow_copy_session(ua_sess, usess, app);
		created = 1;
	}

	health_code_update(&health_thread_cmd);

	if (ua_sess->handle == -1) {
		ret = ustctl_create_session(app->sock);
		if (ret < 0) {
			ERR("Creating session for app pid %d", app->pid);
			delete_ust_app_session(-1, ua_sess);
			if (ret != -ENOMEM) {
				/*
				 * Tracer is probably gone or got an internal error so let's
				 * behave like it will soon unregister or not usable.
				 */
				ret = -ENOTCONN;
			}
			goto error;
		}

		ua_sess->handle = ret;

		/* Add ust app session to app's HT */
		lttng_ht_node_init_ulong(&ua_sess->node, (unsigned long) ua_sess->id);
		lttng_ht_add_unique_ulong(app->sessions, &ua_sess->node);

		DBG2("UST app session created successfully with handle %d", ret);
	}

	*ua_sess_ptr = ua_sess;
	if (is_created) {
		*is_created = created;
	}
	/* Everything went well. */
	ret = 0;

error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Create a context for the channel on the tracer.
 */
static
int create_ust_app_channel_context(struct ust_app_session *ua_sess,
		struct ust_app_channel *ua_chan, struct lttng_ust_context *uctx,
		struct ust_app *app)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	struct ust_app_ctx *ua_ctx;

	DBG2("UST app adding context to channel %s", ua_chan->name);

	lttng_ht_lookup(ua_chan->ctx, (void *)((unsigned long)uctx->ctx), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node != NULL) {
		ret = -EEXIST;
		goto error;
	}

	ua_ctx = alloc_ust_app_ctx(uctx);
	if (ua_ctx == NULL) {
		/* malloc failed */
		ret = -1;
		goto error;
	}

	lttng_ht_node_init_ulong(&ua_ctx->node, (unsigned long) ua_ctx->ctx.ctx);
	lttng_ht_add_unique_ulong(ua_chan->ctx, &ua_ctx->node);

	ret = create_ust_channel_context(ua_chan, ua_ctx, app);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Enable on the tracer side a ust app event for the session and channel.
 */
static
int enable_ust_app_event(struct ust_app_session *ua_sess,
		struct ust_app_event *ua_event, struct ust_app *app)
{
	int ret;

	ret = enable_ust_event(app, ua_sess, ua_event);
	if (ret < 0) {
		goto error;
	}

	ua_event->enabled = 1;

error:
	return ret;
}

/*
 * Disable on the tracer side a ust app event for the session and channel.
 */
static int disable_ust_app_event(struct ust_app_session *ua_sess,
		struct ust_app_event *ua_event, struct ust_app *app)
{
	int ret;

	ret = disable_ust_event(app, ua_sess, ua_event);
	if (ret < 0) {
		goto error;
	}

	ua_event->enabled = 0;

error:
	return ret;
}

/*
 * Lookup ust app channel for session and disable it on the tracer side.
 */
static
int disable_ust_app_channel(struct ust_app_session *ua_sess,
		struct ust_app_channel *ua_chan, struct ust_app *app)
{
	int ret;

	ret = disable_ust_channel(app, ua_sess, ua_chan);
	if (ret < 0) {
		goto error;
	}

	ua_chan->enabled = 0;

error:
	return ret;
}

/*
 * Lookup ust app channel for session and enable it on the tracer side.
 */
static int enable_ust_app_channel(struct ust_app_session *ua_sess,
		struct ltt_ust_channel *uchan, struct ust_app *app)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app_channel *ua_chan;

	lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &iter);
	ua_chan_node = lttng_ht_iter_get_node_str(&iter);
	if (ua_chan_node == NULL) {
		DBG2("Unable to find channel %s in ust session id %u",
				uchan->name, ua_sess->id);
		goto error;
	}

	ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);

	ret = enable_ust_channel(app, ua_sess, ua_chan);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Create UST app channel and create it on the tracer. Set ua_chanp of the
 * newly created channel if not NULL.
 */
static int create_ust_app_channel(struct ust_app_session *ua_sess,
		struct ltt_ust_channel *uchan, struct ust_app *app,
		struct ust_app_channel **ua_chanp)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app_channel *ua_chan;

	/* Lookup channel in the ust app session */
	lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &iter);
	ua_chan_node = lttng_ht_iter_get_node_str(&iter);
	if (ua_chan_node != NULL) {
		ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);
		goto end;
	}

	ua_chan = alloc_ust_app_channel(uchan->name, &uchan->attr);
	if (ua_chan == NULL) {
		/* Only malloc can fail here */
		ret = -ENOMEM;
		goto error;
	}
	shadow_copy_channel(ua_chan, uchan);

	ret = create_ust_channel(app, ua_sess, ua_chan);
	if (ret < 0) {
		/* Not found previously means that it does not exist on the tracer */
		assert(ret != -LTTNG_UST_ERR_EXIST);
		goto error;
	}

	/* Only add the channel if successful on the tracer side. */
	lttng_ht_add_unique_str(ua_sess->channels, &ua_chan->node);

	DBG2("UST app create channel %s for PID %d completed", ua_chan->name,
			app->pid);

end:
	if (ua_chanp) {
		*ua_chanp = ua_chan;
	}

	/* Everything went well. */
	return 0;

error:
	delete_ust_app_channel(-1, ua_chan);
	return ret;
}

/*
 * Create UST app event and create it on the tracer side.
 */
static
int create_ust_app_event(struct ust_app_session *ua_sess,
		struct ust_app_channel *ua_chan, struct ltt_ust_event *uevent,
		struct ust_app *app)
{
	int ret = 0;
	struct ust_app_event *ua_event;

	/* Get event node */
	ua_event = find_ust_app_event(ua_chan->events, uevent->attr.name,
			uevent->filter, uevent->attr.loglevel);
	if (ua_event != NULL) {
		ret = -EEXIST;
		goto end;
	}

	/* Does not exist so create one */
	ua_event = alloc_ust_app_event(uevent->attr.name, &uevent->attr);
	if (ua_event == NULL) {
		/* Only malloc can failed so something is really wrong */
		ret = -ENOMEM;
		goto end;
	}
	shadow_copy_event(ua_event, uevent);

	/* Create it on the tracer side */
	ret = create_ust_event(app, ua_sess, ua_chan, ua_event);
	if (ret < 0) {
		/* Not found previously means that it does not exist on the tracer */
		assert(ret != -LTTNG_UST_ERR_EXIST);
		goto error;
	}

	add_unique_ust_app_event(ua_chan->events, ua_event);

	DBG2("UST app create event %s for PID %d completed", ua_event->name,
			app->pid);

end:
	return ret;

error:
	/* Valid. Calling here is already in a read side lock */
	delete_ust_app_event(-1, ua_event);
	return ret;
}

/*
 * Create UST metadata and open it on the tracer side.
 */
static int create_ust_app_metadata(struct ust_app_session *ua_sess,
		char *pathname, struct ust_app *app)
{
	int ret = 0;

	if (ua_sess->metadata == NULL) {
		/* Allocate UST metadata */
		ua_sess->metadata = trace_ust_create_metadata(pathname);
		if (ua_sess->metadata == NULL) {
			/* malloc() failed */
			goto error;
		}

		ret = open_ust_metadata(app, ua_sess);
		if (ret < 0) {
			DBG3("Opening metadata failed. Cleaning up memory");

			/* Cleanup failed metadata struct */
			free(ua_sess->metadata);
			/*
			 * This is very important because delete_ust_app_session check if
			 * the pointer is null or not in order to delete the metadata.
			 */
			ua_sess->metadata = NULL;
			goto error;
		}

		DBG2("UST metadata opened for app pid %d", app->pid);
	}

	/* Open UST metadata stream */
	if (ua_sess->metadata->stream_obj == NULL) {
		ret = create_ust_metadata_stream(app, ua_sess);
		if (ret < 0) {
			goto error;
		}

		ret = snprintf(ua_sess->metadata->pathname, PATH_MAX,
				"%s/" DEFAULT_METADATA_NAME, ua_sess->path);
		if (ret < 0) {
			PERROR("asprintf UST create stream");
			goto error;
		}

		DBG2("UST metadata stream object created for app pid %d",
				app->pid);
	} else {
		ERR("Attempting to create stream without metadata opened");
		goto error;
	}

	return 0;

error:
	return -1;
}

/*
 * Return pointer to traceable apps list.
 */
struct lttng_ht *ust_app_get_ht(void)
{
	return ust_app_ht;
}

/*
 * Return ust app pointer or NULL if not found.
 */
struct ust_app *ust_app_find_by_pid(pid_t pid)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	rcu_read_lock();
	lttng_ht_lookup(ust_app_ht, (void *)((unsigned long) pid), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == NULL) {
		DBG2("UST app no found with pid %d", pid);
		goto error;
	}
	rcu_read_unlock();

	DBG2("Found UST app by pid %d", pid);

	return caa_container_of(node, struct ust_app, pid_n);

error:
	rcu_read_unlock();
	return NULL;
}

/*
 * Using pid and uid (of the app), allocate a new ust_app struct and
 * add it to the global traceable app list.
 *
 * On success, return 0, else return malloc -ENOMEM, or -EINVAL if app
 * bitness is not supported.
 */
int ust_app_register(struct ust_register_msg *msg, int sock)
{
	struct ust_app *lta;
	int ret;

	if ((msg->bits_per_long == 64 &&
				(uatomic_read(&ust_consumerd64_fd) == -EINVAL))
			|| (msg->bits_per_long == 32 &&
				(uatomic_read(&ust_consumerd32_fd) == -EINVAL))) {
		ERR("Registration failed: application \"%s\" (pid: %d) has "
			"%d-bit long, but no consumerd for this long size is available.\n",
			msg->name, msg->pid, msg->bits_per_long);
		ret = close(sock);
		if (ret) {
			PERROR("close");
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
		return -EINVAL;
	}
	if (msg->major != LTTNG_UST_COMM_MAJOR) {
		ERR("Registration failed: application \"%s\" (pid: %d) has "
			"communication protocol version %u.%u, but sessiond supports 2.x.\n",
			msg->name, msg->pid, msg->major, msg->minor);
		ret = close(sock);
		if (ret) {
			PERROR("close");
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
		return -EINVAL;
	}
	lta = zmalloc(sizeof(struct ust_app));
	if (lta == NULL) {
		PERROR("malloc");
		return -ENOMEM;
	}

	lta->ppid = msg->ppid;
	lta->uid = msg->uid;
	lta->gid = msg->gid;
	lta->compatible = 0;  /* Not compatible until proven */
	lta->bits_per_long = msg->bits_per_long;
	lta->v_major = msg->major;
	lta->v_minor = msg->minor;
	strncpy(lta->name, msg->name, sizeof(lta->name));
	lta->name[16] = '\0';
	lta->sessions = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);

	lta->pid = msg->pid;
	lttng_ht_node_init_ulong(&lta->pid_n, (unsigned long)lta->pid);
	lta->sock = sock;
	lttng_ht_node_init_ulong(&lta->sock_n, (unsigned long)lta->sock);

	CDS_INIT_LIST_HEAD(&lta->teardown_head);

	rcu_read_lock();

	/*
	 * On a re-registration, we want to kick out the previous registration of
	 * that pid
	 */
	lttng_ht_add_replace_ulong(ust_app_ht, &lta->pid_n);

	/*
	 * The socket _should_ be unique until _we_ call close. So, a add_unique
	 * for the ust_app_ht_by_sock is used which asserts fail if the entry was
	 * already in the table.
	 */
	lttng_ht_add_unique_ulong(ust_app_ht_by_sock, &lta->sock_n);

	rcu_read_unlock();

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
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct ust_app_session *ua_sess;
	int ret;

	rcu_read_lock();

	/* Get the node reference for a call_rcu */
	lttng_ht_lookup(ust_app_ht_by_sock, (void *)((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == NULL) {
		ERR("Unable to find app by sock %d", sock);
		goto error;
	}

	lta = caa_container_of(node, struct ust_app, sock_n);

	DBG("PID %d unregistering with sock %d", lta->pid, sock);

	/* Remove application from PID hash table */
	ret = lttng_ht_del(ust_app_ht_by_sock, &iter);
	assert(!ret);

	/* Assign second node for deletion */
	iter.iter.node = &lta->pid_n.node;

	/*
	 * Ignore return value since the node might have been removed before by an
	 * add replace during app registration because the PID can be reassigned by
	 * the OS.
	 */
	ret = lttng_ht_del(ust_app_ht, &iter);
	if (ret) {
		DBG3("Unregister app by PID %d failed. This can happen on pid reuse",
				lta->pid);
	}

	/* Remove sessions so they are not visible during deletion.*/
	cds_lfht_for_each_entry(lta->sessions->ht, &iter.iter, ua_sess,
			node.node) {
		ret = lttng_ht_del(lta->sessions, &iter);
		if (ret) {
			/* The session was already removed so scheduled for teardown. */
			continue;
		}

		/*
		 * Add session to list for teardown. This is safe since at this point we
		 * are the only one using this list.
		 */
		cds_list_add(&ua_sess->teardown_node, &lta->teardown_head);
	}

	/* Free memory */
	call_rcu(&lta->pid_n.head, delete_ust_app_rcu);

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
	count = lttng_ht_get_count(ust_app_ht);
	rcu_read_unlock();

	return count;
}

/*
 * Fill events array with all events name of all registered apps.
 */
int ust_app_list_events(struct lttng_event **events)
{
	int ret, handle;
	size_t nbmem, count = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;
	struct lttng_event *tmp_event;

	nbmem = UST_APP_EVENT_LIST_SIZE;
	tmp_event = zmalloc(nbmem * sizeof(struct lttng_event));
	if (tmp_event == NULL) {
		PERROR("zmalloc ust app events");
		ret = -ENOMEM;
		goto error;
	}

	rcu_read_lock();

	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		struct lttng_ust_tracepoint_iter uiter;

		health_code_update(&health_thread_cmd);

		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		handle = ustctl_tracepoint_list(app->sock);
		if (handle < 0) {
			ERR("UST app list events getting handle failed for app pid %d",
					app->pid);
			continue;
		}

		while ((ret = ustctl_tracepoint_list_get(app->sock, handle,
					&uiter)) != -LTTNG_UST_ERR_NOENT) {
			health_code_update(&health_thread_cmd);
			if (count >= nbmem) {
				/* In case the realloc fails, we free the memory */
				void *ptr;

				DBG2("Reallocating event list from %zu to %zu entries", nbmem,
						2 * nbmem);
				nbmem *= 2;
				ptr = realloc(tmp_event, nbmem * sizeof(struct lttng_event));
				if (ptr == NULL) {
					PERROR("realloc ust app events");
					free(tmp_event);
					ret = -ENOMEM;
					goto rcu_error;
				}
				tmp_event = ptr;
			}
			memcpy(tmp_event[count].name, uiter.name, LTTNG_UST_SYM_NAME_LEN);
			tmp_event[count].loglevel = uiter.loglevel;
			tmp_event[count].type = (enum lttng_event_type) LTTNG_UST_TRACEPOINT;
			tmp_event[count].pid = app->pid;
			tmp_event[count].enabled = -1;
			count++;
		}
	}

	ret = count;
	*events = tmp_event;

	DBG2("UST app list events done (%zu events)", count);

rcu_error:
	rcu_read_unlock();
error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Fill events array with all events name of all registered apps.
 */
int ust_app_list_event_fields(struct lttng_event_field **fields)
{
	int ret, handle;
	size_t nbmem, count = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;
	struct lttng_event_field *tmp_event;

	nbmem = UST_APP_EVENT_LIST_SIZE;
	tmp_event = zmalloc(nbmem * sizeof(struct lttng_event_field));
	if (tmp_event == NULL) {
		PERROR("zmalloc ust app event fields");
		ret = -ENOMEM;
		goto error;
	}

	rcu_read_lock();

	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		struct lttng_ust_field_iter uiter;

		health_code_update(&health_thread_cmd);

		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		handle = ustctl_tracepoint_field_list(app->sock);
		if (handle < 0) {
			ERR("UST app list event fields getting handle failed for app pid %d",
					app->pid);
			continue;
		}

		while ((ret = ustctl_tracepoint_field_list_get(app->sock, handle,
					&uiter)) != -LTTNG_UST_ERR_NOENT) {
			health_code_update(&health_thread_cmd);
			if (count >= nbmem) {
				/* In case the realloc fails, we free the memory */
				void *ptr;

				DBG2("Reallocating event field list from %zu to %zu entries", nbmem,
						2 * nbmem);
				nbmem *= 2;
				ptr = realloc(tmp_event, nbmem * sizeof(struct lttng_event_field));
				if (ptr == NULL) {
					PERROR("realloc ust app event fields");
					free(tmp_event);
					ret = -ENOMEM;
					goto rcu_error;
				}
				tmp_event = ptr;
			}

			memcpy(tmp_event[count].field_name, uiter.field_name, LTTNG_UST_SYM_NAME_LEN);
			tmp_event[count].type = uiter.type;
			tmp_event[count].nowrite = uiter.nowrite;

			memcpy(tmp_event[count].event.name, uiter.event_name, LTTNG_UST_SYM_NAME_LEN);
			tmp_event[count].event.loglevel = uiter.loglevel;
			tmp_event[count].event.type = LTTNG_UST_TRACEPOINT;
			tmp_event[count].event.pid = app->pid;
			tmp_event[count].event.enabled = -1;
			count++;
		}
	}

	ret = count;
	*fields = tmp_event;

	DBG2("UST app list event fields done (%zu events)", count);

rcu_error:
	rcu_read_unlock();
error:
	health_code_update(&health_thread_cmd);
	return ret;
}

/*
 * Free and clean all traceable apps of the global list.
 */
void ust_app_clean_list(void)
{
	int ret;
	struct ust_app *app;
	struct lttng_ht_iter iter;

	DBG2("UST app cleaning registered apps hash table");

	rcu_read_lock();

	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		ret = lttng_ht_del(ust_app_ht, &iter);
		assert(!ret);
		call_rcu(&app->pid_n.head, delete_ust_app_rcu);
	}

	/* Cleanup socket hash table */
	cds_lfht_for_each_entry(ust_app_ht_by_sock->ht, &iter.iter, app,
			sock_n.node) {
		ret = lttng_ht_del(ust_app_ht_by_sock, &iter);
		assert(!ret);
	}

	/* Destroy is done only when the ht is empty */
	lttng_ht_destroy(ust_app_ht);
	lttng_ht_destroy(ust_app_ht_by_sock);

	rcu_read_unlock();
}

/*
 * Init UST app hash table.
 */
void ust_app_ht_alloc(void)
{
	ust_app_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	ust_app_ht_by_sock = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
}

/*
 * For a specific UST session, disable the channel for all registered apps.
 */
int ust_app_disable_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;

	if (usess == NULL || uchan == NULL) {
		ERR("Disabling UST global channel with NULL values");
		ret = -1;
		goto error;
	}

	DBG2("UST app disabling channel %s from global domain for session id %d",
			uchan->name, usess->id);

	rcu_read_lock();

	/* For every registered applications */
	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		struct lttng_ht_iter uiter;
		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		ua_sess = lookup_session_by_app(usess, app);
		if (ua_sess == NULL) {
			continue;
		}

		/* Get channel */
		lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &uiter);
		ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
		/* If the session if found for the app, the channel must be there */
		assert(ua_chan_node);

		ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);
		/* The channel must not be already disabled */
		assert(ua_chan->enabled == 1);

		/* Disable channel onto application */
		ret = disable_ust_app_channel(ua_sess, ua_chan, app);
		if (ret < 0) {
			/* XXX: We might want to report this error at some point... */
			continue;
		}
	}

	rcu_read_unlock();

error:
	return ret;
}

/*
 * For a specific UST session, enable the channel for all registered apps.
 */
int ust_app_enable_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;
	struct ust_app_session *ua_sess;

	if (usess == NULL || uchan == NULL) {
		ERR("Adding UST global channel to NULL values");
		ret = -1;
		goto error;
	}

	DBG2("UST app enabling channel %s to global domain for session id %d",
			uchan->name, usess->id);

	rcu_read_lock();

	/* For every registered applications */
	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		ua_sess = lookup_session_by_app(usess, app);
		if (ua_sess == NULL) {
			continue;
		}

		/* Enable channel onto application */
		ret = enable_ust_app_channel(ua_sess, uchan, app);
		if (ret < 0) {
			/* XXX: We might want to report this error at some point... */
			continue;
		}
	}

	rcu_read_unlock();

error:
	return ret;
}

/*
 * Disable an event in a channel and for a specific session.
 */
int ust_app_disable_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent)
{
	int ret = 0;
	struct lttng_ht_iter iter, uiter;
	struct lttng_ht_node_str *ua_chan_node, *ua_event_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;

	DBG("UST app disabling event %s for all apps in channel "
			"%s for session id %d", uevent->attr.name, uchan->name, usess->id);

	rcu_read_lock();

	/* For all registered applications */
	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		ua_sess = lookup_session_by_app(usess, app);
		if (ua_sess == NULL) {
			/* Next app */
			continue;
		}

		/* Lookup channel in the ust app session */
		lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &uiter);
		ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
		if (ua_chan_node == NULL) {
			DBG2("Channel %s not found in session id %d for app pid %d."
					"Skipping", uchan->name, usess->id, app->pid);
			continue;
		}
		ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);

		lttng_ht_lookup(ua_chan->events, (void *)uevent->attr.name, &uiter);
		ua_event_node = lttng_ht_iter_get_node_str(&uiter);
		if (ua_event_node == NULL) {
			DBG2("Event %s not found in channel %s for app pid %d."
					"Skipping", uevent->attr.name, uchan->name, app->pid);
			continue;
		}
		ua_event = caa_container_of(ua_event_node, struct ust_app_event, node);

		ret = disable_ust_app_event(ua_sess, ua_event, app);
		if (ret < 0) {
			/* XXX: Report error someday... */
			continue;
		}
	}

	rcu_read_unlock();

	return ret;
}

/*
 * For a specific UST session and UST channel, the event for all
 * registered apps.
 */
int ust_app_disable_all_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	int ret = 0;
	struct lttng_ht_iter iter, uiter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;

	DBG("UST app disabling all event for all apps in channel "
			"%s for session id %d", uchan->name, usess->id);

	rcu_read_lock();

	/* For all registered applications */
	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		ua_sess = lookup_session_by_app(usess, app);
		if (!ua_sess) {
			/* The application has problem or is probably dead. */
			continue;
		}

		/* Lookup channel in the ust app session */
		lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &uiter);
		ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
		/* If the channel is not found, there is a code flow error */
		assert(ua_chan_node);

		ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);

		/* Disable each events of channel */
		cds_lfht_for_each_entry(ua_chan->events->ht, &uiter.iter, ua_event,
				node.node) {
			ret = disable_ust_app_event(ua_sess, ua_event, app);
			if (ret < 0) {
				/* XXX: Report error someday... */
				continue;
			}
		}
	}

	rcu_read_unlock();

	return ret;
}

/*
 * For a specific UST session, create the channel for all registered apps.
 */
int ust_app_create_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	int ret = 0, created;
	struct lttng_ht_iter iter;
	struct ust_app *app;
	struct ust_app_session *ua_sess = NULL;

	/* Very wrong code flow */
	assert(usess);
	assert(uchan);

	DBG2("UST app adding channel %s to global domain for session id %d",
			uchan->name, usess->id);

	rcu_read_lock();

	/* For every registered applications */
	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		/*
		 * Create session on the tracer side and add it to app session HT. Note
		 * that if session exist, it will simply return a pointer to the ust
		 * app session.
		 */
		ret = create_ust_app_session(usess, app, &ua_sess, &created);
		if (ret < 0) {
			switch (ret) {
			case -ENOTCONN:
				/*
				 * The application's socket is not valid. Either a bad socket
				 * or a timeout on it. We can't inform the caller that for a
				 * specific app, the session failed so lets continue here.
				 */
				continue;
			case -ENOMEM:
			default:
				goto error_rcu_unlock;
			}
		}
		assert(ua_sess);

		/* Create channel onto application. We don't need the chan ref. */
		ret = create_ust_app_channel(ua_sess, uchan, app, NULL);
		if (ret < 0) {
			if (ret == -ENOMEM) {
				/* No more memory is a fatal error. Stop right now. */
				goto error_rcu_unlock;
			}
			/* Cleanup the created session if it's the case. */
			if (created) {
				delete_ust_app_session(app->sock, ua_sess);
			}
		}
	}

error_rcu_unlock:
	rcu_read_unlock();
	return ret;
}

/*
 * Enable event for a specific session and channel on the tracer.
 */
int ust_app_enable_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent)
{
	int ret = 0;
	struct lttng_ht_iter iter, uiter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;

	DBG("UST app enabling event %s for all apps for session id %d",
			uevent->attr.name, usess->id);

	/*
	 * NOTE: At this point, this function is called only if the session and
	 * channel passed are already created for all apps. and enabled on the
	 * tracer also.
	 */

	rcu_read_lock();

	/* For all registered applications */
	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		ua_sess = lookup_session_by_app(usess, app);
		if (!ua_sess) {
			/* The application has problem or is probably dead. */
			continue;
		}

		/* Lookup channel in the ust app session */
		lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &uiter);
		ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
		/* If the channel is not found, there is a code flow error */
		assert(ua_chan_node);

		ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);

		/* Get event node */
		ua_event = find_ust_app_event(ua_chan->events, uevent->attr.name,
				uevent->filter, uevent->attr.loglevel);
		if (ua_event == NULL) {
			DBG3("UST app enable event %s not found for app PID %d."
					"Skipping app", uevent->attr.name, app->pid);
			continue;
		}

		ret = enable_ust_app_event(ua_sess, ua_event, app);
		if (ret < 0) {
			goto error;
		}
	}

error:
	rcu_read_unlock();
	return ret;
}

/*
 * For a specific existing UST session and UST channel, creates the event for
 * all registered apps.
 */
int ust_app_create_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent)
{
	int ret = 0;
	struct lttng_ht_iter iter, uiter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;

	DBG("UST app creating event %s for all apps for session id %d",
			uevent->attr.name, usess->id);

	rcu_read_lock();

	/* For all registered applications */
	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		ua_sess = lookup_session_by_app(usess, app);
		if (!ua_sess) {
			/* The application has problem or is probably dead. */
			continue;
		}

		/* Lookup channel in the ust app session */
		lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &uiter);
		ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
		/* If the channel is not found, there is a code flow error */
		assert(ua_chan_node);

		ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);

		ret = create_ust_app_event(ua_sess, ua_chan, uevent, app);
		if (ret < 0) {
			if (ret != -LTTNG_UST_ERR_EXIST) {
				/* Possible value at this point: -ENOMEM. If so, we stop! */
				break;
			}
			DBG2("UST app event %s already exist on app PID %d",
					uevent->attr.name, app->pid);
			continue;
		}
	}

	rcu_read_unlock();

	return ret;
}

/*
 * Start tracing for a specific UST session and app.
 */
int ust_app_start_trace(struct ltt_ust_session *usess, struct ust_app *app)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_stream *ustream;
	struct consumer_socket *socket;

	DBG("Starting tracing for ust app pid %d", app->pid);

	rcu_read_lock();

	if (!app->compatible) {
		goto end;
	}

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == NULL) {
		/* The session is in teardown process. Ignore and continue. */
		goto end;
	}

	/* Upon restart, we skip the setup, already done */
	if (ua_sess->started) {
		goto skip_setup;
	}

	/* Create directories if consumer is LOCAL and has a path defined. */
	if (usess->consumer->type == CONSUMER_DST_LOCAL &&
			strlen(usess->consumer->dst.trace_path) > 0) {
		ret = run_as_mkdir_recursive(usess->consumer->dst.trace_path,
				S_IRWXU | S_IRWXG, usess->uid, usess->gid);
		if (ret < 0) {
			if (ret != -EEXIST) {
				ERR("Trace directory creation error");
				ret = -1;
				goto error_rcu_unlock;
			}
		}
	}

	ret = create_ust_app_metadata(ua_sess, usess->pathname, app);
	if (ret < 0) {
		ret = LTTNG_ERR_UST_META_FAIL;
		goto error_rcu_unlock;
	}

	/* For each channel */
	cds_lfht_for_each_entry(ua_sess->channels->ht, &iter.iter, ua_chan,
			node.node) {
		/* Create all streams */
		while (1) {
			/* Create UST stream */
			ustream = alloc_ust_app_stream();
			if (ustream == NULL) {
				goto error_rcu_unlock;
			}

			health_code_update(&health_thread_cmd);

			ret = create_ust_stream(app, ua_chan, ustream);
			if (ret < 0) {
				/* Free unused memory after this point. */
				free(ustream);
				if (ret == -LTTNG_UST_ERR_NOENT) {
					/* Got all streams. Continue normal execution. */
					break;
				}
				/* Error at this point. Stop everything. */
				ret = LTTNG_ERR_UST_STREAM_FAIL;
				goto error_rcu_unlock;
			}

			health_code_update(&health_thread_cmd);

			/* Order is important this is why a list is used. */
			cds_list_add_tail(&ustream->list, &ua_chan->streams.head);
			ua_chan->streams.count++;

			DBG2("UST stream %d ready (handle: %d)", ua_chan->streams.count,
					ustream->handle);
		}

		health_code_update(&health_thread_cmd);
	}

	switch (app->bits_per_long) {
	case 64:
		socket = consumer_find_socket(uatomic_read(&ust_consumerd64_fd),
				usess->consumer);
		if (socket == NULL) {
			goto skip_setup;
		}
		break;
	case 32:
		socket = consumer_find_socket(uatomic_read(&ust_consumerd32_fd),
				usess->consumer);
		if (socket == NULL) {
			goto skip_setup;
		}
		break;
	default:
		ret = -EINVAL;
		goto error_rcu_unlock;
	}

	/* Setup UST consumer socket and send fds to it */
	ret = ust_consumer_send_session(ua_sess, usess->consumer, socket);
	if (ret < 0) {
		goto error_rcu_unlock;
	}

	health_code_update(&health_thread_cmd);

skip_setup:
	/* This start the UST tracing */
	ret = ustctl_start_session(app->sock, ua_sess->handle);
	if (ret < 0) {
		ERR("Error starting tracing for app pid: %d (ret: %d)", app->pid, ret);
		goto error_rcu_unlock;
	}

	/* Indicate that the session has been started once */
	ua_sess->started = 1;

	health_code_update(&health_thread_cmd);

	/* Quiescent wait after starting trace */
	ustctl_wait_quiescent(app->sock);

end:
	rcu_read_unlock();
	health_code_update(&health_thread_cmd);
	return 0;

error_rcu_unlock:
	rcu_read_unlock();
	health_code_update(&health_thread_cmd);
	return -1;
}

/*
 * Stop tracing for a specific UST session and app.
 */
int ust_app_stop_trace(struct ltt_ust_session *usess, struct ust_app *app)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;

	DBG("Stopping tracing for ust app pid %d", app->pid);

	rcu_read_lock();

	if (!app->compatible) {
		goto end;
	}

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == NULL) {
		goto end;
	}

	/*
	 * If started = 0, it means that stop trace has been called for a session
	 * that was never started. It's possible since we can have a fail start
	 * from either the application manager thread or the command thread. Simply
	 * indicate that this is a stop error.
	 */
	if (!ua_sess->started) {
		goto error_rcu_unlock;
	}

	health_code_update(&health_thread_cmd);

	/* This inhibits UST tracing */
	ret = ustctl_stop_session(app->sock, ua_sess->handle);
	if (ret < 0) {
		ERR("Error stopping tracing for app pid: %d (ret: %d)", app->pid, ret);
		goto error_rcu_unlock;
	}

	health_code_update(&health_thread_cmd);

	/* Quiescent wait after stopping trace */
	ustctl_wait_quiescent(app->sock);

	health_code_update(&health_thread_cmd);

	/* Flushing buffers */
	cds_lfht_for_each_entry(ua_sess->channels->ht, &iter.iter, ua_chan,
			node.node) {
		health_code_update(&health_thread_cmd);
		ret = ustctl_sock_flush_buffer(app->sock, ua_chan->obj);
		if (ret < 0) {
			ERR("UST app PID %d channel %s flush failed with ret %d",
					app->pid, ua_chan->name, ret);
			/* Continuing flushing all buffers */
			continue;
		}
	}

	health_code_update(&health_thread_cmd);

	/* Flush all buffers before stopping */
	ret = ustctl_sock_flush_buffer(app->sock, ua_sess->metadata->obj);
	if (ret < 0) {
		ERR("UST app PID %d metadata flush failed with ret %d", app->pid,
				ret);
	}

end:
	rcu_read_unlock();
	health_code_update(&health_thread_cmd);
	return 0;

error_rcu_unlock:
	rcu_read_unlock();
	health_code_update(&health_thread_cmd);
	return -1;
}

/*
 * Destroy a specific UST session in apps.
 */
static int destroy_trace(struct ltt_ust_session *usess, struct ust_app *app)
{
	struct ust_app_session *ua_sess;
	struct lttng_ust_object_data obj;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	int ret;

	DBG("Destroy tracing for ust app pid %d", app->pid);

	rcu_read_lock();

	if (!app->compatible) {
		goto end;
	}

	__lookup_session_by_app(usess, app, &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == NULL) {
		/* Session is being or is deleted. */
		goto end;
	}
	ua_sess = caa_container_of(node, struct ust_app_session, node);
	ret = lttng_ht_del(app->sessions, &iter);
	if (ret) {
		/* Already scheduled for teardown. */
		goto end;
	}

	obj.handle = ua_sess->handle;
	obj.shm_fd = -1;
	obj.wait_fd = -1;
	obj.memory_map_size = 0;
	health_code_update(&health_thread_cmd);
	ustctl_release_object(app->sock, &obj);

	health_code_update(&health_thread_cmd);
	delete_ust_app_session(app->sock, ua_sess);

	/* Quiescent wait after stopping trace */
	ustctl_wait_quiescent(app->sock);

end:
	rcu_read_unlock();
	health_code_update(&health_thread_cmd);
	return 0;
}

/*
 * Start tracing for the UST session.
 */
int ust_app_start_trace_all(struct ltt_ust_session *usess)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;

	DBG("Starting all UST traces");

	rcu_read_lock();

	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		ret = ust_app_start_trace(usess, app);
		if (ret < 0) {
			/* Continue to next apps even on error */
			continue;
		}
	}

	rcu_read_unlock();

	return 0;
}

/*
 * Start tracing for the UST session.
 */
int ust_app_stop_trace_all(struct ltt_ust_session *usess)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;

	DBG("Stopping all UST traces");

	rcu_read_lock();

	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		ret = ust_app_stop_trace(usess, app);
		if (ret < 0) {
			/* Continue to next apps even on error */
			continue;
		}
	}

	rcu_read_unlock();

	return 0;
}

/*
 * Destroy app UST session.
 */
int ust_app_destroy_trace_all(struct ltt_ust_session *usess)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;

	DBG("Destroy all UST traces");

	rcu_read_lock();

	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		ret = destroy_trace(usess, app);
		if (ret < 0) {
			/* Continue to next apps even on error */
			continue;
		}
	}

	rcu_read_unlock();

	return 0;
}

/*
 * Add channels/events from UST global domain to registered apps at sock.
 */
void ust_app_global_update(struct ltt_ust_session *usess, int sock)
{
	int ret = 0;
	struct lttng_ht_iter iter, uiter, iter_ctx;
	struct ust_app *app;
	struct ust_app_session *ua_sess = NULL;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;
	struct ust_app_ctx *ua_ctx;

	assert(usess);

	DBG2("UST app global update for app sock %d for session id %d", sock,
			usess->id);

	rcu_read_lock();

	app = find_app_by_sock(sock);
	if (app == NULL) {
		ERR("Failed to update app sock %d", sock);
		goto error;
	}

	if (!app->compatible) {
		goto error;
	}

	ret = create_ust_app_session(usess, app, &ua_sess, NULL);
	if (ret < 0) {
		/* Tracer is probably gone or ENOMEM. */
		goto error;
	}
	assert(ua_sess);

	/*
	 * We can iterate safely here over all UST app session sicne the create ust
	 * app session above made a shadow copy of the UST global domain from the
	 * ltt ust session.
	 */
	cds_lfht_for_each_entry(ua_sess->channels->ht, &iter.iter, ua_chan,
			node.node) {
		ret = create_ust_channel(app, ua_sess, ua_chan);
		if (ret < 0) {
			/* FIXME: Should we quit here or continue... */
			continue;
		}

		cds_lfht_for_each_entry(ua_chan->ctx->ht, &iter_ctx.iter, ua_ctx,
				node.node) {
			ret = create_ust_channel_context(ua_chan, ua_ctx, app);
			if (ret < 0) {
				/* FIXME: Should we quit here or continue... */
				continue;
			}
		}


		/* For each events */
		cds_lfht_for_each_entry(ua_chan->events->ht, &uiter.iter, ua_event,
				node.node) {
			ret = create_ust_event(app, ua_sess, ua_chan, ua_event);
			if (ret < 0) {
				/* FIXME: Should we quit here or continue... */
				continue;
			}
		}
	}

	if (usess->start_trace) {
		ret = ust_app_start_trace(usess, app);
		if (ret < 0) {
			goto error;
		}

		DBG2("UST trace started for app pid %d", app->pid);
	}

error:
	rcu_read_unlock();
	return;
}

/*
 * Add context to a specific channel for global UST domain.
 */
int ust_app_add_ctx_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_context *uctx)
{
	int ret = 0;
	struct lttng_ht_node_str *ua_chan_node;
	struct lttng_ht_iter iter, uiter;
	struct ust_app_channel *ua_chan = NULL;
	struct ust_app_session *ua_sess;
	struct ust_app *app;

	rcu_read_lock();

	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}
		ua_sess = lookup_session_by_app(usess, app);
		if (ua_sess == NULL) {
			continue;
		}

		/* Lookup channel in the ust app session */
		lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &uiter);
		ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
		if (ua_chan_node == NULL) {
			continue;
		}
		ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel,
				node);

		ret = create_ust_app_channel_context(ua_sess, ua_chan, &uctx->ctx, app);
		if (ret < 0) {
			continue;
		}
	}

	rcu_read_unlock();
	return ret;
}

/*
 * Enable event for a channel from a UST session for a specific PID.
 */
int ust_app_enable_event_pid(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent, pid_t pid)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;

	DBG("UST app enabling event %s for PID %d", uevent->attr.name, pid);

	rcu_read_lock();

	app = ust_app_find_by_pid(pid);
	if (app == NULL) {
		ERR("UST app enable event per PID %d not found", pid);
		ret = -1;
		goto error;
	}

	if (!app->compatible) {
		ret = 0;
		goto error;
	}

	ua_sess = lookup_session_by_app(usess, app);
	if (!ua_sess) {
		/* The application has problem or is probably dead. */
		goto error;
	}

	/* Lookup channel in the ust app session */
	lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &iter);
	ua_chan_node = lttng_ht_iter_get_node_str(&iter);
	/* If the channel is not found, there is a code flow error */
	assert(ua_chan_node);

	ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);

	ua_event = find_ust_app_event(ua_chan->events, uevent->attr.name,
			uevent->filter, uevent->attr.loglevel);
	if (ua_event == NULL) {
		ret = create_ust_app_event(ua_sess, ua_chan, uevent, app);
		if (ret < 0) {
			goto error;
		}
	} else {
		ret = enable_ust_app_event(ua_sess, ua_event, app);
		if (ret < 0) {
			goto error;
		}
	}

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Disable event for a channel from a UST session for a specific PID.
 */
int ust_app_disable_event_pid(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent, pid_t pid)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node, *ua_event_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;

	DBG("UST app disabling event %s for PID %d", uevent->attr.name, pid);

	rcu_read_lock();

	app = ust_app_find_by_pid(pid);
	if (app == NULL) {
		ERR("UST app disable event per PID %d not found", pid);
		ret = -1;
		goto error;
	}

	if (!app->compatible) {
		ret = 0;
		goto error;
	}

	ua_sess = lookup_session_by_app(usess, app);
	if (!ua_sess) {
		/* The application has problem or is probably dead. */
		goto error;
	}

	/* Lookup channel in the ust app session */
	lttng_ht_lookup(ua_sess->channels, (void *)uchan->name, &iter);
	ua_chan_node = lttng_ht_iter_get_node_str(&iter);
	if (ua_chan_node == NULL) {
		/* Channel does not exist, skip disabling */
		goto error;
	}
	ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);

	lttng_ht_lookup(ua_chan->events, (void *)uevent->attr.name, &iter);
	ua_event_node = lttng_ht_iter_get_node_str(&iter);
	if (ua_event_node == NULL) {
		/* Event does not exist, skip disabling */
		goto error;
	}
	ua_event = caa_container_of(ua_event_node, struct ust_app_event, node);

	ret = disable_ust_app_event(ua_sess, ua_event, app);
	if (ret < 0) {
		goto error;
	}

error:
	rcu_read_unlock();
	return ret;
}

/*
 * Validate version of UST apps and set the compatible bit.
 */
int ust_app_validate_version(int sock)
{
	int ret;
	struct ust_app *app;

	rcu_read_lock();

	app = find_app_by_sock(sock);
	assert(app);

	health_code_update(&health_thread_cmd);

	ret = ustctl_tracer_version(sock, &app->version);
	if (ret < 0) {
		goto error;
	}

	/* Validate version */
	if (app->version.major != UST_APP_MAJOR_VERSION) {
		goto error;
	}

	DBG2("UST app PID %d is compatible with internal major version %d "
			"(supporting == %d)", app->pid, app->version.major,
			UST_APP_MAJOR_VERSION);
	app->compatible = 1;
	rcu_read_unlock();
	health_code_update(&health_thread_cmd);
	return 0;

error:
	DBG2("UST app PID %d is not compatible with internal major version %d "
			"(supporting == %d)", app->pid, app->version.major,
			UST_APP_MAJOR_VERSION);
	app->compatible = 0;
	rcu_read_unlock();
	health_code_update(&health_thread_cmd);
	return -1;
}

/*
 * Calibrate registered applications.
 */
int ust_app_calibrate_glb(struct lttng_ust_calibrate *calibrate)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;

	rcu_read_lock();

	cds_lfht_for_each_entry(ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}

		health_code_update(&health_thread_cmd);

		ret = ustctl_calibrate(app->sock, calibrate);
		if (ret < 0) {
			switch (ret) {
			case -ENOSYS:
				/* Means that it's not implemented on the tracer side. */
				ret = 0;
				break;
			default:
				/* TODO: Report error to user */
				DBG2("Calibrate app PID %d returned with error %d",
						app->pid, ret);
				break;
			}
		}
	}

	DBG("UST app global domain calibration finished");

	rcu_read_unlock();

	health_code_update(&health_thread_cmd);

	return ret;
}
