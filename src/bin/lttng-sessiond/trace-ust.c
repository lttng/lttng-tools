/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <common/lttngerr.h>
#include <common/lttng-share.h>

#include "trace-ust.h"

/*
 * Find the channel in the hashtable.
 */
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht,
		char *name)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	rcu_read_lock();
	lttng_ht_lookup(ht, (void *)name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		rcu_read_unlock();
		goto error;
	}
	rcu_read_unlock();

	DBG2("Trace UST channel %s found by name", name);

	return caa_container_of(node, struct ltt_ust_channel, node);

error:
	DBG2("Trace UST channel %s not found by name", name);
	return NULL;
}

/*
 * Find the event in the hashtable.
 */
struct ltt_ust_event *trace_ust_find_event_by_name(struct lttng_ht *ht,
		char *name)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	rcu_read_lock();
	lttng_ht_lookup(ht, (void *) name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		rcu_read_unlock();
		goto error;
	}
	rcu_read_unlock();

	DBG2("Trace UST event found by name %s", name);

	return caa_container_of(node, struct ltt_ust_event, node);

error:
	DBG2("Trace UST event NOT found by name %s", name);
	return NULL;
}

/*
 * Allocate and initialize a ust session data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_session *trace_ust_create_session(char *path, int session_id,
		struct lttng_domain *domain)
{
	int ret;
	struct ltt_ust_session *lus;

	/* Allocate a new ltt ust session */
	lus = zmalloc(sizeof(struct ltt_ust_session));
	if (lus == NULL) {
		PERROR("create ust session zmalloc");
		goto error;
	}

	/* Init data structure */
	lus->id = session_id;
	lus->start_trace = 0;

	/* Alloc UST domain hash tables */
	lus->domain_pid = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	lus->domain_exec = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);

	/* Alloc UST global domain channels' HT */
	lus->domain_global.channels = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);

	/* Set session path */
	ret = snprintf(lus->pathname, PATH_MAX, "%s/ust", path);
	if (ret < 0) {
		PERROR("snprintf kernel traces path");
		goto error_free_session;
	}

	DBG2("UST trace session create successful");

	return lus;

error_free_session:
	free(lus);
error:
	return NULL;
}

/*
 * Allocate and initialize a ust channel data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *chan,
		char *path)
{
	int ret;
	struct ltt_ust_channel *luc;

	luc = zmalloc(sizeof(struct ltt_ust_channel));
	if (luc == NULL) {
		perror("ltt_ust_channel zmalloc");
		goto error;
	}

	/* Copy UST channel attributes */
	luc->attr.overwrite = chan->attr.overwrite;
	luc->attr.subbuf_size = chan->attr.subbuf_size;
	luc->attr.num_subbuf = chan->attr.num_subbuf;
	luc->attr.switch_timer_interval = chan->attr.switch_timer_interval;
	luc->attr.read_timer_interval = chan->attr.read_timer_interval;
	luc->attr.output = chan->attr.output;

	/* Translate to UST output enum */
	switch (luc->attr.output) {
	default:
		luc->attr.output = LTTNG_UST_MMAP;
		break;
	}

	/* Copy channel name */
	strncpy(luc->name, chan->name, sizeof(luc->name));
	luc->name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';

	/* Init node */
	lttng_ht_node_init_str(&luc->node, luc->name);
	/* Alloc hash tables */
	luc->events = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	luc->ctx = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);

	/* Set trace output path */
	ret = snprintf(luc->pathname, PATH_MAX, "%s", path);
	if (ret < 0) {
		perror("asprintf ust create channel");
		goto error_free_channel;
	}

	DBG2("Trace UST channel %s created", luc->name);

	return luc;

error_free_channel:
	free(luc);
error:
	return NULL;
}

/*
 * Allocate and initialize a ust event. Set name and event type.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_event *trace_ust_create_event(struct lttng_event *ev)
{
	struct ltt_ust_event *lue;

	lue = zmalloc(sizeof(struct ltt_ust_event));
	if (lue == NULL) {
		PERROR("ust event zmalloc");
		goto error;
	}

	switch (ev->type) {
	case LTTNG_EVENT_PROBE:
		lue->attr.instrumentation = LTTNG_UST_PROBE;
		break;
	case LTTNG_EVENT_FUNCTION:
		lue->attr.instrumentation = LTTNG_UST_FUNCTION;
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		lue->attr.instrumentation = LTTNG_UST_FUNCTION;
		break;
	case LTTNG_EVENT_TRACEPOINT:
		lue->attr.instrumentation = LTTNG_UST_TRACEPOINT;
		break;
	case LTTNG_EVENT_TRACEPOINT_LOGLEVEL:
		lue->attr.instrumentation = LTTNG_UST_TRACEPOINT_LOGLEVEL;
		break;
	default:
		ERR("Unknown ust instrumentation type (%d)", ev->type);
		goto error_free_event;
	}

	/* Copy event name */
	strncpy(lue->attr.name, ev->name, LTTNG_UST_SYM_NAME_LEN);
	lue->attr.name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';

	/* Init node */
	lttng_ht_node_init_str(&lue->node, lue->attr.name);
	/* Alloc context hash tables */
	lue->ctx = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);

	DBG2("Trace UST event %s created", lue->attr.name);

	return lue;

error_free_event:
	free(lue);
error:
	return NULL;
}

/*
 * Allocate and initialize a ust metadata.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_metadata *trace_ust_create_metadata(char *path)
{
	int ret;
	struct ltt_ust_metadata *lum;

	lum = zmalloc(sizeof(struct ltt_ust_metadata));
	if (lum == NULL) {
		perror("ust metadata zmalloc");
		goto error;
	}

	/* Set default attributes */
	lum->attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	lum->attr.subbuf_size = DEFAULT_METADATA_SUBBUF_SIZE;
	lum->attr.num_subbuf = DEFAULT_METADATA_SUBBUF_NUM;
	lum->attr.switch_timer_interval = DEFAULT_CHANNEL_SWITCH_TIMER;
	lum->attr.read_timer_interval = DEFAULT_CHANNEL_READ_TIMER;
	lum->attr.output = LTTNG_UST_MMAP;

	lum->handle = -1;
	/* Set metadata trace path */
	ret = snprintf(lum->pathname, PATH_MAX, "%s/metadata", path);
	if (ret < 0) {
		perror("asprintf ust metadata");
		goto error_free_metadata;
	}

	return lum;

error_free_metadata:
	free(lum);
error:
	return NULL;
}

/*
 * Allocate and initialize an UST context.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_context *trace_ust_create_context(
		struct lttng_event_context *ctx)
{
	struct ltt_ust_context *uctx;

	uctx = zmalloc(sizeof(struct ltt_ust_context));
	if (uctx == NULL) {
		PERROR("zmalloc ltt_ust_context");
		goto error;
	}

	uctx->ctx.ctx = ctx->ctx;
	lttng_ht_node_init_ulong(&uctx->node, (unsigned long) uctx->ctx.ctx);

	return uctx;

error:
	return NULL;
}

/*
 * RCU safe free context structure.
 */
static void destroy_context_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		caa_container_of(head, struct lttng_ht_node_ulong, head);
	struct ltt_ust_context *ctx =
		caa_container_of(node, struct ltt_ust_context, node);

	free(ctx);
}

/*
 * Cleanup UST context hash table.
 */
static void destroy_contexts(struct lttng_ht *ht)
{
	int ret;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	cds_lfht_for_each_entry(ht->ht, &iter.iter, node, node) {
		ret = lttng_ht_del(ht, &iter);
		if (!ret) {
			call_rcu(&node->head, destroy_context_rcu);
		}
	}

	lttng_ht_destroy(ht);
}

/*
 * Cleanup ust event structure.
 */
void trace_ust_destroy_event(struct ltt_ust_event *event)
{
	DBG2("Trace destroy UST event %s", event->attr.name);
	destroy_contexts(event->ctx);

	free(event);
}

/*
 * URCU intermediate call to complete destroy event.
 */
static void destroy_event_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_str *node =
		caa_container_of(head, struct lttng_ht_node_str, head);
	struct ltt_ust_event *event =
		caa_container_of(node, struct ltt_ust_event, node);

	trace_ust_destroy_event(event);
}

/*
 * Cleanup UST events hashtable.
 */
static void destroy_events(struct lttng_ht *events)
{
	int ret;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	cds_lfht_for_each_entry(events->ht, &iter.iter, node, node) {
		ret = lttng_ht_del(events, &iter);
		assert(!ret);
		call_rcu(&node->head, destroy_event_rcu);
	}

	lttng_ht_destroy(events);
}

/*
 * Cleanup ust channel structure.
 */
void trace_ust_destroy_channel(struct ltt_ust_channel *channel)
{
	DBG2("Trace destroy UST channel %s", channel->name);

	rcu_read_lock();

	/* Destroying all events of the channel */
	destroy_events(channel->events);
	/* Destroying all context of the channel */
	destroy_contexts(channel->ctx);

	free(channel);

	rcu_read_unlock();
}

/*
 * URCU intermediate call to complete destroy channel.
 */
static void destroy_channel_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_str *node =
		caa_container_of(head, struct lttng_ht_node_str, head);
	struct ltt_ust_channel *channel =
		caa_container_of(node, struct ltt_ust_channel, node);

	trace_ust_destroy_channel(channel);
}

/*
 * Cleanup ust metadata structure.
 */
void trace_ust_destroy_metadata(struct ltt_ust_metadata *metadata)
{
	DBG2("Trace UST destroy metadata %d", metadata->handle);

	free(metadata);
}

/*
 * Iterate over a hash table containing channels and cleanup safely.
 */
static void destroy_channels(struct lttng_ht *channels)
{
	int ret;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	rcu_read_lock();

	cds_lfht_for_each_entry(channels->ht, &iter.iter, node, node) {
		ret = lttng_ht_del(channels, &iter);
		assert(!ret);
		call_rcu(&node->head, destroy_channel_rcu);
	}

	lttng_ht_destroy(channels);

	rcu_read_unlock();
}

/*
 * Cleanup UST pid domain.
 */
static void destroy_domain_pid(struct lttng_ht *ht)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ltt_ust_domain_pid *dpid;

	cds_lfht_for_each_entry(ht->ht, &iter.iter, dpid, node.node) {
		ret = lttng_ht_del(ht , &iter);
		assert(!ret);
		destroy_channels(dpid->channels);
	}

	lttng_ht_destroy(ht);
}

/*
 * Cleanup UST exec name domain.
 */
static void destroy_domain_exec(struct lttng_ht *ht)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ltt_ust_domain_exec *dexec;

	cds_lfht_for_each_entry(ht->ht, &iter.iter, dexec, node.node) {
		ret = lttng_ht_del(ht , &iter);
		assert(!ret);
		destroy_channels(dexec->channels);
	}

	lttng_ht_destroy(ht);
}

/*
 * Cleanup UST global domain.
 */
static void destroy_domain_global(struct ltt_ust_domain_global *dom)
{
	destroy_channels(dom->channels);
}

/*
 * Cleanup ust session structure
 */
void trace_ust_destroy_session(struct ltt_ust_session *session)
{
	/* Extra protection */
	if (session == NULL) {
		return;
	}

	rcu_read_lock();

	DBG2("Trace UST destroy session %d", session->id);

	/* Cleaning up UST domain */
	destroy_domain_global(&session->domain_global);
	destroy_domain_pid(session->domain_pid);
	destroy_domain_exec(session->domain_exec);

	free(session);

	rcu_read_unlock();
}
