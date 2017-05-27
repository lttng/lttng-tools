/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <common/common.h>
#include <common/defaults.h>

#include "buffer-registry.h"
#include "trace-ust.h"
#include "utils.h"
#include "ust-app.h"
#include "agent.h"

/*
 * Match function for the events hash table lookup.
 *
 * Matches by name only. Used by the disable command.
 */
int trace_ust_ht_match_event_by_name(struct cds_lfht_node *node,
		const void *_key)
{
	struct ltt_ust_event *event;
	const char *name;

	assert(node);
	assert(_key);

	event = caa_container_of(node, struct ltt_ust_event, node.node);
	name = _key;

	/* Event name */
	if (strncmp(event->attr.name, name, sizeof(event->attr.name)) != 0) {
		goto no_match;
	}

	/* Match */
	return 1;

no_match:
	return 0;
}

/*
 * Match function for the hash table lookup.
 *
 * It matches an ust event based on three attributes which are the event name,
 * the filter bytecode and the loglevel.
 */
int trace_ust_ht_match_event(struct cds_lfht_node *node, const void *_key)
{
	struct ltt_ust_event *event;
	const struct ltt_ust_ht_key *key;
	int ev_loglevel_value;
	int ll_match;

	assert(node);
	assert(_key);

	event = caa_container_of(node, struct ltt_ust_event, node.node);
	key = _key;
	ev_loglevel_value = event->attr.loglevel;

	/* Match the 4 elements of the key: name, filter, loglevel, exclusions. */

	/* Event name */
	if (strncmp(event->attr.name, key->name, sizeof(event->attr.name)) != 0) {
		goto no_match;
	}

	/* Event loglevel value and type. */
	ll_match = loglevels_match(event->attr.loglevel_type,
		ev_loglevel_value, key->loglevel_type,
		key->loglevel_value, LTTNG_UST_LOGLEVEL_ALL);

	if (!ll_match) {
		goto no_match;
	}

	/* Only one of the filters is NULL, fail. */
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

	/* If only one of the exclusions is NULL, fail. */
	if ((key->exclusion && !event->exclusion) || (!key->exclusion && event->exclusion)) {
		goto no_match;
	}

	if (key->exclusion && event->exclusion) {
		size_t i;

		/* Check exclusion counts first. */
		if (event->exclusion->count != key->exclusion->count) {
			goto no_match;
		}

		/* Compare names individually. */
		for (i = 0; i < event->exclusion->count; ++i) {
			size_t j;
		        bool found = false;
			const char *name_ev =
				LTTNG_EVENT_EXCLUSION_NAME_AT(
					event->exclusion, i);

			/*
			 * Compare this exclusion name to all the key's
			 * exclusion names.
			 */
			for (j = 0; j < key->exclusion->count; ++j) {
				const char *name_key =
					LTTNG_EVENT_EXCLUSION_NAME_AT(
						key->exclusion, j);

				if (!strncmp(name_ev, name_key,
						LTTNG_SYMBOL_NAME_LEN)) {
					/* Names match! */
					found = true;
					break;
				}
			}

			/*
			 * If the current exclusion name was not found amongst
			 * the key's exclusion names, then there's no match.
			 */
			if (!found) {
				goto no_match;
			}
		}
	}
	/* Match. */
	return 1;

no_match:
	return 0;
}

/*
 * Find the channel in the hashtable and return channel pointer. RCU read side
 * lock MUST be acquired before calling this.
 */
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht,
		char *name)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	/*
	 * If we receive an empty string for channel name, it means the
	 * default channel name is requested.
	 */
	if (name[0] == '\0')
		name = DEFAULT_CHANNEL_NAME;

	lttng_ht_lookup(ht, (void *)name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		goto error;
	}

	DBG2("Trace UST channel %s found by name", name);

	return caa_container_of(node, struct ltt_ust_channel, node);

error:
	DBG2("Trace UST channel %s not found by name", name);
	return NULL;
}

/*
 * Find the event in the hashtable and return event pointer. RCU read side lock
 * MUST be acquired before calling this.
 */
struct ltt_ust_event *trace_ust_find_event(struct lttng_ht *ht,
		char *name, struct lttng_filter_bytecode *filter,
		enum lttng_ust_loglevel_type loglevel_type, int loglevel_value,
		struct lttng_event_exclusion *exclusion)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct ltt_ust_ht_key key;

	assert(name);
	assert(ht);

	key.name = name;
	key.filter = filter;
	key.loglevel_type = loglevel_type;
	key.loglevel_value = loglevel_value;
	key.exclusion = exclusion;

	cds_lfht_lookup(ht->ht, ht->hash_fct((void *) name, lttng_ht_seed),
			trace_ust_ht_match_event, &key, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == NULL) {
		goto error;
	}

	DBG2("Trace UST event %s found", key.name);

	return caa_container_of(node, struct ltt_ust_event, node);

error:
	DBG2("Trace UST event %s NOT found", key.name);
	return NULL;
}

/*
 * Lookup an agent in the session agents hash table by domain type and return
 * the object if found else NULL.
 *
 * RCU read side lock must be acquired before calling and only released
 * once the agent is no longer in scope or being used.
 */
struct agent *trace_ust_find_agent(struct ltt_ust_session *session,
		enum lttng_domain_type domain_type)
{
	struct agent *agt = NULL;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	uint64_t key;

	assert(session);

	DBG3("Trace ust agent lookup for domain %d", domain_type);

	key = domain_type;

	lttng_ht_lookup(session->agents, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		goto end;
	}
	agt = caa_container_of(node, struct agent, node);

end:
	return agt;
}

/*
 * Allocate and initialize a ust session data structure.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_session *trace_ust_create_session(uint64_t session_id)
{
	struct ltt_ust_session *lus;

	/* Allocate a new ltt ust session */
	lus = zmalloc(sizeof(struct ltt_ust_session));
	if (lus == NULL) {
		PERROR("create ust session zmalloc");
		goto error;
	}

	/* Init data structure */
	lus->id = session_id;
	lus->active = 0;

	/* Set default metadata channel attribute. */
	lus->metadata_attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	lus->metadata_attr.subbuf_size = default_get_metadata_subbuf_size();
	lus->metadata_attr.num_subbuf = DEFAULT_METADATA_SUBBUF_NUM;
	lus->metadata_attr.switch_timer_interval = DEFAULT_METADATA_SWITCH_TIMER;
	lus->metadata_attr.read_timer_interval = DEFAULT_METADATA_READ_TIMER;
	lus->metadata_attr.output = LTTNG_UST_MMAP;

	/*
	 * Default buffer type. This can be changed through an enable channel
	 * requesting a different type. Note that this can only be changed once
	 * during the session lifetime which is at the first enable channel and
	 * only before start. The flag buffer_type_changed indicates the status.
	 */
	lus->buffer_type = LTTNG_BUFFER_PER_UID;
	/* Once set to 1, the buffer_type is immutable for the session. */
	lus->buffer_type_changed = 0;
	/* Init it in case it get used after allocation. */
	CDS_INIT_LIST_HEAD(&lus->buffer_reg_uid_list);

	/* Alloc UST global domain channels' HT */
	lus->domain_global.channels = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	/* Alloc agent hash table. */
	lus->agents = lttng_ht_new(0, LTTNG_HT_TYPE_U64);

	lus->consumer = consumer_create_output(CONSUMER_DST_LOCAL);
	if (lus->consumer == NULL) {
		goto error_consumer;
	}

	DBG2("UST trace session create successful");

	return lus;

error_consumer:
	ht_cleanup_push(lus->domain_global.channels);
	ht_cleanup_push(lus->agents);
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
		enum lttng_domain_type domain)
{
	struct ltt_ust_channel *luc;

	assert(chan);

	luc = zmalloc(sizeof(struct ltt_ust_channel));
	if (luc == NULL) {
		PERROR("ltt_ust_channel zmalloc");
		goto error;
	}

	luc->domain = domain;

	/* Copy UST channel attributes */
	luc->attr.overwrite = chan->attr.overwrite;
	luc->attr.subbuf_size = chan->attr.subbuf_size;
	luc->attr.num_subbuf = chan->attr.num_subbuf;
	luc->attr.switch_timer_interval = chan->attr.switch_timer_interval;
	luc->attr.read_timer_interval = chan->attr.read_timer_interval;
	luc->attr.output = (enum lttng_ust_output) chan->attr.output;
	luc->monitor_timer_interval = ((struct lttng_channel_extended *)
			chan->attr.extended.ptr)->monitor_timer_interval;
	luc->attr.u.s.blocking_timeout = ((struct lttng_channel_extended *)
			chan->attr.extended.ptr)->blocking_timeout;

	/* Translate to UST output enum */
	switch (luc->attr.output) {
	default:
		luc->attr.output = LTTNG_UST_MMAP;
		break;
	}

	/*
	 * If we receive an empty string for channel name, it means the
	 * default channel name is requested.
	 */
	if (chan->name[0] == '\0') {
		strncpy(luc->name, DEFAULT_CHANNEL_NAME, sizeof(luc->name));
	} else {
		/* Copy channel name */
		strncpy(luc->name, chan->name, sizeof(luc->name));
	}
	luc->name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';

	/* Init node */
	lttng_ht_node_init_str(&luc->node, luc->name);
	CDS_INIT_LIST_HEAD(&luc->ctx_list);

	/* Alloc hash tables */
	luc->events = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	luc->ctx = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);

	/* On-disk circular buffer parameters */
	luc->tracefile_size = chan->attr.tracefile_size;
	luc->tracefile_count = chan->attr.tracefile_count;

	DBG2("Trace UST channel %s created", luc->name);

error:
	return luc;
}

/*
 * Validates an exclusion list.
 *
 * Returns 0 if valid, negative value if invalid.
 */
static int validate_exclusion(struct lttng_event_exclusion *exclusion)
{
	size_t i;
	int ret = 0;

	assert(exclusion);

	for (i = 0; i < exclusion->count; ++i) {
		size_t j;
		const char *name_a =
			LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, i);

		for (j = 0; j < i; ++j) {
			const char *name_b =
				LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, j);

			if (!strncmp(name_a, name_b, LTTNG_SYMBOL_NAME_LEN)) {
				/* Match! */
				ret = -1;
				goto end;
			}
		}
	}

end:
	return ret;
}

/*
 * Allocate and initialize a ust event. Set name and event type.
 * We own filter_expression, filter, and exclusion.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_event *trace_ust_create_event(struct lttng_event *ev,
		char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		bool internal_event)
{
	struct ltt_ust_event *lue;

	assert(ev);

	if (exclusion && validate_exclusion(exclusion)) {
		goto error;
	}

	lue = zmalloc(sizeof(struct ltt_ust_event));
	if (lue == NULL) {
		PERROR("ust event zmalloc");
		goto error;
	}

	lue->internal = internal_event;

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
	default:
		ERR("Unknown ust instrumentation type (%d)", ev->type);
		goto error_free_event;
	}

	/* Copy event name */
	strncpy(lue->attr.name, ev->name, LTTNG_UST_SYM_NAME_LEN);
	lue->attr.name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';

	switch (ev->loglevel_type) {
	case LTTNG_EVENT_LOGLEVEL_ALL:
		lue->attr.loglevel_type = LTTNG_UST_LOGLEVEL_ALL;
		lue->attr.loglevel = -1;	/* Force to -1 */
		break;
	case LTTNG_EVENT_LOGLEVEL_RANGE:
		lue->attr.loglevel_type = LTTNG_UST_LOGLEVEL_RANGE;
		lue->attr.loglevel = ev->loglevel;
		break;
	case LTTNG_EVENT_LOGLEVEL_SINGLE:
		lue->attr.loglevel_type = LTTNG_UST_LOGLEVEL_SINGLE;
		lue->attr.loglevel = ev->loglevel;
		break;
	default:
		ERR("Unknown ust loglevel type (%d)", ev->loglevel_type);
		goto error_free_event;
	}

	/* Same layout. */
	lue->filter_expression = filter_expression;
	lue->filter = filter;
	lue->exclusion = exclusion;

	/* Init node */
	lttng_ht_node_init_str(&lue->node, lue->attr.name);

	DBG2("Trace UST event %s, loglevel (%d,%d) created",
		lue->attr.name, lue->attr.loglevel_type,
		lue->attr.loglevel);

	return lue;

error_free_event:
	free(lue);
error:
	free(filter_expression);
	free(filter);
	free(exclusion);
	return NULL;
}

static
int trace_ust_context_type_event_to_ust(
		enum lttng_event_context_type type)
{
	int utype;

	switch (type) {
	case LTTNG_EVENT_CONTEXT_VTID:
		utype = LTTNG_UST_CONTEXT_VTID;
		break;
	case LTTNG_EVENT_CONTEXT_VPID:
		utype = LTTNG_UST_CONTEXT_VPID;
		break;
	case LTTNG_EVENT_CONTEXT_PTHREAD_ID:
		utype = LTTNG_UST_CONTEXT_PTHREAD_ID;
		break;
	case LTTNG_EVENT_CONTEXT_PROCNAME:
		utype = LTTNG_UST_CONTEXT_PROCNAME;
		break;
	case LTTNG_EVENT_CONTEXT_IP:
		utype = LTTNG_UST_CONTEXT_IP;
		break;
	case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
		if (!ustctl_has_perf_counters()) {
			utype = -1;
			WARN("Perf counters not implemented in UST");
		} else {
			utype = LTTNG_UST_CONTEXT_PERF_THREAD_COUNTER;
		}
		break;
	case LTTNG_EVENT_CONTEXT_APP_CONTEXT:
		utype = LTTNG_UST_CONTEXT_APP_CONTEXT;
		break;
	default:
		utype = -1;
		break;
	}
	return utype;
}

/*
 * Return 1 if contexts match, 0 otherwise.
 */
int trace_ust_match_context(struct ltt_ust_context *uctx,
		struct lttng_event_context *ctx)
{
	int utype;

	utype = trace_ust_context_type_event_to_ust(ctx->ctx);
	if (utype < 0) {
		return 0;
	}
	if (uctx->ctx.ctx != utype) {
		return 0;
	}
	switch (utype) {
	case LTTNG_UST_CONTEXT_PERF_THREAD_COUNTER:
		if (uctx->ctx.u.perf_counter.type
				!= ctx->u.perf_counter.type) {
			return 0;
		}
		if (uctx->ctx.u.perf_counter.config
				!= ctx->u.perf_counter.config) {
			return 0;
		}
		if (strncmp(uctx->ctx.u.perf_counter.name,
				ctx->u.perf_counter.name,
				LTTNG_UST_SYM_NAME_LEN)) {
			return 0;
		}
		break;
	case LTTNG_UST_CONTEXT_APP_CONTEXT:
		assert(uctx->ctx.u.app_ctx.provider_name);
		assert(uctx->ctx.u.app_ctx.ctx_name);
		if (strcmp(uctx->ctx.u.app_ctx.provider_name,
				ctx->u.app_ctx.provider_name) ||
				strcmp(uctx->ctx.u.app_ctx.ctx_name,
				ctx->u.app_ctx.ctx_name)) {
			return 0;
		}
	default:
		break;

	}
	return 1;
}

/*
 * Allocate and initialize an UST context.
 *
 * Return pointer to structure or NULL.
 */
struct ltt_ust_context *trace_ust_create_context(
		struct lttng_event_context *ctx)
{
	struct ltt_ust_context *uctx = NULL;
	int utype;

	assert(ctx);

	utype = trace_ust_context_type_event_to_ust(ctx->ctx);
	if (utype < 0) {
		ERR("Invalid UST context");
		goto end;
	}

	uctx = zmalloc(sizeof(struct ltt_ust_context));
	if (!uctx) {
		PERROR("zmalloc ltt_ust_context");
		goto end;
	}

	uctx->ctx.ctx = (enum lttng_ust_context_type) utype;
	switch (utype) {
	case LTTNG_UST_CONTEXT_PERF_THREAD_COUNTER:
		uctx->ctx.u.perf_counter.type = ctx->u.perf_counter.type;
		uctx->ctx.u.perf_counter.config = ctx->u.perf_counter.config;
		strncpy(uctx->ctx.u.perf_counter.name, ctx->u.perf_counter.name,
				LTTNG_UST_SYM_NAME_LEN);
		uctx->ctx.u.perf_counter.name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
		break;
	case LTTNG_UST_CONTEXT_APP_CONTEXT:
	{
		char *provider_name = NULL, *ctx_name = NULL;

		provider_name = strdup(ctx->u.app_ctx.provider_name);
		if (!provider_name) {
			goto error;
		}
		uctx->ctx.u.app_ctx.provider_name = provider_name;

		ctx_name = strdup(ctx->u.app_ctx.ctx_name);
		if (!ctx_name) {
			goto error;
		}
		uctx->ctx.u.app_ctx.ctx_name = ctx_name;
		break;
	}
	default:
		break;
	}
	lttng_ht_node_init_ulong(&uctx->node, (unsigned long) uctx->ctx.ctx);
end:
	return uctx;
error:
	trace_ust_destroy_context(uctx);
	return NULL;
}

static
void destroy_pid_tracker_node_rcu(struct rcu_head *head)
{
	struct ust_pid_tracker_node *tracker_node =
		caa_container_of(head, struct ust_pid_tracker_node, node.head);
	free(tracker_node);
}

static
void destroy_pid_tracker_node(struct ust_pid_tracker_node *tracker_node)
{

	call_rcu(&tracker_node->node.head, destroy_pid_tracker_node_rcu);
}

static
int init_pid_tracker(struct ust_pid_tracker *pid_tracker)
{
	int ret = 0;

	pid_tracker->ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!pid_tracker->ht) {
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 * Teardown pid tracker content, but don't free pid_tracker object.
 */
static
void fini_pid_tracker(struct ust_pid_tracker *pid_tracker)
{
	struct ust_pid_tracker_node *tracker_node;
	struct lttng_ht_iter iter;

	if (!pid_tracker->ht) {
		return;
	}
	rcu_read_lock();
	cds_lfht_for_each_entry(pid_tracker->ht->ht,
			&iter.iter, tracker_node, node.node) {
		int ret = lttng_ht_del(pid_tracker->ht, &iter);

		assert(!ret);
		destroy_pid_tracker_node(tracker_node);
	}
	rcu_read_unlock();
	ht_cleanup_push(pid_tracker->ht);
	pid_tracker->ht = NULL;
}

static
struct ust_pid_tracker_node *pid_tracker_lookup(
		struct ust_pid_tracker *pid_tracker, int pid,
		struct lttng_ht_iter *iter)
{
	unsigned long _pid = (unsigned long) pid;
	struct lttng_ht_node_ulong *node;

	lttng_ht_lookup(pid_tracker->ht, (void *) _pid, iter);
	node = lttng_ht_iter_get_node_ulong(iter);
	if (node) {
		return caa_container_of(node, struct ust_pid_tracker_node,
			node);
	} else {
		return NULL;
	}
}

static
int pid_tracker_add_pid(struct ust_pid_tracker *pid_tracker, int pid)
{
	int retval = LTTNG_OK;
	struct ust_pid_tracker_node *tracker_node;
	struct lttng_ht_iter iter;

	if (pid < 0) {
		retval = LTTNG_ERR_INVALID;
		goto end;
	}
	tracker_node = pid_tracker_lookup(pid_tracker, pid, &iter);
	if (tracker_node) {
		/* Already exists. */
		retval = LTTNG_ERR_PID_TRACKED;
		goto end;
	}
	tracker_node = zmalloc(sizeof(*tracker_node));
	if (!tracker_node) {
		retval = LTTNG_ERR_NOMEM;
		goto end;
	}
	lttng_ht_node_init_ulong(&tracker_node->node, (unsigned long) pid);
	lttng_ht_add_unique_ulong(pid_tracker->ht, &tracker_node->node);
end:
	return retval;
}

static
int pid_tracker_del_pid(struct ust_pid_tracker *pid_tracker, int pid)
{
	int retval = LTTNG_OK, ret;
	struct ust_pid_tracker_node *tracker_node;
	struct lttng_ht_iter iter;

	if (pid < 0) {
		retval = LTTNG_ERR_INVALID;
		goto end;
	}
	tracker_node = pid_tracker_lookup(pid_tracker, pid, &iter);
	if (!tracker_node) {
		/* Not found */
		retval = LTTNG_ERR_PID_NOT_TRACKED;
		goto end;
	}
	ret = lttng_ht_del(pid_tracker->ht, &iter);
	assert(!ret);

	destroy_pid_tracker_node(tracker_node);
end:
	return retval;
}

/*
 * The session lock is held when calling this function.
 */
int trace_ust_pid_tracker_lookup(struct ltt_ust_session *session, int pid)
{
	struct lttng_ht_iter iter;

	if (!session->pid_tracker.ht) {
		return 1;
	}
	if (pid_tracker_lookup(&session->pid_tracker, pid, &iter)) {
		return 1;
	}
	return 0;
}

/*
 * Called with the session lock held.
 */
int trace_ust_track_pid(struct ltt_ust_session *session, int pid)
{
	int retval = LTTNG_OK;

	if (pid == -1) {
		/* Track all pids: destroy tracker if exists. */
		if (session->pid_tracker.ht) {
			fini_pid_tracker(&session->pid_tracker);
			/* Ensure all apps have session. */
			ust_app_global_update_all(session);
		}
	} else {
		int ret;

		if (!session->pid_tracker.ht) {
			/* Create tracker. */
			if (init_pid_tracker(&session->pid_tracker)) {
				ERR("Error initializing PID tracker");
				retval = LTTNG_ERR_NOMEM;
				goto end;
			}
			ret = pid_tracker_add_pid(&session->pid_tracker, pid);
			if (ret != LTTNG_OK) {
				retval = ret;
				fini_pid_tracker(&session->pid_tracker);
				goto end;
			}
			/* Remove all apps from session except pid. */
			ust_app_global_update_all(session);
		} else {
			struct ust_app *app;

			ret = pid_tracker_add_pid(&session->pid_tracker, pid);
			if (ret != LTTNG_OK) {
				retval = ret;
				goto end;
			}
			/* Add session to application */
			app = ust_app_find_by_pid(pid);
			if (app) {
				ust_app_global_update(session, app);
			}
		}
	}
end:
	return retval;
}

/*
 * Called with the session lock held.
 */
int trace_ust_untrack_pid(struct ltt_ust_session *session, int pid)
{
	int retval = LTTNG_OK;

	if (pid == -1) {
		/* Create empty tracker, replace old tracker. */
		struct ust_pid_tracker tmp_tracker;

		tmp_tracker = session->pid_tracker;
		if (init_pid_tracker(&session->pid_tracker)) {
			ERR("Error initializing PID tracker");
			retval = LTTNG_ERR_NOMEM;
			/* Rollback operation. */
			session->pid_tracker = tmp_tracker;
			goto end;
		}
		fini_pid_tracker(&tmp_tracker);

		/* Remove session from all applications */
		ust_app_global_update_all(session);
	} else {
		int ret;
		struct ust_app *app;

		if (!session->pid_tracker.ht) {
			/* No PID being tracked. */
			retval = LTTNG_ERR_PID_NOT_TRACKED;
			goto end;
		}
		/* Remove PID from tracker */
		ret = pid_tracker_del_pid(&session->pid_tracker, pid);
		if (ret != LTTNG_OK) {
			retval = ret;
			goto end;
		}
		/* Remove session from application. */
		app = ust_app_find_by_pid(pid);
		if (app) {
			ust_app_global_update(session, app);
		}
	}
end:
	return retval;
}

/*
 * Called with session lock held.
 */
ssize_t trace_ust_list_tracker_pids(struct ltt_ust_session *session,
		int32_t **_pids)
{
	struct ust_pid_tracker_node *tracker_node;
	struct lttng_ht_iter iter;
	unsigned long count, i = 0;
	long approx[2];
	int32_t *pids;
	int ret = 0;

	if (!session->pid_tracker.ht) {
		/* Tracker disabled. Set first entry to -1. */
		pids = zmalloc(sizeof(*pids));
		if (!pids) {
			ret = -1;
			goto end;
		}
		pids[0] = -1;
		*_pids = pids;
		return 1;
	}

	rcu_read_lock();
	cds_lfht_count_nodes(session->pid_tracker.ht->ht,
		&approx[0], &count, &approx[1]);
	pids = zmalloc(sizeof(*pids) * count);
	if (!pids) {
		ret = -1;
		goto end;
	}
	cds_lfht_for_each_entry(session->pid_tracker.ht->ht,
			&iter.iter, tracker_node, node.node) {
		pids[i++] = tracker_node->node.key;
	}
	*_pids = pids;
	ret = count;
end:
	rcu_read_unlock();
	return ret;
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

	trace_ust_destroy_context(ctx);
}

/*
 * Cleanup UST context hash table.
 */
static void destroy_contexts(struct lttng_ht *ht)
{
	int ret;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct ltt_ust_context *ctx;

	assert(ht);

	rcu_read_lock();
	cds_lfht_for_each_entry(ht->ht, &iter.iter, node, node) {
		/* Remove from ordered list. */
		ctx = caa_container_of(node, struct ltt_ust_context, node);
		cds_list_del(&ctx->list);
		/* Remove from channel's hash table. */
		ret = lttng_ht_del(ht, &iter);
		if (!ret) {
			call_rcu(&node->head, destroy_context_rcu);
		}
	}
	rcu_read_unlock();

	ht_cleanup_push(ht);
}

/*
 * Cleanup ust event structure.
 */
void trace_ust_destroy_event(struct ltt_ust_event *event)
{
	assert(event);

	DBG2("Trace destroy UST event %s", event->attr.name);
	free(event->filter_expression);
	free(event->filter);
	free(event->exclusion);
	free(event);
}

/*
 * Cleanup ust context structure.
 */
void trace_ust_destroy_context(struct ltt_ust_context *ctx)
{
	assert(ctx);

	if (ctx->ctx.ctx == LTTNG_UST_CONTEXT_APP_CONTEXT) {
		free(ctx->ctx.u.app_ctx.provider_name);
		free(ctx->ctx.u.app_ctx.ctx_name);
	}
	free(ctx);
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

	assert(events);

	rcu_read_lock();
	cds_lfht_for_each_entry(events->ht, &iter.iter, node, node) {
		ret = lttng_ht_del(events, &iter);
		assert(!ret);
		call_rcu(&node->head, destroy_event_rcu);
	}
	rcu_read_unlock();

	ht_cleanup_push(events);
}

/*
 * Cleanup ust channel structure.
 *
 * Should _NOT_ be called with RCU read lock held.
 */
static void _trace_ust_destroy_channel(struct ltt_ust_channel *channel)
{
	assert(channel);

	DBG2("Trace destroy UST channel %s", channel->name);

	free(channel);
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

	_trace_ust_destroy_channel(channel);
}

void trace_ust_destroy_channel(struct ltt_ust_channel *channel)
{
	/* Destroying all events of the channel */
	destroy_events(channel->events);
	/* Destroying all context of the channel */
	destroy_contexts(channel->ctx);

	call_rcu(&channel->node.head, destroy_channel_rcu);
}

/*
 * Remove an UST channel from a channel HT.
 */
void trace_ust_delete_channel(struct lttng_ht *ht,
		struct ltt_ust_channel *channel)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(ht);
	assert(channel);

	iter.iter.node = &channel->node.node;
	ret = lttng_ht_del(ht, &iter);
	assert(!ret);
}

/*
 * Iterate over a hash table containing channels and cleanup safely.
 */
static void destroy_channels(struct lttng_ht *channels)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	assert(channels);

	rcu_read_lock();
	cds_lfht_for_each_entry(channels->ht, &iter.iter, node, node) {
		struct ltt_ust_channel *chan =
			caa_container_of(node, struct ltt_ust_channel, node);

		trace_ust_delete_channel(channels, chan);
		trace_ust_destroy_channel(chan);
	}
	rcu_read_unlock();

	ht_cleanup_push(channels);
}

/*
 * Cleanup UST global domain.
 */
static void destroy_domain_global(struct ltt_ust_domain_global *dom)
{
	assert(dom);

	destroy_channels(dom->channels);
}

/*
 * Cleanup ust session structure
 *
 * Should *NOT* be called with RCU read-side lock held.
 */
void trace_ust_destroy_session(struct ltt_ust_session *session)
{
	struct agent *agt;
	struct buffer_reg_uid *reg, *sreg;
	struct lttng_ht_iter iter;

	assert(session);

	DBG2("Trace UST destroy session %" PRIu64, session->id);

	/* Cleaning up UST domain */
	destroy_domain_global(&session->domain_global);

	rcu_read_lock();
	cds_lfht_for_each_entry(session->agents->ht, &iter.iter, agt, node.node) {
		int ret = lttng_ht_del(session->agents, &iter);

		assert(!ret);
		agent_destroy(agt);
	}
	rcu_read_unlock();

	ht_cleanup_push(session->agents);

	/* Cleanup UID buffer registry object(s). */
	cds_list_for_each_entry_safe(reg, sreg, &session->buffer_reg_uid_list,
			lnode) {
		cds_list_del(&reg->lnode);
		buffer_reg_uid_remove(reg);
		buffer_reg_uid_destroy(reg, session->consumer);
	}

	consumer_output_put(session->consumer);

	fini_pid_tracker(&session->pid_tracker);

	free(session);
}
