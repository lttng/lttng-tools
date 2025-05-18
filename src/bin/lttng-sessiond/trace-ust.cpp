/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "agent.hpp"
#include "buffer-registry.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/defaults.hpp>
#include <common/trace-chunk.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace lsu = lttng::sessiond::ust;

/*
 * Match function for the events hash table lookup.
 *
 * Matches by name only. Used by the disable command.
 */
int trace_ust_ht_match_event_by_name(struct cds_lfht_node *node, const void *_key)
{
	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	auto *event = lttng_ht_node_container_of(node, &ltt_ust_event::node);
	const auto *name = (const char *) _key;

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
	int ev_loglevel_value;
	bool ll_match;

	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	auto *event = lttng_ht_node_container_of(node, &ltt_ust_event::node);
	const auto *key = (ltt_ust_ht_key *) _key;
	ev_loglevel_value = event->attr.loglevel;

	/* Match the 4 elements of the key: name, filter, loglevel, exclusions. */

	/* Event name */
	if (strncmp(event->attr.name, key->name, sizeof(event->attr.name)) != 0) {
		goto no_match;
	}

	/* Event loglevel value and type. */
	ll_match = loglevels_match(event->attr.loglevel_type,
				   ev_loglevel_value,
				   key->loglevel_type,
				   key->loglevel_value,
				   LTTNG_UST_ABI_LOGLEVEL_ALL);

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
		    memcmp(event->filter->data, key->filter->data, event->filter->len) != 0) {
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
			const char *name_ev = LTTNG_EVENT_EXCLUSION_NAME_AT(event->exclusion, i);

			/*
			 * Compare this exclusion name to all the key's
			 * exclusion names.
			 */
			for (j = 0; j < key->exclusion->count; ++j) {
				const char *name_key =
					LTTNG_EVENT_EXCLUSION_NAME_AT(key->exclusion, j);

				if (!strncmp(name_ev, name_key, LTTNG_SYMBOL_NAME_LEN)) {
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
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht, const char *name)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	ASSERT_RCU_READ_LOCKED();
	/*
	 * If we receive an empty string for channel name, it means the
	 * default channel name is requested.
	 */
	if (name[0] == '\0')
		name = DEFAULT_CHANNEL_NAME;

	lttng_ht_lookup(ht, (void *) name, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_str>(&iter);
	if (node == nullptr) {
		goto error;
	}

	DBG2("Trace UST channel %s found by name", name);

	return lttng::utils::container_of(node, &ltt_ust_channel::node);

error:
	DBG2("Trace UST channel %s not found by name", name);
	return nullptr;
}

/*
 * Find the event in the hashtable and return event pointer. RCU read side lock
 * MUST be acquired before calling this.
 */
struct ltt_ust_event *trace_ust_find_event(struct lttng_ht *ht,
					   char *name,
					   struct lttng_bytecode *filter,
					   enum lttng_ust_abi_loglevel_type loglevel_type,
					   int loglevel_value,
					   struct lttng_event_exclusion *exclusion)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct ltt_ust_ht_key key;

	LTTNG_ASSERT(name);
	LTTNG_ASSERT(ht);
	ASSERT_RCU_READ_LOCKED();

	key.name = name;
	key.filter = filter;
	key.loglevel_type = loglevel_type;
	key.loglevel_value = loglevel_value;
	key.exclusion = exclusion;

	cds_lfht_lookup(ht->ht,
			ht->hash_fct((void *) name, lttng_ht_seed),
			trace_ust_ht_match_event,
			&key,
			&iter.iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_str>(&iter);
	if (node == nullptr) {
		goto error;
	}

	DBG2("Trace UST event %s found", key.name);

	return lttng::utils::container_of(node, &ltt_ust_event::node);

error:
	DBG2("Trace UST event %s NOT found", key.name);
	return nullptr;
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
	struct agent *agt = nullptr;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	uint64_t key;

	LTTNG_ASSERT(session);

	DBG3("Trace ust agent lookup for domain %d", domain_type);

	key = domain_type;

	lttng_ht_lookup(session->agents, &key, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (!node) {
		goto end;
	}
	agt = lttng::utils::container_of(node, &agent::node);

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
	lus = zmalloc<ltt_ust_session>();
	if (lus == nullptr) {
		PERROR("create ust session zmalloc");
		goto error_alloc;
	}

	/* Init data structure */
	lus->id = session_id;
	lus->active = false;

	/* Set default metadata channel attribute. */
	lus->metadata_attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	lus->metadata_attr.subbuf_size = default_get_metadata_subbuf_size();
	lus->metadata_attr.num_subbuf = DEFAULT_METADATA_SUBBUF_NUM;
	lus->metadata_attr.switch_timer_interval = DEFAULT_METADATA_SWITCH_TIMER;
	lus->metadata_attr.read_timer_interval = DEFAULT_METADATA_READ_TIMER;
	lus->metadata_attr.output = LTTNG_UST_ABI_MMAP;
	lus->metadata_attr.u.s.type = LTTNG_UST_ABI_CHAN_METADATA;

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

	lus->tracker_vpid = process_attr_tracker_create();
	if (!lus->tracker_vpid) {
		goto error;
	}
	lus->tracker_vuid = process_attr_tracker_create();
	if (!lus->tracker_vuid) {
		goto error;
	}
	lus->tracker_vgid = process_attr_tracker_create();
	if (!lus->tracker_vgid) {
		goto error;
	}
	lus->consumer = consumer_create_output(CONSUMER_DST_LOCAL);
	if (lus->consumer == nullptr) {
		goto error;
	}

	DBG2("UST trace session create successful");

	return lus;

error:
	process_attr_tracker_destroy(lus->tracker_vpid);
	process_attr_tracker_destroy(lus->tracker_vuid);
	process_attr_tracker_destroy(lus->tracker_vgid);
	lttng_ht_destroy(lus->domain_global.channels);
	lttng_ht_destroy(lus->agents);
	free(lus);
error_alloc:
	return nullptr;
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

	LTTNG_ASSERT(chan);

	luc = zmalloc<ltt_ust_channel>();
	if (luc == nullptr) {
		PERROR("ltt_ust_channel zmalloc");
		return nullptr;
	}

	luc->domain = domain;

	/* Copy UST channel attributes */
	luc->attr.overwrite = chan->attr.overwrite;
	luc->attr.subbuf_size = chan->attr.subbuf_size;
	luc->attr.num_subbuf = chan->attr.num_subbuf;
	luc->attr.switch_timer_interval = chan->attr.switch_timer_interval;
	luc->attr.read_timer_interval = chan->attr.read_timer_interval;
	luc->attr.output = (enum lttng_ust_abi_output) chan->attr.output;
	luc->monitor_timer_interval =
		((struct lttng_channel_extended *) chan->attr.extended.ptr)->monitor_timer_interval;
	luc->attr.u.s.blocking_timeout =
		((struct lttng_channel_extended *) chan->attr.extended.ptr)->blocking_timeout;

	const auto extended =
		static_cast<const struct lttng_channel_extended *>(chan->attr.extended.ptr);

	const auto allocation_policy =
		static_cast<enum lttng_channel_allocation_policy>(extended->allocation_policy);

	switch (allocation_policy) {
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU:
		luc->attr.u.s.type = LTTNG_UST_ABI_CHAN_PER_CPU;
		break;
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CHANNEL:
		luc->attr.u.s.type = LTTNG_UST_ABI_CHAN_PER_CHANNEL;
		break;
	default:
		PERROR("Unknown channel stream allocation");
		goto error;
	}

	/* Translate to UST output enum */
	switch (luc->attr.output) {
	default:
		luc->attr.output = LTTNG_UST_ABI_MMAP;
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
	luc->name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';

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

	return luc;

error:
	free(luc);
	return nullptr;
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

	LTTNG_ASSERT(exclusion);

	for (i = 0; i < exclusion->count; ++i) {
		size_t j;
		const char *name_a = LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, i);

		for (j = 0; j < i; ++j) {
			const char *name_b = LTTNG_EVENT_EXCLUSION_NAME_AT(exclusion, j);

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
 * Return an lttng_error_code
 */
enum lttng_error_code trace_ust_create_event(struct lttng_event *ev,
					     char *filter_expression,
					     struct lttng_bytecode *filter,
					     struct lttng_event_exclusion *exclusion,
					     bool internal_event,
					     struct ltt_ust_event **ust_event)
{
	enum lttng_error_code ret = LTTNG_OK;
	std::unique_ptr<ltt_ust_event> local_ust_event;

	LTTNG_ASSERT(ev);

	if (exclusion && validate_exclusion(exclusion)) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	try {
		local_ust_event = lttng::make_unique<ltt_ust_event>();
	} catch (const std::bad_alloc& ex) {
		ERR_FMT("Failed to allocate ltt_ust_event");
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	local_ust_event->internal = internal_event;

	switch (ev->type) {
	case LTTNG_EVENT_PROBE:
		local_ust_event->attr.instrumentation = LTTNG_UST_ABI_PROBE;
		break;
	case LTTNG_EVENT_FUNCTION:
		local_ust_event->attr.instrumentation = LTTNG_UST_ABI_FUNCTION;
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		local_ust_event->attr.instrumentation = LTTNG_UST_ABI_FUNCTION;
		break;
	case LTTNG_EVENT_TRACEPOINT:
		local_ust_event->attr.instrumentation = LTTNG_UST_ABI_TRACEPOINT;
		break;
	default:
		ERR("Unknown ust instrumentation type (%d)", ev->type);
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	/* Copy event name */
	if (lttng_strncpy(local_ust_event->attr.name, ev->name, LTTNG_UST_ABI_SYM_NAME_LEN)) {
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	local_ust_event->attr.name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';

	switch (ev->loglevel_type) {
	case LTTNG_EVENT_LOGLEVEL_ALL:
		local_ust_event->attr.loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
		local_ust_event->attr.loglevel = -1; /* Force to -1 */
		break;
	case LTTNG_EVENT_LOGLEVEL_RANGE:
		local_ust_event->attr.loglevel_type = LTTNG_UST_ABI_LOGLEVEL_RANGE;
		local_ust_event->attr.loglevel = ev->loglevel;
		break;
	case LTTNG_EVENT_LOGLEVEL_SINGLE:
		local_ust_event->attr.loglevel_type = LTTNG_UST_ABI_LOGLEVEL_SINGLE;
		local_ust_event->attr.loglevel = ev->loglevel;
		break;
	default:
		ERR("Unknown ust loglevel type (%d)", ev->loglevel_type);
		ret = LTTNG_ERR_INVALID;
		goto error;
	}

	/* Same layout. */
	local_ust_event->filter_expression = filter_expression;
	local_ust_event->filter = filter;
	local_ust_event->exclusion = exclusion;

	/* Init node */
	lttng_ht_node_init_str(&local_ust_event->node, local_ust_event->attr.name);

	DBG2("Trace UST event %s, loglevel (%d,%d) created",
	     local_ust_event->attr.name,
	     local_ust_event->attr.loglevel_type,
	     local_ust_event->attr.loglevel);

	*ust_event = local_ust_event.release();

	return ret;

error:
	free(filter_expression);
	free(filter);
	free(exclusion);
	return ret;
}

static int trace_ust_context_type_event_to_ust(enum lttng_event_context_type type)
{
	int utype;

	switch (type) {
	case LTTNG_EVENT_CONTEXT_VTID:
		utype = LTTNG_UST_ABI_CONTEXT_VTID;
		break;
	case LTTNG_EVENT_CONTEXT_VPID:
		utype = LTTNG_UST_ABI_CONTEXT_VPID;
		break;
	case LTTNG_EVENT_CONTEXT_PTHREAD_ID:
		utype = LTTNG_UST_ABI_CONTEXT_PTHREAD_ID;
		break;
	case LTTNG_EVENT_CONTEXT_PROCNAME:
		utype = LTTNG_UST_ABI_CONTEXT_PROCNAME;
		break;
	case LTTNG_EVENT_CONTEXT_IP:
		utype = LTTNG_UST_ABI_CONTEXT_IP;
		break;
	case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
		if (!lttng_ust_ctl_has_perf_counters()) {
			utype = -1;
			WARN("Perf counters not implemented in UST");
		} else {
			utype = LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER;
		}
		break;
	case LTTNG_EVENT_CONTEXT_APP_CONTEXT:
		utype = LTTNG_UST_ABI_CONTEXT_APP_CONTEXT;
		break;
	case LTTNG_EVENT_CONTEXT_CGROUP_NS:
		utype = LTTNG_UST_ABI_CONTEXT_CGROUP_NS;
		break;
	case LTTNG_EVENT_CONTEXT_IPC_NS:
		utype = LTTNG_UST_ABI_CONTEXT_IPC_NS;
		break;
	case LTTNG_EVENT_CONTEXT_MNT_NS:
		utype = LTTNG_UST_ABI_CONTEXT_MNT_NS;
		break;
	case LTTNG_EVENT_CONTEXT_NET_NS:
		utype = LTTNG_UST_ABI_CONTEXT_NET_NS;
		break;
	case LTTNG_EVENT_CONTEXT_PID_NS:
		utype = LTTNG_UST_ABI_CONTEXT_PID_NS;
		break;
	case LTTNG_EVENT_CONTEXT_TIME_NS:
		utype = LTTNG_UST_ABI_CONTEXT_TIME_NS;
		break;
	case LTTNG_EVENT_CONTEXT_USER_NS:
		utype = LTTNG_UST_ABI_CONTEXT_USER_NS;
		break;
	case LTTNG_EVENT_CONTEXT_UTS_NS:
		utype = LTTNG_UST_ABI_CONTEXT_UTS_NS;
		break;
	case LTTNG_EVENT_CONTEXT_VUID:
		utype = LTTNG_UST_ABI_CONTEXT_VUID;
		break;
	case LTTNG_EVENT_CONTEXT_VEUID:
		utype = LTTNG_UST_ABI_CONTEXT_VEUID;
		break;
	case LTTNG_EVENT_CONTEXT_VSUID:
		utype = LTTNG_UST_ABI_CONTEXT_VSUID;
		break;
	case LTTNG_EVENT_CONTEXT_VGID:
		utype = LTTNG_UST_ABI_CONTEXT_VGID;
		break;
	case LTTNG_EVENT_CONTEXT_VEGID:
		utype = LTTNG_UST_ABI_CONTEXT_VEGID;
		break;
	case LTTNG_EVENT_CONTEXT_VSGID:
		utype = LTTNG_UST_ABI_CONTEXT_VSGID;
		break;
	case LTTNG_EVENT_CONTEXT_CPU_ID:
		utype = LTTNG_UST_ABI_CONTEXT_CPU_ID;
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
int trace_ust_match_context(const struct ltt_ust_context *uctx,
			    const struct lttng_event_context *ctx)
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
	case LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER:
		if (uctx->ctx.u.perf_counter.type != ctx->u.perf_counter.type) {
			return 0;
		}
		if (uctx->ctx.u.perf_counter.config != ctx->u.perf_counter.config) {
			return 0;
		}
		if (strncmp(uctx->ctx.u.perf_counter.name,
			    ctx->u.perf_counter.name,
			    LTTNG_UST_ABI_SYM_NAME_LEN) != 0) {
			return 0;
		}
		break;
	case LTTNG_UST_ABI_CONTEXT_APP_CONTEXT:
		LTTNG_ASSERT(uctx->ctx.u.app_ctx.provider_name);
		LTTNG_ASSERT(uctx->ctx.u.app_ctx.ctx_name);
		if (strcmp(uctx->ctx.u.app_ctx.provider_name, ctx->u.app_ctx.provider_name) != 0 ||
		    strcmp(uctx->ctx.u.app_ctx.ctx_name, ctx->u.app_ctx.ctx_name) != 0) {
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
struct ltt_ust_context *trace_ust_create_context(const struct lttng_event_context *ctx)
{
	struct ltt_ust_context *uctx = nullptr;
	int utype;

	LTTNG_ASSERT(ctx);

	utype = trace_ust_context_type_event_to_ust(ctx->ctx);
	if (utype < 0) {
		ERR("Invalid UST context");
		goto end;
	}

	uctx = zmalloc<ltt_ust_context>();
	if (!uctx) {
		PERROR("zmalloc ltt_ust_context");
		goto end;
	}

	uctx->ctx.ctx = (enum lttng_ust_abi_context_type) utype;
	switch (utype) {
	case LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER:
		uctx->ctx.u.perf_counter.type = ctx->u.perf_counter.type;
		uctx->ctx.u.perf_counter.config = ctx->u.perf_counter.config;
		strncpy(uctx->ctx.u.perf_counter.name,
			ctx->u.perf_counter.name,
			LTTNG_UST_ABI_SYM_NAME_LEN);
		uctx->ctx.u.perf_counter.name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		break;
	case LTTNG_UST_ABI_CONTEXT_APP_CONTEXT:
	{
		char *provider_name = nullptr, *ctx_name = nullptr;

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
	return nullptr;
}

static void destroy_id_tracker_node_rcu(struct rcu_head *head)
{
	auto *wrapper_node = lttng::utils::container_of(head, &lttng_ht_node_ulong::head);
	auto *tracker_node = lttng::utils::container_of(wrapper_node, &ust_id_tracker_node::node);

	free(tracker_node);
}

static void destroy_id_tracker_node(struct ust_id_tracker_node *tracker_node)
{
	call_rcu(&tracker_node->node.head, destroy_id_tracker_node_rcu);
}

static int init_id_tracker(struct ust_id_tracker *id_tracker)
{
	int ret = LTTNG_OK;

	id_tracker->ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!id_tracker->ht) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

end:
	return ret;
}

/*
 * Teardown id tracker content, but don't free id_tracker object.
 */
static void fini_id_tracker(struct ust_id_tracker *id_tracker)
{
	if (!id_tracker->ht) {
		return;
	}

	for (auto *tracker_node :
	     lttng::urcu::lfht_iteration_adapter<ust_id_tracker_node,
						 decltype(ust_id_tracker_node::node),
						 &ust_id_tracker_node::node>(*id_tracker->ht->ht)) {
		const int ret = cds_lfht_del(id_tracker->ht->ht, &tracker_node->node.node);

		LTTNG_ASSERT(!ret);
		destroy_id_tracker_node(tracker_node);
	}

	lttng_ht_destroy(id_tracker->ht);
	id_tracker->ht = nullptr;
}

static struct ust_id_tracker_node *
id_tracker_lookup(struct ust_id_tracker *id_tracker, int id, struct lttng_ht_iter *iter)
{
	const unsigned long _id = (unsigned long) id;
	struct lttng_ht_node_ulong *node;

	lttng_ht_lookup(id_tracker->ht, (void *) _id, iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_ulong>(iter);
	if (node) {
		return lttng::utils::container_of(node, &ust_id_tracker_node::node);
	} else {
		return nullptr;
	}
}

static int id_tracker_add_id(struct ust_id_tracker *id_tracker, int id)
{
	int retval = LTTNG_OK;
	struct ust_id_tracker_node *tracker_node;
	struct lttng_ht_iter iter;

	if (id < 0) {
		retval = LTTNG_ERR_INVALID;
		goto end;
	}
	tracker_node = id_tracker_lookup(id_tracker, id, &iter);
	if (tracker_node) {
		/* Already exists. */
		retval = LTTNG_ERR_PROCESS_ATTR_EXISTS;
		goto end;
	}
	tracker_node = zmalloc<ust_id_tracker_node>();
	if (!tracker_node) {
		retval = LTTNG_ERR_NOMEM;
		goto end;
	}
	lttng_ht_node_init_ulong(&tracker_node->node, (unsigned long) id);
	lttng_ht_add_unique_ulong(id_tracker->ht, &tracker_node->node);
end:
	return retval;
}

static int id_tracker_del_id(struct ust_id_tracker *id_tracker, int id)
{
	int retval = LTTNG_OK, ret;
	struct ust_id_tracker_node *tracker_node;
	struct lttng_ht_iter iter;

	if (id < 0) {
		retval = LTTNG_ERR_INVALID;
		goto end;
	}
	tracker_node = id_tracker_lookup(id_tracker, id, &iter);
	if (!tracker_node) {
		/* Not found */
		retval = LTTNG_ERR_PROCESS_ATTR_MISSING;
		goto end;
	}
	ret = lttng_ht_del(id_tracker->ht, &iter);
	LTTNG_ASSERT(!ret);

	destroy_id_tracker_node(tracker_node);
end:
	return retval;
}

static struct ust_id_tracker *get_id_tracker(struct ltt_ust_session *session,
					     enum lttng_process_attr process_attr)
{
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		return &session->vpid_tracker;
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		return &session->vuid_tracker;
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		return &session->vgid_tracker;
	default:
		return nullptr;
	}
}

static struct process_attr_tracker *
_trace_ust_get_process_attr_tracker(struct ltt_ust_session *session,
				    enum lttng_process_attr process_attr)
{
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		return session->tracker_vpid;
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		return session->tracker_vuid;
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		return session->tracker_vgid;
	default:
		return nullptr;
	}
}

const struct process_attr_tracker *
trace_ust_get_process_attr_tracker(struct ltt_ust_session *session,
				   enum lttng_process_attr process_attr)
{
	return (const struct process_attr_tracker *) _trace_ust_get_process_attr_tracker(
		session, process_attr);
}

/*
 * The session lock is held when calling this function.
 */
int trace_ust_id_tracker_lookup(enum lttng_process_attr process_attr,
				struct ltt_ust_session *session,
				int id)
{
	struct lttng_ht_iter iter;
	struct ust_id_tracker *id_tracker;

	id_tracker = get_id_tracker(session, process_attr);
	if (!id_tracker) {
		abort();
	}
	if (!id_tracker->ht) {
		return 1;
	}
	if (id_tracker_lookup(id_tracker, id, &iter)) {
		return 1;
	}
	return 0;
}

/*
 * Called with the session lock held.
 */
enum lttng_error_code
trace_ust_process_attr_tracker_set_tracking_policy(struct ltt_ust_session *session,
						   enum lttng_process_attr process_attr,
						   enum lttng_tracking_policy policy)
{
	int ret;
	enum lttng_error_code ret_code = LTTNG_OK;
	struct ust_id_tracker *id_tracker = get_id_tracker(session, process_attr);
	struct process_attr_tracker *tracker =
		_trace_ust_get_process_attr_tracker(session, process_attr);
	bool should_update_apps = false;
	enum lttng_tracking_policy previous_policy;

	if (!tracker) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	previous_policy = process_attr_tracker_get_tracking_policy(tracker);
	ret = process_attr_tracker_set_tracking_policy(tracker, policy);
	if (ret) {
		ret_code = LTTNG_ERR_UNK;
		goto end;
	}

	if (previous_policy == policy) {
		goto end;
	}

	switch (policy) {
	case LTTNG_TRACKING_POLICY_INCLUDE_ALL:
		/* Track all values: destroy tracker if exists. */
		if (id_tracker->ht) {
			fini_id_tracker(id_tracker);
			/* Ensure all apps have session. */
			should_update_apps = true;
		}
		break;
	case LTTNG_TRACKING_POLICY_EXCLUDE_ALL:
	case LTTNG_TRACKING_POLICY_INCLUDE_SET:
		/* fall-through. */
		fini_id_tracker(id_tracker);
		ret_code = (lttng_error_code) init_id_tracker(id_tracker);
		if (ret_code != LTTNG_OK) {
			ERR("Error initializing ID tracker");
			goto end;
		}
		/* Remove all apps from session. */
		should_update_apps = true;
		break;
	default:
		abort();
	}
	if (should_update_apps && session->active) {
		ust_app_global_update_all(session);
	}
end:
	return ret_code;
}

/* Called with the session lock held. */
enum lttng_error_code
trace_ust_process_attr_tracker_inclusion_set_add_value(struct ltt_ust_session *session,
						       enum lttng_process_attr process_attr,
						       const struct process_attr_value *value)
{
	enum lttng_error_code ret_code = LTTNG_OK;
	bool should_update_apps = false;
	struct ust_id_tracker *id_tracker = get_id_tracker(session, process_attr);
	struct process_attr_tracker *tracker;
	int integral_value;
	enum process_attr_tracker_status status;
	struct ust_app *app;

	/*
	 * Convert process attribute tracker value to the integral
	 * representation required by the kern-ctl API.
	 */
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		integral_value = (int) value->value.pid;
		break;
	case LTTNG_PROCESS_ATTR_USER_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		if (value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME) {
			uid_t uid;

			ret_code = utils_user_id_from_name(value->value.user_name, &uid);
			if (ret_code != LTTNG_OK) {
				goto end;
			}
			integral_value = (int) uid;
		} else {
			integral_value = (int) value->value.uid;
		}
		break;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		if (value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME) {
			gid_t gid;

			ret_code = utils_group_id_from_name(value->value.group_name, &gid);
			if (ret_code != LTTNG_OK) {
				goto end;
			}
			integral_value = (int) gid;
		} else {
			integral_value = (int) value->value.gid;
		}
		break;
	default:
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	tracker = _trace_ust_get_process_attr_tracker(session, process_attr);
	if (!tracker) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	status = process_attr_tracker_inclusion_set_add_value(tracker, value);
	if (status != PROCESS_ATTR_TRACKER_STATUS_OK) {
		switch (status) {
		case PROCESS_ATTR_TRACKER_STATUS_EXISTS:
			ret_code = LTTNG_ERR_PROCESS_ATTR_EXISTS;
			break;
		case PROCESS_ATTR_TRACKER_STATUS_INVALID_TRACKING_POLICY:
			ret_code = LTTNG_ERR_PROCESS_ATTR_TRACKER_INVALID_TRACKING_POLICY;
			break;
		case PROCESS_ATTR_TRACKER_STATUS_ERROR:
		default:
			ret_code = LTTNG_ERR_UNK;
			break;
		}
		goto end;
	}

	DBG("User space track %s %d for session id %" PRIu64,
	    lttng_process_attr_to_string(process_attr),
	    integral_value,
	    session->id);

	ret_code = (lttng_error_code) id_tracker_add_id(id_tracker, integral_value);
	if (ret_code != LTTNG_OK) {
		goto end;
	}
	/* Add session to application */
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		app = ust_app_find_by_pid(integral_value);
		if (app) {
			should_update_apps = true;
		}
		break;
	default:
		should_update_apps = true;
		break;
	}
	if (should_update_apps && session->active) {
		ust_app_global_update_all(session);
	}
end:
	return ret_code;
}

/* Called with the session lock held. */
enum lttng_error_code
trace_ust_process_attr_tracker_inclusion_set_remove_value(struct ltt_ust_session *session,
							  enum lttng_process_attr process_attr,
							  const struct process_attr_value *value)
{
	enum lttng_error_code ret_code = LTTNG_OK;
	bool should_update_apps = false;
	struct ust_id_tracker *id_tracker = get_id_tracker(session, process_attr);
	struct process_attr_tracker *tracker;
	int integral_value;
	enum process_attr_tracker_status status;
	struct ust_app *app;

	/*
	 * Convert process attribute tracker value to the integral
	 * representation required by the kern-ctl API.
	 */
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_PROCESS_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		integral_value = (int) value->value.pid;
		break;
	case LTTNG_PROCESS_ATTR_USER_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID:
		if (value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_USER_NAME) {
			uid_t uid;

			ret_code = utils_user_id_from_name(value->value.user_name, &uid);
			if (ret_code != LTTNG_OK) {
				goto end;
			}
			integral_value = (int) uid;
		} else {
			integral_value = (int) value->value.uid;
		}
		break;
	case LTTNG_PROCESS_ATTR_GROUP_ID:
	case LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID:
		if (value->type == LTTNG_PROCESS_ATTR_VALUE_TYPE_GROUP_NAME) {
			gid_t gid;

			ret_code = utils_group_id_from_name(value->value.group_name, &gid);
			if (ret_code != LTTNG_OK) {
				goto end;
			}
			integral_value = (int) gid;
		} else {
			integral_value = (int) value->value.gid;
		}
		break;
	default:
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	tracker = _trace_ust_get_process_attr_tracker(session, process_attr);
	if (!tracker) {
		ret_code = LTTNG_ERR_INVALID;
		goto end;
	}

	status = process_attr_tracker_inclusion_set_remove_value(tracker, value);
	if (status != PROCESS_ATTR_TRACKER_STATUS_OK) {
		switch (status) {
		case PROCESS_ATTR_TRACKER_STATUS_MISSING:
			ret_code = LTTNG_ERR_PROCESS_ATTR_MISSING;
			break;
		case PROCESS_ATTR_TRACKER_STATUS_INVALID_TRACKING_POLICY:
			ret_code = LTTNG_ERR_PROCESS_ATTR_TRACKER_INVALID_TRACKING_POLICY;
			break;
		case PROCESS_ATTR_TRACKER_STATUS_ERROR:
		default:
			ret_code = LTTNG_ERR_UNK;
			break;
		}
		goto end;
	}

	DBG("User space untrack %s %d for session id %" PRIu64,
	    lttng_process_attr_to_string(process_attr),
	    integral_value,
	    session->id);

	ret_code = (lttng_error_code) id_tracker_del_id(id_tracker, integral_value);
	if (ret_code != LTTNG_OK) {
		goto end;
	}
	/* Add session to application */
	switch (process_attr) {
	case LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID:
		app = ust_app_find_by_pid(integral_value);
		if (app) {
			should_update_apps = true;
		}
		break;
	default:
		should_update_apps = true;
		break;
	}
	if (should_update_apps && session->active) {
		ust_app_global_update_all(session);
	}
end:
	return ret_code;
}

/*
 * RCU safe free context structure.
 */
static void destroy_context_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		lttng::utils::container_of(head, &lttng_ht_node_ulong::head);
	struct ltt_ust_context *ctx = lttng::utils::container_of(node, &ltt_ust_context::node);

	trace_ust_destroy_context(ctx);
}

/*
 * Cleanup UST context hash table.
 */
static void destroy_contexts(struct lttng_ht *ht)
{
	LTTNG_ASSERT(ht);

	for (auto *ctx : lttng::urcu::lfht_iteration_adapter<ltt_ust_context,
							     decltype(ltt_ust_context::node),
							     &ltt_ust_context::node>(*ht->ht)) {
		/* Remove from ordered list. */
		cds_list_del(&ctx->list);
		/* Remove from channel's hash table. */
		const auto ret = cds_lfht_del(ht->ht, &ctx->node.node);
		if (!ret) {
			call_rcu(&ctx->node.head, destroy_context_rcu);
		}
	}

	lttng_ht_destroy(ht);
}

/*
 * Cleanup ust event structure.
 */
void trace_ust_destroy_event(struct ltt_ust_event *event)
{
	LTTNG_ASSERT(event);

	DBG2("Trace destroy UST event %s", event->attr.name);
	free(event->filter_expression);
	free(event->filter);
	free(event->exclusion);
	delete event;
}

/*
 * Cleanup ust context structure.
 */
void trace_ust_destroy_context(struct ltt_ust_context *ctx)
{
	LTTNG_ASSERT(ctx);

	if (ctx->ctx.ctx == LTTNG_UST_ABI_CONTEXT_APP_CONTEXT) {
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
	struct lttng_ht_node_str *node = lttng::utils::container_of(head, &lttng_ht_node_str::head);
	struct ltt_ust_event *event = lttng::utils::container_of(node, &ltt_ust_event::node);

	trace_ust_destroy_event(event);
}

/*
 * Cleanup UST events hashtable.
 */
static void destroy_events(struct lttng_ht *events)
{
	LTTNG_ASSERT(events);

	for (auto *event : lttng::urcu::lfht_iteration_adapter<ltt_ust_event,
							       decltype(ltt_ust_event::node),
							       &ltt_ust_event::node>(*events->ht)) {
		const auto ret = cds_lfht_del(events->ht, &event->node.node);
		LTTNG_ASSERT(!ret);
		call_rcu(&event->node.head, destroy_event_rcu);
	}

	lttng_ht_destroy(events);
}

/*
 * Cleanup ust channel structure.
 *
 * Should _NOT_ be called with RCU read lock held.
 */
static void _trace_ust_destroy_channel(struct ltt_ust_channel *channel)
{
	LTTNG_ASSERT(channel);

	DBG2("Trace destroy UST channel %s", channel->name);

	free(channel);
}

/*
 * URCU intermediate call to complete destroy channel.
 */
static void destroy_channel_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_str *node = lttng::utils::container_of(head, &lttng_ht_node_str::head);
	struct ltt_ust_channel *channel = lttng::utils::container_of(node, &ltt_ust_channel::node);

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
void trace_ust_delete_channel(struct lttng_ht *ht, struct ltt_ust_channel *channel)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(channel);

	iter.iter.node = &channel->node.node;
	ret = lttng_ht_del(ht, &iter);
	LTTNG_ASSERT(!ret);
}

int trace_ust_regenerate_metadata(struct ltt_ust_session *usess)
{
	int ret = 0;
	struct buffer_reg_session *session_reg = nullptr;

	const lttng::urcu::read_lock_guard read_lock;
	for (auto uid_reg :
	     lttng::urcu::list_iteration_adapter<buffer_reg_uid, &buffer_reg_uid::lnode>(
		     usess->buffer_reg_uid_list)) {
		lsu::registry_session *registry;

		session_reg = uid_reg->registry;
		registry = session_reg->reg.ust;

		try {
			registry->regenerate_metadata();
		} catch (const std::exception& ex) {
			ERR("Failed to regenerate user space session metadata: %s", ex.what());
			ret = -1;
			goto end;
		}
	}

end:
	return ret;
}

/*
 * Iterate over a hash table containing channels and cleanup safely.
 */
static void destroy_channels(struct lttng_ht *channels)
{
	LTTNG_ASSERT(channels);

	for (auto *chan :
	     lttng::urcu::lfht_iteration_adapter<ltt_ust_channel,
						 decltype(ltt_ust_channel::node),
						 &ltt_ust_channel::node>(*channels->ht)) {
		trace_ust_delete_channel(channels, chan);
		trace_ust_destroy_channel(chan);
	}

	lttng_ht_destroy(channels);
}

/*
 * Cleanup UST global domain.
 */
static void destroy_domain_global(struct ltt_ust_domain_global *dom)
{
	LTTNG_ASSERT(dom);

	destroy_channels(dom->channels);
}

/*
 * Cleanup ust session structure, keeping data required by
 * destroy notifier.
 */
void trace_ust_destroy_session(struct ltt_ust_session *session)
{
	LTTNG_ASSERT(session);

	DBG2("Trace UST destroy session %" PRIu64, session->id);

	/* Cleaning up UST domain */
	destroy_domain_global(&session->domain_global);

	for (auto *agt :
	     lttng::urcu::lfht_iteration_adapter<agent, decltype(agent::node), &agent::node>(
		     *session->agents->ht)) {
		const int ret = cds_lfht_del(session->agents->ht, &agt->node.node);

		LTTNG_ASSERT(!ret);
		agent_destroy(agt);
	}

	lttng_ht_destroy(session->agents);

	/* Cleanup UID buffer registry object(s). */
	for (auto reg : lttng::urcu::list_iteration_adapter<buffer_reg_uid, &buffer_reg_uid::lnode>(
		     session->buffer_reg_uid_list)) {
		cds_list_del(&reg->lnode);
		buffer_reg_uid_remove(reg);
		buffer_reg_uid_destroy(reg, session->consumer);
	}

	process_attr_tracker_destroy(session->tracker_vpid);
	process_attr_tracker_destroy(session->tracker_vuid);
	process_attr_tracker_destroy(session->tracker_vgid);

	fini_id_tracker(&session->vpid_tracker);
	fini_id_tracker(&session->vuid_tracker);
	fini_id_tracker(&session->vgid_tracker);
	lttng_trace_chunk_put(session->current_trace_chunk);
}

/* Free elements needed by destroy notifiers. */
void trace_ust_free_session(struct ltt_ust_session *session)
{
	consumer_output_put(session->consumer);
	free(session);
}

bool trace_ust_runtime_ctl_version_matches_build_version()
{
	uint32_t major, minor, patch_level;

	if (lttng_ust_ctl_get_version(&major, &minor, &patch_level)) {
		ERR("Failed to get liblttng-ust-ctl.so version");
		return false;
	}

	if (major != VERSION_MAJOR || minor != VERSION_MINOR) {
		ERR_FMT("Mismatch between liblttng-ust-ctl.so runtime version ({}.{}) and build version ({}.{})",
			major,
			minor,
			VERSION_MAJOR,
			VERSION_MINOR);
		return false;
	}

	return true;
}