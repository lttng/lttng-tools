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
#include "ust-domain-orchestrator.hpp"
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
	lus->metadata_attr.type = LTTNG_UST_ABI_CHAN_METADATA;

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
	if (lus->consumer == nullptr) {
		goto error;
	}

	DBG2("UST trace session create successful");

	return lus;

error:
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

	try {
		luc = new ltt_ust_channel;
	} catch (const std::bad_alloc&) {
		PERROR("Failed to allocate ltt_ust_channel");
		return nullptr;
	}

	const auto extended =
		static_cast<const struct lttng_channel_extended *>(chan->attr.extended.ptr);
	const auto allocation_policy =
		static_cast<enum lttng_channel_allocation_policy>(extended->allocation_policy);

	luc->domain = domain;

	/* Copy UST channel attributes */
	luc->attr.overwrite = chan->attr.overwrite;
	luc->attr.subbuf_size = chan->attr.subbuf_size;
	luc->attr.num_subbuf = chan->attr.num_subbuf;
	luc->attr.switch_timer_interval = chan->attr.switch_timer_interval;
	luc->attr.read_timer_interval = chan->attr.read_timer_interval;
	luc->attr.output = (enum lttng_ust_abi_output) chan->attr.output;
	luc->monitor_timer_interval = extended->monitor_timer_interval;
	luc->attr.blocking_timeout = extended->blocking_timeout;

	if (extended->watchdog_timer_interval.is_set) {
		switch (domain) {
		case LTTNG_DOMAIN_UST: /* Fallthrough */
		case LTTNG_DOMAIN_JUL: /* Fallthrough */
		case LTTNG_DOMAIN_LOG4J: /* Fallthrough */
		case LTTNG_DOMAIN_PYTHON: /* Fallthrough */
		case LTTNG_DOMAIN_LOG4J2:
		{
			const auto watchdog_timer_value =
				LTTNG_OPTIONAL_GET(extended->watchdog_timer_interval);

			LTTNG_OPTIONAL_SET(&luc->watchdog_timer_interval, watchdog_timer_value);
			break;
		}
		default:
			ERR_FMT("Watchdog timer only valid for UST, JUL, LOG4J, PYTHON and LOG4J2 domains: domain={}",
				static_cast<int>(domain));
			goto error;
		}
	}
	luc->attr.blocking_timeout = extended->blocking_timeout;

	if (extended->automatic_memory_reclamation_maximal_age_us.is_set) {
		luc->automatic_memory_reclamation_maximal_age = std::chrono::microseconds(
			LTTNG_OPTIONAL_GET(extended->automatic_memory_reclamation_maximal_age_us));
	}

	switch (allocation_policy) {
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU:
		luc->attr.type = LTTNG_UST_ABI_CHAN_PER_CPU;
		break;
	case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CHANNEL:
		luc->attr.type = LTTNG_UST_ABI_CHAN_PER_CHANNEL;
		break;
	default:
		PERROR("Unknown channel stream allocation");
		goto error;
	}

	luc->preallocation_policy = [](enum lttng_channel_preallocation_policy policy) {
		switch (policy) {
		case LTTNG_CHANNEL_PREALLOCATION_POLICY_PREALLOCATE:
			return lttng::sessiond::config::recording_channel_configuration::
				buffer_preallocation_policy_t::PREALLOCATE;
		case LTTNG_CHANNEL_PREALLOCATION_POLICY_ON_DEMAND:
			return lttng::sessiond::config::recording_channel_configuration::
				buffer_preallocation_policy_t::ON_DEMAND;
		default:
			std::abort();
		}
	}(static_cast<enum lttng_channel_preallocation_policy>(extended->preallocation_policy));

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
		strncpy(luc->name, chan->name, sizeof(luc->name) - 1);
	}
	luc->name[sizeof(luc->name) - 1] = '\0';

	/* Init node */
	lttng_ht_node_init_str(&luc->node, luc->name);
	CDS_INIT_LIST_HEAD(&luc->ctx_list);

	/* Alloc hash tables */
	luc->ctx = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);

	/* On-disk circular buffer parameters */
	luc->tracefile_size = chan->attr.tracefile_size;
	luc->tracefile_count = chan->attr.tracefile_count;

	DBG2("Trace UST channel %s created", luc->name);

	return luc;

error:
	delete luc;
	return nullptr;
}

ltt_ust_context::ltt_ust_context(const lttng::sessiond::config::context_configuration& config) :
	context_config(config)
{
	CDS_INIT_LIST_HEAD(&list);

	const auto ust_ctx_attr = lsu::domain_orchestrator::make_ust_context_attr(config);
	lttng_ht_node_init_ulong(&node, (unsigned long) ust_ctx_attr.ctx);
}

/*
 * Allocate and initialize a UST context from a context_configuration.
 *
 * The context_configuration must outlive the returned structure.
 */
struct ltt_ust_context *
trace_ust_create_context(const lttng::sessiond::config::context_configuration& context_config)
{
	return new ltt_ust_context(context_config);
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
 * Cleanup ust context structure.
 */
void trace_ust_destroy_context(ltt_ust_context *ctx)
{
	LTTNG_ASSERT(ctx);

	delete ctx;
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

	delete channel;
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
	const lttng::urcu::read_lock_guard read_lock;
	for (auto uid_reg :
	     lttng::urcu::list_iteration_adapter<buffer_reg_uid, &buffer_reg_uid::lnode>(
		     usess->buffer_reg_uid_list)) {
		lsu::trace_class *registry;

		auto *session_reg = uid_reg->registry;
		registry = session_reg->reg.ust;

		registry->regenerate_metadata();
	}

	return 0;
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
