/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "agent.hpp"
#include "context.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"

#include <common/error.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/urcu.hpp>

#include <stdio.h>
#include <unistd.h>
#include <urcu/list.h>

/*
 * Add UST context to channel.
 */
static int add_uctx_to_channel(struct ltt_ust_session *usess,
			       enum lttng_domain_type domain,
			       struct ltt_ust_channel *uchan,
			       const struct lttng_event_context *ctx)
{
	int ret;
	struct ltt_ust_context *new_uctx = nullptr;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(uchan);
	LTTNG_ASSERT(ctx);

	/* Check if context is duplicate */
	for (auto uctx_it :
	     lttng::urcu::list_iteration_adapter<ltt_ust_context, &ltt_ust_context::list>(
		     uchan->ctx_list)) {
		if (trace_ust_match_context(uctx_it, ctx)) {
			ret = LTTNG_ERR_UST_CONTEXT_EXIST;
			goto duplicate;
		}
	}

	switch (domain) {
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
	{
		struct agent *agt;

		if (ctx->ctx != LTTNG_EVENT_CONTEXT_APP_CONTEXT) {
			/* Other contexts are not needed by the agent. */
			break;
		}
		agt = trace_ust_find_agent(usess, domain);

		if (!agt) {
			agt = agent_create(domain);
			if (!agt) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}

			/* Ownership of agt is transferred. */
			agent_add(agt, usess->agents);
		}
		ret = agent_add_context(ctx, agt);
		if (ret != LTTNG_OK) {
			goto error;
		}

		ret = agent_enable_context(ctx, domain);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
		break;
	default:
		abort();
	}

	/* Create ltt UST context */
	new_uctx = trace_ust_create_context(ctx);
	if (new_uctx == nullptr) {
		ret = LTTNG_ERR_UST_CONTEXT_INVAL;
		goto error;
	}

	/* Add ltt UST context node to ltt UST channel */
	lttng_ht_add_ulong(uchan->ctx, &new_uctx->node);
	cds_list_add_tail(&new_uctx->list, &uchan->ctx_list);

	if (!usess->active) {
		goto end;
	}

	ret = ust_app_add_ctx_channel_glb(usess, uchan, new_uctx);
	if (ret < 0) {
		goto error;
	}
end:
	DBG("Context UST %d added to channel %s", new_uctx->ctx.ctx, uchan->name);

	return 0;

error:
	free(new_uctx);
duplicate:
	return ret;
}

/*
 * Add UST context to tracer.
 */
int context_ust_add(struct ltt_ust_session *usess,
		    enum lttng_domain_type domain,
		    const struct lttng_event_context *ctx,
		    const char *channel_name)
{
	int ret = LTTNG_OK;
	struct lttng_ht *chan_ht;
	ltt_ust_channel *uchan = nullptr;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(ctx);
	LTTNG_ASSERT(channel_name);

	const lttng::urcu::read_lock_guard read_lock;

	chan_ht = usess->domain_global.channels;

	/* Get UST channel if defined */
	if (channel_name[0] != '\0') {
		uchan = trace_ust_find_channel_by_name(chan_ht, channel_name);
		if (uchan == nullptr) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error;
		}
	}

	if (uchan) {
		/* Add ctx to channel */
		ret = add_uctx_to_channel(usess, domain, uchan, ctx);
	} else {
		/* Add ctx all events, all channels */
		for (auto *iterated_uchan :
		     lttng::urcu::lfht_iteration_adapter<ltt_ust_channel,
							 decltype(ltt_ust_channel::node),
							 &ltt_ust_channel::node>(*chan_ht->ht)) {
			ret = add_uctx_to_channel(usess, domain, iterated_uchan, ctx);
			if (ret) {
				ERR("Failed to add context to channel %s", iterated_uchan->name);
				continue;
			}
		}
	}

	switch (ret) {
	case LTTNG_ERR_UST_CONTEXT_EXIST:
		break;
	case -ENOMEM:
	case -LTTNG_ERR_NOMEM:
		ret = LTTNG_ERR_FATAL;
		break;
	case -EINVAL:
		ret = LTTNG_ERR_UST_CONTEXT_INVAL;
		break;
	case -ENOSYS:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		break;
	default:
		if (ret != 0 && ret != LTTNG_OK) {
			ret = ret > 0 ? ret : LTTNG_ERR_UNK;
		} else {
			ret = LTTNG_OK;
		}
		break;
	}

error:
	return ret;
}
