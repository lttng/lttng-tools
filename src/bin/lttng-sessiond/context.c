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
#include <urcu/list.h>

#include <common/error.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "context.h"
#include "kernel.h"
#include "ust-app.h"
#include "trace-ust.h"
#include "agent.h"

/*
 * Add kernel context to all channel.
 *
 * Assumes the ownership of kctx.
 */
static int add_kctx_all_channels(struct ltt_kernel_session *ksession,
		struct ltt_kernel_context *kctx)
{
	int ret;
	struct ltt_kernel_channel *kchan;

	assert(ksession);
	assert(kctx);

	DBG("Adding kernel context to all channels");

	/* Go over all channels */
	cds_list_for_each_entry(kchan, &ksession->channel_list.head, list) {
		struct ltt_kernel_context *kctx_copy;

		kctx_copy = trace_kernel_copy_context(kctx);
		if (!kctx_copy) {
			PERROR("zmalloc ltt_kernel_context");
			ret = -LTTNG_ERR_NOMEM;
			goto error;
		}

		/* Ownership of kctx_copy is transferred to the callee. */
		ret = kernel_add_channel_context(kchan, kctx_copy);
		kctx_copy = NULL;
		if (ret != 0) {
			goto error;
		}
	}

	ret = LTTNG_OK;

error:
	trace_kernel_destroy_context(kctx);
	return ret;
}

/*
 * Add kernel context to a specific channel.
 *
 * Assumes the ownership of kctx.
 */
static int add_kctx_to_channel(struct ltt_kernel_context *kctx,
		struct ltt_kernel_channel *kchan)
{
	int ret;

	assert(kchan);
	assert(kctx);

	DBG("Add kernel context to channel '%s'", kchan->channel->name);

	/* Ownership of kctx is transferred to the callee. */
	ret = kernel_add_channel_context(kchan, kctx);
	kctx = NULL;
	if (ret != 0) {
		goto error;
	}

	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Add UST context to channel.
 */
static int add_uctx_to_channel(struct ltt_ust_session *usess,
		enum lttng_domain_type domain,
		struct ltt_ust_channel *uchan, struct lttng_event_context *ctx)
{
	int ret;
	struct ltt_ust_context *uctx = NULL;

	assert(usess);
	assert(uchan);
	assert(ctx);

	/* Check if context is duplicate */
	cds_list_for_each_entry(uctx, &uchan->ctx_list, list) {
		if (trace_ust_match_context(uctx, ctx)) {
			ret = LTTNG_ERR_UST_CONTEXT_EXIST;
			goto duplicate;
		}
	}
	uctx = NULL;

	switch (domain) {
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
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
		break;
	default:
		assert(0);
	}

	/* Create ltt UST context */
	uctx = trace_ust_create_context(ctx);
	if (uctx == NULL) {
		ret = LTTNG_ERR_UST_CONTEXT_INVAL;
		goto error;
	}

	ret = ust_app_add_ctx_channel_glb(usess, uchan, uctx);
	if (ret < 0) {
		goto error;
	}

	rcu_read_lock();

	/* Add ltt UST context node to ltt UST channel */
	lttng_ht_add_ulong(uchan->ctx, &uctx->node);
	rcu_read_unlock();
	cds_list_add_tail(&uctx->list, &uchan->ctx_list);

	DBG("Context UST %d added to channel %s", uctx->ctx.ctx, uchan->name);

	return 0;

error:
	free(uctx);
duplicate:
	return ret;
}

/*
 * Add kernel context to tracer.
 */
int context_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_event_context *ctx, char *channel_name)
{
	int ret;
	struct ltt_kernel_channel *kchan;
	struct ltt_kernel_context *kctx;

	assert(ksession);
	assert(ctx);
	assert(channel_name);

	kctx = trace_kernel_create_context(NULL);
	if (!kctx) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	/* Setup kernel context structure */
	switch (ctx->ctx) {
	case LTTNG_EVENT_CONTEXT_PID:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_PID;
		break;
	case LTTNG_EVENT_CONTEXT_PROCNAME:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_PROCNAME;
		break;
	case LTTNG_EVENT_CONTEXT_PRIO:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_PRIO;
		break;
	case LTTNG_EVENT_CONTEXT_NICE:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_NICE;
		break;
	case LTTNG_EVENT_CONTEXT_VPID:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_VPID;
		break;
	case LTTNG_EVENT_CONTEXT_TID:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_TID;
		break;
	case LTTNG_EVENT_CONTEXT_VTID:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_VTID;
		break;
	case LTTNG_EVENT_CONTEXT_PPID:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_PPID;
		break;
	case LTTNG_EVENT_CONTEXT_VPPID:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_VPPID;
		break;
	case LTTNG_EVENT_CONTEXT_HOSTNAME:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_HOSTNAME;
		break;
	case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_PERF_CPU_COUNTER;
		break;
	case LTTNG_EVENT_CONTEXT_INTERRUPTIBLE:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_INTERRUPTIBLE;
		break;
	case LTTNG_EVENT_CONTEXT_PREEMPTIBLE:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_PREEMPTIBLE;
		break;
	case LTTNG_EVENT_CONTEXT_NEED_RESCHEDULE:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_NEED_RESCHEDULE;
		break;
	case LTTNG_EVENT_CONTEXT_MIGRATABLE:
		kctx->ctx.ctx = LTTNG_KERNEL_CONTEXT_MIGRATABLE;
		break;
	default:
		ret = LTTNG_ERR_KERN_CONTEXT_FAIL;
		goto error;
	}

	kctx->ctx.u.perf_counter.type = ctx->u.perf_counter.type;
	kctx->ctx.u.perf_counter.config = ctx->u.perf_counter.config;
	strncpy(kctx->ctx.u.perf_counter.name, ctx->u.perf_counter.name,
			LTTNG_SYMBOL_NAME_LEN);
	kctx->ctx.u.perf_counter.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';

	if (*channel_name == '\0') {
		ret = add_kctx_all_channels(ksession, kctx);
		/* Ownership of kctx is transferred to the callee. */
		kctx = NULL;
		if (ret != LTTNG_OK) {
			goto error;
		}
	} else {
		/* Get kernel channel */
		kchan = trace_kernel_get_channel_by_name(channel_name, ksession);
		if (kchan == NULL) {
			ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
			goto error;
		}

		ret = add_kctx_to_channel(kctx, kchan);
		/* Ownership of kctx is transferred to the callee. */
		kctx = NULL;
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	ret = LTTNG_OK;

error:
	if (kctx) {
		trace_kernel_destroy_context(kctx);
	}
	return ret;
}

/*
 * Add UST context to tracer.
 */
int context_ust_add(struct ltt_ust_session *usess,
		enum lttng_domain_type domain, struct lttng_event_context *ctx,
		char *channel_name)
{
	int ret = LTTNG_OK;
	struct lttng_ht_iter iter;
	struct lttng_ht *chan_ht;
	struct ltt_ust_channel *uchan = NULL;

	assert(usess);
	assert(ctx);
	assert(channel_name);

	rcu_read_lock();

	chan_ht = usess->domain_global.channels;

	/* Get UST channel if defined */
	if (channel_name[0] != '\0') {
		uchan = trace_ust_find_channel_by_name(chan_ht, channel_name);
		if (uchan == NULL) {
			ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
			goto error;
		}
	}

	if (uchan) {
		/* Add ctx to channel */
		ret = add_uctx_to_channel(usess, domain, uchan, ctx);
	} else {
		rcu_read_lock();
		/* Add ctx all events, all channels */
		cds_lfht_for_each_entry(chan_ht->ht, &iter.iter, uchan, node.node) {
			ret = add_uctx_to_channel(usess, domain, uchan, ctx);
			if (ret) {
				ERR("Failed to add context to channel %s",
						uchan->name);
				continue;
			}
		}
		rcu_read_unlock();
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
	rcu_read_unlock();
	return ret;
}
