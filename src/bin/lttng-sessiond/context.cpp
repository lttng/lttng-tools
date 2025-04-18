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
#include "kernel.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"

#include <common/error.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/urcu.hpp>

#include <stdio.h>
#include <unistd.h>
#include <urcu/list.h>

/*
 * Add kernel context to all channel.
 *
 * Assumes the ownership of kctx.
 */
static int add_kctx_all_channels(struct ltt_kernel_session *ksession,
				 struct ltt_kernel_context *kctx)
{
	int ret;

	LTTNG_ASSERT(ksession);
	LTTNG_ASSERT(kctx);

	DBG("Adding kernel context to all channels");

	/* Go over all channels */
	for (auto kchan :
	     lttng::urcu::list_iteration_adapter<ltt_kernel_channel, &ltt_kernel_channel::list>(
		     ksession->channel_list.head)) {
		struct ltt_kernel_context *kctx_copy;

		kctx_copy = trace_kernel_copy_context(kctx);
		if (!kctx_copy) {
			PERROR("zmalloc ltt_kernel_context");
			ret = -LTTNG_ERR_NOMEM;
			goto error;
		}

		/* Ownership of kctx_copy is transferred to the callee. */
		ret = kernel_add_channel_context(kchan, kctx_copy);
		kctx_copy = nullptr;
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
static int add_kctx_to_channel(struct ltt_kernel_context *kctx, struct ltt_kernel_channel *kchan)
{
	int ret;

	LTTNG_ASSERT(kchan);
	LTTNG_ASSERT(kctx);

	DBG("Add kernel context to channel '%s'", kchan->channel->name);

	/* Ownership of kctx is transferred to the callee. */
	ret = kernel_add_channel_context(kchan, kctx);
	kctx = nullptr;
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
 * Add kernel context to tracer.
 */
int context_kernel_add(struct ltt_kernel_session *ksession,
		       const struct lttng_event_context *ctx,
		       const char *channel_name)
{
	int ret;
	struct ltt_kernel_channel *kchan;
	struct ltt_kernel_context *kctx;

	LTTNG_ASSERT(ksession);
	LTTNG_ASSERT(ctx);
	LTTNG_ASSERT(channel_name);

	kctx = trace_kernel_create_context(nullptr);
	if (!kctx) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	/* Setup kernel context structure */
	switch (ctx->ctx) {
	case LTTNG_EVENT_CONTEXT_PID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PID;
		break;
	case LTTNG_EVENT_CONTEXT_PROCNAME:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PROCNAME;
		break;
	case LTTNG_EVENT_CONTEXT_PRIO:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PRIO;
		break;
	case LTTNG_EVENT_CONTEXT_NICE:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_NICE;
		break;
	case LTTNG_EVENT_CONTEXT_VPID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VPID;
		break;
	case LTTNG_EVENT_CONTEXT_TID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_TID;
		break;
	case LTTNG_EVENT_CONTEXT_VTID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VTID;
		break;
	case LTTNG_EVENT_CONTEXT_PPID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PPID;
		break;
	case LTTNG_EVENT_CONTEXT_VPPID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VPPID;
		break;
	case LTTNG_EVENT_CONTEXT_HOSTNAME:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_HOSTNAME;
		break;
	case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PERF_CPU_COUNTER;
		break;
	case LTTNG_EVENT_CONTEXT_INTERRUPTIBLE:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_INTERRUPTIBLE;
		break;
	case LTTNG_EVENT_CONTEXT_PREEMPTIBLE:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PREEMPTIBLE;
		break;
	case LTTNG_EVENT_CONTEXT_NEED_RESCHEDULE:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_NEED_RESCHEDULE;
		break;
	case LTTNG_EVENT_CONTEXT_MIGRATABLE:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_MIGRATABLE;
		break;
	case LTTNG_EVENT_CONTEXT_CALLSTACK_KERNEL:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_CALLSTACK_KERNEL;
		break;
	case LTTNG_EVENT_CONTEXT_CALLSTACK_USER:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_CALLSTACK_USER;
		break;
	case LTTNG_EVENT_CONTEXT_CGROUP_NS:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_CGROUP_NS;
		break;
	case LTTNG_EVENT_CONTEXT_IPC_NS:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_IPC_NS;
		break;
	case LTTNG_EVENT_CONTEXT_MNT_NS:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_MNT_NS;
		break;
	case LTTNG_EVENT_CONTEXT_NET_NS:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_NET_NS;
		break;
	case LTTNG_EVENT_CONTEXT_PID_NS:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_PID_NS;
		break;
	case LTTNG_EVENT_CONTEXT_TIME_NS:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_TIME_NS;
		break;
	case LTTNG_EVENT_CONTEXT_USER_NS:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_USER_NS;
		break;
	case LTTNG_EVENT_CONTEXT_UTS_NS:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_UTS_NS;
		break;
	case LTTNG_EVENT_CONTEXT_UID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_UID;
		break;
	case LTTNG_EVENT_CONTEXT_EUID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_EUID;
		break;
	case LTTNG_EVENT_CONTEXT_SUID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_SUID;
		break;
	case LTTNG_EVENT_CONTEXT_GID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_GID;
		break;
	case LTTNG_EVENT_CONTEXT_EGID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_EGID;
		break;
	case LTTNG_EVENT_CONTEXT_SGID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_SGID;
		break;
	case LTTNG_EVENT_CONTEXT_VUID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VUID;
		break;
	case LTTNG_EVENT_CONTEXT_VEUID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VEUID;
		break;
	case LTTNG_EVENT_CONTEXT_VSUID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VSUID;
		break;
	case LTTNG_EVENT_CONTEXT_VGID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VGID;
		break;
	case LTTNG_EVENT_CONTEXT_VEGID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VEGID;
		break;
	case LTTNG_EVENT_CONTEXT_VSGID:
		kctx->ctx.ctx = LTTNG_KERNEL_ABI_CONTEXT_VSGID;
		break;
	case LTTNG_EVENT_CONTEXT_CPU_ID:
		/* fall through */
	default:
		ret = LTTNG_ERR_KERN_CONTEXT_FAIL;
		goto error;
	}

	kctx->ctx.u.perf_counter.type = ctx->u.perf_counter.type;
	kctx->ctx.u.perf_counter.config = ctx->u.perf_counter.config;
	strncpy(kctx->ctx.u.perf_counter.name, ctx->u.perf_counter.name, LTTNG_SYMBOL_NAME_LEN);
	kctx->ctx.u.perf_counter.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';

	if (*channel_name == '\0') {
		ret = add_kctx_all_channels(ksession, kctx);
		/* Ownership of kctx is transferred to the callee. */
		kctx = nullptr;
		if (ret != LTTNG_OK) {
			goto error;
		}
	} else {
		/* Get kernel channel */
		kchan = trace_kernel_get_channel_by_name(channel_name, ksession);
		if (kchan == nullptr) {
			ret = LTTNG_ERR_KERN_CHAN_NOT_FOUND;
			goto error;
		}

		ret = add_kctx_to_channel(kctx, kchan);
		/* Ownership of kctx is transferred to the callee. */
		kctx = nullptr;
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
