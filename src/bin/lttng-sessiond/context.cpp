/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "context.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"
#include "ust-domain-orchestrator.hpp"

#include <common/error.hpp>
#include <common/format.hpp>
#include <common/urcu.hpp>

#include <cstring>
#include <urcu/list.h>

namespace lsc = lttng::sessiond::config;

namespace {

/*
 * Add a UST context to a channel.
 *
 * The context_configuration must outlive the created ltt_ust_context.
 */
int add_uctx_to_channel(struct ltt_ust_session *usess,
			struct ltt_ust_channel *uchan,
			const lsc::context_configuration& context_config)
{
	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(uchan);

	/* Check for duplicate contexts on this channel. */
	for (auto *uctx_it :
	     lttng::urcu::list_iteration_adapter<ltt_ust_context, &ltt_ust_context::list>(
		     uchan->ctx_list)) {
		if (uctx_it->context_config == context_config) {
			return LTTNG_ERR_UST_CONTEXT_EXIST;
		}
	}

	/* Create ltt UST context from the context_configuration. */
	std::unique_ptr<ltt_ust_context> new_uctx;
	new_uctx.reset((trace_ust_create_context(context_config)));
	if (!new_uctx) {
		return LTTNG_ERR_UST_CONTEXT_INVAL;
	}

	auto *const new_uctx_ptr = new_uctx.get();

	/* Add ltt UST context node to ltt UST channel. */
	lttng_ht_add_ulong(uchan->ctx, &new_uctx_ptr->node);
	cds_list_add_tail(&new_uctx_ptr->list, &uchan->ctx_list);

	LTTNG_ASSERT(!usess->active);
	if (!usess->active) {
		new_uctx.release();
		return 0;
	}

	const auto ret = ust_app_add_ctx_channel_glb(usess, uchan->name, context_config);
	if (ret < 0) {
		/* Roll back insertion to leave channel structures consistent. */
		cds_list_del(&new_uctx_ptr->list);

		lttng_ht_iter iter = {};
		iter.iter.node = &new_uctx_ptr->node.node;
		const auto ht_del_ret = lttng_ht_del(uchan->ctx, &iter);
		LTTNG_ASSERT(!ht_del_ret);

		return ret;
	}

	new_uctx.release();

	DBG("Context UST `%s` added to channel %s",
	    lttng::format("{}", context_config).c_str(),
	    uchan->name);

	return 0;
}

} /* anonymous namespace */

/*
 * Add a UST context from a context_configuration to a specific channe.
 *
 * The context_configuration must outlive the created ltt_ust_context objects.
 */
int context_ust_add(struct ltt_ust_session *usess,
		    const lsc::context_configuration& context_config,
		    const char *channel_name)
{
	int ret = LTTNG_OK;
	struct lttng_ht *chan_ht;
	ltt_ust_channel *uchan = nullptr;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(channel_name);
	LTTNG_ASSERT(strlen(channel_name) != 0);

	chan_ht = usess->domain_global.channels;

	const lttng::urcu::read_lock_guard read_lock;
	uchan = trace_ust_find_channel_by_name(chan_ht, channel_name);
	if (uchan == nullptr) {
		ret = LTTNG_ERR_UST_CHAN_NOT_FOUND;
		goto error;
	}

	ret = add_uctx_to_channel(usess, uchan, context_config);
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
