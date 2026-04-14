/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "context-configuration.hpp"
#include "health-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "recording-channel-configuration.hpp"
#include "ust-app-channel.hpp"
#include "ust-app-ctx.hpp"
#include "ust-app.hpp"

#include <common/common.hpp>
#include <common/compat/errno.hpp>

#include <cstring>

namespace lsu = lttng::sessiond::ust;
namespace lsc = lttng::sessiond::config;

namespace {
/*
 * Alloc new UST app context.
 */
struct ust_app_ctx *alloc_ust_app_ctx(struct lttng_ust_context_attr *uctx,
				      const lsc::context_configuration& ctx_config)
{
	struct ust_app_ctx *ua_ctx;

	try {
		ua_ctx = new ust_app_ctx(ctx_config);
	} catch (const std::bad_alloc&) {
		goto error;
	}

	if (uctx) {
		memcpy(&ua_ctx->ctx, uctx, sizeof(ua_ctx->ctx));
		if (uctx->ctx == LTTNG_UST_ABI_CONTEXT_APP_CONTEXT) {
			char *provider_name = nullptr, *ctx_name = nullptr;

			provider_name = strdup(uctx->u.app_ctx.provider_name);
			ctx_name = strdup(uctx->u.app_ctx.ctx_name);
			if (!provider_name || !ctx_name) {
				free(provider_name);
				free(ctx_name);
				goto error;
			}

			ua_ctx->ctx.u.app_ctx.provider_name = provider_name;
			ua_ctx->ctx.u.app_ctx.ctx_name = ctx_name;
		}
	}

	DBG3("UST app context %d allocated", ua_ctx->ctx.ctx);
	return ua_ctx;
error:
	delete ua_ctx;
	return nullptr;
}

/*
 * Create the channel context on the tracer.
 *
 * Called with UST app session lock held.
 */
int create_ust_channel_context(struct ust_app_channel *ua_chan,
			       struct ust_app_ctx *ua_ctx,
			       lsu::app *app)
{
	int ret = 0;

	health_code_update();

	try {
		app->command_socket.lock().add_context(&ua_ctx->ctx, ua_chan->obj, &ua_ctx->obj);
	} catch (const lsu::app_communication_error&) {
		goto error;
	} catch (const lttng::runtime_error&) {
		ret = -1;
		goto error;
	}

	ua_ctx->handle = ua_ctx->obj->header.handle;

	DBG2("UST app context handle %d created successfully for channel %s",
	     ua_ctx->handle,
	     ua_chan->channel_config.name.c_str());

error:
	health_code_update();
	return ret;
}
} /* anonymous namespace */

/*
 * Delete ust context safely. RCU read lock must be held before calling
 * this function.
 */
void delete_ust_app_ctx(int sock, struct ust_app_ctx *ua_ctx, lsu::app *app)
{
	int ret;

	LTTNG_ASSERT(ua_ctx);

	if (ua_ctx->obj) {
		{
			const auto protocol = app->command_socket.lock();
			ret = lttng_ust_ctl_release_object(sock, ua_ctx->obj);
		}
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release ctx failed. Application is dead: pid = %d, sock = %d",
				     app->pid,
				     app->command_socket.fd());
			} else if (ret == -EAGAIN) {
				WARN("UST app release ctx failed. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->command_socket.fd());
			} else {
				ERR("UST app release ctx obj handle %d failed with ret %d: pid = %d, sock = %d",
				    ua_ctx->obj->header.handle,
				    ret,
				    app->pid,
				    app->command_socket.fd());
			}
		}
		free(ua_ctx->obj);
	}

	if (ua_ctx->ctx.ctx == LTTNG_UST_ABI_CONTEXT_APP_CONTEXT) {
		free(ua_ctx->ctx.u.app_ctx.provider_name);
		free(ua_ctx->ctx.u.app_ctx.ctx_name);
	}

	delete ua_ctx;
}

/*
 * Create a context for the channel on the tracer.
 *
 * Called with UST app session lock held.
 */
int create_ust_app_channel_context(struct ust_app_channel *ua_chan,
				   struct lttng_ust_context_attr *uctx,
				   lsu::app *app,
				   const lsc::context_configuration& ctx_config)
{
	int ret = 0;
	struct ust_app_ctx *ua_ctx;

	DBG2("UST app adding context to channel %s", ua_chan->channel_config.name.c_str());

	if (ua_chan->contexts.find(&ctx_config) != ua_chan->contexts.end()) {
		ret = -EEXIST;
		goto error;
	}

	ua_ctx = alloc_ust_app_ctx(uctx, ctx_config);
	if (ua_ctx == nullptr) {
		/* malloc failed */
		ret = -ENOMEM;
		goto error;
	}

	ua_chan->contexts.emplace(&ctx_config, ua_ctx);

	ret = create_ust_channel_context(ua_chan, ua_ctx, app);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Determine if the context is redundant for the channel.
 *
 * This is used to avoid sending a context registration to UST. However, it
 * should not be used for filtering context to be added internally by the
 * session daemon.
 *
 * The rationale here is that some contexts are provided implicitly by some
 * channels.
 *
 * LTTNG_UST_ABI_CHAN_PER_CPU:
 *   LTTNG_UST_ABI_CONTEXT_CPU_ID:
 *     The CPU ID is implicitly provided in the packer header.
 */
bool is_context_redundant(const lsc::recording_channel_configuration& chan_config,
			  const lsc::context_configuration& ctx_config)
{
	if (chan_config.buffer_allocation_policy ==
	    lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CPU) {
		if (ctx_config.context_type == lsc::context_configuration::type::CPU_ID) {
			return true;
		}
	}

	return false;
}
