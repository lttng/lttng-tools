/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APP_CTX_HPP
#define LTTNG_SESSIOND_UST_APP_CTX_HPP

#include "lttng-ust-ctl.hpp"

namespace lttng {
namespace sessiond {
namespace config {
class context_configuration;
class recording_channel_configuration;
} /* namespace config */
} /* namespace sessiond */
} /* namespace lttng */

struct ust_app_channel;

struct ust_app_ctx {
	explicit ust_app_ctx(ust_app_channel& channel,
			     const lttng::sessiond::config::context_configuration& context_config_,
			     const lttng_ust_context_attr *uctx = nullptr);
	~ust_app_ctx();
	ust_app_ctx(const ust_app_ctx&) = delete;
	ust_app_ctx(ust_app_ctx&&) = delete;
	ust_app_ctx& operator=(const ust_app_ctx&) = delete;
	ust_app_ctx& operator=(ust_app_ctx&&) = delete;

	int handle = 0;
	struct lttng_ust_context_attr ctx = {};
	struct lttng_ust_abi_object_data *obj = nullptr;
	const lttng::sessiond::config::context_configuration& context_config;

private:
	ust_app_channel& _channel;
};

#ifdef HAVE_LIBLTTNG_UST_CTL

int create_ust_app_channel_context(struct ust_app_channel *ua_chan,
				   struct lttng_ust_context_attr *uctx,
				   const lttng::sessiond::config::context_configuration& ctx_config);
bool is_context_redundant(
	const lttng::sessiond::config::recording_channel_configuration& chan_config,
	const lttng::sessiond::config::context_configuration& ctx_config);

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_UST_APP_CTX_HPP */
