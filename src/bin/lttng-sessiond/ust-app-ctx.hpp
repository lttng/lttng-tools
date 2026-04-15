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
namespace ust {
class app_channel;
class app_context;
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

namespace lttng {
namespace sessiond {
namespace ust {

class app_context {
public:
	explicit app_context(app_channel& channel,
			     const lttng::sessiond::config::context_configuration& context_config_,
			     const lttng_ust_context_attr *uctx = nullptr);
	~app_context();
	app_context(const app_context&) = delete;
	app_context(app_context&&) = delete;
	app_context& operator=(const app_context&) = delete;
	app_context& operator=(app_context&&) = delete;

	int handle = 0;
	struct lttng_ust_context_attr ctx = {};
	struct lttng_ust_abi_object_data *obj = nullptr;
	const lttng::sessiond::config::context_configuration& context_config;

private:
	app_channel& _channel;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#ifdef HAVE_LIBLTTNG_UST_CTL

bool is_context_redundant(
	const lttng::sessiond::config::recording_channel_configuration& chan_config,
	const lttng::sessiond::config::context_configuration& ctx_config);

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_UST_APP_CTX_HPP */
