/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APP_EVENT_HPP
#define LTTNG_SESSIOND_UST_APP_EVENT_HPP

#include "lttng-ust-ctl.hpp"

#include <memory>
#include <unordered_map>

struct lttng_bytecode;
struct lttng_event_exclusion;

namespace lttng {
namespace sessiond {
namespace config {
class event_rule_configuration;
} /* namespace config */
namespace ust {
struct app;
class app_channel;
class app_event;
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

namespace lttng {
namespace sessiond {
namespace ust {

class app_event {
public:
	using event_map =
		std::unordered_map<const lttng::sessiond::config::event_rule_configuration *,
				   std::unique_ptr<app_event>>;

	explicit app_event(
		app_channel& channel_,
		const lttng::sessiond::config::event_rule_configuration& event_rule_config_) :
		channel(channel_), event_rule_config(event_rule_config_)
	{
	}

	~app_event();
	app_event(const app_event&) = delete;
	app_event(app_event&&) = delete;
	app_event& operator=(const app_event&) = delete;
	app_event& operator=(app_event&&) = delete;

	/* Enable this event on the UST tracer and update local state. */
	void enable();

	/* Disable this event on the UST tracer and update local state. */
	void disable();

	/* Create this event on the UST tracer and synchronize local state. */
	void create_on_ust();

	/* Create and register a per-app event in the channel's event map. */
	static void create(app_channel& channel,
			   const lttng::sessiond::config::event_rule_configuration& event_config);

	/* Find a per-app event by matching its configuration pointer. */
	static app_event *
	find_by_config(const event_map& events,
		       const lttng::sessiond::config::event_rule_configuration& event_config);

	bool enabled = false;
	int handle = 0;
	struct lttng_ust_abi_object_data *obj = nullptr;
	app_channel& channel;
	const lttng::sessiond::config::event_rule_configuration& event_rule_config;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * UST object tracer-side enable/disable/filter/exclusion helpers. Used
 * both for per-app events and for event notifier rules.
 */
int enable_ust_object(lttng::sessiond::ust::app *app, struct lttng_ust_abi_object_data *ust_object);
int disable_ust_object(lttng::sessiond::ust::app *app, struct lttng_ust_abi_object_data *object);
int set_ust_object_filter(lttng::sessiond::ust::app *app,
			  const struct lttng_bytecode *bytecode,
			  struct lttng_ust_abi_object_data *ust_object);
int set_ust_object_exclusions(lttng::sessiond::ust::app *app,
			      const struct lttng_event_exclusion *exclusions,
			      struct lttng_ust_abi_object_data *ust_object);

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_UST_APP_EVENT_HPP */
