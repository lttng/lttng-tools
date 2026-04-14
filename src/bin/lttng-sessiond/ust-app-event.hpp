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

#include <unordered_map>

struct lttng_bytecode;
struct lttng_event_exclusion;
struct ust_app_channel;

namespace lttng {
namespace sessiond {
namespace config {
class event_rule_configuration;
} /* namespace config */
namespace ust {
struct app;
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

struct ust_app_event {
	using event_map =
		std::unordered_map<const lttng::sessiond::config::event_rule_configuration *,
				   ust_app_event *>;

	explicit ust_app_event(
		struct ust_app_channel& channel_,
		const lttng::sessiond::config::event_rule_configuration& event_rule_config_) :
		channel(channel_), event_rule_config(event_rule_config_)
	{
	}

	~ust_app_event() = default;
	ust_app_event(const ust_app_event&) = delete;
	ust_app_event(ust_app_event&&) = delete;
	ust_app_event& operator=(const ust_app_event&) = delete;
	ust_app_event& operator=(ust_app_event&&) = delete;

	/* Release the tracer-side event object and free local resources. */
	void destroy(int sock);

	/* Enable this event on the UST tracer and update local state. */
	int enable();

	/* Disable this event on the UST tracer and update local state. */
	int disable();

	/* Create this event on the UST tracer and synchronize local state. */
	int create_on_ust();

	/* Create and register a per-app event in the channel's event map. */
	static int create(struct ust_app_channel& channel,
			  const lttng::sessiond::config::event_rule_configuration& event_config);

	/* Find a per-app event by matching its configuration pointer. */
	static struct ust_app_event *
	find_by_config(const event_map& events,
		       const lttng::sessiond::config::event_rule_configuration& event_config);

	bool enabled = false;
	int handle = 0;
	struct lttng_ust_abi_object_data *obj = nullptr;
	struct ust_app_channel& channel;
	const lttng::sessiond::config::event_rule_configuration& event_rule_config;
};

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
