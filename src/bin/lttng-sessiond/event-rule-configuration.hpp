/*
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_EVENT_RULE_CONFIGURATION_HPP
#define LTTNG_SESSIOND_EVENT_RULE_CONFIGURATION_HPP

#include <common/ctl/memory.hpp>
#include <common/format.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <string>

namespace lttng {
namespace sessiond {

/*
 * An event rule configuration represents the configuration of a channel or map's
 * event rule at a given point in time. It belongs to a single channel or map.
 */
class event_rule_configuration final {
public:
	using uptr = std::unique_ptr<event_rule_configuration>;

	event_rule_configuration(bool is_enabled, lttng::event_rule_uptr&& event_rule);

	~event_rule_configuration() = default;
	event_rule_configuration(event_rule_configuration&&) = delete;
	event_rule_configuration(const event_rule_configuration&) = delete;
	event_rule_configuration& operator=(const event_rule_configuration&) = delete;
	event_rule_configuration& operator=(event_rule_configuration&&) = delete;

	void enable() noexcept
	{
		set_enabled(true);
	}

	void disable() noexcept
	{
		set_enabled(false);
	}

	void set_enabled(bool enable) noexcept;

	bool is_enabled;
	const lttng::event_rule_uptr event_rule;
};

} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_EVENT_RULE_CONFIGURATION_HPP */
