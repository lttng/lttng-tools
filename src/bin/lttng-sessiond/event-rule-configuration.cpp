/*
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-rule-configuration.hpp"

namespace ls = lttng::sessiond;

ls::event_rule_configuration::event_rule_configuration(bool is_enabled_,
						       lttng::event_rule_uptr&& event_rule_) :
	is_enabled(is_enabled_), event_rule(std::move(event_rule_))
{
}

void ls::event_rule_configuration::set_enabled(bool enable) noexcept
{
	is_enabled = enable;
}
