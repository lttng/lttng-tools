/*
 * Copyright (C) 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CTL_EVENT_RULE_CONVERT_HPP
#define LTTNG_CTL_EVENT_RULE_CONVERT_HPP

#include "lttng/event-rule/event-rule-internal.hpp"

#include <common/ctl/memory.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <lttng/lttng.h>

#include <vendor/optional.hpp>

#include <memory>
#include <vector>

namespace lttng {
namespace ctl {
event_rule_uptr
create_event_rule_from_lttng_event(const lttng_event& event,
				   lttng_domain_type domain,
				   const nonstd::optional<lttng::c_string_view>& filter_expression,
				   const std::vector<lttng::c_string_view>& exclusions);
} /* namespace ctl */
} /* namespace lttng */

#endif /* LTTNG_CTL_EVENT_RULE_CONVERT_HPP */
