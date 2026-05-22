/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_COUNTER_EVENT_PAYLOAD_HPP
#define LTTNG_SESSIOND_COUNTER_EVENT_PAYLOAD_HPP

#include <cstdint>
#include <vector>

struct lttng_event_rule;
struct lttng_action;

namespace lttng {
namespace sessiond {
namespace map {
namespace details {

/* Build and serialize a UST counter-event ABI payload from rule/action inputs. */
std::vector<char> serialize_for_ust(const lttng_event_rule& event_rule,
				    const lttng_action& incr_map_value_action,
				    std::uint64_t user_token);

/* Build and serialize a kernel counter-event ABI payload from rule/action inputs. */
std::vector<char> serialize_for_modules(const lttng_event_rule& event_rule,
					const lttng_action& incr_map_value_action,
					std::uint64_t user_token);

} /* namespace details */
} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_COUNTER_EVENT_PAYLOAD_HPP */
