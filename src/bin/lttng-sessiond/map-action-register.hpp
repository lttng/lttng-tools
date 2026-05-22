/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MAP_ACTION_REGISTER_HPP
#define LTTNG_SESSIOND_MAP_ACTION_REGISTER_HPP

#include "session.hpp"

#include <functional>

struct lttng_trigger;
struct lttng_action;

namespace lttng {
namespace sessiond {
namespace map {

/*
 * Resolve the action's target and bind its event rule to the target map
 * channel by issuing add_map_channel_event_rule on the matching orchestrator.
 *
 * Throws if required target properties are unset and on orchestrator-side errors.
 *
 * This overload acquires the session list lock and the target session lock.
 */
void attempt_register(const lttng_trigger& trigger, const lttng_action& incr_map_value_action);

/*
 * Same as attempt_register(), but for an already-locked session.
 * Throws if required target properties are unset and on orchestrator-side errors.
 * No-op unless incr_map_value_action targets target_session.
 */
void attempt_register(const lttng_trigger& trigger,
		      const ltt_session::locked_ref& target_session,
		      const lttng_action& incr_map_value_action);

/*
 * Inverse of attempt_register(): remove the matching counter-event rule.
 * Applies the same unset-property exceptions, no-op conditions, and lock
 * acquisition as the first attempt_register() overload.
 */
void attempt_unregister(const lttng_trigger& trigger, const lttng_action& incr_map_value_action);

/* Visit all increment-map-value actions in trigger's action tree. */
void for_each_increment_map_value_action(const lttng_trigger& trigger,
					 const std::function<void(const lttng_action&)>& visitor);

} /* namespace map */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MAP_ACTION_REGISTER_HPP */
