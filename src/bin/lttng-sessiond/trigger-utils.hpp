/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_TRIGGER_UTILS_HPP
#define LTTNG_SESSIOND_TRIGGER_UTILS_HPP

#include "session.hpp"

struct lttng_trigger;

namespace lttng {
namespace sessiond {

/*
 * Whether `trigger` is permitted to interact with `session`: true when the
 * trigger owner's uid equals the session's uid, or the trigger owner is root.
 * Logs a WARN on denial.
 *
 * This is the single owner-or-root policy shared by the action executor (for
 * session-targeting actions) and the map-action binding evaluator (for
 * increment-map-value bindings).
 */
bool is_trigger_allowed_for_session(const lttng_trigger *trigger,
				    const ltt_session::locked_ref& session);

} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_TRIGGER_UTILS_HPP */
