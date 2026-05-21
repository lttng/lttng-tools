/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CLI_COMMANDS_SHOW_MAPS_BUILD_OUTPUT_HPP
#define LTTNG_CLI_COMMANDS_SHOW_MAPS_BUILD_OUTPUT_HPP

#include "show-maps-cmd-cfg.hpp"
#include "show-maps-output-model.hpp"

namespace lttng {
namespace cli {
namespace show_maps {

/*
 * Communicates with the session daemon to fetch every map channel of
 * the configured session, applies
 * selection/aggregation/sorting/limiting, and returns the effective set
 * of tables to show.
 *
 * Throws `lttng::ctl::error` on session daemon error.
 */
output output_from_cmd_cfg(const cmd_cfg& cfg);

} /* namespace show_maps */
} /* namespace cli */
} /* namespace lttng */

#endif /* LTTNG_CLI_COMMANDS_SHOW_MAPS_BUILD_OUTPUT_HPP */
