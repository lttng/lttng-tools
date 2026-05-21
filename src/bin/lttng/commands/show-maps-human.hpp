/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CLI_COMMANDS_SHOW_MAPS_HUMAN_HPP
#define LTTNG_CLI_COMMANDS_SHOW_MAPS_HUMAN_HPP

#include "show-maps-output-model.hpp"

namespace lttng {
namespace cli {
namespace show_maps {

/*
 * Renders `output` to the standard output in human-readable form.
 */
void run_human(const output& out);

} /* namespace show_maps */
} /* namespace cli */
} /* namespace lttng */

#endif /* LTTNG_CLI_COMMANDS_SHOW_MAPS_HUMAN_HPP */
