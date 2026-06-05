/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CLI_COMMANDS_EXPORT_MAPS_MI_HPP
#define LTTNG_CLI_COMMANDS_EXPORT_MAPS_MI_HPP

#include <string>

namespace lttng {
namespace cli {
namespace export_maps {

/*
 * Writes the MI (XML) result of the `export-maps` command to the standard
 * output: an `<export-maps>` element holding a single `<output>` element
 * which holds the whole SQL script `sql`.
 *
 * Throws on MI writer error.
 */
void run_mi(const std::string& sql);

} /* namespace export_maps */
} /* namespace cli */
} /* namespace lttng */

#endif /* LTTNG_CLI_COMMANDS_EXPORT_MAPS_MI_HPP */
