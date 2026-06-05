/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CLI_COMMANDS_EXPORT_MAPS_SQL_HPP
#define LTTNG_CLI_COMMANDS_EXPORT_MAPS_SQL_HPP

#include <string>

namespace lttng {
namespace cli {
namespace export_maps {

/*
 * Communicates with the session daemon to fetch every map channel of
 * the recording session named `session_name` and returns a complete SQL
 * script exporting their raw values as an SQL script.
 *
 * The returned script creates the `channels`, `groups`, `keys`, and
 * `entries` tables as well as the `vmap` view, and then inserts every
 * map entry within a single transaction.
 *
 * Throws `lttng::ctl::error` on session daemon error and a generic
 * error when the recording session doesn't exist.
 */
std::string sql_from_session(const std::string& session_name);

} /* namespace export_maps */
} /* namespace cli */
} /* namespace lttng */

#endif /* LTTNG_CLI_COMMANDS_EXPORT_MAPS_SQL_HPP */
