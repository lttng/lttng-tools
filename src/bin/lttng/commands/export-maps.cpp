/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "../command.hpp"
#include "../exception.hpp"
#include "../utils.hpp"
#include "export-maps-mi.hpp"
#include "export-maps-sql.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/make-unique-wrapper.hpp>

#include <lttng/lttng.h>

#include <vendor/argpar/argpar.hpp>
#include <vendor/optional.hpp>

#include <cstdio>
#include <exception>
#include <string>
#include <utility>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-export-maps.1.h>
	;
#endif /* LTTNG_EMBED_HELP */

namespace lttng {
namespace cli {
namespace export_maps {
namespace {

void reject_dup_opt(const char *const long_name, const bool already_set)
{
	if (already_set) {
		LTTNG_THROW_CLI_INVALID_USAGE(
			fmt::format("Option `--{}` specified more than once", long_name));
	}
}

/*
 * Validates the value of the `--format` option.
 *
 * `sqlite` (an SQL script for the SQLite database engine) is the only
 * accepted format as of this writing; a future incompatible schema or a
 * format for another SQL database engine would introduce a new value.
 */
void check_format_arg(const std::string& arg)
{
	if (arg != "sqlite") {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format(
			"Invalid value for `--format` option: `{}` (expected `sqlite`)", arg));
	}
}

/*
 * Configuration built from the CLI options.
 */
struct cmd_cfg final {
	std::string session_name;
};

/*
 * Parses the CLI arguments and returns a configuration, or
 * `nonstd::nullopt` when the caller should exit successfully (help
 * or `--list-options`).
 *
 * Throws `lttng::cli::invalid_usage_error` on invalid arguments and
 * `lttng::cli::no_default_session_error` if no session can be selected.
 */
nonstd::optional<cmd_cfg> cmd_cfg_from_cli_args(const int argc, const char **const argv)
{
	enum export_maps_option_type {
		OPT_HELP,
		OPT_LIST_OPTIONS,
		OPT_SESSION,
		OPT_FORMAT,
	};

	constexpr argpar_opt_descr export_maps_options[] = {
		{ OPT_HELP, 'h', "help", false },
		{ OPT_LIST_OPTIONS, '\0', "list-options", false },
		{ OPT_SESSION, 's', "session", true },
		{ OPT_FORMAT, 'f', "format", true },
		ARGPAR_OPT_DESCR_SENTINEL,
	};

	argpar::Iter<nonstd::optional<argpar::Item>> argpar_iter(
		argc - 1, argv + 1, export_maps_options);

	nonstd::optional<std::string> session_name;
	nonstd::optional<std::string> format;

	try {
		while (const auto item = argpar_iter.next()) {
			if (item->isNonOpt()) {
				LTTNG_THROW_CLI_INVALID_USAGE(
					fmt::format("Unexpected positional argument `{}`",
						    item->asNonOpt().arg()));
			}

			const auto& opt = item->asOpt();
			const auto long_name = opt.descr().long_name;

			switch (opt.descr().id) {
			case OPT_HELP:
				SHOW_HELP_THROW("export-maps");
				return nonstd::nullopt;
			case OPT_LIST_OPTIONS:
				list_cmd_options_argpar(stdout, export_maps_options);
				return nonstd::nullopt;
			case OPT_SESSION:
				reject_dup_opt(long_name, session_name.has_value());
				session_name = opt.arg();
				break;
			case OPT_FORMAT:
				reject_dup_opt(long_name, format.has_value());
				check_format_arg(opt.arg());
				format = opt.arg();
				break;
			default:
				break;
			}
		}
	} catch (const argpar::UnknownOptError& exc) {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Unknown option `{}`", exc.name()));
	} catch (const argpar::MissingOptArgumentError& exc) {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Missing argument for option `{}{}`",
							  exc.descr().isShort() ? "-" : "--",
							  exc.descr().isShort() ?
								  &exc.descr().descr().short_name :
								  exc.descr().descr().long_name));
	} catch (const argpar::UnexpectedOptArgumentError& exc) {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Unexpected argument for option `{}{}`",
							  exc.descr().isShort() ? "-" : "--",
							  exc.descr().isShort() ?
								  &exc.descr().descr().short_name :
								  exc.descr().descr().long_name));
	}

	cmd_cfg cmd_cfg;

	if (session_name) {
		cmd_cfg.session_name = std::move(*session_name);
	} else {
		const auto def_session_name =
			make_unique_wrapper<char, memory::free>(get_session_name());

		if (!def_session_name) {
			LTTNG_THROW_CLI_NO_DEFAULT_SESSION();
		}

		cmd_cfg.session_name = def_session_name.get();
	}

	return cmd_cfg;
}

} /* namespace */
} /* namespace export_maps */
} /* namespace cli */
} /* namespace lttng */

int cmd_export_maps(const int argc, const char **const argv)
{
	namespace em = lttng::cli::export_maps;

	try {
		if (const auto cmd_cfg = em::cmd_cfg_from_cli_args(argc, argv)) {
			const auto sql = em::sql_from_session(cmd_cfg->session_name);

			if (lttng_opt_mi) {
				em::run_mi(sql);
			} else {
				std::fputs(sql.c_str(), stdout);
			}
		}
	} catch (const lttng::ctl::error& exc) {
		ERR_FMT("Failed to export maps: {}", lttng_strerror(exc.code()));
		return CMD_ERROR;
	} catch (const std::exception& exc) {
		ERR_FMT("Failed to export maps: {}", exc.what());
		return CMD_ERROR;
	}

	return CMD_SUCCESS;
}
