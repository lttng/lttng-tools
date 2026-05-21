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
#include "show-maps-build-output.hpp"
#include "show-maps-human.hpp"
#include "show-maps-mi.hpp"

#include <common/argpar-utils/argpar-utils.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/utils.hpp>

#include <lttng/lttng.h>
#include <lttng/map/channel-type.h>

#include <vendor/argpar/argpar.hpp>
#include <vendor/optional.hpp>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <set>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-show-maps.1.h>
	;
#endif /* LTTNG_EMBED_HELP */

namespace lttng {
namespace cli {
namespace show_maps {
namespace {

void reject_dup_opt(const char *const long_name, const bool already_set)
{
	if (already_set) {
		LTTNG_THROW_CLI_INVALID_USAGE(
			fmt::format("Option `--{}` specified more than once", long_name));
	}
}

aggregation_level per_from_arg(const std::string& arg)
{
	if (arg == "channel") {
		return aggregation_level::CHANNEL;
	} else if (arg == "owner") {
		return aggregation_level::OWNER;
	} else if (arg == "part" || arg == "cpu") {
		return aggregation_level::PART;
	}

	LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Invalid value for `--per` option: `{}` "
						  "(expected `channel`, `owner`, `cpu`, or `part`)",
						  arg));
}

sort_column sort_by_from_arg(const std::string& arg)
{
	if (arg == "key") {
		return sort_column::KEY;
	} else if (arg == "value") {
		return sort_column::VALUE;
	}

	LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Invalid value for `--sort-by` option: `{}` "
						  "(expected `key` or `value`)",
						  arg));
}

sort_direction sort_order_from_arg(const std::string& arg)
{
	if (arg == "asc") {
		return sort_direction::ASC;
	} else if (arg == "desc") {
		return sort_direction::DESC;
	}

	LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Invalid value for `--sort-order` option: `{}` "
						  "(expected `asc` or `desc`)",
						  arg));
}

lttng_map_channel_type channel_type_from_arg(const std::string& arg)
{
	if (arg == "kernel") {
		return LTTNG_MAP_CHANNEL_TYPE_KERNEL;
	} else if (arg == "user") {
		return LTTNG_MAP_CHANNEL_TYPE_USER;
	}

	LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Invalid value for `--type` option: `{}` "
						  "(expected `kernel` or `user`)",
						  arg));
}

/*
 * Tries to parse `arg` as a non-negative decimal integer.
 *
 * Returns `nonstd::nullopt` if `arg` is empty, has a leading sign, has
 * trailing garbage, or overflows.
 *
 * Does NOT throw.
 *
 * strtoull() silently accepts a leading `-` and wraps the result,
 * therefore we reject any leading sign explicitly.
 */
nonstd::optional<std::uint64_t> try_parse_uint_arg(const std::string& arg)
{
	if (arg.empty() || arg.front() == '-' || arg.front() == '+') {
		return nonstd::nullopt;
	}

	errno = 0;

	char *end = nullptr;
	const auto value = std::strtoull(arg.c_str(), &end, 10);

	if (errno != 0 || end == arg.c_str() || *end != '\0') {
		return nonstd::nullopt;
	}

	return value;
}

/*
 * Parses `arg` as a non-negative decimal integer, throwing a CLI usage
 * error on parse error.
 *
 * `long_name` is the option long name (without the leading `--`) used
 * in error messages.
 */
std::uint64_t parse_uint_arg(const std::string& arg, const char *const long_name)
{
	if (arg.empty()) {
		LTTNG_THROW_CLI_INVALID_USAGE(
			fmt::format("Empty value for `--{}` option", long_name));
	}

	const auto value = try_parse_uint_arg(arg);

	if (!value) {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Invalid value for `--{}` option: `{}` "
							  "(expected a non-negative integer)",
							  long_name,
							  arg));
	}

	return *value;
}

std::uint64_t limit_from_arg(const std::string& arg)
{
	const auto value = parse_uint_arg(arg, "limit");

	if (value == 0) {
		LTTNG_THROW_CLI_INVALID_USAGE("Value for `--limit` option must be greater than 0");
	}

	return value;
}

pid_t pid_from_arg(const std::string& arg)
{
	return static_cast<pid_t>(parse_uint_arg(arg, "pid"));
}

unsigned int part_id_from_arg(const std::string& arg, const char *const long_name)
{
	return static_cast<unsigned int>(parse_uint_arg(arg, long_name));
}

/*
 * Resolves a Unix user designator to a numeric UID.
 *
 * Accepts a decimal UID as is; otherwise looks up the name
 * with utils_user_id_from_name().
 */
uid_t uid_from_arg(const std::string& arg)
{
	if (arg.empty()) {
		LTTNG_THROW_CLI_INVALID_USAGE("Empty value for `--uid` option");
	}

	/* Try as a numeric UID first */
	if (const auto value = try_parse_uint_arg(arg)) {
		return static_cast<uid_t>(*value);
	}

	/* Name resolution */
	uid_t uid;
	const auto ret_code = utils_user_id_from_name(arg.c_str(), &uid);

	if (ret_code == LTTNG_ERR_USER_NOT_FOUND) {
		LTTNG_THROW_CLI_INVALID_USAGE(fmt::format("Unknown Unix user name `{}`", arg));
	} else if (ret_code != LTTNG_OK) {
		LTTNG_THROW_CLI_INVALID_USAGE(
			fmt::format("Failed to resolve Unix user name `{}`: {}",
				    arg,
				    lttng_strerror(-ret_code)));
	}

	return uid;
}

/*
 * Parses the CLI arguments and returns a configuration, or `nonstd::nullopt`
 * when the caller should exit successfully (help or `--list-options`).
 *
 * Throws `lttng::cli::invalid_usage_error` on invalid arguments and
 * `lttng::cli::no_default_session_error` if no session can be selected.
 */
nonstd::optional<cmd_cfg> cmd_cfg_from_cli_args(const int argc, const char **const argv)
{
	enum show_maps_option_type {
		OPT_HELP,
		OPT_LIST_OPTIONS,
		OPT_SESSION,
		OPT_PER,
		OPT_SORT_BY,
		OPT_SORT_ORDER,
		OPT_LIMIT,
		OPT_CHANNEL,
		OPT_TYPE,
		OPT_UID,
		OPT_ALL_UIDS,
		OPT_PID,
		OPT_ALL_PIDS,
		OPT_SYSTEM,
		OPT_SHARED,
		OPT_CPU_ID,
		OPT_PART_ID,
		OPT_KEY,
		OPT_KEY_GLOB,
		OPT_NON_INIT_VALUES,
	};

	constexpr argpar_opt_descr show_maps_options[] = {
		{ OPT_HELP, 'h', "help", false },
		{ OPT_LIST_OPTIONS, '\0', "list-options", false },
		{ OPT_SESSION, 's', "session", true },
		{ OPT_PER, '\0', "per", true },
		{ OPT_SORT_BY, '\0', "sort-by", true },
		{ OPT_SORT_ORDER, '\0', "sort-order", true },
		{ OPT_LIMIT, '\0', "limit", true },
		{ OPT_CHANNEL, 'c', "channel", true },
		{ OPT_TYPE, '\0', "type", true },
		{ OPT_UID, '\0', "uid", true },
		{ OPT_ALL_UIDS, '\0', "all-uids", false },
		{ OPT_PID, '\0', "pid", true },
		{ OPT_ALL_PIDS, '\0', "all-pids", false },
		{ OPT_SYSTEM, '\0', "system", false },
		{ OPT_SHARED, '\0', "shared", false },
		{ OPT_CPU_ID, '\0', "cpu-id", true },
		{ OPT_PART_ID, '\0', "part-id", true },
		{ OPT_KEY, '\0', "key", true },
		{ OPT_KEY_GLOB, '\0', "key-glob", true },
		{ OPT_NON_INIT_VALUES, '\0', "non-init-values", false },
		ARGPAR_OPT_DESCR_SENTINEL,
	};

	/* Parse CLI arguments */
	argpar::Iter<nonstd::optional<argpar::Item>> argpar_iter(
		argc - 1, argv + 1, show_maps_options);

	nonstd::optional<std::string> session_name;
	nonstd::optional<aggregation_level> per;
	nonstd::optional<sort_column> sort_by;
	nonstd::optional<sort_direction> sort_order;
	nonstd::optional<std::uint64_t> limit;
	std::set<std::string> channel_names;
	std::set<lttng_map_channel_type> channel_types;
	owner_filter owner;
	std::set<unsigned int> part_ids;
	std::set<std::string> keys;
	std::set<std::string> key_globs;
	bool non_init_values = false;

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
				SHOW_HELP_THROW("show-maps");
				return nonstd::nullopt;
			case OPT_LIST_OPTIONS:
				list_cmd_options_argpar(stdout, show_maps_options);
				return nonstd::nullopt;
			case OPT_SESSION:
				reject_dup_opt(long_name, session_name.has_value());
				session_name = opt.arg();
				break;
			case OPT_PER:
				reject_dup_opt(long_name, per.has_value());
				per = per_from_arg(opt.arg());
				break;
			case OPT_SORT_BY:
				reject_dup_opt(long_name, sort_by.has_value());
				sort_by = sort_by_from_arg(opt.arg());
				break;
			case OPT_SORT_ORDER:
				reject_dup_opt(long_name, sort_order.has_value());
				sort_order = sort_order_from_arg(opt.arg());
				break;
			case OPT_LIMIT:
				reject_dup_opt(long_name, limit.has_value());
				limit = limit_from_arg(opt.arg());
				break;
			case OPT_CHANNEL:
				channel_names.insert(opt.arg());
				break;
			case OPT_TYPE:
				channel_types.insert(channel_type_from_arg(opt.arg()));
				break;
			case OPT_UID:
				if (owner.all_uids) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						"Options `--uid` and `--all-uids` are mutually exclusive");
				}

				owner.uids.insert(uid_from_arg(opt.arg()));
				break;
			case OPT_ALL_UIDS:
				if (!owner.uids.empty()) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						"Options `--uid` and `--all-uids` are mutually exclusive");
				}

				owner.all_uids = true;
				break;
			case OPT_PID:
				if (owner.all_pids) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						"Options `--pid` and `--all-pids` are mutually exclusive");
				}

				owner.pids.insert(pid_from_arg(opt.arg()));
				break;
			case OPT_ALL_PIDS:
				if (!owner.pids.empty()) {
					LTTNG_THROW_CLI_INVALID_USAGE(
						"Options `--pid` and `--all-pids` are mutually exclusive");
				}

				owner.all_pids = true;
				break;
			case OPT_SYSTEM:
				owner.system = true;
				break;
			case OPT_CPU_ID:
				part_ids.insert(part_id_from_arg(opt.arg(), "cpu-id"));
				break;
			case OPT_PART_ID:
				part_ids.insert(part_id_from_arg(opt.arg(), "part-id"));
				break;
			case OPT_KEY:
				keys.insert(opt.arg());
				break;
			case OPT_KEY_GLOB:
				key_globs.insert(opt.arg());
				break;
			case OPT_NON_INIT_VALUES:
				non_init_values = true;
				break;
			case OPT_SHARED:
				owner.shared = true;
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

	/* Create command configuration from parsed arguments */
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

	if (per) {
		cmd_cfg.per = *per;
	}

	if (sort_by) {
		cmd_cfg.sort_by = *sort_by;
	}

	if (sort_order) {
		cmd_cfg.sort_order = *sort_order;
	}

	cmd_cfg.limit = limit;
	cmd_cfg.selection.channel_names = std::move(channel_names);
	cmd_cfg.selection.channel_types = std::move(channel_types);
	cmd_cfg.selection.owner_filt = std::move(owner);
	cmd_cfg.selection.part_ids = std::move(part_ids);
	cmd_cfg.selection.keys = std::move(keys);
	cmd_cfg.selection.key_globs = std::move(key_globs);
	cmd_cfg.selection.non_init_values = non_init_values;
	return cmd_cfg;
}

} /* namespace */
} /* namespace show_maps */
} /* namespace cli */
} /* namespace lttng */

int cmd_show_maps(const int argc, const char **const argv)
{
	namespace sm = lttng::cli::show_maps;

	try {
		if (const auto cmd_cfg = sm::cmd_cfg_from_cli_args(argc, argv)) {
			const auto out = sm::output_from_cmd_cfg(*cmd_cfg);

			if (lttng_opt_mi) {
				sm::run_mi(out);
			} else {
				sm::run_human(out);
			}
		}
	} catch (const lttng::ctl::error& exc) {
		ERR_FMT("Failed to show maps: {}", lttng_strerror(exc.code()));
		return CMD_ERROR;
	} catch (const std::exception& exc) {
		ERR_FMT("Failed to show maps: {}", exc.what());
		return CMD_ERROR;
	}

	return CMD_SUCCESS;
}
