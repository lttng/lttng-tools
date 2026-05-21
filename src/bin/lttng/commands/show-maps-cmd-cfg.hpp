/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CLI_COMMANDS_SHOW_MAPS_CMD_CFG_HPP
#define LTTNG_CLI_COMMANDS_SHOW_MAPS_CMD_CFG_HPP

#include <lttng/map/channel-type.h>

#include <vendor/optional.hpp>

#include <cstdint>
#include <set>
#include <string>
#include <sys/types.h>

namespace lttng {
namespace cli {
namespace show_maps {

/*
 * Aggregation level (`--per` option).
 *
 * Also discriminates the map table hierarchy: each level maps to one
 * map table type, and `map_table::level()` returns the level of a given
 * table (see show-maps-output-model.hpp).
 */
enum class aggregation_level { CHANNEL, OWNER, PART };

/*
 * Sorting column (`--sort-by` option).
 */
enum class sort_column { KEY, VALUE };

/*
 * Sorting direction (`--sort-order` option).
 */
enum class sort_direction { ASC, DESC };

/*
 * Owner axis selection (`--uid`, `--all-uids`, `--pid`, `--all-pids`,
 * `--system`, and `--shared` options).
 *
 * For the purpose of this command, an owner is the whole system (a
 * Linux kernel map channel), a Unix user (a user space map channel with
 * the per-user buffer ownership model), a process ID (a user space map
 * channel with the per-process buffer ownership model), or the session
 * daemon itself (the shared map group).
 *
 * The axis is "restricted" as soon as the user sets _any_ of its
 * options; until then every owner passes (see is_restricted()).
 */
struct owner_filter final {
	/* `--system`: select the system (Linux kernel) counters */
	bool system = false;

	/* `--shared`: select the shared counters */
	bool shared = false;

	/* `--uid`: selected Unix user IDs */
	std::set<std::uint64_t> uids;

	/*
	 * `--all-uids`: select all the Unix users (mutually exclusive
	 * with `uids`).
	 */
	bool all_uids = false;

	/* `--pid`: selected process IDs */
	std::set<std::uint64_t> pids;

	/*
	 * `--all-pids`: select all the process IDs (mutually exclusive
	 * with `pids`).
	 */
	bool all_pids = false;

	bool is_restricted() const noexcept
	{
		return system || shared || all_uids || all_pids || !uids.empty() || !pids.empty();
	}
};

/*
 * Command configuration built from the CLI options.
 */
struct cmd_cfg final {
	/* Recording session */
	std::string session_name;

	/* Aggregation */
	aggregation_level per = aggregation_level::CHANNEL;

	/* Sorting and display */
	sort_column sort_by = sort_column::KEY;
	sort_direction sort_order = sort_direction::ASC;
	nonstd::optional<std::uint64_t> limit;

	/*
	 * Selection axes.
	 *
	 * Each set is "empty means do not restrict this axis"; see also
	 * owner_filter::is_restricted() for the owner axis.
	 */
	struct {
		/* Channel */
		std::set<std::string> channel_names;
		std::set<lttng_map_channel_type> channel_types;

		/* Owner */
		owner_filter owner_filt;

		/* Partition ID */
		std::set<unsigned int> part_ids;

		/* Key */
		std::set<std::string> keys;
		std::set<std::string> key_globs;

		/* Value */
		bool non_init_values = false;
	} selection;
};

} /* namespace show_maps */
} /* namespace cli */
} /* namespace lttng */

#endif /* LTTNG_CLI_COMMANDS_SHOW_MAPS_CMD_CFG_HPP */
