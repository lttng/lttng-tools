/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "bin/lttng/commands/show-maps-cmd-cfg.hpp"
#include "common/macros.hpp"
#define _LGPL_SOURCE

#include "show-maps-build-output.hpp"
#include "view-wrappers.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/make-unique.hpp>

#include <lttng/lttng.h>

#include <vendor/optional.hpp>

#include <algorithm>
#include <cstdint>
#include <fnmatch.h>
#include <set>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace lttng {
namespace cli {
namespace show_maps {
namespace {

/*
 * Builder of `output` instance from a command configuration.
 *
 * Walks every map channel of the configured session, applies the
 * selection/aggregation/sorting/limiting policy from the configuration,
 * and accumulates the effective set of tables into the output
 * to return.
 *
 * build() resets its internal state on entry, so it may be called more
 * than once.
 */
class output_builder final {
public:
	explicit output_builder(const cmd_cfg& cfg) noexcept : _cfg(&cfg)
	{
	}

	output_builder(const output_builder&) = delete;
	output_builder(output_builder&&) = delete;
	output_builder& operator=(const output_builder&) = delete;
	output_builder& operator=(output_builder&&) = delete;
	~output_builder() = default;

	output build()
	{
		/*
		 * Reset any state left over from a previous call so that
		 * build() may be invoked more than once.
		 */
		_output = output{};

		const session_list sessions;
		const auto session = sessions.find_by_name(_cfg->session_name.c_str());

		if (!session) {
			LTTNG_THROW_ERROR(
				format("Recording session `{}` not found", _cfg->session_name));
		}

		if (_channel_type_passes(LTTNG_MAP_CHANNEL_TYPE_KERNEL)) {
			_process_channel(*session, LTTNG_MAP_CHANNEL_TYPE_KERNEL);
		}

		if (_channel_type_passes(LTTNG_MAP_CHANNEL_TYPE_USER)) {
			_process_channel(*session, LTTNG_MAP_CHANNEL_TYPE_USER);
		}

		return std::move(_output);
	}

private:
	/*
	 * Returns whether or not the `name` passes the map channel name
	 * axis filter.
	 */
	bool _channel_name_passes(const char *const name) const
	{
		return _cfg->selection.channel_names.empty() ||
			_cfg->selection.channel_names.count(name) > 0;
	}

	/*
	 * Returns whether or not `type` passes the map channel type
	 * axis filter.
	 */
	bool _channel_type_passes(const lttng_map_channel_type type) const
	{
		return _cfg->selection.channel_types.empty() ||
			_cfg->selection.channel_types.count(type) > 0;
	}

	/*
	 * Returns whether or not `group` passes the owner axis.
	 *
	 * The owner axis (see `owner_filter`) selects which owners the
	 * command includes; until the user restricts it, every
	 * owner passes.
	 */
	bool _map_group_passes(const map_group& group) const
	{
		const auto& owner_filt = _cfg->selection.owner_filt;
		const auto is_restricted = owner_filt.is_restricted();

		switch (group.type()) {
		case LTTNG_MAP_GROUP_TYPE_SHARED:
			return !is_restricted || owner_filt.shared;
		case LTTNG_MAP_GROUP_TYPE_KERNEL_GLOBAL:
			return !is_restricted || owner_filt.system;
		case LTTNG_MAP_GROUP_TYPE_USER_PER_USER:
		case LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS:
		{
			if (!is_restricted) {
				return true;
			}

			const auto is_per_user = group.type() == LTTNG_MAP_GROUP_TYPE_USER_PER_USER;
			const auto& selected_owner_ids = is_per_user ? owner_filt.uids :
								       owner_filt.pids;
			const auto all_owner_ids = is_per_user ? owner_filt.all_uids :
								 owner_filt.all_pids;

			return all_owner_ids ||
				selected_owner_ids.count(group.as_user().owner_id()) > 0;
		}
		}

		return false;
	}

	/*
	 * Returns whether or not `part_id` passes the partition ID
	 * axis filter.
	 */
	bool _part_id_passes(const nonstd::optional<unsigned int>& part_id) const
	{
		return !part_id || _cfg->selection.part_ids.empty() ||
			_cfg->selection.part_ids.count(*part_id) > 0;
	}

	/*
	 * Returns whether or not `map_key_str` passes the key
	 * axis filter.
	 */
	bool _key_passes(const char *const map_key_str) const
	{
		if (_cfg->selection.keys.empty() && _cfg->selection.key_globs.empty()) {
			return true;
		}

		if (_cfg->selection.keys.count(map_key_str) > 0) {
			return true;
		}

		for (auto& pattern : _cfg->selection.key_globs) {
			if (fnmatch(pattern.c_str(), map_key_str, 0) == 0) {
				return true;
			}
		}

		return false;
	}

	/*
	 * Returns whether or not the raw, per-partition counter value
	 * `val` passes the value axis filter.
	 */
	bool _val_passes(const std::int64_t val) const noexcept
	{
		return !_cfg->selection.non_init_values || val != 0;
	}

	/*
	 * Holds the per-map key contribution that the aggregation pass
	 * collects: the sum of integer map values and the logical OR of
	 * overflow indicators.
	 */
	struct _per_map_key_acc final {
		std::string key;

		/*
		 * A `bigint` so that summing the per-partition map
		 * values during aggregation can't overflow: the command
		 * never sets an overflow indicator of its own.
		 */
		bigint val;

		bool has_overflow = false;
	};

	/*
	 * Indexes per-map key accumulators by map_key::index(), the
	 * integral entry index of the map key within the entry index
	 * space of the owning map channel.
	 *
	 * That index remains stable across every partition of a given
	 * channel, which lets the aggregation pass fold the
	 * per-partition contributions of a given map key into the
	 * same slot.
	 *
	 * Map keys which the key axis filter rejects have no entry.
	 * Every other map key gets one as soon as at least one selected
	 * partition reaches the aggregation pass for the
	 * corresponding scope.
	 */
	using _per_map_key_acc_map = std::unordered_map<std::uint64_t, _per_map_key_acc>;

	/*
	 * Folds the per-partition map values `values` of one partition
	 * into `accs`, keyed by map_key::index() of each map key
	 * of `key_set`.
	 *
	 * Keys that the key axis filter (see _key_passes()) rejects get
	 * no accumulator entry.
	 */
	void _accumulate_part(const map_key_set& map_key_set,
			      const signed_int_map_values& values,
			      _per_map_key_acc_map& accs) const
	{
		for (const auto& map_key : map_key_set) {
			LTTNG_ASSERT(map_key.type() == LTTNG_MAP_KEY_TYPE_STRING);

			const auto key_str = map_key.as_string().string();

			if (!_key_passes(key_str.data())) {
				continue;
			}

			const auto part_map_val = values.value(map_key);

			if (!_val_passes(part_map_val)) {
				continue;
			}

			const auto part_has_overflow = values.has_overflow(map_key);

			/*
			 * `it.second` is true on the first contrib. of
			 * this map key.
			 */
			const auto it = accs.emplace(map_key.index(), _per_map_key_acc{});
			auto& acc = it.first->second;

			if (it.second) {
				/* New */
				acc.key = key_str.data();
				acc.val = part_map_val;
				acc.has_overflow = part_has_overflow;
			} else {
				/* Exists: add */
				acc.val += part_map_val;
				acc.has_overflow = acc.has_overflow || part_has_overflow;
			}
		}
	}

	void _sort_and_limit_rows(std::vector<map_table_row>& rows) const
	{
		const auto is_desc = _cfg->sort_order == sort_direction::DESC;

		if (_cfg->sort_by == sort_column::KEY) {
			std::stable_sort(rows.begin(),
					 rows.end(),
					 [is_desc](const map_table_row& lhs,
						   const map_table_row& rhs) {
						 return is_desc ? rhs.key() < lhs.key() :
								  lhs.key() < rhs.key();
					 });
		} else {
			LTTNG_ASSERT(_cfg->sort_by == sort_column::VALUE);
			std::stable_sort(rows.begin(),
					 rows.end(),
					 [is_desc](const map_table_row& lhs,
						   const map_table_row& rhs) {
						 return is_desc ? rhs.val() < lhs.val() :
								  lhs.val() < rhs.val();
					 });
		}

		if (_cfg->limit && rows.size() > *_cfg->limit) {
			rows.erase(rows.begin() + static_cast<std::ptrdiff_t>(*_cfg->limit),
				   rows.end());
		}
	}

	/*
	 * Returns the final map table rows for the contributions which
	 * `accs` holds: builds one row per accumulator entry, sorts
	 * them, and applies the row count limit, all according to the
	 * configured sorting and limiting policy.
	 */
	std::vector<map_table_row> _build_rows(const _per_map_key_acc_map& accs) const
	{
		std::vector<map_table_row> rows;

		rows.reserve(accs.size());

		for (const auto& entry : accs) {
			const auto& acc = entry.second;

			rows.emplace_back(acc.key, acc.val, acc.has_overflow);
		}

		_sort_and_limit_rows(rows);
		return rows;
	}

	/*
	 * Outcome of processing a single map group within a map
	 * channel: tells the per-map channel level loop whether the
	 * group had any selected partition ID (so that the map channel
	 * level provenance can include it) and whether or not any
	 * emitted table references `group` (so that the loop keeps the
	 * group set alive).
	 */
	struct _map_group_outcome final {
		bool any_part_id_selected = false;
		bool table_emitted = false;
	};

	/*
	 * Emits a per-partition map table for `group`/`partition_id`,
	 * unless the key axis filter rejected every map key, leaving no
	 * row to show.
	 *
	 * Returns whether or not it emitted a table.
	 */
	bool _emit_per_part_table(const std::string& channel_name,
				  const lttng_map_channel_type channel_type,
				  const map_key_set& key_set,
				  const signed_int_map_values& signed_values,
				  const map_group& group,
				  const unsigned int partition_id)
	{
		_per_map_key_acc_map part_acc;

		_accumulate_part(key_set, signed_values, part_acc);

		auto rows = _build_rows(part_acc);

		if (rows.empty()) {
			return false;
		}

		_output.tables.push_back(make_unique<per_part_map_table>(_cfg->session_name,
									 channel_name,
									 channel_type,
									 std::move(rows),
									 group,
									 partition_id));
		return true;
	}

	/*
	 * Emits a per-owner map table for `group`, unless the key axis
	 * filter rejected every map key, leaving no row to show.
	 *
	 * Returns whether or not it emitted a table.
	 */
	bool _emit_per_owner_table(const std::string& channel_name,
				   const lttng_map_channel_type channel_type,
				   const _per_map_key_acc_map& group_acc,
				   const map_group& group,
				   std::set<unsigned int> group_part_ids)
	{
		auto rows = _build_rows(group_acc);

		if (rows.empty()) {
			return false;
		}

		_output.tables.push_back(
			make_unique<per_owner_map_table>(_cfg->session_name,
							 channel_name,
							 channel_type,
							 std::move(rows),
							 group,
							 std::move(group_part_ids)));
		return true;
	}

	/*
	 * Emits a per-map channel map table, unless the key axis filter
	 * rejected every map key, leaving no row to show.
	 *
	 * Returns whether or not it emitted a table.
	 */
	bool _emit_per_channel_table(const std::string& channel_name,
				     const lttng_map_channel_type channel_type,
				     const _per_map_key_acc_map& channel_acc,
				     std::set<map_group> channel_groups,
				     std::set<unsigned int> channel_part_ids)
	{
		auto rows = _build_rows(channel_acc);

		if (rows.empty()) {
			return false;
		}

		_output.tables.push_back(
			make_unique<per_channel_map_table>(_cfg->session_name,
							   channel_name,
							   channel_type,
							   std::move(rows),
							   std::move(channel_groups),
							   std::move(channel_part_ids)));
		return true;
	}

	/*
	 * Processes one selected map group of a map channel.
	 *
	 * At per-partition level, emits one table per selected
	 * partition ID.
	 *
	 * At per-owner level, folds the per-map key contributions of
	 * every selected partition of the map group into a single
	 * accumulator and emits one per-owner map table from it.
	 *
	 * At per-map channel level, folds contributions of the map
	 * group into `channel_acc` and `channel_part_ids` for the
	 * channel-level loop to emit later.
	 */
	_map_group_outcome _process_map_group(const std::string& channel_name,
					      const lttng_map_channel_type channel_type,
					      const map_key_set& key_set,
					      const map_group& group,
					      _per_map_key_acc_map& channel_acc,
					      std::set<unsigned int>& channel_part_ids)
	{
		/*
		 * The shared map group has no per-partition
		 * decomposition: at the per-partition aggregation
		 * level, emit a per-owner table for it instead so its
		 * values still appear.
		 */
		const auto effective_per = (_cfg->per == aggregation_level::PART &&
					    group.type() == LTTNG_MAP_GROUP_TYPE_SHARED) ?
			aggregation_level::OWNER :
			_cfg->per;
		_per_map_key_acc_map map_group_acc;
		std::set<unsigned int> map_group_part_ids;
		_map_group_outcome outcome;

		for (const auto& map_values : group.values()) {
			const auto part_id = map_values.partition_id();

			if (!_part_id_passes(part_id)) {
				continue;
			}

			outcome.any_part_id_selected = true;

			if (effective_per == aggregation_level::PART) {
				/*
				 * The branch above diverts shared map
				 * groups to the per-owner level,
				 * therefore `part_id` always holds a
				 * value here.
				 */
				LTTNG_ASSERT(part_id);

				if (_emit_per_part_table(channel_name,
							 channel_type,
							 key_set,
							 map_values.as_signed_int(),
							 group,
							 *part_id)) {
					outcome.table_emitted = true;
				}
			} else if (effective_per == aggregation_level::OWNER) {
				_accumulate_part(
					key_set, map_values.as_signed_int(), map_group_acc);

				if (part_id) {
					map_group_part_ids.insert(*part_id);
				}
			} else {
				LTTNG_ASSERT(effective_per == aggregation_level::CHANNEL);
				_accumulate_part(key_set, map_values.as_signed_int(), channel_acc);

				if (part_id) {
					channel_part_ids.insert(*part_id);
				}
			}
		}

		if (effective_per == aggregation_level::OWNER && outcome.any_part_id_selected) {
			/*
			 * At the per-owner level, the partition loop
			 * above folded every selected partition of
			 * `group` into `map_group_acc`: emit the
			 * resulting single per-owner map table now that
			 * the aggregate is complete.
			 */
			if (_emit_per_owner_table(channel_name,
						  channel_type,
						  map_group_acc,
						  group,
						  std::move(map_group_part_ids))) {
				outcome.table_emitted = true;
			}
		}

		return outcome;
	}

	/*
	 * Processes one map channel, delegating per-map group work to
	 * _process_map_group() and emitting at most one per-map channel
	 * table at the end.
	 *
	 * The per-map group helper emits per-partition and per-owner
	 * tables directly when those aggregation levels are active.
	 *
	 * At the per-map channel level, it folds the contributions of
	 * each map group into the map channel-wide accumulator and
	 * provenance sets which this function owns; this function then
	 * turns that aggregate into the single per-map channel table.
	 */
	void _process_channel(const map_channel& channel)
	{
		if (!_channel_name_passes(channel.name().data())) {
			return;
		}

		const auto type = channel.type();
		const std::string name = channel.name().data();
		const auto map_key_set = channel.keys();

		/*
		 * Keep this map group set alive for the lifetime of
		 * `_output`: the grouped map tables which this function
		 * produces below hold non-owning `map_group` views into
		 * its library handle (see grouped_map_table::group()).
		 *
		 * This function moves it into `_output.map_group_sets`
		 * once a table references one of its groups.
		 */
		auto map_groups = channel.groups();
		bool map_groups_referenced = false;

		/*
		 * Per-channel aggregation state (used only at per-map
		 * channel level).
		 */
		_per_map_key_acc_map acc_map;
		std::set<map_group> channel_map_groups;
		std::set<unsigned int> channel_part_ids;
		auto any_map_group_selected = false;

		for (auto& map_group : map_groups) {
			if (!_map_group_passes(map_group)) {
				continue;
			}

			any_map_group_selected = true;

			const auto outcome = _process_map_group(
				name, type, map_key_set, map_group, acc_map, channel_part_ids);

			if (outcome.table_emitted) {
				map_groups_referenced = true;
			}

			if (_cfg->per == aggregation_level::CHANNEL &&
			    outcome.any_part_id_selected) {
				channel_map_groups.insert(map_group);
			}
		}

		if (_cfg->per == aggregation_level::CHANNEL && any_map_group_selected) {
			/*
			 * The per-map channel table holds non-owning
			 * views into `map_groups` through
			 * `channel_map_groups` (see
			 * per_channel_map_table::map_groups()),
			 * therefore retain the map group set whenever
			 * the table is actually emitted.
			 */
			if (_emit_per_channel_table(name,
						    type,
						    acc_map,
						    std::move(channel_map_groups),
						    std::move(channel_part_ids))) {
				map_groups_referenced = true;
			}
		}

		if (map_groups_referenced) {
			_output.map_group_sets.push_back(std::move(map_groups));
		}
	}

	/*
	 * Processes every map channel of type `type` in `session`.
	 *
	 * `type` already passed the map channel type axis filter by the
	 * time you call this; the per-map channel overload applies the
	 * remaining per-map channel filters (name, owners, partition
	 * IDs, keys).
	 */
	void _process_channel(const session& session, const lttng_map_channel_type type)
	{
		for (const auto& channel : session.map_channels(type)) {
			_process_channel(channel);
		}
	}

	const cmd_cfg *_cfg;
	output _output;
};

} /* namespace */

output output_from_cmd_cfg(const cmd_cfg& cfg)
{
	return output_builder(cfg).build();
}

} /* namespace show_maps */
} /* namespace cli */
} /* namespace lttng */
