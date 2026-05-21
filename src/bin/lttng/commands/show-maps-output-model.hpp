/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef LTTNG_CLI_COMMANDS_SHOW_MAPS_OUTPUT_MODEL_HPP
#define LTTNG_CLI_COMMANDS_SHOW_MAPS_OUTPUT_MODEL_HPP

#include "show-maps-cmd-cfg.hpp"
#include "view-wrappers.hpp"

#include <common/bigint.hpp>

#include <lttng/map/channel-type.h>

#include <memory>
#include <set>
#include <string>
#include <vector>

namespace lttng {
namespace cli {
namespace show_maps {

/*
 * One row of a map table.
 */
class map_table_row final {
public:
	map_table_row(std::string key, const bigint& val, const bool has_overflow) :
		_key(std::move(key)), _val(val), _has_overflow(has_overflow)
	{
	}

	const std::string& key() const noexcept
	{
		return _key;
	}

	const bigint& val() const noexcept
	{
		return _val;
	}

	bool has_overflow() const noexcept
	{
		return _has_overflow;
	}

private:
	std::string _key;
	bigint _val;
	bool _has_overflow;
};

/*
 * Abstract base class for any map table: holds the properties common to
 * every aggregation level.
 *
 * Each concrete level has its own derived type below; level()
 * discriminates between them so that a renderer can switch on it and
 * cast to the matching type to reach the level-specific properties.
 */
class map_table {
protected:
	map_table(std::string session_name,
		  std::string channel_name,
		  const lttng_map_channel_type channel_type,
		  std::vector<map_table_row> rows) :
		_session_name(std::move(session_name)),
		_channel_name(std::move(channel_name)),
		_channel_type(channel_type),
		_rows(std::move(rows))
	{
	}

public:
	map_table(const map_table&) = delete;
	map_table(map_table&&) = delete;
	map_table& operator=(const map_table&) = delete;
	map_table& operator=(map_table&&) = delete;
	virtual ~map_table() = default;
	virtual aggregation_level level() const noexcept = 0;

	const std::string& session_name() const noexcept
	{
		return _session_name;
	}

	const std::string& channel_name() const noexcept
	{
		return _channel_name;
	}

	lttng_map_channel_type channel_type() const noexcept
	{
		return _channel_type;
	}

	const std::vector<map_table_row>& rows() const noexcept
	{
		return _rows;
	}

private:
	std::string _session_name;
	std::string _channel_name;
	lttng_map_channel_type _channel_type;
	std::vector<map_table_row> _rows;
};

/*
 * A map table aggregated at the channel level
 * (see `aggregation_level::CHANNEL`).
 *
 * groups() and part_ids() describe the input that fed the aggregation:
 *
 * groups():
 *     The map groups whose data actually contributed.
 *
 *     A non-shared map group is included only if at least one of its
 *     partitions passed the partition ID filter; a shared map group,
 *     having no partitions, is always included (provided it passed the
 *     owner axis filter).
 *
 * part_ids():
 *     The union of those passing partition IDs across every non-shared
 *     contributing map group.
 *
 *     Empty when only shared map groups contributed.
 */
class per_channel_map_table final : public map_table {
public:
	per_channel_map_table(std::string session_name,
			      std::string channel_name,
			      const lttng_map_channel_type channel_type,
			      std::vector<map_table_row> rows,
			      std::set<map_group> map_groups,
			      std::set<unsigned int> part_ids) :
		map_table(std::move(session_name),
			  std::move(channel_name),
			  channel_type,
			  std::move(rows)),
		_map_groups(std::move(map_groups)),
		_part_ids(std::move(part_ids))
	{
	}

	aggregation_level level() const noexcept override
	{
		return aggregation_level::CHANNEL;
	}

	const std::set<map_group>& map_groups() const noexcept
	{
		return _map_groups;
	}

	const std::set<unsigned int>& part_ids() const noexcept
	{
		return _part_ids;
	}

private:
	/*
	 * Non-owning views into a map group set owned by the containing
	 * `output` instance (see `output::group_sets`), which must
	 * outlive this table.
	 */
	std::set<map_group> _map_groups;

	std::set<unsigned int> _part_ids;
};

/*
 * Abstract base class for map tables which pertain to a single map
 * group: the owner-level and partition-level tables below.
 *
 * A map group is the only property they share beyond the
 * per-channel level.
 */
class grouped_map_table : public map_table {
protected:
	grouped_map_table(std::string session_name,
			  std::string channel_name,
			  const lttng_map_channel_type channel_type,
			  std::vector<map_table_row> rows,
			  const cli::map_group map_group) :
		map_table(std::move(session_name),
			  std::move(channel_name),
			  channel_type,
			  std::move(rows)),
		_map_group(map_group)
	{
	}

public:
	const cli::map_group& map_group() const noexcept
	{
		return _map_group;
	}

private:
	/*
	 * Non-owning view into a map group set owned by the containing
	 * `output` instance (see `output::group_sets`), which must
	 * outlive this table.
	 */
	cli::map_group _map_group;
};

/*
 * A map table aggregated at the owner level
 * (see `aggregation_level::OWNER`).
 *
 * part_ids() is the set of partition IDs that passed the partition ID
 * filter and contributed to the aggregation; it's empty for shared map
 * groups, which have no partitions.
 */
class per_owner_map_table final : public grouped_map_table {
public:
	per_owner_map_table(std::string session_name,
			    std::string channel_name,
			    const lttng_map_channel_type channel_type,
			    std::vector<map_table_row> rows,
			    const cli::map_group map_group,
			    std::set<unsigned int> part_ids) :
		grouped_map_table(std::move(session_name),
				  std::move(channel_name),
				  channel_type,
				  std::move(rows),
				  map_group),
		_part_ids(std::move(part_ids))
	{
	}

	aggregation_level level() const noexcept override
	{
		return aggregation_level::OWNER;
	}

	const std::set<unsigned int>& part_ids() const noexcept
	{
		return _part_ids;
	}

private:
	std::set<unsigned int> _part_ids;
};

/*
 * A map table aggregated at the partition level (see
 * `aggregation_level::PART`): a single partition of a single map group.
 */
class per_part_map_table final : public grouped_map_table {
public:
	per_part_map_table(std::string session_name,
			   std::string channel_name,
			   const lttng_map_channel_type channel_type,
			   std::vector<map_table_row> rows,
			   const cli::map_group map_group,
			   const unsigned int part_id) :
		grouped_map_table(std::move(session_name),
				  std::move(channel_name),
				  channel_type,
				  std::move(rows),
				  map_group),
		_part_id(part_id)
	{
	}

	aggregation_level level() const noexcept override
	{
		return aggregation_level::PART;
	}

	/* CPU ID */
	unsigned int part_id() const noexcept
	{
		return _part_id;
	}

private:
	unsigned int _part_id;
};

/*
 * Set of tables ready to be rendered, in the order in which they
 * should appear.
 */
struct output final {
	/*
	 * Owns the library map group sets which back the `map_group`
	 * views held by the grouped tables (see
	 * grouped_map_table::group()), keeping those views valid for
	 * the lifetime of the `output` instance.
	 */
	std::vector<map_group_set> map_group_sets;

	/* Actual tables to render */
	std::vector<std::unique_ptr<map_table>> tables;
};

} /* namespace show_maps */
} /* namespace cli */
} /* namespace lttng */

#endif /* LTTNG_CLI_COMMANDS_SHOW_MAPS_OUTPUT_MODEL_HPP */
