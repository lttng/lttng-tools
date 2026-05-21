/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "show-maps-mi.hpp"

#include <common/error.hpp>
#include <common/format.hpp>
#include <common/mi-lttng.hpp>

#include <lttng/map/channel-type.h>
#include <lttng/map/group-type.h>
#include <lttng/map/value-type.h>

#include <cstdint>

namespace lttng {
namespace cli {
namespace show_maps {
namespace {

const char *channel_type_string(const lttng_map_channel_type type)
{
	switch (type) {
	case LTTNG_MAP_CHANNEL_TYPE_KERNEL:
		return "kernel";
	case LTTNG_MAP_CHANNEL_TYPE_USER:
		return "user";
	}

	LTTNG_THROW_ERROR("Unknown map channel type");
}

const char *group_type_string(const lttng_map_group_type type)
{
	switch (type) {
	case LTTNG_MAP_GROUP_TYPE_KERNEL_GLOBAL:
		return "kernel-global";
	case LTTNG_MAP_GROUP_TYPE_USER_PER_USER:
		return "user-per-user";
	case LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS:
		return "user-per-process";
	case LTTNG_MAP_GROUP_TYPE_SHARED:
		return "shared";
	}

	LTTNG_THROW_ERROR("Unknown map group type");
}

const char *effective_value_type_string(const lttng_map_value_type value_type)
{
	switch (value_type) {
	case LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32:
		return "signed-int-32";
	case LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64:
		return "signed-int-64";
	case LTTNG_MAP_VALUE_TYPE_SIGNED_INT_MAX:
		break;
	}

	LTTNG_THROW_ERROR("Unexpected effective map value type");
}

class mi_writer final {
public:
	explicit mi_writer(const char *const command_name) :
		_mi_writer(mi_lttng_writer_create(fileno(stdout), LTTNG_MI_XML))
	{
		if (!_mi_writer) {
			LTTNG_THROW_ERROR("Failed to create MI writer");
		}

		if (mi_lttng_writer_command_open(_mi_writer.get(), command_name)) {
			LTTNG_THROW_ERROR("Failed to open MI `<command>` element");
		}
	}

	mi_writer(const mi_writer&) = delete;
	mi_writer(mi_writer&&) = delete;
	mi_writer& operator=(const mi_writer&) = delete;
	mi_writer& operator=(mi_writer&&) = delete;

	~mi_writer()
	{
		if (mi_lttng_writer_command_close(_mi_writer.get())) {
			ERR("Failed to close MI `<command>` element");
		}
	}

	void open_elem(const char *const name)
	{
		if (mi_lttng_writer_open_element(_mi_writer.get(), name)) {
			LTTNG_THROW_ERROR(fmt::format("Failed to open MI element `<{}>`", name));
		}
	}

	void close_elem(const char *const name)
	{
		if (mi_lttng_writer_close_element(_mi_writer.get())) {
			LTTNG_THROW_ERROR(fmt::format("Failed to close MI element `<{}>`", name));
		}
	}

	void write_success_elem(const bool success)
	{
		if (mi_lttng_writer_write_element_bool(
			    _mi_writer.get(), mi_lttng_element_command_success, success ? 1 : 0)) {
			LTTNG_THROW_ERROR("Failed to write MI `<success>` element");
		}
	}

	void write_map_table(const map_table& table)
	{
		switch (table.level()) {
		case aggregation_level::CHANNEL:
			_write_per_channel_map_table(
				static_cast<const per_channel_map_table&>(table));
			break;

		case aggregation_level::OWNER:
			_write_per_owner_map_table(static_cast<const per_owner_map_table&>(table));
			break;

		case aggregation_level::PART:
			_write_per_part_map_table(static_cast<const per_part_map_table&>(table));
			break;
		}
	}

private:
	void _write_elem(const char *const name, const char *const value)
	{
		if (mi_lttng_writer_write_element_string(_mi_writer.get(), name, value)) {
			LTTNG_THROW_ERROR(fmt::format("Failed to write MI element `<{}>`", name));
		}
	}

	void _write_elem(const char *const name, const std::uint64_t value)
	{
		if (mi_lttng_writer_write_element_unsigned_int(_mi_writer.get(), name, value)) {
			LTTNG_THROW_ERROR(fmt::format("Failed to write MI element `<{}>`", name));
		}
	}

	void _write_user_group(const user_map_group& user_group)
	{
		_write_elem("owner_id", user_group.owner_id());
		_write_elem("owner_name", user_group.owner_name().c_str());
	}

	void _write_map_group(const map_group& group)
	{
		open_elem("map_group");
		_write_elem("type", group_type_string(group.type()));
		_write_elem("effective_value_type",
			    effective_value_type_string(group.effective_value_type()));

		switch (group.type()) {
		case LTTNG_MAP_GROUP_TYPE_USER_PER_USER:
		case LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS:
		{
			_write_user_group(group.as_user());
			break;
		}

		case LTTNG_MAP_GROUP_TYPE_KERNEL_GLOBAL:
		case LTTNG_MAP_GROUP_TYPE_SHARED:
			break;
		}

		close_elem("map_group");
	}

	void _write_map_table_common(const map_table& table)
	{
		_write_elem("session_name", table.session_name().c_str());
		_write_elem("channel_name", table.channel_name().c_str());
		_write_elem("channel_type", channel_type_string(table.channel_type()));
	}

	void _write_part_ids(const std::set<unsigned int>& part_ids)
	{
		open_elem("part_ids");

		for (const auto part_id : part_ids) {
			_write_elem("part_id", part_id);
		}

		close_elem("part_ids");
	}

	void _write_map_table_rows(const std::vector<map_table_row>& rows)
	{
		open_elem("rows");

		for (const auto& row : rows) {
			open_elem("row");
			_write_elem("key", row.key().c_str());

			if (mi_lttng_writer_open_element(_mi_writer.get(), "value") ||
			    mi_lttng_writer_write_attribute(_mi_writer.get(),
							    "has_overflow",
							    row.has_overflow() ? "true" :
										 "false") ||
			    mi_lttng_writer_write_string(_mi_writer.get(),
							 row.val().str().c_str()) ||
			    mi_lttng_writer_close_element(_mi_writer.get())) {
				LTTNG_THROW_ERROR("Failed to emit MI `<value>` element");
			}

			close_elem("row");
		}

		close_elem("rows");
	}

	void _write_per_channel_map_table(const per_channel_map_table& table)
	{
		open_elem("per_channel_map_table");
		_write_map_table_common(table);
		open_elem("map_groups");

		for (const auto& group : table.map_groups()) {
			_write_map_group(group);
		}

		close_elem("map_groups");
		_write_part_ids(table.part_ids());
		_write_map_table_rows(table.rows());
		close_elem("per_channel_map_table");
	}

	template <typename WriteSpecFuncType>
	void _write_grouped_map_table(const char *const elem_name,
				      const grouped_map_table& map_table,
				      WriteSpecFuncType&& write_spec_func)
	{
		open_elem(elem_name);
		_write_map_table_common(map_table);
		_write_map_group(map_table.map_group());
		write_spec_func();
		_write_map_table_rows(map_table.rows());
		close_elem(elem_name);
	}

	void _write_per_owner_map_table(const per_owner_map_table& table)
	{
		_write_grouped_map_table("per_owner_map_table", table, [this, &table] {
			_write_part_ids(table.part_ids());
		});
	}

	void _write_per_part_map_table(const per_part_map_table& table)
	{
		_write_grouped_map_table("per_part_map_table", table, [this, &table] {
			_write_elem("part_id", table.part_id());
		});
	}

	mi_writer_uptr _mi_writer;
};

} /* namespace */

void run_mi(const output& out)
{
	mi_writer writer("show-maps");

	try {
		writer.open_elem(mi_lttng_element_command_output);
		writer.open_elem("show-maps");

		for (const auto& table : out.tables) {
			writer.write_map_table(*table);
		}

		writer.close_elem("show-maps");
		writer.close_elem(mi_lttng_element_command_output);
	} catch (...) {
		writer.write_success_elem(false);
		throw;
	}

	writer.write_success_elem(true);
}

} /* namespace show_maps */
} /* namespace cli */
} /* namespace lttng */
