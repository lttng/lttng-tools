/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "../utils.hpp"
#include "show-maps-human.hpp"
#include "show-maps-output-model.hpp"

#include <common/format.hpp>
#include <common/make-unique.hpp>
#include <common/mint.hpp>
#include <common/table-writer.hpp>
#include <common/term-utils.hpp>
#include <common/time.hpp>

#include <lttng/map/channel-type.h>
#include <lttng/map/group-type.h>
#include <lttng/map/value-type.h>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lttng {
namespace cli {
namespace show_maps {
namespace {

const char *channel_type_str(const lttng_map_channel_type type) noexcept
{
	switch (type) {
	case LTTNG_MAP_CHANNEL_TYPE_KERNEL:
		return "Linux kernel";
	case LTTNG_MAP_CHANNEL_TYPE_USER:
		return "User space";
	}

	return "unknown";
}

/*
 * Returns the " (`NAME`)" suffix to append after an owner ID, or an
 * empty string when the owner name of `user_group` is empty.
 */
std::string owner_name_suffix(const user_map_group& user_group)
{
	const auto owner_name = user_group.owner_name();

	if (owner_name.empty()) {
		return "";
	}

	return mint_format(" ([-]`[/][!*]{}[/][-]`[/])", owner_name);
}

/*
 * Human-readable description of an effective value type, as a counter
 * value width.
 */
const char *effective_value_type_str(const lttng_map_value_type value_type) noexcept
{
	switch (value_type) {
	case LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32:
		return "32-bit int. values";
	case LTTNG_MAP_VALUE_TYPE_SIGNED_INT_64:
		return "64-bit int. values";
	default:
		return "unknown value type";
	}
}

std::string group_info(const map_group& group)
{
	switch (group.type()) {
	case LTTNG_MAP_GROUP_TYPE_SHARED:
		return ", shared counters";
	case LTTNG_MAP_GROUP_TYPE_USER_PER_USER:
	case LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS:
	{
		const auto user_group = group.as_user();

		return mint_format(", {} [!*]{}[/]{} ({})",
				   group.type() == LTTNG_MAP_GROUP_TYPE_USER_PER_USER ?
					   "user ID" :
					   "process ID",
				   user_group.owner_id(),
				   owner_name_suffix(user_group),
				   effective_value_type_str(group.effective_value_type()));
	}
	default:
		std::abort();
	}
}

void write_map_table(std::ostream& os, const map_table& map_table)
{
	os << mint_format("Recording session [-]`[/][!*]{}[/][-]`[/]:\n", map_table.session_name());
	os << mint_format("{} map channel [-]`[/][c!*]{}[/][-]`[/]",
			  channel_type_str(map_table.channel_type()),
			  map_table.channel_name());

	switch (map_table.level()) {
	case aggregation_level::OWNER:
	{
		auto& map_group = static_cast<const per_owner_map_table&>(map_table).map_group();

		if (map_group.type() != LTTNG_MAP_GROUP_TYPE_KERNEL_GLOBAL) {
			os << group_info(map_group);
		}

		break;
	}
	case aggregation_level::PART:
	{
		auto& spec_map_table = static_cast<const per_part_map_table&>(map_table);

		if (spec_map_table.map_group().type() != LTTNG_MAP_GROUP_TYPE_KERNEL_GLOBAL) {
			os << group_info(spec_map_table.map_group());
		}

		os << mint_format(", CPU [!*]{}[/]", spec_map_table.part_id());
		break;
	}
	default:
		break;
	}

	os << ":\n";

	std::vector<tw::table_col_descr::uptr> cols;

	cols.push_back(
		make_unique<tw::table_str_col_descr>("Key", tw::table_cell_align::LEFT, true));
	cols.push_back(make_unique<tw::table_bigint_col_descr>("Value"));
	cols.push_back(
		make_unique<tw::table_str_col_descr>("Overflow?", tw::table_cell_align::CENTER));

	tw::table_writer writer(std::move(cols), locale_supports_utf8(), true);

	for (const auto& row : map_table.rows()) {
		std::vector<tw::table_cell::uptr> cells;

		cells.push_back(tw::make_str_cell(row.key()));
		cells.push_back(tw::make_bigint_cell(row.val()));
		cells.push_back(tw::make_str_cell(
			row.has_overflow() ? (locale_supports_utf8() ? "✔" : "*") : ""));

		writer.append_row(std::move(cells));
	}

	writer.write(os, term_columns());
}

} /* namespace */

void run_human(const output& out)
{
	if (out.tables.empty()) {
		std::cout << mint_format("[!y]Nothing to show![/]\n");
		return;
	}

	auto nl_sep = "";

	for (const auto& table : out.tables) {
		std::cout << nl_sep;
		write_map_table(std::cout, *table);
		nl_sep = "\n";
	}
}

} /* namespace show_maps */
} /* namespace cli */
} /* namespace lttng */
