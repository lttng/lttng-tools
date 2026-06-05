/*
 * SPDX-FileCopyrightText: 2026 Philippe Proulx <philippe.proulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "export-maps-sql.hpp"
#include "view-wrappers.hpp"

#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/macros.hpp>

#include <lttng/lttng.h>
#include <lttng/map/channel-type.h>
#include <lttng/map/group-type.h>
#include <lttng/map/key-type.h>

#include <vendor/optional.hpp>

#include <cstdint>
#include <string>
#include <unordered_map>

namespace lttng {
namespace cli {
namespace export_maps {
namespace {

/*
 * The SQL schema: tables, constraints, and the `vmap` convenience view.
 *
 * Keep this synchronized with the schema documented in the
 * lttng-export-maps(1) manual page. Any incompatible change to the schema
 * needs a new `--format` value.
 */
constexpr char schema[] =
	R"sql(CREATE TABLE channels (
  id   INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('kernel', 'user')),
  UNIQUE (name, type)
);

CREATE TABLE groups (
  id          INTEGER PRIMARY KEY,
  channel_id  INTEGER NOT NULL REFERENCES channels(id),
  type        TEXT NOT NULL
              CHECK (type IN ('kernel-global', 'user-per-user',
                              'user-per-process', 'shared')),
  owner_id    INTEGER,
  owner_name  TEXT,
  value_type  TEXT NOT NULL
              CHECK (value_type IN ('signed-int-32', 'signed-int-64')),
  CHECK ((owner_id IS NULL) = (type NOT IN ('user-per-user', 'user-per-process')))
);

CREATE TABLE keys (
  id   INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE entries (
  group_id     INTEGER NOT NULL REFERENCES groups(id),
  part_id      INTEGER,
  key_id       INTEGER NOT NULL REFERENCES keys(id),
  value        INTEGER NOT NULL,
  has_overflow INTEGER NOT NULL CHECK (has_overflow IN (0, 1))
);

CREATE VIEW vmap AS
SELECT c.name AS channel_name,
       c.type AS channel_type,
       g.type AS group_type,
       g.owner_id,
       g.owner_name,
       g.value_type,
       e.part_id,
       k.name AS key,
       e.value,
       e.has_overflow
FROM entries e
JOIN groups g   ON e.group_id   = g.id
JOIN channels c ON g.channel_id = c.id
JOIN keys k     ON e.key_id     = k.id;
)sql";

const char *channel_type_str(const lttng_map_channel_type type)
{
	switch (type) {
	case LTTNG_MAP_CHANNEL_TYPE_KERNEL:
		return "kernel";
	case LTTNG_MAP_CHANNEL_TYPE_USER:
		return "user";
	}

	LTTNG_THROW_ERROR("Unknown map channel type");
}

const char *group_type_str(const lttng_map_group_type type)
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

/*
 * Returns `str` as an SQLite string literal: single quotes doubled and
 * the whole wrapped in single quotes.
 *
 * This is correct for SQLite, which doesn't treat the backslash as an
 * escape character within string literals; it isn't necessarily safe
 * for other SQL database engines, hence the `sqlite`-specific output
 * format (see the `--format` option in the lttng-export-maps(1) manual
 * page).
 */
std::string quote_text(const char *const str)
{
	std::string quoted("'");

	for (auto ch = str; *ch != '\0'; ++ch) {
		if (*ch == '\'') {
			quoted += "''";
		} else {
			quoted += *ch;
		}
	}

	quoted += '\'';
	return quoted;
}

/*
 * Builder of an SQL export from the map channels of a recording session.
 *
 * Walks every map channel/group/partition/key of the recording session
 * and appends the corresponding `INSERT INTO` statements directly into a
 * single string buffer.
 *
 * The walk visits every parent before its children (a channel before its
 * groups, a group before its entries, and a key just before the first
 * entry referencing it), so the buffer is naturally in dependency order:
 * no reordering or per-table buckets are needed.
 *
 * build() then assembles the schema, the transaction-wrapped
 * insertions, and returns the complete SQL script. It resets its
 * internal state on entry, so it may be called more than once.
 */
class sql_builder final {
public:
	explicit sql_builder(const std::string& session_name) noexcept :
		_session_name(&session_name)
	{
	}

	sql_builder(const sql_builder&) = delete;
	sql_builder(sql_builder&&) = delete;
	sql_builder& operator=(const sql_builder&) = delete;
	sql_builder& operator=(sql_builder&&) = delete;
	~sql_builder() = default;

	std::string build()
	{
		/*
		 * Reset any state left over from a previous call so
		 * that build() may be invoked more than once.
		 */
		_sql.clear();
		_key_ids.clear();
		_next_channel_id = 1;
		_next_group_id = 1;
		_next_key_id = 1;

		const session_list sessions;
		const auto session = sessions.find_by_name(_session_name->c_str());

		if (!session) {
			LTTNG_THROW_ERROR(
				format("Recording session `{}` not found", *_session_name));
		}

		_process_channels(*session, LTTNG_MAP_CHANNEL_TYPE_KERNEL);
		_process_channels(*session, LTTNG_MAP_CHANNEL_TYPE_USER);

		/*
		 * Wrap every insertion in a single transaction: without
		 * one, SQLite commits after each statement, which is
		 * much slower.
		 */
		return std::string(schema) + "\nBEGIN;\n" + _sql + "COMMIT;\n";
	}

private:
	void _process_channels(const session& session, const lttng_map_channel_type type)
	{
		for (auto& channel : session.map_channels(type)) {
			_process_channel(channel);
		}
	}

	void _process_channel(const map_channel& channel)
	{
		const auto channel_id = _next_channel_id++;

		_sql += fmt::format(
			"INSERT INTO channels (id, name, type) VALUES ({}, {}, '{}');\n",
			channel_id,
			quote_text(channel.name().data()),
			channel_type_str(channel.type()));

		/*
		 * Fetch the keys once per channel: every map of a
		 * channel shares the same keys at the same
		 * entry indices.
		 */
		const auto key_set = channel.keys();

		for (const auto& group : channel.groups()) {
			_process_group(channel_id, group, key_set);
		}
	}

	void _process_group(const std::uint64_t channel_id,
			    const map_group& group,
			    const map_key_set& key_set)
	{
		const auto group_id = _next_group_id++;
		const auto type = group.type();
		std::string owner_id_sql = "NULL";
		std::string owner_name_sql = "NULL";
		const char *const value_type_sql = group.effective_value_type() ==
				LTTNG_MAP_VALUE_TYPE_SIGNED_INT_32 ?
			"'signed-int-32'" :
			"'signed-int-64'";

		if (type == LTTNG_MAP_GROUP_TYPE_USER_PER_USER ||
		    type == LTTNG_MAP_GROUP_TYPE_USER_PER_PROCESS) {
			const auto user_group = group.as_user();

			owner_id_sql = fmt::format("{}", user_group.owner_id());

			const auto owner_name = user_group.owner_name();

			if (!owner_name.empty()) {
				owner_name_sql = quote_text(owner_name.c_str());
			}
		}

		_sql += fmt::format("INSERT INTO groups "
				    "(id, channel_id, type, owner_id, owner_name, value_type) "
				    "VALUES ({}, {}, '{}', {}, {}, {});\n",
				    group_id,
				    channel_id,
				    group_type_str(type),
				    owner_id_sql,
				    owner_name_sql,
				    value_type_sql);

		for (const auto& values : group.values()) {
			const auto part_id = values.partition_id();
			const auto part_id_sql = part_id ? fmt::format("{}", *part_id) :
							   std::string("NULL");
			const auto vals = values.as_signed_int();

			for (auto& key : key_set) {
				LTTNG_ASSERT(key.type() == LTTNG_MAP_KEY_TYPE_STRING);

				_sql += fmt::format(
					"INSERT INTO entries "
					"(group_id, part_id, key_id, value, has_overflow) "
					"VALUES ({}, {}, {}, {}, {});\n",
					group_id,
					part_id_sql,
					_key_id(key.as_string().string().data()),
					vals.value(key),
					vals.has_overflow(key) ? 1 : 0);
			}
		}
	}

	/*
	 * Returns the surrogate ID of the key named `name`, appending
	 * an `INSERT INTO keys` statement the first time a given key
	 * name is seen so that each name appears exactly once (the
	 * `keys` table deduplicates names across channels).
	 */
	std::uint64_t _key_id(const std::string& name)
	{
		const auto it = _key_ids.find(name);

		if (it != _key_ids.end()) {
			return it->second;
		}

		const auto id = _next_key_id++;

		_key_ids.emplace(name, id);
		_sql += fmt::format("INSERT INTO keys (id, name) "
				    "VALUES ({}, {});\n",
				    id,
				    quote_text(name.c_str()));
		return id;
	}

	const std::string *_session_name;
	std::string _sql;
	std::unordered_map<std::string, std::uint64_t> _key_ids;
	std::uint64_t _next_channel_id = 1;
	std::uint64_t _next_group_id = 1;
	std::uint64_t _next_key_id = 1;
};

} /* namespace */

std::string sql_from_session(const std::string& session_name)
{
	return sql_builder(session_name).build();
}

} /* namespace export_maps */
} /* namespace cli */
} /* namespace lttng */
