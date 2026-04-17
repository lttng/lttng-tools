/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MAP_CHANNEL_CONFIGURATION_HPP
#define LTTNG_SESSIOND_MAP_CHANNEL_CONFIGURATION_HPP

#include "channel-configuration.hpp"

#include <common/format.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace lttng {
namespace sessiond {
namespace config {

/*
 * A map channel configuration represents the configuration of a map channel
 * belonging to a recording session.
 */
class map_channel_configuration final {
public:
	using uptr = std::unique_ptr<map_channel_configuration>;

	enum class key_type_t {
		STRING,
	};

	enum class value_type_t {
		SIGNED_INT_32,
		SIGNED_INT_64,
		SIGNED_INT_MAX,
	};

	map_channel_configuration(std::string name_,
				  key_type_t key_type_,
				  value_type_t value_type_,
				  bool coalesce_hits_,
				  std::uint64_t max_entry_count_,
				  ownership_model_t buffer_ownership_) :
		name(std::move(name_)),
		key_type(key_type_),
		value_type(value_type_),
		coalesce_hits(coalesce_hits_),
		max_entry_count(max_entry_count_),
		buffer_ownership(buffer_ownership_)
	{
	}

	~map_channel_configuration() = default;
	map_channel_configuration(const map_channel_configuration&) = delete;
	map_channel_configuration(map_channel_configuration&&) = delete;
	map_channel_configuration& operator=(const map_channel_configuration&) = delete;
	map_channel_configuration& operator=(map_channel_configuration&&) = delete;

	const std::string name;
	const key_type_t key_type;
	const value_type_t value_type;
	const bool coalesce_hits;
	std::uint64_t max_entry_count;
	const ownership_model_t buffer_ownership;
};

} /* namespace config */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Due to a bug in g++ < 7.1, these specializations must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::config::map_channel_configuration::key_type_t>
	: formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::config::map_channel_configuration::key_type_t key_type,
	       FormatContextType& ctx) const
	{
		auto name = "UNKNOWN";

		switch (key_type) {
		case lttng::sessiond::config::map_channel_configuration::key_type_t::STRING:
			name = "STRING";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng::sessiond::config::map_channel_configuration::value_type_t>
	: formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::config::map_channel_configuration::value_type_t value_type,
	       FormatContextType& ctx) const
	{
		auto name = "UNKNOWN";

		switch (value_type) {
		case lttng::sessiond::config::map_channel_configuration::value_type_t::SIGNED_INT_32:
			name = "SIGNED_INT_32";
			break;
		case lttng::sessiond::config::map_channel_configuration::value_type_t::SIGNED_INT_64:
			name = "SIGNED_INT_64";
			break;
		case lttng::sessiond::config::map_channel_configuration::value_type_t::SIGNED_INT_MAX:
			name = "SIGNED_INT_MAX";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng::sessiond::config::map_channel_configuration> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(const lttng::sessiond::config::map_channel_configuration& channel,
	       FormatContextType& ctx) const
	{
		return format_to(ctx.out(),
				 "`{}` (key_type: {}, value_type: {}, "
				 "coalesce_hits: {}"
				 "max_entry_count: {}, buffer_ownership: {})",
				 channel.name,
				 channel.key_type,
				 channel.value_type,
				 channel.coalesce_hits,
				 channel.max_entry_count,
				 channel.buffer_ownership);
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_MAP_CHANNEL_CONFIGURATION_HPP */
