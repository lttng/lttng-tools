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
		/*
		 * String keys assembled by the tracer at enabler-sync time from a per-rule token
		 * template (literal / event name / provider name) and reported back to the
		 * sessiond. Used by map channels populated through counter-event rules.
		 */
		STRING,
		/*
		 * Externally-managed integer keys: sessiond picks a flat index from its own pool
		 * and binds it to whatever identifier it cares about (e.g. a trigger's tracer
		 * token), then tells the tracer which index to use for element mutations.
		 *
		 * No token template is rendered and no string is ever reported back from the
		 * tracer; the dimension size is the pool size.
		 *
		 * Used today by event-notifier error accounting which allocates one slot per
		 * registered trigger.
		 */
		INDEX,
	};

	enum class value_type_t {
		SIGNED_INT_32,
		SIGNED_INT_64,
		SIGNED_INT_MAX,
	};

	/*
	 * How event-rule matches are accounted for in the map.
	 *
	 * PER_EVENT (coalesce:true): a single firing event produces at most one
         * increment per map regardless of how many event-rules match it.
	 *
	 * PER_RULE_MATCH (coalesce:false): every matching event-rule
	 * produces its own increment.
	 */
	enum class update_policy_t {
		PER_EVENT,
		PER_RULE_MATCH,
	};

	map_channel_configuration(std::string name_,
				  key_type_t key_type_,
				  value_type_t value_type_,
				  update_policy_t update_policy_,
				  std::uint64_t max_entry_count_,
				  ownership_model_t buffer_ownership_) :
		name(std::move(name_)),
		key_type(key_type_),
		value_type(value_type_),
		update_policy(update_policy_),
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
	const update_policy_t update_policy;
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
		case lttng::sessiond::config::map_channel_configuration::key_type_t::INDEX:
			name = "INDEX";
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
struct formatter<lttng::sessiond::config::map_channel_configuration::update_policy_t>
	: formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::config::map_channel_configuration::update_policy_t update_policy,
	       FormatContextType& ctx) const
	{
		auto name = "UNKNOWN";

		switch (update_policy) {
		case lttng::sessiond::config::map_channel_configuration::update_policy_t::PER_EVENT:
			name = "PER_EVENT";
			break;
		case lttng::sessiond::config::map_channel_configuration::update_policy_t::
			PER_RULE_MATCH:
			name = "PER_RULE_MATCH";
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
				 "update_policy: {}, "
				 "max_entry_count: {}, buffer_ownership: {})",
				 channel.name,
				 channel.key_type,
				 channel.value_type,
				 channel.update_policy,
				 channel.max_entry_count,
				 channel.buffer_ownership);
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_MAP_CHANNEL_CONFIGURATION_HPP */
