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

	/*
	 * What to do with the values held by a tracer-backed map_group when
	 * its owning partition disappears (per-PID UST: app exit). The kernel
	 * (one group per channel) and UST per-UID (groups live as long as
	 * the channel) cases never produce a "dead group" event; this field
	 * is a no-op for them, but exists uniformly across map channels for
	 * API symmetry and forward compatibility.
	 *
	 * DROP: discard the dying group's values.
	 *
	 * SUM_INTO_SHARED: merge each (index, value) pair into the channel's
	 * shared group via integer addition.
	 *
	 * Future variants (e.g. PRESERVE_MAX_VALUE) are additive.
	 */
	enum class dead_group_policy_t {
		DROP,
		SUM_INTO_SHARED,
	};

	map_channel_configuration(std::string name_,
				  key_type_t key_type_,
				  value_type_t value_type_,
				  update_policy_t update_policy_,
				  std::uint64_t max_entry_count_,
				  ownership_model_t buffer_ownership_,
				  dead_group_policy_t dead_group_policy_) :
		name(std::move(name_)),
		key_type(key_type_),
		value_type(value_type_),
		update_policy(update_policy_),
		max_entry_count(max_entry_count_),
		buffer_ownership(buffer_ownership_),
		dead_group_policy(dead_group_policy_)
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
	const dead_group_policy_t dead_group_policy;
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
struct formatter<lttng::sessiond::config::map_channel_configuration::dead_group_policy_t>
	: formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::config::map_channel_configuration::dead_group_policy_t policy,
	       FormatContextType& ctx) const
	{
		auto name = "UNKNOWN";

		switch (policy) {
		case lttng::sessiond::config::map_channel_configuration::dead_group_policy_t::DROP:
			name = "DROP";
			break;
		case lttng::sessiond::config::map_channel_configuration::dead_group_policy_t::
			SUM_INTO_SHARED:
			name = "SUM_INTO_SHARED";
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
				 "max_entry_count: {}, buffer_ownership: {}, "
				 "dead_group_policy: {})",
				 channel.name,
				 channel.key_type,
				 channel.value_type,
				 channel.update_policy,
				 channel.max_entry_count,
				 channel.buffer_ownership,
				 channel.dead_group_policy);
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_MAP_CHANNEL_CONFIGURATION_HPP */
