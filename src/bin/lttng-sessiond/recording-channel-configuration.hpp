/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_RECORDING_CHANNEL_CONFIGURATION_HPP
#define LTTNG_SESSIOND_RECORDING_CHANNEL_CONFIGURATION_HPP

#include "event-rule-configuration.hpp"

#include <common/ctl/memory.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/make-unique.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

namespace lttng {
namespace sessiond {

#define LTTNG_THROW_EVENT_RULE_CONFIGURATION_NOT_FOUND_ERROR(event_rule)             \
	throw lttng::sessiond::exceptions::event_rule_configuration_not_found_error( \
		event_rule, LTTNG_SOURCE_LOCATION())

namespace exceptions {
/*
 * @class event_rule_configuration_not_found_error
 * @brief Represents a event-rule-configuration-not-found error and provides the
 * name of the channel looked-up for use by error-reporting code.
 */
class event_rule_configuration_not_found_error : public lttng::runtime_error {
public:
	explicit event_rule_configuration_not_found_error(
		const lttng_event_rule& event_rule, const lttng::source_location& source_location);
};
} /* namespace exceptions */

/*
 * A recording channel configuration represents the configuration of a recording session's
 * channel at a given point in time. It belongs to a single recording session.
 */
class recording_channel_configuration final {
public:
	using uptr = std::unique_ptr<recording_channel_configuration>;
	using timer_period_us = std::uint64_t;

	enum class buffer_full_policy_t {
		DISCARD_EVENT,
		OVERWRITE_OLDEST_PACKET,
	};

	enum class buffer_allocation_policy_t {
		PER_CPU,
		PER_CHANNEL,
	};

	enum class buffer_consumption_backend_t {
		MMAP,
		SPLICE,
	};

	enum class owership_model_t {
		PER_PID,
		PER_UID,
	};

	struct consumption_blocking_policy {
		enum class mode {
			NONE,
			TIMED,
			UNBOUNDED,
		};

		explicit consumption_blocking_policy(
			mode mode,
			const nonstd::optional<timer_period_us>& timeout_us = nonstd::nullopt);

		const mode mode_;
		/* Only set in TIMED mode. */
		const nonstd::optional<timer_period_us> timeout_us;
	};

	recording_channel_configuration(
		bool is_enabled,
		std::string name,
		buffer_full_policy_t buffer_full_policy,
		buffer_consumption_backend_t buffer_consumption_backend,
		buffer_allocation_policy_t buffer_allocation_policy,
		std::uint64_t subbuffer_size_bytes,
		unsigned int subbuffer_count,
		const nonstd::optional<timer_period_us>& switch_timer_period_us,
		const nonstd::optional<timer_period_us>& read_timer_period_us,
		const nonstd::optional<timer_period_us>& live_timer_period_us,
		const nonstd::optional<timer_period_us>& monitor_timer_period_us,
		const nonstd::optional<timer_period_us>& watchdog_timer_period_us,
		consumption_blocking_policy consumption_blocking_policy,
		const nonstd::optional<std::uint64_t>& trace_file_size_limit_bytes,
		const nonstd::optional<unsigned int>& trace_file_count_limit);

	~recording_channel_configuration() = default;
	recording_channel_configuration(recording_channel_configuration&&) = delete;
	recording_channel_configuration(const recording_channel_configuration&) = delete;
	recording_channel_configuration& operator=(const recording_channel_configuration&) = delete;
	recording_channel_configuration& operator=(recording_channel_configuration&&) = delete;

	void enable() noexcept
	{
		set_enabled(true);
	}

	void disable() noexcept
	{
		set_enabled(false);
	}

	void set_enabled(bool enable) noexcept;

	template <typename... Args>
	void add_event_rule_configuration(Args&&...args)
	{
		auto config =
			lttng::make_unique<event_rule_configuration>(std::forward<Args>(args)...);

		event_rules.emplace(std::cref(*config->event_rule), std::move(config));
	}

	const lttng::sessiond::event_rule_configuration&
	get_event_rule_configuration(const lttng_event_rule& matching_event_rule_to_lookup) const;
	lttng::sessiond::event_rule_configuration&
	get_event_rule_configuration(const lttng_event_rule& matching_event_rule_to_lookup);

	const std::string name;
	const buffer_full_policy_t buffer_full_policy;
	const buffer_consumption_backend_t buffer_consumption_backend;
	const buffer_allocation_policy_t buffer_allocation_policy;
	const std::uint64_t subbuffer_size_bytes;
	const unsigned int subbuffer_count;
	const nonstd::optional<timer_period_us> switch_timer_period_us;
	const nonstd::optional<timer_period_us> read_timer_period_us;
	const nonstd::optional<timer_period_us> live_timer_period_us;
	const nonstd::optional<timer_period_us> monitor_timer_period_us;
	const nonstd::optional<timer_period_us> watchdog_timer_period_us;
	const consumption_blocking_policy consumption_blocking_policy_;
	const nonstd::optional<std::uint64_t> trace_file_size_limit_bytes;
	const nonstd::optional<unsigned int> trace_file_count_limit;

	bool is_enabled;

	std::unordered_map<std::reference_wrapper<const lttng_event_rule>,
			   event_rule_configuration::uptr,
			   std::hash<std::reference_wrapper<const lttng_event_rule>>,
			   lttng_event_rule_ref_equal>
		event_rules;
};

} /* namespace sessiond */
} /* namespace lttng */

/*
 * Specialize fmt::formatter for consumption_blocking_policy's mode.
 *
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::recording_channel_configuration::consumption_blocking_policy::mode>
	: formatter<std::string> {
	/* Format function to convert enum to string. */
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::recording_channel_configuration::consumption_blocking_policy::mode
		       mode,
	       FormatContextType& ctx) const
	{
		auto name = "UNKNOWN";

		switch (mode) {
		case lttng::sessiond::recording_channel_configuration::consumption_blocking_policy::
			mode::NONE:
			name = "NONE";
			break;
		case lttng::sessiond::recording_channel_configuration::consumption_blocking_policy::
			mode::UNBOUNDED:
			name = "UNBOUNDED";
			break;
		case lttng::sessiond::recording_channel_configuration::consumption_blocking_policy::
			mode::TIMED:
			name = "TIMED";
			break;
		}

		/* Write the string representation to the format context output iterator. */
		return format_to(ctx.out(), name);
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_RECORDING_CHANNEL_CONFIGURATION_HPP */
