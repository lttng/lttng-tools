/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_DOMAIN_ORCHESTRATOR_HPP
#define LTTNG_SESSIOND_DOMAIN_ORCHESTRATOR_HPP

#include <common/exception.hpp>
#include <common/format.hpp>

#include <vendor/optional.hpp>

#include <bin/lttng-sessiond/channel-memory-types.hpp>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

struct consumer_output;

namespace lttng {
namespace sessiond {

namespace config {
class recording_channel_configuration;
class event_rule_configuration;
class context_configuration;

enum class process_attribute_type {
	PID,
	VPID,
	UID,
	VUID,
	GID,
	VGID,
};

enum class tracking_policy;

} /* namespace config */

/*
 * Runtime statistics for a recording channel, as reported by the consumer
 * daemon. Both fields are cumulative counts since the start of the session
 * and aggregated across all streams of the channel.
 */
struct recording_channel_runtime_stats {
	std::uint64_t discarded_events;
	std::uint64_t lost_packets;
};

/*
 * A domain orchestrator manages the runtime tracing resources (stream groups,
 * streams, buffers, and consumer connections) for a specific instrumentation
 * domain (kernel or user space) within a recording session.
 *
 * It coordinates between the tracer (kernel module or UST applications) and
 * the consumer daemon to realize the session's domain configuration.
 *
 * Each recording session owns one orchestrator per active domain. The
 * orchestrator is created when the domain is first used and destroyed with
 * the session.
 *
 * All operations that target a specific channel or event rule accept a
 * reference to the corresponding configuration object. The orchestrator
 * uses the pointer identity of these objects as a lookup key: configuration
 * objects are unique within a config::domain and are never moved or copied.
 */
class domain_orchestrator {
protected:
	domain_orchestrator() = default;

public:
	virtual ~domain_orchestrator() = default;

	domain_orchestrator(const domain_orchestrator&) = delete;
	domain_orchestrator(domain_orchestrator&&) = delete;
	domain_orchestrator& operator=(const domain_orchestrator&) = delete;
	domain_orchestrator& operator=(domain_orchestrator&&) = delete;

	virtual void
	create_channel(const config::recording_channel_configuration& channel_config) = 0;
	virtual void
	enable_channel(const config::recording_channel_configuration& channel_config) = 0;
	virtual void
	disable_channel(const config::recording_channel_configuration& channel_config) = 0;

	virtual void enable_event(const config::recording_channel_configuration& channel_config,
				  const config::event_rule_configuration& event_rule_config) = 0;
	virtual void disable_event(const config::recording_channel_configuration& channel_config,
				   const config::event_rule_configuration& event_rule_config) = 0;

	virtual void add_context(const config::recording_channel_configuration& channel_config,
				 const config::context_configuration& context_config) = 0;

	virtual void set_tracking_policy(config::process_attribute_type attribute_type,
					 config::tracking_policy policy) = 0;
	virtual void track_process_attribute(config::process_attribute_type attribute_type,
					     std::uint64_t value) = 0;
	virtual void untrack_process_attribute(config::process_attribute_type attribute_type,
					       std::uint64_t value) = 0;

	virtual void start() = 0;
	virtual void stop() = 0;

	virtual void rotate() = 0;
	virtual void clear() = 0;
	virtual void open_packets() = 0;

	virtual void record_snapshot(const struct consumer_output& snapshot_consumer,
				     std::uint64_t nb_packets_per_stream) = 0;

	virtual void regenerate_metadata() = 0;
	virtual void regenerate_statedump() = 0;

	virtual commands::reclaim_channel_memory_result reclaim_channel_memory(
		const config::recording_channel_configuration& target_channel,
		const nonstd::optional<std::chrono::microseconds>& reclaim_older_than_age,
		bool require_consumed,
		commands::completion_callback_t on_complete,
		commands::cancellation_callback_t on_cancel) = 0;

	virtual std::vector<commands::stream_memory_usage_group> get_channel_memory_usage(
		const config::recording_channel_configuration& target_channel) const = 0;

	/*
	 * Query the consumer daemon for the runtime statistics of a
	 * recording channel (discarded events and lost packets).
	 */
	virtual recording_channel_runtime_stats get_recording_channel_runtime_stats(
		const config::recording_channel_configuration& channel_config) const = 0;
};

namespace exceptions {

/*
 * @class rotation_failure
 * @brief Thrown when a consumer channel rotation request fails.
 */
class rotation_failure : public lttng::runtime_error {
public:
	explicit rotation_failure(const std::string& msg,
				  const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class snapshot_failure
 * @brief Thrown when a consumer channel snapshot request fails.
 */
class snapshot_failure : public lttng::runtime_error {
public:
	explicit snapshot_failure(const std::string& msg,
				  const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class clear_relay_disallowed
 * @brief Thrown when the relay daemon disallows a clear operation on a channel.
 */
class clear_relay_disallowed : public lttng::runtime_error {
public:
	explicit clear_relay_disallowed(const std::string& msg,
					const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class clear_failure
 * @brief Thrown when a consumer channel clear request fails.
 */
class clear_failure : public lttng::runtime_error {
public:
	explicit clear_failure(const std::string& msg,
			       const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class open_packets_failure
 * @brief Thrown when a consumer open-packets request fails on a channel.
 */
class open_packets_failure : public lttng::runtime_error {
public:
	explicit open_packets_failure(const std::string& msg,
				      const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class regenerate_metadata_failure
 * @brief Thrown when a metadata regeneration request fails.
 */
class regenerate_metadata_failure : public lttng::runtime_error {
public:
	explicit regenerate_metadata_failure(const std::string& msg,
					     const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class regenerate_statedump_failure
 * @brief Thrown when a statedump regeneration request fails.
 */
class regenerate_statedump_failure : public lttng::runtime_error {
public:
	explicit regenerate_statedump_failure(const std::string& msg,
					      const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

} /* namespace exceptions */

} /* namespace sessiond */
} /* namespace lttng */

#define LTTNG_THROW_ROTATION_FAILURE(msg) \
	throw lttng::sessiond::exceptions::rotation_failure(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_SNAPSHOT_FAILURE(msg) \
	throw lttng::sessiond::exceptions::snapshot_failure(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_CLEAR_RELAY_DISALLOWED(msg) \
	throw lttng::sessiond::exceptions::clear_relay_disallowed(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_CLEAR_FAILURE(msg) \
	throw lttng::sessiond::exceptions::clear_failure(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_OPEN_PACKETS_FAILURE(msg) \
	throw lttng::sessiond::exceptions::open_packets_failure(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_REGENERATE_METADATA_FAILURE(msg) \
	throw lttng::sessiond::exceptions::regenerate_metadata_failure(msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_REGENERATE_STATEDUMP_FAILURE(msg)                        \
	throw lttng::sessiond::exceptions::regenerate_statedump_failure(msg, \
									LTTNG_SOURCE_LOCATION())

/*
 * Specialize fmt::formatter for process_attribute_type.
 *
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::config::process_attribute_type> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::config::process_attribute_type attribute_type,
	       FormatContextType& ctx) const
	{
		auto name = "UNKNOWN";

		switch (attribute_type) {
		case lttng::sessiond::config::process_attribute_type::PID:
			name = "PID";
			break;
		case lttng::sessiond::config::process_attribute_type::VPID:
			name = "VPID";
			break;
		case lttng::sessiond::config::process_attribute_type::UID:
			name = "UID";
			break;
		case lttng::sessiond::config::process_attribute_type::VUID:
			name = "VUID";
			break;
		case lttng::sessiond::config::process_attribute_type::GID:
			name = "GID";
			break;
		case lttng::sessiond::config::process_attribute_type::VGID:
			name = "VGID";
			break;
		}

		return format_to(ctx.out(), name);
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_DOMAIN_ORCHESTRATOR_HPP */
