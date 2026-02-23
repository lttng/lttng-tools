/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MODULES_DOMAIN_ORCHESTRATOR_HPP
#define LTTNG_SESSIOND_MODULES_DOMAIN_ORCHESTRATOR_HPP

#include "context-configuration.hpp"
#include "domain-orchestrator.hpp"
#include "domain.hpp"
#include "event-rule-configuration.hpp"
#include "recording-channel-configuration.hpp"
#include "stream-group.hpp"

#include <common/file-descriptor.hpp>
#include <common/make-unique.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <unordered_map>
#include <vector>

struct consumer_output;
struct ltt_kernel_session;

namespace lttng {
namespace sessiond {
namespace modules {

namespace config = lttng::sessiond::config;

namespace exceptions {

/*
 * @class kernel_event_already_exists
 * @brief Thrown when the kernel tracer reports that an event already exists (EEXIST).
 */
class kernel_event_already_exists : public lttng::runtime_error {
public:
	explicit kernel_event_already_exists(const lttng::source_location& source_location_) :
		lttng::runtime_error("Kernel event already exists", source_location_)
	{
	}
};

/*
 * @class kernel_event_type_unsupported
 * @brief Thrown when the kernel tracer does not implement the requested event type (ENOSYS).
 */
class kernel_event_type_unsupported : public lttng::runtime_error {
public:
	explicit kernel_event_type_unsupported(const lttng::source_location& source_location_) :
		lttng::runtime_error("Event type not implemented by kernel tracer",
				     source_location_)
	{
	}
};

/*
 * @class kernel_event_enable_failure
 * @brief Thrown when a kernel event could not be enabled (e.g. event not found,
 * callsite addition failed).
 */
class kernel_event_enable_failure : public lttng::runtime_error {
public:
	explicit kernel_event_enable_failure(const std::string& msg,
					     const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class kernel_filter_out_of_memory
 * @brief Thrown when the kernel tracer cannot allocate memory for a filter (ENOMEM).
 */
class kernel_filter_out_of_memory : public lttng::runtime_error {
public:
	explicit kernel_filter_out_of_memory(const lttng::source_location& source_location_) :
		lttng::runtime_error("Kernel filter out of memory", source_location_)
	{
	}
};

/*
 * @class kernel_filter_invalid
 * @brief Thrown when the kernel tracer rejects a filter bytecode as invalid.
 */
class kernel_filter_invalid : public lttng::runtime_error {
public:
	explicit kernel_filter_invalid(const lttng::source_location& source_location_) :
		lttng::runtime_error("Invalid kernel filter", source_location_)
	{
	}
};

} /* namespace exceptions */

#define LTTNG_THROW_KERNEL_EVENT_ALREADY_EXISTS()                                \
	throw lttng::sessiond::modules::exceptions::kernel_event_already_exists( \
		LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_KERNEL_EVENT_TYPE_UNSUPPORTED()                                \
	throw lttng::sessiond::modules::exceptions::kernel_event_type_unsupported( \
		LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_KERNEL_EVENT_ENABLE_FAILURE(msg)                             \
	throw lttng::sessiond::modules::exceptions::kernel_event_enable_failure( \
		msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_KERNEL_FILTER_OUT_OF_MEMORY()                                \
	throw lttng::sessiond::modules::exceptions::kernel_filter_out_of_memory( \
		LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_KERNEL_FILTER_INVALID() \
	throw lttng::sessiond::modules::exceptions::kernel_filter_invalid(LTTNG_SOURCE_LOCATION())

/*
 * Runtime handle for a kernel event rule that has been created against the
 * lttng-modules tracer.
 */
class event_rule final {
public:
	explicit event_rule(lttng::file_descriptor tracer_event_fd,
			    const config::event_rule_configuration& configuration) :
		_tracer_event_fd(std::move(tracer_event_fd)), _configuration(configuration)
	{
	}

	~event_rule() = default;

	event_rule(event_rule&&) = default;
	event_rule(const event_rule&) = delete;
	event_rule& operator=(event_rule&&) = delete;
	event_rule& operator=(const event_rule&) = delete;

	lttng::file_descriptor& tracer_handle() noexcept
	{
		return _tracer_event_fd;
	}

	const lttng::file_descriptor& tracer_handle() const noexcept
	{
		return _tracer_event_fd;
	}

	const config::event_rule_configuration& configuration() const noexcept
	{
		return _configuration;
	}

private:
	lttng::file_descriptor _tracer_event_fd;
	const config::event_rule_configuration& _configuration;
};

/*
 * Runtime representation of a kernel channel managed by the LTTng-modules
 * tracer.
 *
 * Extends the base stream_group (which manages the consumer key and stream
 * instances) with kernel-domain-specific state: the tracer channel fd,
 * the channel configuration reference, consumer/notification lifecycle
 * flags, and event rules.
 */
class stream_group final : public lttng::sessiond::stream_group<lttng::file_descriptor> {
public:
	explicit stream_group(lttng::file_descriptor tracer_channel_fd,
			      uint64_t consumer_key,
			      const config::recording_channel_configuration& configuration) :
		lttng::sessiond::stream_group<lttng::file_descriptor>(consumer_key),
		_tracer_channel_fd(std::move(tracer_channel_fd)),
		_configuration(configuration)
	{
	}

	~stream_group() override = default;

	stream_group(stream_group&&) = delete;
	stream_group(const stream_group&) = delete;
	stream_group& operator=(stream_group&&) = delete;
	stream_group& operator=(const stream_group&) = delete;

	lttng::file_descriptor& tracer_handle() noexcept
	{
		return _tracer_channel_fd;
	}

	const lttng::file_descriptor& tracer_handle() const noexcept
	{
		return _tracer_channel_fd;
	}

	const config::recording_channel_configuration& configuration() const noexcept
	{
		return _configuration;
	}

	uint64_t stream_group_key() const noexcept
	{
		return consumer_key();
	}

	bool is_sent_to_consumer() const noexcept
	{
		return _sent_to_consumer;
	}

	void mark_sent_to_consumer() noexcept
	{
		_sent_to_consumer = true;
	}

	bool is_published_to_notification_thread() const noexcept
	{
		return _published_to_notification_thread;
	}

	void mark_published_to_notification_thread() noexcept
	{
		_published_to_notification_thread = true;
	}

	void add_event_rule(const config::event_rule_configuration& event_rule_config,
			    lttng::file_descriptor tracer_event_fd)
	{
		_event_rules.emplace_back(std::move(tracer_event_fd), event_rule_config);
	}

	/*
	 * Find the runtime event rule associated with the given configuration.
	 * Returns nullptr if no matching event rule is found.
	 */
	event_rule *
	find_event_rule(const config::event_rule_configuration& event_rule_config) noexcept
	{
		for (auto& rule : _event_rules) {
			if (&rule.configuration() == &event_rule_config) {
				return &rule;
			}
		}

		return nullptr;
	}

	const event_rule *
	find_event_rule(const config::event_rule_configuration& event_rule_config) const noexcept
	{
		for (const auto& rule : _event_rules) {
			if (&rule.configuration() == &event_rule_config) {
				return &rule;
			}
		}

		return nullptr;
	}

private:
	lttng::file_descriptor _tracer_channel_fd;
	const config::recording_channel_configuration& _configuration;
	bool _sent_to_consumer = false;
	bool _published_to_notification_thread = false;
	std::vector<event_rule> _event_rules;
};

/*
 * Runtime representation of the metadata channel for a kernel tracing session
 * managed by the lttng-modules tracer.
 *
 * The metadata stream is opened separately from the metadata channel itself
 * (kernctl_open_metadata vs. kernctl_create_stream on the metadata fd), hence
 * the optional stream fd.
 */
class metadata_channel final {
public:
	explicit metadata_channel(lttng::file_descriptor tracer_metadata_fd,
				  uint64_t consumer_key) :
		_tracer_metadata_fd(std::move(tracer_metadata_fd)), _consumer_key(consumer_key)
	{
	}

	~metadata_channel() = default;

	metadata_channel(metadata_channel&&) = default;
	metadata_channel(const metadata_channel&) = delete;
	metadata_channel& operator=(metadata_channel&&) = delete;
	metadata_channel& operator=(const metadata_channel&) = delete;

	lttng::file_descriptor& tracer_handle() noexcept
	{
		return _tracer_metadata_fd;
	}

	const lttng::file_descriptor& tracer_handle() const noexcept
	{
		return _tracer_metadata_fd;
	}

	uint64_t consumer_key() const noexcept
	{
		return _consumer_key;
	}

	void stream_fd(lttng::file_descriptor fd)
	{
		_stream_fd = std::move(fd);
	}

	lttng::file_descriptor& stream_fd()
	{
		return *_stream_fd;
	}

	const lttng::file_descriptor& stream_fd() const
	{
		return *_stream_fd;
	}

	bool has_stream() const noexcept
	{
		return static_cast<bool>(_stream_fd);
	}

private:
	lttng::file_descriptor _tracer_metadata_fd;
	const uint64_t _consumer_key;
	nonstd::optional<lttng::file_descriptor> _stream_fd;
};

/*
 * Concrete domain orchestrator for the lttng-modules kernel tracer.
 *
 * Manages the runtime tracing resources — session fd, channels, streams,
 * metadata, and consumer connections — for the kernel domain within a
 * recording session.
 *
 * The orchestrator reads configuration exclusively from the config::domain
 * passed at construction time. It does not copy configuration fields; the
 * config objects are the single source of truth.
 */
class domain_orchestrator final : public sessiond::domain_orchestrator {
public:
	explicit domain_orchestrator(lttng::file_descriptor tracer_session_fd,
				     config::domain& domain_configuration,
				     struct consumer_output& consumer,
				     struct ltt_kernel_session *legacy_kernel_session,
				     int kernel_pipe) :
		_tracer_session_fd(std::move(tracer_session_fd)),
		_domain_configuration(domain_configuration),
		_consumer(consumer),
		_legacy_kernel_session(legacy_kernel_session),
		_kernel_pipe(kernel_pipe)
	{
	}

	~domain_orchestrator() override = default;

	domain_orchestrator(const domain_orchestrator&) = delete;
	domain_orchestrator(domain_orchestrator&&) = delete;
	domain_orchestrator& operator=(const domain_orchestrator&) = delete;
	domain_orchestrator& operator=(domain_orchestrator&&) = delete;

	void create_channel(const config::recording_channel_configuration& channel_config) override;
	void enable_channel(const config::recording_channel_configuration& channel_config) override;
	void
	disable_channel(const config::recording_channel_configuration& channel_config) override;

	void enable_event(const config::recording_channel_configuration& channel_config,
			  const config::event_rule_configuration& event_rule_config) override;
	void disable_event(const config::recording_channel_configuration& channel_config,
			   const config::event_rule_configuration& event_rule_config) override;

	void add_context(const config::recording_channel_configuration& channel_config,
			 const config::context_configuration& context_config) override;

	void set_tracking_policy(config::process_attribute_type attribute_type,
				 config::tracking_policy policy) override;
	void track_process_attribute(config::process_attribute_type attribute_type,
				     std::uint64_t value) override;
	void untrack_process_attribute(config::process_attribute_type attribute_type,
				       std::uint64_t value) override;

	void start() override;
	void stop() override;

	void rotate() override;
	void clear() override;
	void open_packets() override;

	void record_snapshot(const struct consumer_output& snapshot_consumer,
			     std::uint64_t nb_packets_per_stream) override;

	void regenerate_metadata() override;
	void regenerate_statedump() override;

	/* Unsupported by the LTTng-modules tracer. */
	[[noreturn]] void reclaim_channel_memory(
		const config::recording_channel_configuration& target_channel) override;

private:
	/*
	 * Look up a runtime channel by its configuration object.
	 *
	 * Channels are keyed by the pointer identity of their configuration:
	 * configuration objects are unique within a config::domain and are
	 * not moved or copied, so pointer equality is a reliable key.
	 */
	stream_group& _get_channel(const config::recording_channel_configuration& channel_config)
	{
		const auto it = _channels.find(&channel_config);
		if (it == _channels.end()) {
			LTTNG_THROW_CHANNEL_NOT_FOUND_BY_NAME_ERROR(channel_config.name);
		}

		return *it->second;
	}

	consumer_socket& _get_consumer_socket();

	lttng::file_descriptor _tracer_session_fd;
	config::domain& _domain_configuration;
	struct consumer_output& _consumer;
	std::unordered_map<const config::recording_channel_configuration *,
			   std::unique_ptr<stream_group>>
		_channels;
	nonstd::optional<metadata_channel> _metadata;

	/*
	 * These fields will be removed once the orchestrator fully owns the
	 * kernel domain runtime state.
	 */
	struct ltt_kernel_session *_legacy_kernel_session;
	int _kernel_pipe;
};

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MODULES_DOMAIN_ORCHESTRATOR_HPP */
