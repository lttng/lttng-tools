/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MODULES_DOMAIN_ORCHESTRATOR_HPP
#define LTTNG_SESSIOND_MODULES_DOMAIN_ORCHESTRATOR_HPP

#include "consumer.hpp"
#include "context-configuration.hpp"
#include "domain-orchestrator.hpp"
#include "domain.hpp"
#include "event-rule-configuration.hpp"
#include "hotplug-handler.hpp"
#include "recording-channel-configuration.hpp"
#include "stream-group.hpp"

#include <common/file-descriptor.hpp>
#include <common/make-unique.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

struct consumer_output;
struct consumer_socket;
struct ltt_session;

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

/*
 * @class kernel_consumer_send_failure
 * @brief Thrown when the session daemon fails to send kernel session objects (stream groups and
 * streams) to the consumer daemon.
 */
class kernel_consumer_send_failure : public lttng::runtime_error {
public:
	explicit kernel_consumer_send_failure(const std::string& msg,
					      const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class kernel_start_failure
 * @brief Thrown when the kernel tracer fails to start tracing.
 */
class kernel_start_failure : public lttng::runtime_error {
public:
	explicit kernel_start_failure(const std::string& msg,
				      const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class kernel_stop_failure
 * @brief Thrown when the kernel tracer fails to stop tracing.
 */
class kernel_stop_failure : public lttng::runtime_error {
public:
	explicit kernel_stop_failure(const std::string& msg,
				     const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class kernel_metadata_creation_error
 * @brief Thrown when the kernel tracer fails to create a metadata stream.
 */
class kernel_metadata_creation_error : public lttng::runtime_error {
public:
	explicit kernel_metadata_creation_error(const std::string& msg,
						const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
	{
	}
};

/*
 * @class kernel_stream_creation_error
 * @brief Thrown when the kernel tracer fails to create a stream.
 */
class kernel_stream_creation_error : public lttng::runtime_error {
public:
	explicit kernel_stream_creation_error(const std::string& msg,
					      const lttng::source_location& source_location_) :
		lttng::runtime_error(msg, source_location_)
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
#define LTTNG_THROW_KERNEL_CONSUMER_SEND_FAILURE(msg)                             \
	throw lttng::sessiond::modules::exceptions::kernel_consumer_send_failure( \
		msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_KERNEL_START_FAILURE(msg)                                 \
	throw lttng::sessiond::modules::exceptions::kernel_start_failure(msg, \
									 LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_KERNEL_STOP_FAILURE(msg)                                 \
	throw lttng::sessiond::modules::exceptions::kernel_stop_failure(msg, \
									LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_KERNEL_METADATA_CREATION_ERROR(msg)                             \
	throw lttng::sessiond::modules::exceptions::kernel_metadata_creation_error( \
		msg, LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_KERNEL_STREAM_CREATION_ERROR(msg)                             \
	throw lttng::sessiond::modules::exceptions::kernel_stream_creation_error( \
		msg, LTTNG_SOURCE_LOCATION())

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
 * Runtime representation of a kernel stream group managed by the LTTng-modules
 * tracer.
 *
 * Extends the base stream_group (which manages the consumer key and stream
 * instances) with kernel-domain-specific state: the tracer channel fd,
 * the channel configuration reference, consumer/notification lifecycle
 * flags, and event rules.
 */
class stream_group final : public lttng::sessiond::stream_group<lttng::file_descriptor> {
public:
	/*
	 * Kernel-specific stream that extends the base stream with a
	 * sent_to_consumer flag. This flag tracks whether each individual
	 * stream (ring buffer instance) has been sent to the consumer daemon.
	 *
	 * Only the kernel domain needs per-stream sent_to_consumer tracking
	 * because the kernel orchestrator sends streams to the consumer
	 * individually as they are opened.
	 */
	struct kernel_stream final
		: public lttng::sessiond::stream_group<lttng::file_descriptor>::stream {
		kernel_stream(unsigned int cpu_index, lttng::file_descriptor handle_) :
			stream(cpu_index, std::move(handle_))
		{
		}

		~kernel_stream() override = default;

		kernel_stream(kernel_stream&&) = default;
		kernel_stream& operator=(kernel_stream&&) = delete;
		kernel_stream(const kernel_stream&) = delete;
		kernel_stream& operator=(const kernel_stream&) = delete;

		bool sent_to_consumer = false;
	};

	explicit stream_group(lttng::file_descriptor tracer_channel_fd,
			      uint64_t consumer_key,
			      const config::recording_channel_configuration& configuration) :
		lttng::sessiond::stream_group<lttng::file_descriptor>(consumer_key),
		_tracer_stream_group_fd(std::move(tracer_channel_fd)),
		_configuration(configuration)
	{
	}

	~stream_group() override = default;

	stream_group(stream_group&&) = delete;
	stream_group(const stream_group&) = delete;
	stream_group& operator=(stream_group&&) = delete;
	stream_group& operator=(const stream_group&) = delete;

	/* Override to insert kernel_stream instances. */
	void add_stream(unsigned int cpu, lttng::file_descriptor handle) override
	{
		_add_stream(lttng::make_unique<kernel_stream>(cpu, std::move(handle)));
	}

	lttng::file_descriptor& tracer_handle() noexcept
	{
		return _tracer_stream_group_fd;
	}

	const lttng::file_descriptor& tracer_handle() const noexcept
	{
		return _tracer_stream_group_fd;
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

	bool is_monitored_for_hotplug() const noexcept
	{
		return _monitored_for_hotplug;
	}

	void mark_monitored_for_hotplug() noexcept
	{
		_monitored_for_hotplug = true;
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
	lttng::file_descriptor _tracer_stream_group_fd;
	const config::recording_channel_configuration& _configuration;
	bool _sent_to_consumer = false;
	bool _published_to_notification_thread = false;
	bool _monitored_for_hotplug = false;
	std::vector<event_rule> _event_rules;
};

/*
 * Runtime representation of the metadata stream group for a kernel tracing session
 * managed by the lttng-modules tracer.
 *
 * Extends stream_group to reuse consumer key tracking and stream management.
 * Metadata always has exactly one stream (cpu 0) which is opened separately
 * from the metadata stream group itself (kernctl_open_metadata vs.
 * kernctl_create_stream on the metadata fd).
 */
class metadata_stream_group final : public lttng::sessiond::stream_group<lttng::file_descriptor> {
public:
	explicit metadata_stream_group(lttng::file_descriptor tracer_metadata_fd,
				       uint64_t consumer_key,
				       const config::metadata_channel_configuration& configuration) :
		lttng::sessiond::stream_group<lttng::file_descriptor>(consumer_key),
		_tracer_metadata_stream_group_fd(std::move(tracer_metadata_fd)),
		_configuration(configuration)
	{
	}

	~metadata_stream_group() override = default;

	metadata_stream_group(metadata_stream_group&&) = delete;
	metadata_stream_group(const metadata_stream_group&) = delete;
	metadata_stream_group& operator=(metadata_stream_group&&) = delete;
	metadata_stream_group& operator=(const metadata_stream_group&) = delete;

	lttng::file_descriptor& tracer_handle() noexcept
	{
		return _tracer_metadata_stream_group_fd;
	}

	const lttng::file_descriptor& tracer_handle() const noexcept
	{
		return _tracer_metadata_stream_group_fd;
	}

	const config::metadata_channel_configuration& configuration() const noexcept
	{
		return _configuration;
	}

	bool is_sent_to_consumer() const noexcept
	{
		return _sent_to_consumer;
	}

	void mark_sent_to_consumer() noexcept
	{
		_sent_to_consumer = true;
	}

private:
	lttng::file_descriptor _tracer_metadata_stream_group_fd;
	const config::metadata_channel_configuration& _configuration;
	bool _sent_to_consumer = false;
};

/*
 * Concrete domain orchestrator for the lttng-modules kernel tracer.
 *
 * Manages the runtime tracing resources (session fd, stream groups, streams,
 * metadata, and consumer connections) for the kernel domain within a
 * recording session.
 *
 * The orchestrator reads configuration exclusively from the config::domain
 * owned by the ltt_session. It does not copy configuration fields; the
 * config objects are the single source of truth.
 *
 * The ltt_session referenced by the orchestrator always outlives it: the
 * orchestrator is owned (via unique_ptr) by the ltt_session itself, so
 * the session is guaranteed to be valid for the entire lifetime of the
 * orchestrator.
 */
class domain_orchestrator final : public sessiond::domain_orchestrator {
public:
	using hotplug_command = lttng::sessiond::hotplug_handler::command;

	struct consumer_output_deleter {
		void operator()(struct consumer_output *output) const noexcept
		{
			consumer_output_put(output);
		}
	};

	using consumer_output_uptr =
		std::unique_ptr<struct consumer_output, consumer_output_deleter>;

	explicit domain_orchestrator(const struct ltt_session& session,
				     consumer_output_uptr consumer_output,
				     hotplug_handler::session_id_t session_id,
				     lttng::command_queue<hotplug_command>& hotplug_queue);

	~domain_orchestrator() override;

	domain_orchestrator(const domain_orchestrator&) = delete;
	domain_orchestrator(domain_orchestrator&&) = delete;
	domain_orchestrator& operator=(const domain_orchestrator&) = delete;
	domain_orchestrator& operator=(domain_orchestrator&&) = delete;

	struct consumer_output& get_consumer_output() noexcept
	{
		return *_consumer_output;
	}

	const struct consumer_output& consumer() const noexcept
	{
		return *_consumer_output;
	}

	/*
	 * Replace the consumer output with `new_output` and return the
	 * previously-held consumer output.
	 *
	 * Used by snapshot_record to temporarily install the snapshot
	 * consumer so that session_set_trace_chunk propagates the trace
	 * chunk with the correct relayd configuration.
	 */
	consumer_output_uptr exchange_consumer_output(consumer_output_uptr new_output) noexcept
	{
		std::swap(_consumer_output, new_output);
		return new_output;
	}

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

	recording_channel_runtime_stats get_recording_channel_runtime_stats(
		const config::recording_channel_configuration& channel_config) const override;

	/*
	 * Return the number of streams opened for a channel.
	 *
	 * The stream count reflects the number of per-CPU ring buffers that
	 * have been opened by start(). Returns 0 if the session has not
	 * been started yet.
	 */
	unsigned int get_stream_count_for_channel(
		const config::recording_channel_configuration& channel_config) const;

	/*
	 * Handle a CPU hotplug event on the given channel.
	 *
	 * Opens newly-available streams via kernctl_create_stream() and,
	 * if tracing is active and consumer fds have already been sent,
	 * sends the new streams to the consumer daemon.
	 */
	void handle_stream_group_hotplug(stream_group& channel);

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
		const auto it = _stream_groups.find(&channel_config);
		if (it == _stream_groups.end()) {
			LTTNG_THROW_CHANNEL_NOT_FOUND_BY_NAME_ERROR(channel_config.name);
		}

		return *it->second;
	}

	consumer_socket& _get_consumer_socket();

	/*
	 * Open the ring buffer streams for a channel via kernctl_create_stream()
	 * and register them in the stream_group.
	 *
	 * Returns the number of streams created.
	 */
	unsigned int _open_streams(stream_group& channel);

	/*
	 * Flush all ring buffer streams of a channel.
	 */
	void _flush_stream_group_streams(const stream_group& channel) const;

	/*
	 * Send all session data (metadata, stream groups, streams) to the consumer daemon.
	 *
	 * The consumer socket lock must be held by the caller.
	 */
	void _send_stream_groups_to_consumer(consumer_socket& socket);

	/*
	 * Send a single stream group and its streams to the consumer daemon.
	 * Registers the stream group with the notification thread.
	 *
	 * The consumer socket lock must be held by the caller.
	 */
	void _send_stream_group_to_consumer(consumer_socket& socket,
					    stream_group& channel,
					    bool monitor);

	/*
	 * Send the metadata stream group and its stream to the consumer daemon.
	 *
	 * The consumer socket lock must be held by the caller.
	 */
	void _send_metadata_to_consumer(consumer_socket& socket,
					const consumer_output& snapshot_consumer,
					bool monitor);

	/*
	 * Open the metadata channel from the kernel tracer and create the
	 * metadata_stream_group. Populates _metadata.
	 */
	void _open_metadata();

	/*
	 * Open the metadata stream on the metadata channel and register it
	 * in the metadata_stream_group.
	 */
	void _open_metadata_stream();

	/*
	 * Notify the consumer daemon to destroy the stream group (channel or
	 * metadata) identified by the given consumer key.
	 */
	void _destroy_consumer_stream_group(consumer_socket& socket, uint64_t consumer_key);

	lttng::file_descriptor _tracer_session_fd;
	const struct ltt_session& _session;
	consumer_output_uptr _consumer_output;
	hotplug_handler::session_id_t _session_id;
	lttng::command_queue<hotplug_command>& _hotplug_queue;
	std::unordered_map<const config::recording_channel_configuration *,
			   std::unique_ptr<stream_group>>
		_stream_groups;
	std::unique_ptr<metadata_stream_group> _metadata_stream_group;
	bool _active = false;
};

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MODULES_DOMAIN_ORCHESTRATOR_HPP */
