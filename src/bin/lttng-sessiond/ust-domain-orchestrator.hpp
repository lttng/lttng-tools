/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_DOMAIN_ORCHESTRATOR_HPP
#define LTTNG_SESSIOND_UST_DOMAIN_ORCHESTRATOR_HPP

#include "domain-orchestrator.hpp"
#include "recording-channel-configuration.hpp"

#include <vendor/optional.hpp>

#include <cstdint>

#ifdef HAVE_LIBLTTNG_UST_CTL

#include "ust-application-abi.hpp"
#include "ust-stream-group.hpp"
#include "ust-trace-class.hpp"

#include <functional>
#include <memory>
#include <unordered_map>
#include <unordered_set>

struct agent;
struct ltt_session;
struct ltt_ust_session;
struct lttng_ht;
struct lttng_ust_context_attr;
struct ust_app;

namespace lttng {
namespace sessiond {

namespace config {
class event_rule_configuration;
class context_configuration;
} /* namespace config */

namespace ust {

/*
 * The UST domain orchestrator manages user space tracing runtime resources on
 * behalf of a recording session. It coordinates between UST applications and
 * the consumer daemons to realize the session's user space domain
 * configuration.
 *
 * During the transition period, methods delegate to the existing UST helper
 * functions (channel_ust_create, ust_app_start_trace_all, etc.). These will
 * be progressively internalized in later phases.
 */
class domain_orchestrator final : public sessiond::domain_orchestrator {
public:
	struct consumer_output_deleter {
		void operator()(struct consumer_output *output) const noexcept;
	};

	using consumer_output_uptr =
		std::unique_ptr<struct consumer_output, consumer_output_deleter>;

	explicit domain_orchestrator(
		ltt_ust_session& ust_session,
		const ltt_session& session,
		config::recording_channel_configuration::owership_model_t default_buffer_ownership,
		consumer_output_uptr consumer_output);

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

	const struct ltt_session& recording_session() const noexcept
	{
		return _session;
	}

	/*
	 * Return a non-owning raw pointer to the consumer output. Used
	 * during the transition to set the legacy usess->consumer alias.
	 * This will be removed once all usess->consumer access sites are
	 * migrated to the orchestrator.
	 */
	struct consumer_output *get_consumer_output_ptr() noexcept
	{
		return _consumer_output.get();
	}

	/*
	 * Temporarily replace the consumer output (e.g. during snapshot
	 * recording) and return the previous one. The caller is
	 * responsible for restoring the original consumer output.
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

	/*
	 * Close all per-UID metadata channels on the consumer daemon.
	 *
	 * Must be called during session teardown, before the consumer
	 * sockets become unavailable. For per-PID buffers, metadata is
	 * closed when the application disconnects (in
	 * delete_ust_app_session). For per-UID buffers, the metadata
	 * channels outlive the applications and must be closed
	 * explicitly.
	 */
	void close_per_uid_metadata_on_consumer(struct consumer_output& consumer) const;

	void record_snapshot(const struct consumer_output& snapshot_consumer,
			     std::uint64_t nb_packets_per_stream) override;

	void regenerate_metadata() override;
	void regenerate_statedump() override;

	void reclaim_channel_memory(
		const config::recording_channel_configuration& target_channel) override;

	/*
	 * Create the output subdirectories for UST trace data in the
	 * given trace chunk. For per-UID mode, creates one directory tree
	 * per (uid, abi) combination. For per-PID mode, creates the
	 * toplevel ust/ directory plus one directory tree per registered
	 * application.
	 *
	 * Called during trace chunk rotation for local traces.
	 */
	void create_channel_subdirectories(lttng_trace_chunk& trace_chunk) const;

	recording_channel_runtime_stats get_recording_channel_runtime_stats(
		const config::recording_channel_configuration& channel_config) const override;

	/*
	 * Compute the total size added by one more packet per stream across
	 * all data channels. Channels whose subbuffer count is at most
	 * cur_nr_packets are excluded (all packets already grabbed).
	 *
	 * Used during snapshot sizing to determine how many packets fit
	 * within the snapshot max size.
	 */
	std::uint64_t get_size_one_more_packet_per_stream(std::uint64_t cur_nr_packets) const;

	/*
	 * Descriptor yielded to the for_each_consumer_stream_group() callback.
	 *
	 * Each descriptor represents a single consumer-side channel: either
	 * a data channel (backed by a stream_group) or a metadata channel
	 * (backed by a trace_class).
	 *
	 * `channel_config` refers to the channel_configuration from which
	 * the consumer channel was derived. For data channels, the actual
	 * type is recording_channel_configuration; for metadata channels,
	 * it is metadata_channel_configuration. Use `is_metadata` to
	 * determine the concrete type when a downcast is needed.
	 */
	struct consumer_stream_group_descriptor {
		application_abi abi;
		std::uint64_t consumer_key;
		bool is_metadata;
		ust::trace_class& trace_class;
		const config::channel_configuration& channel_config;
		/* Set in per-UID mode; absent in per-PID mode. */
		nonstd::optional<uid_t> owner_uid;
		/* Set in per-PID mode; absent in per-UID mode. */
		nonstd::optional<pid_t> owner_pid;
	};

	/*
	 * Iterate all consumer stream groups (data + metadata) owned by this
	 * orchestrator and call `visitor` for each one.
	 *
	 * For per-UID mode, iterates the per-UID stream groups (data
	 * channels) and per-UID trace classes (metadata channels).
	 *
	 * For per-PID mode, iterates the per-PID stream groups (data
	 * channels) and per-PID trace classes (metadata channels).
	 *
	 * Metadata channels with a zero key (not yet allocated) are
	 * skipped.
	 *
	 * This method decouples callers (rotate, clear, open_packets,
	 * snapshot, channel memory commands) from ust_app_session
	 * internals.
	 */

	using consumer_stream_group_visitor =
		std::function<void(const consumer_stream_group_descriptor&)>;

	void for_each_consumer_stream_group(const consumer_stream_group_visitor& visitor) const;

	/*
	 * Convert a context_configuration to the lttng_ust_context_attr ABI
	 * structure used to communicate with the UST tracer.
	 *
	 * This is a public static method so that it can be used by code outside
	 * the orchestrator (e.g. ust-app.cpp) during the transition period.
	 * It will become a private helper once per-app context creation is
	 * internalized.
	 */
	static lttng_ust_context_attr
	make_ust_context_attr(const config::context_configuration& context_config);

	/*
	 * Return the trace class stream class handle assigned to a
	 * recording channel configuration. This handle is used by the
	 * per-app sync path as a key for trace_class::add_channel() and
	 * stream class lookups.
	 *
	 * This is a transitional accessor: it will be eliminated once
	 * the orchestrator owns trace class and buffer registry
	 * creation directly (at which point the handle becomes an
	 * internal detail).
	 */
	std::uint64_t trace_class_stream_class_handle(
		const config::recording_channel_configuration& channel_config) const;

	/*
	 * Find or create a per-UID trace class for the given (uid, abi)
	 * combination. The orchestrator owns the returned trace_class
	 * (via unique_ptr in _per_uid_trace_classes). The caller receives
	 * a reference and must NOT delete it.
	 *
	 * This is called from the per-app sync path
	 * (find_or_create_ust_app_session) which supplies app-specific parameters
	 * (ABI, tracer version, shared memory paths). Parameters that
	 * come from the session (trace_format, uid, gid, tracing_id) are
	 * obtained internally from _session and _ust_session.
	 *
	 * If a trace_class already exists for the key, the existing one
	 * is returned and the creation parameters are ignored (the first
	 * app for a given uid/abi pair determines the trace_class).
	 */
	ust::trace_class& find_or_create_per_uid_trace_class(uid_t uid,
							     application_abi abi,
							     const trace::abi& tracer_abi,
							     std::uint32_t tracer_major,
							     std::uint32_t tracer_minor,
							     const char *root_shm_path,
							     const char *shm_path);

	/*
	 * Find or create a per-PID trace class for the given application.
	 * Called from find_or_create_ust_app_session() during per-app
	 * synchronization.
	 */
	ust::trace_class& find_or_create_per_pid_trace_class(ust_app& app,
							     std::uint64_t app_session_id,
							     const trace::abi& tracer_abi,
							     std::uint32_t tracer_major,
							     std::uint32_t tracer_minor,
							     const char *root_shm_path,
							     const char *shm_path,
							     uid_t euid,
							     gid_t egid);

	/*
	 * Release the per-PID trace class associated with the given
	 * application. The trace_class is destroyed, which cleans up
	 * shared memory files. Called from ust_app_unregister()
	 * when a per-PID application departs.
	 *
	 * No-op if no trace class exists for the given app (e.g. the
	 * app session was being set up and failed before the trace
	 * class was created).
	 */
	void release_per_pid_trace_class(const ust_app& app);

	/*
	 * Release all per-PID stream groups associated with the given
	 * application. Called from delete_ust_app_session() when a
	 * per-PID application departs, alongside
	 * release_per_pid_trace_class().
	 *
	 * No-op if no stream groups exist for the given app.
	 */
	void release_per_pid_stream_groups(const ust_app& app);

	/*
	 * Find or create a per-UID stream group for the given
	 * (channel_config, uid, abi) combination. The orchestrator owns
	 * the returned stream_group (via unique_ptr in
	 * _per_uid_stream_groups). The caller receives a reference and
	 * must NOT delete it.
	 *
	 * Called from create_channel_per_uid() after the buffer registry
	 * channel has been set up. The channel_object is the "master"
	 * channel handle obtained from the consumer daemon; it is owned
	 * by the stream_group from this point on and will be duplicated
	 * for each subsequent application that shares the same UID/ABI.
	 *
	 * If a stream_group already exists for the key, the existing one
	 * is returned (this happens when multiple apps share the same
	 * UID/ABI in per-UID mode -- only the first app creates the
	 * stream group).
	 */
	ust::stream_group& find_or_create_per_uid_stream_group(
		const config::recording_channel_configuration& channel_config,
		uid_t uid,
		application_abi abi,
		std::uint64_t consumer_key,
		ust_object_data channel_object,
		ust::trace_class& trace_class,
		ust::stream_class& stream_class);

	/*
	 * Look up an existing per-UID stream group for the given
	 * (channel_config, uid, abi) combination.
	 *
	 * Returns a reference to the stream group. Throws
	 * std::out_of_range if no stream group exists for the key
	 * (which indicates a code flow error -- the caller should
	 * guarantee a stream group was previously created).
	 */
	ust::stream_group&
	get_per_uid_stream_group(const config::recording_channel_configuration& channel_config,
				 uid_t uid,
				 application_abi abi);

	/*
	 * Check whether a per-UID stream group already exists for the
	 * given (channel_config, uid, abi) combination.
	 */
	bool has_per_uid_stream_group(const config::recording_channel_configuration& channel_config,
				      uid_t uid,
				      application_abi abi) const;

	/*
	 * Find or create a per-PID stream group for the given
	 * (channel_config, app) combination. The orchestrator owns
	 * the returned stream_group (via unique_ptr in
	 * _per_pid_stream_groups). The caller receives a reference and
	 * must NOT delete it.
	 *
	 * Called from create_channel_per_pid() after the consumer
	 * channel has been created. In per-PID mode, the channel and
	 * stream objects are sent directly to the application and
	 * consumed; the stream_group does not hold master object
	 * handles for duplication (unlike per-UID).
	 *
	 * Unlike per-UID, each app always gets its own stream group
	 * (no sharing).
	 */
	ust::stream_group& find_or_create_per_pid_stream_group(
		const config::recording_channel_configuration& channel_config,
		const ust_app& app,
		std::uint64_t consumer_key,
		ust_object_data channel_object,
		ust::trace_class& trace_class,
		ust::stream_class& stream_class);

	/*
	 * Accumulate per-PID closed-app discarded events and lost packets
	 * for a channel. Called when a per-PID application's channel is
	 * torn down; the counters are saved so they can be included in
	 * the runtime statistics reported by get_recording_channel_runtime_stats().
	 */
	void accumulate_per_pid_closed_app_stats(
		const config::recording_channel_configuration& channel_config,
		std::uint64_t discarded_events,
		std::uint64_t lost_packets);

	static struct lttng_ust_abi_channel_attr default_metadata_channel_attr() noexcept;

	/*
	 * Find the agent for a given domain type (JUL, Log4j2, Python).
	 * Returns nullptr if no agent exists for the domain.
	 */
	struct agent *find_agent(enum lttng_domain_type domain_type) const noexcept;

	/*
	 * Find or create the agent for a given domain type. Throws on
	 * allocation failure.
	 */
	struct agent& find_or_create_agent(enum lttng_domain_type domain_type);

	/* Underlying hash table for agent iteration. */
	struct lttng_ht& agents_ht() const noexcept
	{
		return *_agents;
	}

	const std::string& root_shm_path() const noexcept
	{
		return _root_shm_path;
	}

	const std::string& shm_path() const noexcept
	{
		return _shm_path;
	}

	bool supports_madv_remove() const noexcept;

private:
	ltt_ust_session& _ust_session;
	const ltt_session& _session;
	const config::recording_channel_configuration::owership_model_t _default_buffer_ownership;
	consumer_output_uptr _consumer_output;
	bool _active = false;
	nonstd::optional<lttng_buffer_type> _locked_buffer_type;
	struct lttng_ht *_agents;
	const std::string _root_shm_path;
	const std::string _shm_path;

	/*
	 * Tracks which event rule configurations have had their per-app
	 * events created (via ust_app_create_event_glb). Used to
	 * distinguish the initial creation from a re-enable. This will
	 * be superseded by more structured per-app state when channel
	 * and event management are fully internalized.
	 */
	std::unordered_set<const config::event_rule_configuration *> _created_event_rules;

	/*
	 * Monotonically increasing counter used to assign a unique
	 * trace class stream class handle to each recording channel.
	 * This handle serves as the key for trace_class::add_channel()
	 * and stream class lookups.
	 */
	std::uint64_t _next_trace_class_stream_class_handle = 0;

	/*
	 * Maps each recording channel configuration to the trace class
	 * stream class handle assigned at channel creation time.
	 */
	std::unordered_map<const config::recording_channel_configuration *, std::uint64_t>
		_channel_handles;

	static void
	_validate_channel_attributes(const config::recording_channel_configuration& channel_config);

	void _record_snapshot_per_uid(const struct consumer_output& snapshot_consumer,
				      std::uint64_t nb_packets_per_stream) const;
	void _record_snapshot_per_pid(const struct consumer_output& snapshot_consumer,
				      std::uint64_t nb_packets_per_stream) const;

	/*
	 * Trace class and stream group ownership.
	 *
	 * Two sets of maps exist: one for per-UID mode, one for per-PID.
	 * Only one set is populated, depending on
	 * _default_buffer_ownership.
	 *
	 * Per-UID mode:
	 *   - One trace_class per (uid, abi). Multiple apps with the
	 *     same UID and ABI share a single trace_class.
	 *   - One stream_group per (channel_config, uid, abi). Shared
	 *     ring buffers: the first app creates them, subsequent apps
	 *     receive duplicated object handles.
	 *
	 * Per-PID mode:
	 *   - One trace_class per app. Each app has its own metadata.
	 *   - One stream_group per (channel_config, app). Private ring
	 *     buffers per app.
	 *   - When an app departs, its trace_class is destroyed via
	 *     release_per_pid_trace_class() and its stream groups are
	 *     destroyed via release_per_pid_stream_groups() (both
	 *     called from delete_ust_app_session).
	 */

	static std::size_t _hash_combine(std::size_t seed, std::size_t value) noexcept
	{
		/*
		 * Golden-ratio hash combining (boost::hash_combine inspired). Use
		 * the 64-bit constant when size_t is 8 bytes wide.
		 */
		constexpr auto golden_ratio = sizeof(std::size_t) == 8 ?
			std::size_t(0x9e3779b97f4a7c15) :
			std::size_t(0x9e3779b9);
		return seed ^ (value + golden_ratio + (seed << 6) + (seed >> 2));
	}

	template <typename KeyType>
	struct _key_hasher {
		std::size_t operator()(const KeyType& key) const noexcept
		{
			return key.hash();
		}
	};

	struct _per_uid_trace_class_key {
		uid_t uid;
		application_abi abi;

		bool operator==(const _per_uid_trace_class_key& other) const noexcept;
		std::size_t hash() const noexcept;
	};

	struct _per_uid_stream_group_key {
		const config::recording_channel_configuration *channel_config;
		uid_t uid;
		application_abi abi;

		bool operator==(const _per_uid_stream_group_key& other) const noexcept;
		std::size_t hash() const noexcept;
	};

	struct _per_pid_stream_group_key {
		const config::recording_channel_configuration *channel_config;
		const ust_app *app;

		bool operator==(const _per_pid_stream_group_key& other) const noexcept;
		std::size_t hash() const noexcept;
	};

	/*
	 * Per-PID closed-app statistics. When an application exits in
	 * per-PID buffer mode, its discarded events and lost packets
	 * are accumulated here, keyed by recording channel configuration.
	 * These counters are added to the live-app stats when reporting
	 * runtime statistics.
	 */
	struct _per_pid_closed_app_counters {
		std::uint64_t discarded_events = 0;
		std::uint64_t lost_packets = 0;
	};

	std::unordered_map<const config::recording_channel_configuration *,
			   _per_pid_closed_app_counters>
		_per_pid_closed_app_stats;

	/* (uid, abi) -> trace_class */
	std::unordered_map<_per_uid_trace_class_key,
			   std::shared_ptr<ust::trace_class>,
			   _key_hasher<_per_uid_trace_class_key>>
		_per_uid_trace_classes;

	/* (uid, abi, recording channel configuration) -> stream group */
	std::unordered_map<_per_uid_stream_group_key,
			   std::unique_ptr<ust::stream_group>,
			   _key_hasher<_per_uid_stream_group_key>>
		_per_uid_stream_groups;

	/*
	 * Per-PID trace classes are keyed by app pointer. Each app gets
	 * its own trace_class.
	 */
	std::unordered_map<const ust_app *, std::shared_ptr<ust::trace_class>>
		_per_pid_trace_classes;

	/*
	 * Maps app pointers to the ust_app_session::app_session_id used
	 * as the trace_class_index key for per-PID trace classes. Needed
	 * so that release_per_pid_trace_class() can unregister from the
	 * index without the caller providing the app_session_id.
	 */
	std::unordered_map<const ust_app *, std::uint64_t> _per_pid_app_session_ids;

	/* (app, recording channel configuration) -> stream group */
	std::unordered_map<_per_pid_stream_group_key,
			   std::unique_ptr<ust::stream_group>,
			   _key_hasher<_per_pid_stream_group_key>>
		_per_pid_stream_groups;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#else /* !HAVE_LIBLTTNG_UST_CTL */

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * Stub definition for builds without lttng-ust. The class is never
 * instantiated; it exists only so that code which static_casts a
 * domain_orchestrator reference and calls its methods can compile and
 * link. The methods abort since reaching them would indicate a logic
 * error.
 */
class domain_orchestrator final : public sessiond::domain_orchestrator {
public:
	struct consumer_output_deleter {
		void operator()(struct consumer_output *) const noexcept
		{
			std::abort();
		}
	};

	using consumer_output_uptr =
		std::unique_ptr<struct consumer_output, consumer_output_deleter>;

	struct consumer_output& get_consumer_output() noexcept
	{
		std::abort();
	}

	const struct consumer_output& consumer() const noexcept
	{
		std::abort();
	}

	struct consumer_output *get_consumer_output_ptr() noexcept
	{
		std::abort();
	}

	consumer_output_uptr
	exchange_consumer_output(consumer_output_uptr /* new_output */) noexcept
	{
		std::abort();
	}

	std::uint64_t trace_class_stream_class_handle(
		const config::recording_channel_configuration& channel_config
		[[maybe_unused]]) const
	{
		std::abort();
	}

	void create_channel_subdirectories(struct lttng_trace_chunk& trace_chunk
					   [[maybe_unused]]) const
	{
		std::abort();
	}

	std::uint64_t get_size_one_more_packet_per_stream(std::uint64_t cur_nr_packets
							  [[maybe_unused]]) const
	{
		std::abort();
	}

	void close_per_uid_metadata_on_consumer(struct consumer_output& consumer
						[[maybe_unused]]) const
	{
		std::abort();
	}

	void record_snapshot(const struct consumer_output& /* snapshot_consumer */,
			     std::uint64_t /* nb_packets_per_stream */) override
	{
		std::abort();
	}

	const std::string& shm_path() const noexcept
	{
		std::abort();
	}

	bool supports_madv_remove() const noexcept
	{
		std::abort();
	}

	const struct ltt_session& recording_session() const noexcept
	{
		std::abort();
	}

	static struct lttng_ust_abi_channel_attr default_metadata_channel_attr() noexcept
	{
		std::abort();
	}

	const std::string& root_shm_path() const noexcept
	{
		std::abort();
	}

	struct agent *find_agent(enum lttng_domain_type /* domain_type */) const noexcept
	{
		std::abort();
	}

	struct agent& find_or_create_agent(enum lttng_domain_type /* domain_type */)
	{
		std::abort();
	}

	struct lttng_ht& agents_ht() const noexcept
	{
		std::abort();
	}
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_UST_DOMAIN_ORCHESTRATOR_HPP */
