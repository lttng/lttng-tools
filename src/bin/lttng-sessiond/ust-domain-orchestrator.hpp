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
#include "ust-application-abi.hpp"
#include "ust-stream-group.hpp"
#include "ust-trace-class.hpp"

#include <cstdint>
#include <memory>
#include <unordered_map>
#include <unordered_set>

struct ltt_session;
struct ltt_ust_session;
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
	explicit domain_orchestrator(
		ltt_ust_session& ust_session,
		const ltt_session& session,
		config::recording_channel_configuration::owership_model_t default_buffer_ownership);

	~domain_orchestrator() override;

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

	void reclaim_channel_memory(
		const config::recording_channel_configuration& target_channel) override;

	recording_channel_runtime_stats get_recording_channel_runtime_stats(
		const config::recording_channel_configuration& channel_config) const override;

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
	 * buffer_reg_channel lookups.
	 *
	 * This is a transitional accessor: it will be eliminated once
	 * the orchestrator owns trace class and buffer registry
	 * creation directly (at which point the handle becomes an
	 * internal detail).
	 */
	std::uint64_t trace_class_stream_class_handle(
		const config::recording_channel_configuration& channel_config) const;

private:
	ltt_ust_session& _ust_session;
	const ltt_session& _session;
	const config::recording_channel_configuration::owership_model_t _default_buffer_ownership;
	bool _active = false;

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
	 * and buffer_reg_channel lookups until the orchestrator owns
	 * those subsystems directly.
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
	 *   - When an app departs, its trace_class and stream_groups
	 *     are destroyed and per-PID closed-app statistics are
	 *     accumulated (TODO).
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

	/* (uid, abi) -> trace_class */
	std::unordered_map<_per_uid_trace_class_key,
			   std::unique_ptr<ust::trace_class>,
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
	std::unordered_map<const ust_app *, std::unique_ptr<ust::trace_class>>
		_per_pid_trace_classes;

	/* (app, recording channel configuration) -> stream group */
	std::unordered_map<_per_pid_stream_group_key,
			   std::unique_ptr<ust::stream_group>,
			   _key_hasher<_per_pid_stream_group_key>>
		_per_pid_stream_groups;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_DOMAIN_ORCHESTRATOR_HPP */
