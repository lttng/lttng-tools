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

#include <cstdint>

struct ltt_session;
struct ltt_ust_session;

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

private:
	ltt_ust_session& _ust_session;
	const ltt_session& _session;
	const config::recording_channel_configuration::owership_model_t _default_buffer_ownership;
	bool _active = false;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_DOMAIN_ORCHESTRATOR_HPP */
