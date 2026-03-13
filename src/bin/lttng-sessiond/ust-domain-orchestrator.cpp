/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-domain-orchestrator.hpp"

#include <common/macros.hpp>

namespace ls = lttng::sessiond;

ls::ust::domain_orchestrator::domain_orchestrator(ltt_ust_session& ust_session,
						  const ltt_session& session) :
	_ust_session(ust_session), _session(session)
{
}

ls::ust::domain_orchestrator::~domain_orchestrator() = default;

/*
 * Suppress noreturn warnings for the stub methods below. These are skeleton
 * implementations that will be filled in as the UST domain orchestrator is
 * fleshed out.
 */
DIAGNOSTIC_PUSH
DIAGNOSTIC_IGNORE_MISSING_NORETURN

void ls::ust::domain_orchestrator::create_channel(const config::recording_channel_configuration&)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Creating a channel is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::enable_channel(const config::recording_channel_configuration&)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Enabling a channel is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::disable_channel(const config::recording_channel_configuration&)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Disabling a channel is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::enable_event(const config::recording_channel_configuration&,
						const config::event_rule_configuration&)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Enabling an event is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::disable_event(const config::recording_channel_configuration&,
						 const config::event_rule_configuration&)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Disabling an event is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::add_context(const config::recording_channel_configuration&,
					       const config::context_configuration&)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Adding context is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::set_tracking_policy(config::process_attribute_type,
						       config::tracking_policy)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Setting tracking policy is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::track_process_attribute(config::process_attribute_type,
							   std::uint64_t)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Tracking process attribute is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::untrack_process_attribute(config::process_attribute_type,
							     std::uint64_t)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Untracking process attribute is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::start()
{
	LTTNG_THROW_UNSUPPORTED_ERROR("Starting the UST domain orchestrator is not supported");
}

void ls::ust::domain_orchestrator::stop()
{
	LTTNG_THROW_UNSUPPORTED_ERROR("Stopping the UST domain orchestrator is not supported");
}

void ls::ust::domain_orchestrator::rotate()
{
	LTTNG_THROW_UNSUPPORTED_ERROR("Rotating the UST domain orchestrator is not supported");
}

void ls::ust::domain_orchestrator::clear()
{
	LTTNG_THROW_UNSUPPORTED_ERROR("Clearing the UST domain orchestrator is not supported");
}

void ls::ust::domain_orchestrator::open_packets()
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Opening packets is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::record_snapshot(const struct consumer_output&, std::uint64_t)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Recording a snapshot is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::regenerate_metadata()
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Regenerating metadata is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::regenerate_statedump()
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Regenerating statedump is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::reclaim_channel_memory(
	const config::recording_channel_configuration&)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Reclaiming channel memory is not supported in the UST domain orchestrator");
}

ls::recording_channel_runtime_stats
ls::ust::domain_orchestrator::get_recording_channel_runtime_stats(
	const config::recording_channel_configuration&) const
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Getting recording channel runtime stats is not supported in the UST domain orchestrator");
}

DIAGNOSTIC_POP /* DIAGNOSTIC_IGNORE_MISSING_NORETURN */
