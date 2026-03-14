/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "channel.hpp"
#include "event-rule-configuration.hpp"
#include "event.hpp"
#include "lttng-channel-from-config.hpp"
#include "recording-channel-configuration.hpp"
#include "session.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"
#include "ust-domain-orchestrator.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/macros.hpp>

#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/user-tracepoint.h>

namespace ls = lttng::sessiond;
namespace lsc = lttng::sessiond::config;

ls::ust::domain_orchestrator::domain_orchestrator(
	ltt_ust_session& ust_session,
	const ltt_session& session,
	lsc::recording_channel_configuration::owership_model_t default_buffer_ownership) :
	_ust_session(ust_session),
	_session(session),
	_default_buffer_ownership(default_buffer_ownership)
{
}

ls::ust::domain_orchestrator::~domain_orchestrator() = default;

void ls::ust::domain_orchestrator::create_channel(
	const config::recording_channel_configuration& channel_config)
{
	const auto lttng_channel = ls::make_lttng_channel(channel_config);
	const auto buffer_type = _default_buffer_ownership ==
			lsc::recording_channel_configuration::owership_model_t::PER_PID ?
		LTTNG_BUFFER_PER_PID :
		LTTNG_BUFFER_PER_UID;

	const auto ret = channel_ust_create(&_ust_session, lttng_channel.get(), buffer_type);
	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to create UST channel", ret);
	}
}

void ls::ust::domain_orchestrator::enable_channel(
	const config::recording_channel_configuration& channel_config)
{
	auto *const uchan = trace_ust_find_channel_by_name(_ust_session.domain_global.channels,
							   channel_config.name.c_str());
	if (!uchan) {
		LTTNG_THROW_CTL("UST channel not found", LTTNG_ERR_UST_CHAN_NOT_FOUND);
	}

	const auto ret = channel_ust_enable(&_ust_session, uchan);
	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to enable UST channel", ret);
	}
}

void ls::ust::domain_orchestrator::disable_channel(
	const config::recording_channel_configuration& channel_config)
{
	auto *const uchan = trace_ust_find_channel_by_name(_ust_session.domain_global.channels,
							   channel_config.name.c_str());
	if (!uchan) {
		LTTNG_THROW_CTL("UST channel not found", LTTNG_ERR_UST_CHAN_NOT_FOUND);
	}

	const auto ret = channel_ust_disable(&_ust_session, uchan);
	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to disable UST channel",
				static_cast<lttng_error_code>(ret));
	}
}

void ls::ust::domain_orchestrator::disable_event(
	const config::recording_channel_configuration& channel_config,
	const config::event_rule_configuration& event_rule_config)
{
	auto *const uchan = trace_ust_find_channel_by_name(_ust_session.domain_global.channels,
							   channel_config.name.c_str());
	if (!uchan) {
		LTTNG_THROW_CTL("UST channel not found", LTTNG_ERR_UST_CHAN_NOT_FOUND);
	}

	const auto *rule = event_rule_config.event_rule.get();
	LTTNG_ASSERT(lttng_event_rule_get_type(rule) == LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT);

	const char *pattern_or_name;
	const auto status =
		lttng_event_rule_user_tracepoint_get_name_pattern(rule, &pattern_or_name);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		LTTNG_THROW_CTL("Failed to get event rule name pattern", LTTNG_ERR_INVALID);
	}

	const auto ret = event_ust_disable_tracepoint(&_ust_session, uchan, pattern_or_name);
	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to disable UST event", static_cast<lttng_error_code>(ret));
	}
}

/*
 * Suppress noreturn warnings for the stub methods below. These are skeleton
 * implementations that will be filled in as the UST domain orchestrator is
 * fleshed out.
 */
DIAGNOSTIC_PUSH
DIAGNOSTIC_IGNORE_MISSING_NORETURN

void ls::ust::domain_orchestrator::enable_event(const config::recording_channel_configuration&,
						const config::event_rule_configuration&)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Enabling an event is not supported in the UST domain orchestrator");
}

void ls::ust::domain_orchestrator::add_context(const config::recording_channel_configuration&,
					       const config::context_configuration&)
{
	LTTNG_THROW_UNSUPPORTED_ERROR(
		"Adding context is not supported in the UST domain orchestrator");
}

DIAGNOSTIC_POP; /* DIAGNOSTIC_IGNORE_MISSING_NORETURN */

void ls::ust::domain_orchestrator::set_tracking_policy(config::process_attribute_type,
						       config::tracking_policy)
{
	/*
	 * The config has already been updated by the command layer. Push the
	 * updated configuration to all running applications if tracing is active.
	 */
	if (_active) {
		ust_app_global_update_all(&_ust_session, _session.user_space_domain);
	}
}

void ls::ust::domain_orchestrator::track_process_attribute(config::process_attribute_type,
							   std::uint64_t)
{
	if (_active) {
		ust_app_global_update_all(&_ust_session, _session.user_space_domain);
	}
}

void ls::ust::domain_orchestrator::untrack_process_attribute(config::process_attribute_type,
							     std::uint64_t)
{
	if (_active) {
		ust_app_global_update_all(&_ust_session, _session.user_space_domain);
	}
}

void ls::ust::domain_orchestrator::start()
{
	if (_active) {
		return;
	}

	const auto ret = ust_app_start_trace_all(&_ust_session, _session.user_space_domain);
	if (ret < 0) {
		LTTNG_THROW_CTL("Failed to start UST tracing", LTTNG_ERR_UST_START_FAIL);
	}

	_active = true;
}

void ls::ust::domain_orchestrator::stop()
{
	if (!_active) {
		return;
	}

	const auto ret = ust_app_stop_trace_all(&_ust_session);
	if (ret < 0) {
		LTTNG_THROW_CTL("Failed to stop UST tracing", LTTNG_ERR_UST_STOP_FAIL);
	}

	_active = false;
}

void ls::ust::domain_orchestrator::rotate()
{
	const auto ret = ust_app_rotate_session(_session);
	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to rotate UST session", ret);
	}
}

void ls::ust::domain_orchestrator::clear()
{
	const auto ret = ust_app_clear_session(_session);
	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to clear UST session", ret);
	}
}

void ls::ust::domain_orchestrator::open_packets()
{
	const auto ret = ust_app_open_packets(_session);
	if (ret != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to open UST packets", ret);
	}
}

void ls::ust::domain_orchestrator::record_snapshot(const struct consumer_output& snapshot_consumer,
						   std::uint64_t nb_packets_per_stream)
{
	const auto ret =
		ust_app_snapshot_record(&_ust_session, &snapshot_consumer, nb_packets_per_stream);
	if (ret != LTTNG_OK) {
		LTTNG_THROW_SNAPSHOT_FAILURE("Failed to record UST snapshot");
	}
}

void ls::ust::domain_orchestrator::regenerate_metadata()
{
	trace_ust_regenerate_metadata(&_ust_session);
}

void ls::ust::domain_orchestrator::regenerate_statedump()
{
	const auto ret = ust_app_regenerate_statedump_all(&_ust_session);
	if (ret < 0) {
		LTTNG_THROW_REGENERATE_STATEDUMP_FAILURE("Failed to regenerate UST statedump");
	}
}

DIAGNOSTIC_PUSH
DIAGNOSTIC_IGNORE_MISSING_NORETURN

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

DIAGNOSTIC_POP; /* DIAGNOSTIC_IGNORE_MISSING_NORETURN */
