/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "context-configuration.hpp"
#include "event-rule-configuration.hpp"
#include "lttng-channel-from-config.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-ust-error.hpp"
#include "recording-channel-configuration.hpp"
#include "session.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"
#include "ust-domain-orchestrator.hpp"

#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/macros.hpp>
#include <common/scope-exit.hpp>
#include <common/urcu.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/user-tracepoint.h>

#include <cstring>
#include <functional>

namespace ls = lttng::sessiond;
namespace lsc = lttng::sessiond::config;

lttng_ust_context_attr ls::ust::domain_orchestrator::make_ust_context_attr(
	const lsc::context_configuration& context_config)
{
	struct lttng_ust_context_attr ust_ctx = {};

	switch (context_config.context_type) {
	case lsc::context_configuration::type::VTID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_VTID;
		break;
	case lsc::context_configuration::type::VPID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_VPID;
		break;
	case lsc::context_configuration::type::PTHREAD_ID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_PTHREAD_ID;
		break;
	case lsc::context_configuration::type::PROCNAME:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_PROCNAME;
		break;
	case lsc::context_configuration::type::IP:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_IP;
		break;
	case lsc::context_configuration::type::PERF_THREAD_COUNTER:
	{
		const auto& perf_config =
			static_cast<const lsc::perf_counter_context_configuration&>(context_config);

		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER;
		ust_ctx.u.perf_counter.type = static_cast<uint32_t>(perf_config.perf_type);
		ust_ctx.u.perf_counter.config = perf_config.perf_config;
		strncpy(ust_ctx.u.perf_counter.name,
			perf_config.name.c_str(),
			LTTNG_UST_ABI_SYM_NAME_LEN);
		ust_ctx.u.perf_counter.name[LTTNG_UST_ABI_SYM_NAME_LEN - 1] = '\0';
		break;
	}
	case lsc::context_configuration::type::APP_CONTEXT:
	{
		const auto& app_config =
			static_cast<const lsc::app_context_configuration&>(context_config);

		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_APP_CONTEXT;
		/*
		 * The provider_name and ctx_name pointers in the ABI struct
		 * are non-owning. The caller must ensure the
		 * context_configuration outlives the returned struct.
		 */
		ust_ctx.u.app_ctx.provider_name =
			const_cast<char *>(app_config.provider_name.c_str());
		ust_ctx.u.app_ctx.ctx_name = const_cast<char *>(app_config.context_name.c_str());
		break;
	}
	case lsc::context_configuration::type::CPU_ID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_CPU_ID;
		break;
	case lsc::context_configuration::type::CGROUP_NS:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_CGROUP_NS;
		break;
	case lsc::context_configuration::type::IPC_NS:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_IPC_NS;
		break;
	case lsc::context_configuration::type::MNT_NS:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_MNT_NS;
		break;
	case lsc::context_configuration::type::NET_NS:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_NET_NS;
		break;
	case lsc::context_configuration::type::PID_NS:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_PID_NS;
		break;
	case lsc::context_configuration::type::TIME_NS:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_TIME_NS;
		break;
	case lsc::context_configuration::type::USER_NS:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_USER_NS;
		break;
	case lsc::context_configuration::type::UTS_NS:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_UTS_NS;
		break;
	case lsc::context_configuration::type::VUID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_VUID;
		break;
	case lsc::context_configuration::type::VEUID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_VEUID;
		break;
	case lsc::context_configuration::type::VSUID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_VSUID;
		break;
	case lsc::context_configuration::type::VGID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_VGID;
		break;
	case lsc::context_configuration::type::VEGID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_VEGID;
		break;
	case lsc::context_configuration::type::VSGID:
		ust_ctx.ctx = LTTNG_UST_ABI_CONTEXT_VSGID;
		break;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			fmt::format("Context type is not supported by the UST domain: type={}",
				    context_config.context_type));
	}

	return ust_ctx;
}

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
	_validate_channel_attributes(channel_config);

	const auto buffer_type = _default_buffer_ownership ==
			lsc::recording_channel_configuration::owership_model_t::PER_PID ?
		LTTNG_BUFFER_PER_PID :
		LTTNG_BUFFER_PER_UID;

	/*
	 * Detect the agent sub-domain from the channel name. Agent channels
	 * (JUL, Log4j, Log4j2, Python) use well-known names.
	 */
	auto domain = LTTNG_DOMAIN_UST;
	if (channel_config.name == DEFAULT_JUL_CHANNEL_NAME) {
		domain = LTTNG_DOMAIN_JUL;
	} else if (channel_config.name == DEFAULT_LOG4J_CHANNEL_NAME) {
		domain = LTTNG_DOMAIN_LOG4J;
	} else if (channel_config.name == DEFAULT_LOG4J2_CHANNEL_NAME) {
		domain = LTTNG_DOMAIN_LOG4J2;
	} else if (channel_config.name == DEFAULT_PYTHON_CHANNEL_NAME) {
		domain = LTTNG_DOMAIN_PYTHON;
	}

	/*
	 * Build the legacy lttng_channel and ltt_ust_channel structures.
	 * The per-app sync path still reads from ltt_ust_channel (name,
	 * attributes, trace_class_stream_class_handle). This will be
	 * eliminated when the sync path is internalized.
	 */
	auto lttng_channel = ls::make_lttng_channel(channel_config);

	if (lttng_channel->attr.overwrite == DEFAULT_CHANNEL_OVERWRITE) {
		lttng_channel->attr.overwrite = !!_ust_session.snapshot_mode;
	}

	if (_ust_session.snapshot_mode) {
		lttng_channel->attr.output = LTTNG_EVENT_MMAP;
	}

	auto uchan = lttng::make_unique_wrapper<ltt_ust_channel, trace_ust_destroy_channel>(
		trace_ust_create_channel(lttng_channel.get(), domain));
	if (!uchan) {
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR("Failed to create UST channel structure");
	}

	uchan->trace_class_stream_class_handle =
		trace_ust_get_trace_class_stream_class_handle(&_ust_session);

	/* Lock buffer type on the session. */
	if (!_ust_session.buffer_type_changed) {
		_ust_session.buffer_type = buffer_type;
		_ust_session.buffer_type_changed = 1;
	} else if (_ust_session.buffer_type != buffer_type) {
		LTTNG_THROW_CTL("Buffer type mismatch", LTTNG_ERR_BUFFER_TYPE_MISMATCH);
	}

	/*
	 * Add the channel to the legacy hash table. Metadata channels
	 * are handled specially: their attributes are copied to the
	 * session instead of being added to the hash table.
	 */
	{
		const lttng::urcu::read_lock_guard rcu_read_lock;

		if (lttng::c_string_view(uchan->name) != DEFAULT_METADATA_NAME) {
			lttng_ht_add_unique_str(_ust_session.domain_global.channels, &uchan->node);
		} else {
			memcpy(&_ust_session.metadata_attr,
			       &uchan->attr,
			       sizeof(_ust_session.metadata_attr));
		}

	}

	DBG_FMT("UST domain orchestrator created channel: channel_name=`{}`, trace_class_stream_class_handle={}",
		channel_config.name.c_str(),
		uchan->trace_class_stream_class_handle);

	/* Channel is now owned by the hash table. */
	/* NOLINTNEXTLINE(bugprone-unused-return-value) */
	uchan.release();
}

void ls::ust::domain_orchestrator::_validate_channel_attributes(
	const lsc::recording_channel_configuration& channel_config)
{
	const auto subbuf_size = channel_config.subbuffer_size_bytes;
	const auto num_subbuf = channel_config.subbuffer_count;

	/* Overwrite mode requires at least 2 subbuffers. */
	if (channel_config.buffer_full_policy ==
		    lsc::channel_configuration::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET &&
	    num_subbuf < 2) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Overwrite mode requires at least 2 subbuffers");
	}

	/* Subbuffer size must be a nonzero power of 2. */
	if (!subbuf_size || (subbuf_size & (subbuf_size - 1))) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Subbuffer size must be a nonzero power of 2");
	}

	/* Subbuffer size must be at least the page size. */
	if (subbuf_size < static_cast<std::uint64_t>(the_page_size)) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR("Subbuffer size must be at least the page size");
	}

	/* Number of subbuffers must be a nonzero power of 2. */
	if (!num_subbuf || (num_subbuf & (num_subbuf - 1))) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Number of subbuffers must be a nonzero power of 2");
	}

	/* UST only supports MMAP output. */
	if (channel_config.buffer_consumption_backend !=
	    lsc::channel_configuration::buffer_consumption_backend_t::MMAP) {
		LTTNG_THROW_UNSUPPORTED_ERROR("UST only supports MMAP output");
	}

	/* Tracefile size must be >= subbuffer size when set. */
	if (channel_config.trace_file_size_limit_bytes &&
	    *channel_config.trace_file_size_limit_bytes > 0 &&
	    *channel_config.trace_file_size_limit_bytes < subbuf_size) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Tracefile size must be at least the subbuffer size");
	}
}

void ls::ust::domain_orchestrator::enable_channel(
	const config::recording_channel_configuration& channel_config)
{
	if (!_active) {
		/*
		 * The channel will be enabled on all applications when the
		 * session is started as part of the synchronization.
		 */
		return;
	}

	/*
	 * Enable channel for UST global domain on all applications. Ignore return
	 * value here since whatever error we got, it means that the channel was
	 * not enabled on one or many registered applications and we can not report
	 * this to the user yet. However, at this stage, the channel was
	 * successfully enabled on the session daemon side so the enable-channel
	 * command is a success.
	 */
	(void) ust_app_enable_channel_glb(&_ust_session, channel_config.name);
}

void ls::ust::domain_orchestrator::disable_channel(
	const config::recording_channel_configuration& channel_config)
{
	if (!_active) {
		/*
		 * If the session is inactive, the tracers are not notified
		 * right away. The disabled state will be picked up on the
		 * next synchronization.
		 */
		return;
	}

	const auto ret = ust_app_disable_channel_glb(&_ust_session, channel_config.name);
	if (ret < 0 && ret != -LTTNG_UST_ERR_EXIST) {
		LTTNG_THROW_CTL("Failed to disable UST channel", LTTNG_ERR_UST_CHAN_DISABLE_FAIL);
	}
}

void ls::ust::domain_orchestrator::disable_event(
	const config::recording_channel_configuration& channel_config,
	const config::event_rule_configuration& event_rule_config)
{
	if (!_ust_session.active) {
		return;
	}

	const auto ret =
		ust_app_disable_event_glb(&_ust_session, channel_config.name, event_rule_config);
	if (ret < 0) {
		LTTNG_THROW_CTL("Failed to disable UST event", LTTNG_ERR_UST_DISABLE_FAIL);
	}
}

void ls::ust::domain_orchestrator::add_context(const config::recording_channel_configuration&,
					       const config::context_configuration&)
{
	/*
	 * Nothing to do: the config layer already recorded the context
	 * in the recording_channel_configuration. The per-app sync path
	 * reads contexts from the config directly.
	 */
	LTTNG_ASSERT(!_active);
}

void ls::ust::domain_orchestrator::enable_event(
	const config::recording_channel_configuration& channel_config,
	const config::event_rule_configuration& event_rule_config)
{
	if (!_ust_session.active) {
		_created_event_rules.insert(&event_rule_config);
		return;
	}

	const auto already_created = _created_event_rules.count(&event_rule_config) > 0;

	int ret;
	if (already_created) {
		ret = ust_app_enable_event_glb(
			&_ust_session, channel_config.name, event_rule_config);
	} else {
		ret = ust_app_create_event_glb(
			&_ust_session, channel_config.name, event_rule_config);
		if (ret >= 0) {
			_created_event_rules.insert(&event_rule_config);
		}
	}

	if (ret < 0) {
		LTTNG_THROW_CTL("Failed to enable UST event", LTTNG_ERR_UST_ENABLE_FAIL);
	}
}

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

/* Key comparison and hash implementations. */

bool ls::ust::domain_orchestrator::_per_uid_trace_class_key::operator==(
	const _per_uid_trace_class_key& other) const noexcept
{
	return uid == other.uid && abi == other.abi;
}

std::size_t ls::ust::domain_orchestrator::_per_uid_trace_class_key::hash() const noexcept
{
	return _hash_combine(std::hash<uid_t>{}(uid),
			     std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(abi)));
}

bool ls::ust::domain_orchestrator::_per_uid_stream_group_key::operator==(
	const _per_uid_stream_group_key& other) const noexcept
{
	return channel_config == other.channel_config && uid == other.uid && abi == other.abi;
}

std::size_t ls::ust::domain_orchestrator::_per_uid_stream_group_key::hash() const noexcept
{
	auto h = std::hash<const void *>{}(channel_config);
	h = _hash_combine(h, std::hash<uid_t>{}(uid));
	h = _hash_combine(h, std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(abi)));
	return h;
}

bool ls::ust::domain_orchestrator::_per_pid_stream_group_key::operator==(
	const _per_pid_stream_group_key& other) const noexcept
{
	return channel_config == other.channel_config && app == other.app;
}

std::size_t ls::ust::domain_orchestrator::_per_pid_stream_group_key::hash() const noexcept
{
	return _hash_combine(std::hash<const void *>{}(channel_config),
			     std::hash<const void *>{}(app));
}
