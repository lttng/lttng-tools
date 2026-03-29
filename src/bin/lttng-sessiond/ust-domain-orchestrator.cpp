/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "agent.hpp"
#include "consumer.hpp"
#include "context-configuration.hpp"
#include "event-rule-configuration.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-ust-error.hpp"
#include "recording-channel-configuration.hpp"
#include "session.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"
#include "ust-domain-orchestrator.hpp"
#include "ust-registry.hpp"
#include "ust-trace-class-index.hpp"

#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/fs-utils.hpp>
#include <common/macros.hpp>
#include <common/scope-exit.hpp>
#include <common/trace-chunk.hpp>

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

void ls::ust::domain_orchestrator::consumer_output_deleter::operator()(
	struct consumer_output *output) const noexcept
{
	consumer_output_put(output);
}

ls::ust::domain_orchestrator::domain_orchestrator(
	ltt_ust_session& ust_session,
	const ltt_session& session,
	lsc::recording_channel_configuration::owership_model_t default_buffer_ownership,
	consumer_output_uptr consumer_output) :
	_ust_session(ust_session),
	_session(session),
	_default_buffer_ownership(default_buffer_ownership),
	_consumer_output(std::move(consumer_output)),
	_agents(lttng_ht_new(0, LTTNG_HT_TYPE_U64)),
	_root_shm_path(session.shm_path),
	_shm_path(session.shm_path[0] != '\0' ? std::string(session.shm_path) + "/ust" :
						std::string())
{
	LTTNG_ASSERT(_consumer_output);
	LTTNG_ASSERT(_agents);
}

struct lttng_ust_abi_channel_attr
ls::ust::domain_orchestrator::default_metadata_channel_attr() noexcept
{
	struct lttng_ust_abi_channel_attr attr = {};

	attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	attr.subbuf_size = default_get_metadata_subbuf_size();
	attr.num_subbuf = DEFAULT_METADATA_SUBBUF_NUM;
	attr.switch_timer_interval = DEFAULT_METADATA_SWITCH_TIMER;
	attr.read_timer_interval = DEFAULT_METADATA_READ_TIMER;
	attr.output = LTTNG_UST_ABI_MMAP;
	attr.type = LTTNG_UST_ABI_CHAN_METADATA;
	return attr;
}

bool ls::ust::domain_orchestrator::supports_madv_remove() const noexcept
{
	return lttng::utils::fs_supports_madv_remove(!_shm_path.empty() ? _shm_path.c_str() :
									  nullptr);
}

ls::ust::domain_orchestrator::~domain_orchestrator()
{
	/* Unregister all per-UID trace classes from the global index. */
	for (const auto& entry : _per_uid_trace_classes) {
		the_trace_class_index->remove_per_uid(
			_session.id, static_cast<std::uint32_t>(entry.first.abi), entry.first.uid);
	}

	/* Unregister any remaining per-PID trace classes from the global index. */
	for (const auto& entry : _per_pid_app_session_ids) {
		the_trace_class_index->remove_per_pid(entry.second);
	}

	/* Destroy all agents. */
	if (_agents) {
		const lttng::urcu::read_lock_guard read_lock;

		for (auto *agt :
		     lttng::urcu::lfht_iteration_adapter<agent, decltype(agent::node), &agent::node>(
			     *_agents->ht)) {
			const int ret = cds_lfht_del(_agents->ht, &agt->node.node);

			LTTNG_ASSERT(!ret);
			agent_destroy(agt);
		}

		lttng_ht_destroy(_agents);
	}
}

struct agent *
ls::ust::domain_orchestrator::find_agent(enum lttng_domain_type domain_type) const noexcept
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	uint64_t key = domain_type;

	lttng_ht_lookup(_agents, &key, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (!node) {
		return nullptr;
	}

	return lttng::utils::container_of(node, &agent::node);
}

struct agent& ls::ust::domain_orchestrator::find_or_create_agent(enum lttng_domain_type domain_type)
{
	auto *agt = find_agent(domain_type);
	if (agt) {
		return *agt;
	}

	agt = agent_create(domain_type);
	if (!agt) {
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR("Failed to create agent");
	}

	agent_add(agt, _agents);
	return *agt;
}

std::uint64_t ls::ust::domain_orchestrator::trace_class_stream_class_handle(
	const config::recording_channel_configuration& channel_config) const
{
	const auto it = _channel_handles.find(&channel_config);
	LTTNG_ASSERT(it != _channel_handles.end());
	return it->second;
}

ls::ust::trace_class& ls::ust::domain_orchestrator::find_or_create_per_uid_trace_class(
	uid_t uid,
	application_abi abi,
	const lttng::sessiond::trace::abi& tracer_abi,
	std::uint32_t tracer_major,
	std::uint32_t tracer_minor,
	const char *root_shm_path,
	const char *shm_path)
{
	LTTNG_ASSERT(_default_buffer_ownership ==
		     lsc::recording_channel_configuration::owership_model_t::PER_UID);

	const _per_uid_trace_class_key key = { uid, abi };
	const auto it = _per_uid_trace_classes.find(key);
	if (it != _per_uid_trace_classes.end()) {
		return *it->second;
	}

	std::shared_ptr<ust::trace_class> tc(ust_trace_class_per_uid_create(_session.trace_format,
									    tracer_abi,
									    tracer_major,
									    tracer_minor,
									    root_shm_path,
									    shm_path,
									    _session.uid,
									    _session.gid,
									    _session.id,
									    uid));
	if (!tc) {
		LTTNG_THROW_ERROR(
			lttng::format("Failed to create per-UID trace class: uid={}, abi={}",
				      uid,
				      static_cast<int>(abi)));
	}

	auto& ref = *tc;
	_per_uid_trace_classes.emplace(key, tc);

	/* Register in the global trace class index for consumer metadata lookups. */
	the_trace_class_index->add_per_uid(_session.id, static_cast<std::uint32_t>(abi), uid, tc);

	DBG_FMT("UST domain orchestrator created per-UID trace class: uid={}, abi={}",
		uid,
		static_cast<int>(abi));

	return ref;
}

ls::ust::trace_class& ls::ust::domain_orchestrator::find_or_create_per_pid_trace_class(
	ust_app& app,
	std::uint64_t app_session_id,
	const lttng::sessiond::trace::abi& tracer_abi,
	std::uint32_t tracer_major,
	std::uint32_t tracer_minor,
	const char *root_shm_path,
	const char *shm_path,
	uid_t euid,
	gid_t egid)
{
	LTTNG_ASSERT(_default_buffer_ownership ==
		     lsc::recording_channel_configuration::owership_model_t::PER_PID);

	const auto it = _per_pid_trace_classes.find(&app);
	if (it != _per_pid_trace_classes.end()) {
		return *it->second;
	}

	std::shared_ptr<ust::trace_class> tc(ust_trace_class_per_pid_create(&app,
									    _session.trace_format,
									    tracer_abi,
									    tracer_major,
									    tracer_minor,
									    root_shm_path,
									    shm_path,
									    euid,
									    egid,
									    _session.id));
	if (!tc) {
		LTTNG_THROW_ERROR(
			lttng::format("Failed to create per-PID trace class: pid={}", app.pid));
	}

	auto& ref = *tc;
	_per_pid_trace_classes.emplace(&app, tc);
	_per_pid_app_session_ids.emplace(&app, app_session_id);

	/* Register in the global trace class index for consumer metadata lookups. */
	the_trace_class_index->add_per_pid(app_session_id, tc);

	DBG_FMT("UST domain orchestrator created per-PID trace class: pid={}", app.pid);

	return ref;
}

void ls::ust::domain_orchestrator::release_per_pid_trace_class(const ust_app& app)
{
	const auto it = _per_pid_trace_classes.find(&app);
	if (it == _per_pid_trace_classes.end()) {
		return;
	}

	/* Unregister from the global trace class index. */
	const auto id_it = _per_pid_app_session_ids.find(&app);
	if (id_it != _per_pid_app_session_ids.end()) {
		the_trace_class_index->remove_per_pid(id_it->second);
		_per_pid_app_session_ids.erase(id_it);
	}

	DBG_FMT("UST domain orchestrator releasing per-PID trace class: pid={}", app.pid);
	_per_pid_trace_classes.erase(it);
}

ls::ust::stream_group& ls::ust::domain_orchestrator::find_or_create_per_uid_stream_group(
	const config::recording_channel_configuration& channel_config,
	uid_t uid,
	application_abi abi,
	std::uint64_t consumer_key,
	ust::ust_object_data channel_object,
	ust::trace_class& trace_class,
	ust::stream_class& stream_class)
{
	LTTNG_ASSERT(_default_buffer_ownership ==
		     lsc::recording_channel_configuration::owership_model_t::PER_UID);

	const _per_uid_stream_group_key key = { &channel_config, uid, abi };
	const auto it = _per_uid_stream_groups.find(key);
	if (it != _per_uid_stream_groups.end()) {
		return *it->second;
	}

	auto sg = lttng::make_unique<ust::stream_group>(
		consumer_key, std::move(channel_object), channel_config, trace_class, stream_class);

	auto& ref = *sg;
	_per_uid_stream_groups.emplace(key, std::move(sg));

	DBG_FMT("UST domain orchestrator created per-UID stream group: "
		"channel_name=`{}`, uid={}, abi={}, consumer_key={}",
		channel_config.name,
		uid,
		static_cast<int>(abi),
		consumer_key);

	return ref;
}

ls::ust::stream_group& ls::ust::domain_orchestrator::get_per_uid_stream_group(
	const config::recording_channel_configuration& channel_config,
	uid_t uid,
	application_abi abi)
{
	const _per_uid_stream_group_key key = { &channel_config, uid, abi };
	const auto it = _per_uid_stream_groups.find(key);
	if (it == _per_uid_stream_groups.end()) {
		LTTNG_THROW_ERROR(lttng::format(
			"Per-UID stream group not found: channel_name=`{}`, uid={}, abi={}",
			channel_config.name,
			uid,
			static_cast<int>(abi)));
	}

	return *it->second;
}

bool ls::ust::domain_orchestrator::has_per_uid_stream_group(
	const config::recording_channel_configuration& channel_config,
	uid_t uid,
	application_abi abi) const
{
	const _per_uid_stream_group_key key = { &channel_config, uid, abi };

	return _per_uid_stream_groups.find(key) != _per_uid_stream_groups.end();
}

ls::ust::stream_group& ls::ust::domain_orchestrator::find_or_create_per_pid_stream_group(
	const config::recording_channel_configuration& channel_config,
	const ust_app& app,
	std::uint64_t consumer_key,
	ust::ust_object_data channel_object,
	ust::trace_class& trace_class,
	ust::stream_class& stream_class)
{
	LTTNG_ASSERT(_default_buffer_ownership ==
		     lsc::recording_channel_configuration::owership_model_t::PER_PID);

	const _per_pid_stream_group_key key = { &channel_config, &app };
	const auto it = _per_pid_stream_groups.find(key);
	if (it != _per_pid_stream_groups.end()) {
		return *it->second;
	}

	auto sg = lttng::make_unique<ust::stream_group>(
		consumer_key, std::move(channel_object), channel_config, trace_class, stream_class);

	auto& ref = *sg;
	_per_pid_stream_groups.emplace(key, std::move(sg));

	DBG_FMT("UST domain orchestrator created per-PID stream group: "
		"channel_name=`{}`, pid={}, consumer_key={}",
		channel_config.name,
		app.pid,
		consumer_key);

	return ref;
}

void ls::ust::domain_orchestrator::release_per_pid_stream_groups(const ust_app& app)
{
	auto it = _per_pid_stream_groups.begin();
	while (it != _per_pid_stream_groups.end()) {
		if (it->first.app == &app) {
			DBG_FMT("UST domain orchestrator releasing per-PID stream group: "
				"channel_name=`{}`, pid={}",
				it->second->configuration().name,
				app.pid);
			it = _per_pid_stream_groups.erase(it);
		} else {
			++it;
		}
	}
}

void ls::ust::domain_orchestrator::create_channel(
	const config::recording_channel_configuration& channel_config)
{
	_validate_channel_attributes(channel_config);

	const auto buffer_type = _default_buffer_ownership ==
			lsc::recording_channel_configuration::owership_model_t::PER_PID ?
		LTTNG_BUFFER_PER_PID :
		LTTNG_BUFFER_PER_UID;

	const auto handle = _next_trace_class_stream_class_handle++;
	_channel_handles[&channel_config] = handle;

	/* Lock buffer type on first channel creation. */
	if (!_locked_buffer_type) {
		_locked_buffer_type = buffer_type;
		_ust_session.buffer_type = buffer_type;
	} else if (*_locked_buffer_type != buffer_type) {
		LTTNG_THROW_CTL("Buffer type mismatch", LTTNG_ERR_BUFFER_TYPE_MISMATCH);
	}

	DBG_FMT("UST domain orchestrator created channel: channel_name=`{}`, trace_class_stream_class_handle={}",
		channel_config.name.c_str(),
		handle);
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
		ust_app_global_update_all(&_ust_session, _session.user_space_domain, *this);
	}
}

void ls::ust::domain_orchestrator::track_process_attribute(config::process_attribute_type,
							   std::uint64_t)
{
	if (_active) {
		ust_app_global_update_all(&_ust_session, _session.user_space_domain, *this);
	}
}

void ls::ust::domain_orchestrator::untrack_process_attribute(config::process_attribute_type,
							     std::uint64_t)
{
	if (_active) {
		ust_app_global_update_all(&_ust_session, _session.user_space_domain, *this);
	}
}

void ls::ust::domain_orchestrator::start()
{
	if (_active) {
		return;
	}

	const auto ret = ust_app_start_trace_all(&_ust_session, _session.user_space_domain, *this);
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

	const auto ret = ust_app_stop_trace_all(&_ust_session, *this);
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

void ls::ust::domain_orchestrator::close_per_uid_metadata_on_consumer(
	struct consumer_output& consumer) const
{
	const lttng::urcu::read_lock_guard read_lock;

	for (const auto& tc_entry : _per_uid_trace_classes) {
		const auto& abi = tc_entry.first.abi;
		const auto& trace_class = *tc_entry.second;

		if (!trace_class._metadata_key) {
			continue;
		}

		auto *socket = consumer_find_socket_by_bitness(static_cast<int>(abi), &consumer);
		if (!socket) {
			continue;
		}

		(void) consumer_close_metadata(socket, trace_class._metadata_key);
	}
}

void ls::ust::domain_orchestrator::record_snapshot(const struct consumer_output& snapshot_consumer,
						   std::uint64_t nb_packets_per_stream)
{
	if (_default_buffer_ownership ==
	    lsc::recording_channel_configuration::owership_model_t::PER_UID) {
		_record_snapshot_per_uid(snapshot_consumer, nb_packets_per_stream);
	} else {
		const auto ret = ust_app_snapshot_record(
			&_ust_session, &snapshot_consumer, nb_packets_per_stream);
		if (ret != LTTNG_OK) {
			LTTNG_THROW_SNAPSHOT_FAILURE("Failed to record UST snapshot");
		}
	}
}

void ls::ust::domain_orchestrator::_record_snapshot_per_uid(
	const struct consumer_output& snapshot_consumer, std::uint64_t nb_packets_per_stream) const
{
	for (const auto& tc_entry : _per_uid_trace_classes) {
		const auto& tc_key = tc_entry.first;
		auto& trace_class = *tc_entry.second;

		if (!trace_class._metadata_key) {
			/* Skip since no metadata is present. */
			continue;
		}

		lttng::urcu::read_lock_guard read_lock;
		auto *socket = consumer_find_socket_by_bitness(static_cast<int>(tc_key.abi),
							       _consumer_output.get());
		if (!socket) {
			LTTNG_THROW_CTL("Failed to find consumer socket for snapshot",
					LTTNG_ERR_INVALID);
		}

		const auto uid_path = lttng::format(
			"uid/{}/{}-bit", tc_key.uid, static_cast<unsigned int>(tc_key.abi));

		std::size_t consumer_path_offset = 0;
		const auto trace_path_raw = setup_channel_trace_path(
			_consumer_output.get(), uid_path.c_str(), &consumer_path_offset);
		if (!trace_path_raw) {
			LTTNG_THROW_CTL("Failed to setup channel trace path for snapshot",
					LTTNG_ERR_INVALID);
		}

		const auto free_trace_path = lttng::make_scope_exit(
			[trace_path_raw]() noexcept { free(trace_path_raw); });
		const auto *trace_path = &trace_path_raw[consumer_path_offset];

		/* Snapshot data channels. */
		for (const auto& sg_entry : _per_uid_stream_groups) {
			if (sg_entry.first.uid != tc_key.uid || sg_entry.first.abi != tc_key.abi) {
				continue;
			}

			const auto status =
				consumer_snapshot_channel(socket,
							  sg_entry.second->consumer_key(),
							  &snapshot_consumer,
							  0,
							  trace_path,
							  nb_packets_per_stream);
			if (status != LTTNG_OK) {
				LTTNG_THROW_SNAPSHOT_FAILURE("Failed to snapshot UST data channel");
			}
		}

		/* Snapshot metadata channel. */
		const auto status = consumer_snapshot_channel(
			socket, trace_class._metadata_key, &snapshot_consumer, 1, trace_path, 0);
		if (status != LTTNG_OK) {
			LTTNG_THROW_SNAPSHOT_FAILURE("Failed to snapshot UST metadata channel");
		}
	}
}

void ls::ust::domain_orchestrator::regenerate_metadata()
{
	for (const auto& tc_entry : _per_uid_trace_classes) {
		tc_entry.second->regenerate_metadata();
	}
}

void ls::ust::domain_orchestrator::regenerate_statedump()
{
	const auto ret = ust_app_regenerate_statedump_all(&_ust_session);
	if (ret < 0) {
		LTTNG_THROW_REGENERATE_STATEDUMP_FAILURE("Failed to regenerate UST statedump");
	}
}

void ls::ust::domain_orchestrator::create_channel_subdirectories(
	lttng_trace_chunk& trace_chunk) const
{
	if (_default_buffer_ownership ==
	    lsc::recording_channel_configuration::owership_model_t::PER_UID) {
		for (const auto& tc_entry : _per_uid_trace_classes) {
			const auto uid = tc_entry.first.uid;
			const auto bits_per_long = static_cast<unsigned int>(tc_entry.first.abi);

			const auto pathname = lttng::format(DEFAULT_UST_TRACE_DIR
							    "/uid/{}/{}-bit/" DEFAULT_INDEX_DIR,
							    uid,
							    bits_per_long);

			const auto chunk_status = lttng_trace_chunk_create_subdirectory(
				&trace_chunk, pathname.c_str());
			if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
				LTTNG_THROW_CTL("Failed to create UST channel subdirectory",
						LTTNG_ERR_CREATE_DIR_FAIL);
			}
		}
	} else {
		/*
		 * Create the toplevel ust/ directory in case no apps are running.
		 */
		auto chunk_status =
			lttng_trace_chunk_create_subdirectory(&trace_chunk, DEFAULT_UST_TRACE_DIR);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			LTTNG_THROW_CTL("Failed to create UST trace directory",
					LTTNG_ERR_CREATE_DIR_FAIL);
		}

		for (auto *app :
		     lttng::urcu::lfht_iteration_adapter<ust_app,
							 decltype(ust_app::pid_n),
							 &ust_app::pid_n>(*ust_app_ht->ht)) {
			if (!ust_app_get(*app)) {
				DBG("Could not get application reference as it is being torn down; skipping application");
				continue;
			}

			const ust_app_reference app_ref(app);

			const auto *ua_sess = ust_app_lookup_app_session(&_ust_session, app);
			if (!ua_sess) {
				continue;
			}

			const auto *registry =
				ust_app_get_session_registry(ua_sess->get_identifier());
			if (!registry) {
				DBG("Application session is being torn down. Skip application.");
				continue;
			}

			const auto pathname = lttng::format(
				DEFAULT_UST_TRACE_DIR "/{}/" DEFAULT_INDEX_DIR, ua_sess->path);

			chunk_status = lttng_trace_chunk_create_subdirectory(&trace_chunk,
									     pathname.c_str());
			if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
				LTTNG_THROW_CTL("Failed to create UST channel subdirectory",
						LTTNG_ERR_CREATE_DIR_FAIL);
			}
		}
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

DIAGNOSTIC_POP; /* DIAGNOSTIC_IGNORE_MISSING_NORETURN */

void ls::ust::domain_orchestrator::accumulate_per_pid_closed_app_stats(
	const config::recording_channel_configuration& channel_config,
	std::uint64_t discarded_events,
	std::uint64_t lost_packets)
{
	auto& counters = _per_pid_closed_app_stats[&channel_config];

	counters.discarded_events += discarded_events;
	counters.lost_packets += lost_packets;
}

ls::recording_channel_runtime_stats
ls::ust::domain_orchestrator::get_recording_channel_runtime_stats(
	const config::recording_channel_configuration& channel_config) const
{
	recording_channel_runtime_stats stats = {};
	const auto is_overwrite = channel_config.buffer_full_policy ==
		lsc::channel_configuration::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET;

	if (_default_buffer_ownership ==
	    lsc::recording_channel_configuration::owership_model_t::PER_UID) {
		/*
		 * Find the first per-UID stream group matching this channel
		 * configuration and query the consumer daemon for its stats.
		 */
		uint64_t consumer_chan_key = 0;
		bool found = false;

		for (const auto& sg_entry : _per_uid_stream_groups) {
			if (sg_entry.first.channel_config == &channel_config) {
				consumer_chan_key = sg_entry.second->consumer_key();
				found = true;
				break;
			}
		}

		if (!found) {
			/* Channel not yet created on the consumer side. */
			goto add_closed_app_stats;
		}

		if (is_overwrite) {
			const auto ret_lost = consumer_get_lost_packets(_session.id,
									consumer_chan_key,
									_consumer_output.get(),
									&stats.lost_packets);
			if (ret_lost < 0) {
				LTTNG_THROW_ERROR(lttng::format(
					"Failed to get lost packets from consumer: channel_name=`{}`",
					channel_config.name));
			}
		} else {
			const auto ret_disc =
				consumer_get_discarded_events(_session.id,
							      consumer_chan_key,
							      _consumer_output.get(),
							      &stats.discarded_events);
			if (ret_disc < 0) {
				LTTNG_THROW_ERROR(lttng::format(
					"Failed to get discarded events from consumer: channel_name=`{}`",
					channel_config.name));
			}
		}
	} else {
		/*
		 * Per-PID: iterate all per-PID stream groups matching this
		 * channel configuration and query the consumer daemon for
		 * each app's stats.
		 */
		for (const auto& sg_entry : _per_pid_stream_groups) {
			if (sg_entry.first.channel_config != &channel_config) {
				continue;
			}

			const auto consumer_chan_key = sg_entry.second->consumer_key();

			if (is_overwrite) {
				uint64_t lost = 0;

				const auto ret = consumer_get_lost_packets(_session.id,
									   consumer_chan_key,
									   _consumer_output.get(),
									   &lost);
				if (ret < 0) {
					break;
				}

				stats.lost_packets += lost;
			} else {
				uint64_t discarded = 0;

				const auto ret =
					consumer_get_discarded_events(_session.id,
								      consumer_chan_key,
								      _consumer_output.get(),
								      &discarded);
				if (ret < 0) {
					break;
				}

				stats.discarded_events += discarded;
			}
		}
	}

add_closed_app_stats:
	/* Add accumulated stats from applications that have already exited. */
	{
		const auto closed_it = _per_pid_closed_app_stats.find(&channel_config);
		if (closed_it != _per_pid_closed_app_stats.end()) {
			stats.discarded_events += closed_it->second.discarded_events;
			stats.lost_packets += closed_it->second.lost_packets;
		}
	}

	return stats;
}

std::uint64_t ls::ust::domain_orchestrator::get_size_one_more_packet_per_stream(
	std::uint64_t cur_nr_packets) const
{
	std::uint64_t tot_size = 0;

	if (_default_buffer_ownership ==
	    lsc::recording_channel_configuration::owership_model_t::PER_UID) {
		for (const auto& sg_entry : _per_uid_stream_groups) {
			const auto& config = sg_entry.second->configuration();

			if (cur_nr_packets >= config.subbuffer_count) {
				continue;
			}

			tot_size += config.subbuffer_size_bytes * sg_entry.second->stream_count();
		}
	} else {
		for (const auto& sg_entry : _per_pid_stream_groups) {
			const auto& config = sg_entry.second->configuration();

			if (cur_nr_packets >= config.subbuffer_count) {
				continue;
			}

			tot_size += config.subbuffer_size_bytes * sg_entry.second->stream_count();
		}
	}

	return tot_size;
}

void ls::ust::domain_orchestrator::for_each_consumer_stream_group(
	const consumer_stream_group_visitor& visitor) const
{
	const auto& metadata_config = _session.user_space_domain.metadata_channel();

	if (_default_buffer_ownership ==
	    lsc::recording_channel_configuration::owership_model_t::PER_UID) {
		for (const auto& sg_entry : _per_uid_stream_groups) {
			visitor(consumer_stream_group_descriptor{
				sg_entry.first.abi,
				sg_entry.second->consumer_key(),
				false,
				sg_entry.second->get_trace_class(),
				*sg_entry.first.channel_config,
				nonstd::optional<uid_t>(sg_entry.first.uid),
				nonstd::nullopt });
		}

		for (const auto& tc_entry : _per_uid_trace_classes) {
			if (!tc_entry.second->_metadata_key) {
				continue;
			}

			visitor(consumer_stream_group_descriptor{
				tc_entry.first.abi,
				tc_entry.second->_metadata_key,
				true,
				*tc_entry.second,
				metadata_config,
				nonstd::optional<uid_t>(tc_entry.first.uid),
				nonstd::nullopt });
		}
	} else {
		for (const auto& sg_entry : _per_pid_stream_groups) {
			const auto app_abi = sg_entry.first.app->abi.bits_per_long == 32 ?
				application_abi::ABI_32 :
				application_abi::ABI_64;

			visitor(consumer_stream_group_descriptor{
				app_abi,
				sg_entry.second->consumer_key(),
				false,
				sg_entry.second->get_trace_class(),
				*sg_entry.first.channel_config,
				nonstd::nullopt,
				nonstd::optional<pid_t>(sg_entry.first.app->pid) });
		}

		for (const auto& tc_entry : _per_pid_trace_classes) {
			if (!tc_entry.second->_metadata_key) {
				continue;
			}

			const auto app_abi = tc_entry.first->abi.bits_per_long == 32 ?
				application_abi::ABI_32 :
				application_abi::ABI_64;

			visitor(consumer_stream_group_descriptor{
				app_abi,
				tc_entry.second->_metadata_key,
				true,
				*tc_entry.second,
				metadata_config,
				nonstd::nullopt,
				nonstd::optional<pid_t>(tc_entry.first->pid) });
		}
	}
}

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
