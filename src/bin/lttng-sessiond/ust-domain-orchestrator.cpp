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
#include "fd-limit.hpp"
#include "health-sessiond.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "notification-thread-commands.hpp"
#include "pending-memory-reclamation-request.hpp"
#include "recording-channel-configuration.hpp"
#include "session.hpp"
#include "trace-ust.hpp"
#include "ust-app-channel.hpp"
#include "ust-app-ctx.hpp"
#include "ust-app-event.hpp"
#include "ust-app.hpp"
#include "ust-consumer.hpp"
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
#include <common/urcu.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/user-tracepoint.h>

#include <cstring>
#include <functional>
#include <numeric>

namespace ls = lttng::sessiond;
namespace lsc = lttng::sessiond::config;

void ls::ust::domain_orchestrator::_assert_app_sessions_consistent() const
{
	/*
	 * Verify that every entry in _app_sessions has a non-null
	 * session pointer. The orchestrator is the sole owner, so
	 * there is no external state to cross-check against.
	 */
	for (const auto& app_session_pair : _app_sessions) {
		LTTNG_ASSERT(app_session_pair.first);
		LTTNG_ASSERT(app_session_pair.second);
	}
}

lttng_ust_context_attr ls::ust::domain_orchestrator::_make_ust_context_attr(
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
	const ltt_session& session,
	lsc::recording_channel_configuration::owership_model_t default_buffer_ownership,
	consumer_output_uptr consumer_output) :
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
ls::ust::domain_orchestrator::_default_metadata_channel_attr() noexcept
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

std::uint64_t ls::ust::domain_orchestrator::_session_id() const noexcept
{
	return _session.id;
}

lttng_buffer_type ls::ust::domain_orchestrator::buffer_type() const noexcept
{
	return _default_buffer_ownership ==
			lsc::recording_channel_configuration::owership_model_t::PER_UID ?
		LTTNG_BUFFER_PER_UID :
		LTTNG_BUFFER_PER_PID;
}

ls::ust::domain_orchestrator::~domain_orchestrator()
{
	/*
	 * Close per-UID metadata channels on the consumer before
	 * destroying trace classes. Per-PID metadata is closed when
	 * each application disconnects; per-UID metadata outlives the
	 * applications and must be closed explicitly.
	 */
	_close_per_uid_metadata_on_consumer();

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

std::uint64_t ls::ust::domain_orchestrator::_trace_class_stream_class_handle(
	const config::recording_channel_configuration& channel_config) const
{
	const auto it = _channel_handles.find(&channel_config);
	LTTNG_ASSERT(it != _channel_handles.end());
	return it->second;
}

ls::ust::trace_class& ls::ust::domain_orchestrator::_find_or_create_per_uid_trace_class(
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

	std::shared_ptr<ust::trace_class> tc(ust_trace_class_per_uid_create(
		_session.trace_format,
		tracer_abi,
		tracer_major,
		tracer_minor,
		root_shm_path,
		shm_path,
		_session.uid,
		_session.gid,
		_session.id,
		uid,
		_session.has_auto_generated_name ? DEFAULT_SESSION_NAME : _session.name,
		_session.hostname,
		_session.creation_time));
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

ls::ust::trace_class& ls::ust::domain_orchestrator::_find_or_create_per_pid_trace_class(
	ls::ust::app& app,
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

	std::shared_ptr<ust::trace_class> tc(ust_trace_class_per_pid_create(
		&app,
		_session.trace_format,
		tracer_abi,
		tracer_major,
		tracer_minor,
		root_shm_path,
		shm_path,
		euid,
		egid,
		_session.id,
		_session.has_auto_generated_name ? DEFAULT_SESSION_NAME : _session.name,
		_session.hostname,
		_session.creation_time));
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

void ls::ust::domain_orchestrator::_release_per_pid_trace_class(const ls::ust::app& app)
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

ls::ust::stream_group& ls::ust::domain_orchestrator::_find_or_create_per_uid_stream_group(
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

ls::ust::stream_group& ls::ust::domain_orchestrator::_get_per_uid_stream_group(
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

bool ls::ust::domain_orchestrator::_has_per_uid_stream_group(
	const config::recording_channel_configuration& channel_config,
	uid_t uid,
	application_abi abi) const
{
	const _per_uid_stream_group_key key = { &channel_config, uid, abi };

	return _per_uid_stream_groups.find(key) != _per_uid_stream_groups.end();
}

ls::ust::stream_group& ls::ust::domain_orchestrator::_find_or_create_per_pid_stream_group(
	const config::recording_channel_configuration& channel_config,
	const ls::ust::app& app,
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

void ls::ust::domain_orchestrator::_release_per_pid_stream_groups(const ls::ust::app& app)
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

void ls::ust::domain_orchestrator::_enable_channel_on_apps(lttng::c_string_view channel_name)
{
	const lttng::urcu::read_lock_guard read_lock;

	for (const auto& app_session_pair : _app_sessions) {
		auto *app = const_cast<ust::app *>(app_session_pair.first);
		auto *ua_sess = app_session_pair.second.get();

		if (!ust_app_get(*app)) {
			continue;
		}

		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			continue;
		}

		/* Enable channel onto application. */
		(void) enable_ust_app_channel(ua_sess->lock(), channel_name, app);
	}
}

void ls::ust::domain_orchestrator::_disable_channel_on_apps(lttng::c_string_view channel_name)
{
	int ret = 0;
	const lttng::urcu::read_lock_guard read_lock;

	for (const auto& app_session_pair : _app_sessions) {
		auto *app = const_cast<ust::app *>(app_session_pair.first);
		auto *ua_sess = app_session_pair.second.get();

		if (!ust_app_get(*app)) {
			continue;
		}

		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			continue;
		}

		struct lttng_ht_iter uiter;
		lttng_ht_lookup(ua_sess->channels, (void *) channel_name.data(), &uiter);
		auto *ua_chan_node = lttng_ht_iter_get_node<lttng_ht_node_str>(&uiter);

		/* If the session exists for the app, the channel must be there. */
		LTTNG_ASSERT(ua_chan_node);

		auto *ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);
		LTTNG_ASSERT(ua_chan->enabled);

		ret = disable_ust_app_channel(ua_sess->lock(), ua_chan, app);
		if (ret < 0) {
			continue;
		}
	}
}

int ls::ust::domain_orchestrator::_create_event_on_apps(
	lttng::c_string_view channel_name,
	const config::event_rule_configuration& event_rule_config)
{
	int ret = 0;
	const lttng::urcu::read_lock_guard read_lock;

	for (const auto& app_session_pair : _app_sessions) {
		auto *app = const_cast<ust::app *>(app_session_pair.first);
		auto *ua_sess = app_session_pair.second.get();

		if (!ust_app_get(*app)) {
			continue;
		}

		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			continue;
		}

		auto locked_ua_sess = ua_sess->lock();
		if (locked_ua_sess->deleted) {
			continue;
		}

		struct lttng_ht_iter uiter;
		lttng_ht_lookup(ua_sess->channels, (void *) channel_name.data(), &uiter);
		auto *ua_chan_node = lttng_ht_iter_get_node<lttng_ht_node_str>(&uiter);
		/* If the channel is not found, there is a code flow error. */
		LTTNG_ASSERT(ua_chan_node);

		auto *ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

		ret = create_ust_app_event(ua_chan, app, event_rule_config);
		if (ret < 0) {
			if (ret != -LTTNG_UST_ERR_EXIST) {
				break;
			}

			DBG2("UST app event already exists on app PID %d", app->pid);
			continue;
		}
	}

	return ret;
}

int ls::ust::domain_orchestrator::_enable_event_on_apps(
	lttng::c_string_view channel_name,
	const config::event_rule_configuration& event_rule_config)
{
	int ret = 0;
	const lttng::urcu::read_lock_guard read_lock;

	for (const auto& app_session_pair : _app_sessions) {
		auto *app = const_cast<ust::app *>(app_session_pair.first);
		auto *ua_sess = app_session_pair.second.get();

		if (!ust_app_get(*app)) {
			continue;
		}

		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			continue;
		}

		auto locked_ua_sess = ua_sess->lock();
		if (ua_sess->deleted) {
			continue;
		}

		struct lttng_ht_iter uiter;
		lttng_ht_lookup(ua_sess->channels, (void *) channel_name.data(), &uiter);
		auto *ua_chan_node = lttng_ht_iter_get_node<lttng_ht_node_str>(&uiter);
		if (!ua_chan_node) {
			continue;
		}

		auto *ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

		auto *ua_event = find_ust_app_event_by_config(ua_chan->events, event_rule_config);
		if (ua_event == nullptr) {
			DBG3("UST app enable event not found for app PID %d. Skipping app",
			     app->pid);
			continue;
		}

		ret = enable_ust_app_event(ua_event, app);
		if (ret < 0) {
			return ret;
		}
	}

	return ret;
}

int ls::ust::domain_orchestrator::_disable_event_on_apps(
	lttng::c_string_view channel_name,
	const config::event_rule_configuration& event_rule_config)
{
	int ret = 0;
	const lttng::urcu::read_lock_guard read_lock;

	for (const auto& app_session_pair : _app_sessions) {
		auto *app = const_cast<ust::app *>(app_session_pair.first);
		auto *ua_sess = app_session_pair.second.get();

		if (!ust_app_get(*app)) {
			continue;
		}

		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			continue;
		}

		struct lttng_ht_iter uiter;
		lttng_ht_lookup(ua_sess->channels, (void *) channel_name.data(), &uiter);
		auto *ua_chan_node = lttng_ht_iter_get_node<lttng_ht_node_str>(&uiter);
		if (ua_chan_node == nullptr) {
			DBG2("Channel %s not found in session id %" PRIu64
			     " for app pid %d. Skipping",
			     channel_name.data(),
			     _session_id(),
			     app->pid);
			continue;
		}

		auto *ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

		auto *ua_event = find_ust_app_event_by_config(ua_chan->events, event_rule_config);
		if (ua_event == nullptr) {
			DBG2("Event not found in channel %s for app pid %d. Skipping",
			     channel_name.data(),
			     app->pid);
			continue;
		}

		ret = disable_ust_app_event(ua_event, app);
		if (ret < 0) {
			continue;
		}
	}

	return ret;
}

void ls::ust::domain_orchestrator::_add_context_on_apps(
	lttng::c_string_view channel_name, const config::context_configuration& ctx_config)
{
	const lttng::urcu::read_lock_guard read_lock;

	for (const auto& app_session_pair : _app_sessions) {
		auto *app = const_cast<ust::app *>(app_session_pair.first);
		auto *ua_sess = app_session_pair.second.get();

		if (!ust_app_get(*app)) {
			continue;
		}

		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			continue;
		}

		const auto locked_ua_sess = ua_sess->lock();
		if (locked_ua_sess->deleted) {
			continue;
		}

		struct lttng_ht_iter uiter;
		lttng_ht_lookup(ua_sess->channels, (void *) channel_name.data(), &uiter);
		auto *ua_chan_node = lttng_ht_iter_get_node<lttng_ht_node_str>(&uiter);
		if (ua_chan_node == nullptr) {
			continue;
		}

		auto *ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

		auto ust_ctx_attr = _make_ust_context_attr(ctx_config);
		(void) create_ust_app_channel_context(ua_chan, &ust_ctx_attr, app, ctx_config);
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
	_enable_channel_on_apps(channel_config.name);

	_assert_app_sessions_consistent();
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

	_disable_channel_on_apps(channel_config.name);

	_assert_app_sessions_consistent();
}

void ls::ust::domain_orchestrator::disable_event(
	const config::recording_channel_configuration& channel_config,
	const config::event_rule_configuration& event_rule_config)
{
	if (!_active) {
		return;
	}

	const auto ret = _disable_event_on_apps(channel_config.name, event_rule_config);
	if (ret < 0) {
		LTTNG_THROW_CTL("Failed to disable UST event", LTTNG_ERR_UST_DISABLE_FAIL);
	}

	_assert_app_sessions_consistent();
}

void ls::ust::domain_orchestrator::add_context(
	const config::recording_channel_configuration& channel_config,
	const config::context_configuration& ctx_config)
{
	if (!_active) {
		/*
		 * The config layer already recorded the context in
		 * the recording_channel_configuration. The per-app sync
		 * path reads contexts from the config directly when
		 * applications register while the session is inactive.
		 */
		return;
	}

	_add_context_on_apps(channel_config.name, ctx_config);

	_assert_app_sessions_consistent();
}

void ls::ust::domain_orchestrator::enable_event(
	const config::recording_channel_configuration& channel_config,
	const config::event_rule_configuration& event_rule_config)
{
	if (!_active) {
		_created_event_rules.insert(&event_rule_config);
		return;
	}

	const auto already_created = _created_event_rules.count(&event_rule_config) > 0;

	int ret;
	if (already_created) {
		ret = _enable_event_on_apps(channel_config.name, event_rule_config);
	} else {
		ret = _create_event_on_apps(channel_config.name, event_rule_config);
		if (ret >= 0) {
			_created_event_rules.insert(&event_rule_config);
		}
	}

	if (ret < 0) {
		LTTNG_THROW_CTL("Failed to enable UST event", LTTNG_ERR_UST_ENABLE_FAIL);
	}

	_assert_app_sessions_consistent();
}

void ls::ust::domain_orchestrator::set_tracking_policy(config::process_attribute_type,
						       config::tracking_policy)
{
	/*
	 * The config has already been updated by the command layer. Push the
	 * updated configuration to all running applications if tracing is active.
	 */
	if (_active) {
		_synchronize_all_apps();
	}
}

void ls::ust::domain_orchestrator::track_process_attribute(config::process_attribute_type,
							   std::uint64_t)
{
	if (_active) {
		_synchronize_all_apps();
	}
}

void ls::ust::domain_orchestrator::untrack_process_attribute(config::process_attribute_type,
							     std::uint64_t)
{
	if (_active) {
		_synchronize_all_apps();
	}
}

namespace {

void copy_channel_attr_to_ustctl(struct lttng_ust_ctl_consumer_channel_attr *attr,
				 const struct lttng_ust_abi_channel_attr *uattr)
{
	attr->subbuf_size = uattr->subbuf_size;
	attr->num_subbuf = uattr->num_subbuf;
	attr->overwrite = uattr->overwrite;
	attr->switch_timer_interval = uattr->switch_timer_interval;
	attr->read_timer_interval = uattr->read_timer_interval;
	attr->output = static_cast<lttng_ust_abi_output>(uattr->output);
	attr->blocking_timeout = uattr->blocking_timeout;
	attr->type = static_cast<enum lttng_ust_abi_chan_type>(uattr->type);
}

/*
 * Wrapper that acquires shared ownership of a trace class (session registry)
 * and locks it. The lock is released when the wrapper is destroyed.
 *
 * Callers that need a `const locked_ref&` (e.g. push_metadata) should
 * use the locked_ref() accessor.
 */
struct owned_locked_registry {
	std::shared_ptr<ls::ust::trace_class> _ownership;
	ls::ust::trace_class::locked_ref _lock;

	explicit operator bool() const noexcept
	{
		return _ownership != nullptr;
	}

	ls::ust::trace_class *operator->() const noexcept
	{
		return _ownership.get();
	}

	ls::ust::trace_class& operator*() const noexcept
	{
		return *_ownership;
	}

	ls::ust::trace_class::locked_ref& locked_ref() noexcept
	{
		return _lock;
	}

	const ls::ust::trace_class::locked_ref& locked_ref() const noexcept
	{
		return _lock;
	}

	void reset() noexcept
	{
		_lock.reset();
		_ownership.reset();
	}
};

owned_locked_registry
get_locked_session_registry(const ls::ust::app_session::identifier& identifier)
{
	auto session = ust_app_get_session_registry(identifier);
	ls::ust::trace_class::locked_ref lock;

	if (session) {
		pthread_mutex_lock(&session->_lock);
		lock = ls::ust::trace_class::locked_ref{ session.get() };
	}

	return { std::move(session), std::move(lock) };
}

} /* anonymous namespace */

void ls::ust::domain_orchestrator::_init_app_session(ust::app_session *ua_sess, ust::app *app)
{
	struct tm *timeinfo;
	char datetime[16];
	int ret;
	char tmp_shm_path[PATH_MAX];

	timeinfo = localtime(&app->registration_time);
	strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);

	DBG2("Shadow copy of session handle %d", ua_sess->handle);

	ua_sess->recording_session_id = _session_id();
	ua_sess->app_session_id = get_next_session_id();
	LTTNG_OPTIONAL_SET(&ua_sess->real_credentials.uid, app->uid);
	LTTNG_OPTIONAL_SET(&ua_sess->real_credentials.gid, app->gid);
	LTTNG_OPTIONAL_SET(&ua_sess->effective_credentials.uid, _session.uid);
	LTTNG_OPTIONAL_SET(&ua_sess->effective_credentials.gid, _session.gid);
	ua_sess->buffer_type = buffer_type();
	ua_sess->bits_per_long = app->abi.bits_per_long;

	/* There is only one consumer object per session possible. */
	consumer_output_get(get_consumer_output_ptr());
	ua_sess->consumer = get_consumer_output_ptr();

	switch (ua_sess->buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		ret = snprintf(ua_sess->path,
			       sizeof(ua_sess->path),
			       DEFAULT_UST_TRACE_PID_PATH "/%s-%d-%s",
			       app->name,
			       app->pid,
			       datetime);
		break;
	case LTTNG_BUFFER_PER_UID:
		ret = snprintf(ua_sess->path,
			       sizeof(ua_sess->path),
			       DEFAULT_UST_TRACE_UID_PATH,
			       lttng_credentials_get_uid(&ua_sess->real_credentials),
			       app->abi.bits_per_long);
		break;
	default:
		abort();
		goto error;
	}
	if (ret < 0) {
		PERROR("asprintf UST shadow copy session");
		abort();
		goto error;
	}

	strncpy(ua_sess->root_shm_path, _root_shm_path.c_str(), sizeof(ua_sess->root_shm_path));
	ua_sess->root_shm_path[sizeof(ua_sess->root_shm_path) - 1] = '\0';
	strncpy(ua_sess->shm_path, shm_path().c_str(), sizeof(ua_sess->shm_path));
	ua_sess->shm_path[sizeof(ua_sess->shm_path) - 1] = '\0';
	if (ua_sess->shm_path[0]) {
		switch (ua_sess->buffer_type) {
		case LTTNG_BUFFER_PER_PID:
			ret = snprintf(tmp_shm_path,
				       sizeof(tmp_shm_path),
				       "/" DEFAULT_UST_TRACE_PID_PATH "/%s-%d-%s",
				       app->name,
				       app->pid,
				       datetime);
			break;
		case LTTNG_BUFFER_PER_UID:
			ret = snprintf(tmp_shm_path,
				       sizeof(tmp_shm_path),
				       "/" DEFAULT_UST_TRACE_UID_PATH,
				       app->uid,
				       app->abi.bits_per_long);
			break;
		default:
			abort();
			goto error;
		}
		if (ret < 0) {
			PERROR("sprintf UST shadow copy session");
			abort();
			goto error;
		}
		strncat(ua_sess->shm_path,
			tmp_shm_path,
			sizeof(ua_sess->shm_path) - strlen(ua_sess->shm_path) - 1);
		ua_sess->shm_path[sizeof(ua_sess->shm_path) - 1] = '\0';
	}
	return;

error:
	consumer_output_put(ua_sess->consumer);
}

int ls::ust::domain_orchestrator::_find_or_create_app_session(ust::app *app,
							      ust::app_session **ua_sess_ptr)
{
	int ret;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess_ptr);

	health_code_update();

	{
		const auto it = _app_sessions.find(app);
		if (it != _app_sessions.end()) {
			*ua_sess_ptr = it->second.get();
			return 0;
		}
	}

	DBG2("UST app pid: %d session id %" PRIu64 " not found, creating it",
	     app->pid,
	     _session_id());

	std::unique_ptr<ust::app_session> new_session(alloc_ust_app_session());
	if (!new_session) {
		ret = -ENOMEM;
		goto error;
	}

	_init_app_session(new_session.get(), app);

	switch (buffer_type()) {
	case LTTNG_BUFFER_PER_PID:
	{
		try {
			_find_or_create_per_pid_trace_class(
				*app,
				new_session->app_session_id,
				app->abi,
				app->version.major,
				app->version.minor,
				new_session->root_shm_path,
				new_session->shm_path,
				lttng_credentials_get_uid(&new_session->effective_credentials),
				lttng_credentials_get_gid(&new_session->effective_credentials));
		} catch (const std::exception& ex) {
			ERR("Failed to create per-PID trace class: %s", ex.what());
			delete_ust_app_session(-1, new_session.release(), app);
			ret = -1;
			goto error;
		}
		break;
	}
	case LTTNG_BUFFER_PER_UID:
	{
		const auto app_abi = app->abi.bits_per_long == 32 ? application_abi::ABI_32 :
								    application_abi::ABI_64;

		try {
			_find_or_create_per_uid_trace_class(app->uid,
							    app_abi,
							    app->abi,
							    app->version.major,
							    app->version.minor,
							    new_session->root_shm_path,
							    new_session->shm_path);
		} catch (const std::exception& ex) {
			ERR("Failed to create per-UID trace class: %s", ex.what());
			delete_ust_app_session(-1, new_session.release(), app);
			ret = -1;
			goto error;
		}
		break;
	}
	default:
		abort();
		ret = -EINVAL;
		goto error;
	}

	health_code_update();

	if (new_session->handle == -1) {
		int handle;
		try {
			handle = app->command_socket.lock().create_session();
		} catch (const ls::ust::app_communication_error&) {
			delete_ust_app_session(-1, new_session.release(), app);
			ret = -ENOTCONN;
			goto error;
		} catch (const lttng::runtime_error&) {
			delete_ust_app_session(-1, new_session.release(), app);
			ret = -ENOTCONN;
			goto error;
		}

		new_session->handle = handle;

		/* Register the session's objd in the app's registry. */
		new_session->objd_token = app->objd_registry.register_session_objd(
			new_session->handle, new_session->get_identifier());

		DBG2("UST app session created successfully with handle %d", handle);
	}

	{
		auto *ua_sess = new_session.get();
		_app_sessions[app] = std::move(new_session);
		*ua_sess_ptr = ua_sess;
	}

	ret = 0;

error:
	health_code_update();
	return ret;
}

int ls::ust::domain_orchestrator::_allocate_app_channel(
	const ust::app_session::locked_weak_ref& ua_sess,
	struct ust_app_channel **ua_chanp,
	const lsc::recording_channel_configuration& channel_config,
	std::uint64_t trace_class_stream_class_handle)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app_channel *ua_chan;

	ASSERT_RCU_READ_LOCKED();

	/* Lookup channel in the ust app session */
	lttng_ht_lookup(ua_sess->channels, (void *) channel_config.name.c_str(), &iter);
	ua_chan_node = lttng_ht_iter_get_node<lttng_ht_node_str>(&iter);
	if (ua_chan_node != nullptr) {
		ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);
		goto end;
	}

	ua_chan = alloc_ust_app_channel(ua_sess, nullptr, channel_config);
	if (ua_chan == nullptr) {
		/* Only malloc can fail here */
		ret = -ENOMEM;
		goto error;
	}
	init_ust_app_channel_from_config(ua_chan);
	ua_chan->trace_class_stream_class_handle = trace_class_stream_class_handle;
	ua_chan->attr.type =
		allocation_policy_to_ust_channel_type(channel_config.buffer_allocation_policy);

end:
	if (ua_chanp) {
		*ua_chanp = ua_chan;
	}

	/* Everything went well. */
	return 0;

error:
	return ret;
}

int ls::ust::domain_orchestrator::_create_channel_per_uid(ust::app *app,
							  ust::app_session *ua_sess,
							  struct ust_app_channel *ua_chan)
{
	int ret;
	enum lttng_error_code notification_ret;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);
	ASSERT_RCU_READ_LOCKED();

	auto *consumer = get_consumer_output_ptr();
	auto& session = const_cast<ltt_session&>(_session);

	DBG("UST app creating channel %s with per UID buffers",
	    ua_chan->channel_config.name.c_str());

	const auto& recording_config =
		static_cast<const lsc::recording_channel_configuration&>(ua_chan->channel_config);
	const auto app_abi = app->abi.bits_per_long == 32 ? ust::application_abi::ABI_32 :
							    ust::application_abi::ABI_64;

	/*
	 * Check if the per-UID stream group already exists for this
	 * channel. If so, the channel has already been created on the
	 * consumer and we only need to send it to this application.
	 */
	if (_has_per_uid_stream_group(recording_config, app->uid, app_abi)) {
		goto send_channel;
	}

	/*
	 * Look up the per-UID trace class. It must exist: it was created
	 * during app-session setup (find_or_create_ust_app_session).
	 */
	{
		auto trace_class_ptr = the_trace_class_index->find_per_uid(
			_session_id(), static_cast<std::uint32_t>(app_abi), app->uid);
		LTTNG_ASSERT(trace_class_ptr);

		/* Register the stream class (CTF channel) in the trace class. */
		try {
			trace_class_ptr->add_channel(
				ua_chan->trace_class_stream_class_handle,
				ust_channel_type_to_allocation_policy(ua_chan->attr.type));
		} catch (const std::exception& ex) {
			ERR("Failed to add a channel registry to userspace registry session: %s",
			    ex.what());
			ret = -1;
			goto error;
		}

		/*
		 * Create the buffers on the consumer side. This call populates the
		 * ust app channel object with all streams and data object.
		 */
		ret = do_consumer_create_channel(consumer,
						 ua_sess,
						 ua_chan,
						 app->abi.bits_per_long,
						 trace_class_ptr.get(),
						 session.current_trace_chunk,
						 session.trace_format,
						 _session.output_traces,
						 _session.live_timer);
		if (ret < 0) {
			ERR("Error creating UST channel \"%s\" on the consumer daemon",
			    ua_chan->channel_config.name.c_str());

			auto locked_registry = trace_class_ptr->lock();
			try {
				locked_registry->remove_channel(
					ua_chan->trace_class_stream_class_handle, false);
			} catch (const std::exception& ex) {
				DBG("Could not find channel for removal: %s", ex.what());
			}
			goto error;
		}

		/* Set the consumer key on the stream class. */
		{
			auto locked_registry = trace_class_ptr->lock();
			auto& ust_reg_chan =
				locked_registry->channel(ua_chan->trace_class_stream_class_handle);

			ust_reg_chan._consumer_key = ua_chan->key;
		}

		/*
		 * Transfer channel and stream objects directly to the
		 * orchestrator's stream group.
		 */
		{
			auto locked_registry = trace_class_ptr->lock();
			auto& stream_class_ref =
				locked_registry->channel(ua_chan->trace_class_stream_class_handle);

			ust::ust_object_data channel_obj(ua_chan->obj);
			ua_chan->obj = nullptr;

			auto& stream_group =
				_find_or_create_per_uid_stream_group(recording_config,
								     app->uid,
								     app_abi,
								     ua_chan->key,
								     std::move(channel_obj),
								     *trace_class_ptr,
								     stream_class_ref);

			unsigned int cpu_idx = 0;
			for (auto *stream :
			     lttng::urcu::list_iteration_adapter<ust::app_stream,
								 &ust::app_stream::list>(
				     ua_chan->streams.head)) {
				stream_group.add_stream(cpu_idx, ust::ust_object_data(stream->obj));
				stream->obj = nullptr;
				cpu_idx++;
			}
		}
	}

	/* Notify the notification subsystem of the channel's creation. */
	notification_ret = notification_thread_command_add_channel(
		the_notification_thread_handle,
		_session.id,
		ua_chan->channel_config.name.c_str(),
		ua_chan->key,
		LTTNG_DOMAIN_UST,
		ua_chan->attr.subbuf_size * ua_chan->attr.num_subbuf);
	if (notification_ret != LTTNG_OK) {
		ret = -(int) notification_ret;
		ERR("Failed to add channel to notification thread");
		goto error;
	}

send_channel:
	/* Send buffers to the application. */
	{
		auto& sg = _get_per_uid_stream_group(recording_config, app->uid, app_abi);

		ret = send_channel_uid_to_ust(sg, app, ua_sess, ua_chan);
		if (ret < 0) {
			if (ret != -ENOTCONN) {
				ERR("Error sending channel to application");
			}
			goto error;
		}
	}

error:
	return ret;
}

int ls::ust::domain_orchestrator::_create_channel_per_pid(
	ust::app *app,
	const ust::app_session::locked_weak_ref& ua_sess,
	struct ust_app_channel *ua_chan)
{
	int ret;
	enum lttng_error_code cmd_ret;
	uint64_t chan_reg_key;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_chan);

	auto *consumer = get_consumer_output_ptr();
	auto& session = const_cast<ltt_session&>(_session);

	DBG("UST app creating channel %s with per PID buffers",
	    ua_chan->channel_config.name.c_str());

	const lttng::urcu::read_lock_guard read_lock;

	auto registry = ust_app_get_session_registry(ua_sess->get_identifier());
	/* The UST app session lock is held, registry shall not be null. */
	LTTNG_ASSERT(registry);

	ASSERT_LOCKED(session._lock);

	/* Create and add a new channel registry to session. */
	try {
		registry->add_channel(ua_chan->key,
				      ust_channel_type_to_allocation_policy(ua_chan->attr.type));
	} catch (const std::exception& ex) {
		ERR("Error creating the UST channel \"%s\" registry instance: %s",
		    ua_chan->channel_config.name.c_str(),
		    ex.what());
		ret = -1;
		goto error;
	}

	/* Create and get channel on the consumer side. */
	ret = do_consumer_create_channel(consumer,
					 &ua_sess.get(),
					 ua_chan,
					 app->abi.bits_per_long,
					 registry.get(),
					 session.current_trace_chunk,
					 session.trace_format,
					 _session.output_traces,
					 _session.live_timer);
	if (ret < 0) {
		ERR("Error creating UST channel \"%s\" on the consumer daemon",
		    ua_chan->channel_config.name.c_str());
		goto error_remove_from_registry;
	}

	ret = send_channel_pid_to_ust(app, &ua_sess.get(), ua_chan);
	if (ret < 0) {
		if (ret != -ENOTCONN) {
			ERR("Error sending channel to application");
		}
		goto error_remove_from_registry;
	}

	chan_reg_key = ua_chan->key;
	{
		auto locked_registry = registry->lock();

		auto& ust_reg_chan = locked_registry->channel(chan_reg_key);
		ust_reg_chan._consumer_key = ua_chan->key;
	}

	/*
	 * Populate the orchestrator's per-PID stream group map.
	 * During the dual-write transition, the per-app channel
	 * retains the authoritative channel and stream objects. The
	 * stream group's channel object is null during this period;
	 * ownership will be transferred when the per-app channel
	 * objects are managed by the orchestrator.
	 */
	{
		const auto& recording_config =
			static_cast<const lsc::recording_channel_configuration&>(
				ua_chan->channel_config);
		auto& trace_class_ref = *registry;
		auto locked_registry = trace_class_ref.lock();
		auto& stream_class_ref = locked_registry->channel(chan_reg_key);

		_find_or_create_per_pid_stream_group(recording_config,
						     *app,
						     ua_chan->key,
						     ust::ust_object_data(nullptr),
						     trace_class_ref,
						     stream_class_ref);
	}

	cmd_ret = notification_thread_command_add_channel(the_notification_thread_handle,
							  _session.id,
							  ua_chan->channel_config.name.c_str(),
							  ua_chan->key,
							  LTTNG_DOMAIN_UST,
							  ua_chan->attr.subbuf_size *
								  ua_chan->attr.num_subbuf);
	if (cmd_ret != LTTNG_OK) {
		ret = -(int) cmd_ret;
		ERR("Failed to add channel to notification thread");
		goto error_remove_from_registry;
	}

error_remove_from_registry:
	if (ret) {
		try {
			auto locked_registry = registry->lock();
			locked_registry->remove_channel(ua_chan->key, false);
		} catch (const std::exception& ex) {
			DBG("Could not find channel for removal: %s", ex.what());
		}
	}
error:
	return ret;
}

int ls::ust::domain_orchestrator::_send_app_channel(ust::app *app,
						    const ust::app_session::locked_weak_ref& ua_sess,
						    struct ust_app_channel *ua_chan)
{
	int ret;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_chan);
	ASSERT_RCU_READ_LOCKED();

	/* Handle buffer type before sending the channel to the application. */
	switch (buffer_type()) {
	case LTTNG_BUFFER_PER_UID:
	{
		ret = _create_channel_per_uid(app, &ua_sess.get(), ua_chan);
		if (ret < 0) {
			goto error;
		}
		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		ret = _create_channel_per_pid(app, ua_sess, ua_chan);
		if (ret < 0) {
			goto error;
		}
		break;
	}
	default:
		abort();
		ret = -EINVAL;
		goto error;
	}

	/* Register the channel's objd in the app's registry. */
	{
		const auto chan_reg_key = (buffer_type() == LTTNG_BUFFER_PER_UID) ?
			ua_chan->trace_class_stream_class_handle :
			ua_chan->key;

		ua_chan->objd_token = app->objd_registry.register_channel_objd(
			ua_chan->handle, ua_sess->get_identifier(), chan_reg_key);
	}

	/* If channel is not enabled, disable it on the tracer */
	if (!ua_chan->enabled) {
		ret = disable_ust_channel(app, ua_chan);
		if (ret < 0) {
			goto error;
		}
	}

error:
	return ret;
}

int ls::ust::domain_orchestrator::_create_app_channel(
	const ust::app_session::locked_weak_ref& ua_sess,
	ust::app *app,
	struct ust_app_channel **_ua_chan,
	const lsc::recording_channel_configuration& channel_config,
	std::uint64_t trace_class_stream_class_handle)
{
	int ret = 0;
	struct ust_app_channel *ua_chan = nullptr;

	/*
	 * Create channel onto application and synchronize its
	 * configuration.
	 */
	ret = _allocate_app_channel(
		ua_sess, &ua_chan, channel_config, trace_class_stream_class_handle);
	if (ret < 0) {
		goto error;
	}

	ret = _send_app_channel(app, ua_sess, ua_chan);
	if (ret) {
		goto error;
	}

	/* Only publish the channel if successfully created on the tracer/consumer. */
	lttng_ht_add_unique_str(ua_sess->channels, &ua_chan->node);

	/* Add contexts. */
	for (const auto& ctx_uptr : channel_config.get_contexts()) {
		const auto& ctx_config = *ctx_uptr;

		if (is_context_redundant(channel_config, ctx_config)) {
			continue;
		}

		auto ust_ctx_attr = _make_ust_context_attr(ctx_config);
		ret = create_ust_app_channel_context(ua_chan, &ust_ctx_attr, app, ctx_config);
		if (ret) {
			goto error;
		}
	}

error:
	if (ret < 0 && ua_chan) {
		const auto registry = ust_app_get_session_registry(ua_sess->get_identifier());
		/* The UST app session lock is held, registry shall not be null. */
		LTTNG_ASSERT(registry);

		const auto locked_registry = registry->lock();
		delete_ust_app_channel(-1, ua_chan, app, locked_registry);
		ua_chan = nullptr;
	} else if (ret == 0 && _ua_chan) {
		/*
		 * Only return the application's channel on success. Note
		 * that the channel can still be part of the application's
		 * channel hashtable on error.
		 */
		*_ua_chan = ua_chan;
	}

	return ret;
}

int ls::ust::domain_orchestrator::_find_or_create_app_channel(
	const ust::app_session::locked_weak_ref& ua_sess,
	ust::app *app,
	struct ust_app_channel **ua_chan,
	const lsc::recording_channel_configuration& channel_config,
	std::uint64_t trace_class_stream_class_handle)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;

	lttng_ht_lookup(ua_sess->channels, (void *) channel_config.name.c_str(), &iter);
	ua_chan_node = lttng_ht_iter_get_node<lttng_ht_node_str>(&iter);
	if (ua_chan_node) {
		*ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);
		goto end;
	}

	ret = _create_app_channel(
		ua_sess, app, ua_chan, channel_config, trace_class_stream_class_handle);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

int ls::ust::domain_orchestrator::_synchronize_channel_event(
	struct ust_app_channel *ua_chan,
	ust::app *app,
	const lsc::event_rule_configuration& event_config)
{
	int ret = 0;

	auto *ua_event = find_ust_app_event_by_config(ua_chan->events, event_config);
	if (!ua_event) {
		ret = create_ust_app_event(ua_chan, app, event_config);
		if (ret < 0) {
			goto end;
		}
	} else {
		if (ua_event->enabled != event_config.is_enabled) {
			ret = event_config.is_enabled ? enable_ust_app_event(ua_event, app) :
							disable_ust_app_event(ua_event, app);
		}
	}

end:
	return ret;
}

void ls::ust::domain_orchestrator::_synchronize_all_channels(
	const ust::app_session::locked_weak_ref& ua_sess, ust::app *app)
{
	LTTNG_ASSERT(app);
	ASSERT_RCU_READ_LOCKED();

	const auto& config_domain = _session.user_space_domain;

	for (const auto& chan_config : config_domain.recording_channels()) {
		struct ust_app_channel *ua_chan;

		const auto handle = _trace_class_stream_class_handle(chan_config);

		/*
		 * Search for a matching ust_app_channel. If none is found,
		 * create it. Creating the channel will cause the ua_chan
		 * structure to be allocated, the channel buffers to be
		 * allocated (if necessary) and sent to the application, and
		 * all enabled contexts will be added to the channel.
		 */
		int ret = _find_or_create_app_channel(ua_sess, app, &ua_chan, chan_config, handle);
		if (ret) {
			/* Tracer is probably gone or ENOMEM. */
			goto end;
		}

		if (!ua_chan) {
			/* ua_chan will be NULL for the metadata channel */
			continue;
		}

		for (const auto& event_rule_entry : chan_config.event_rules) {
			ret = _synchronize_channel_event(ua_chan, app, *event_rule_entry.second);
			if (ret) {
				goto end;
			}
		}

		if (ua_chan->enabled != chan_config.is_enabled) {
			ret = chan_config.is_enabled ?
				enable_ust_channel(app, ua_chan) :
				disable_ust_app_channel(ua_sess, ua_chan, app);
			if (ret) {
				goto end;
			}
		}
	}
end:
	return;
}

/*
 * Create UST metadata and open it on the tracer side.
 *
 * Called with UST app session lock held and RCU read side lock.
 */
int ls::ust::domain_orchestrator::_create_app_metadata(
	const ust::app_session::locked_weak_ref& ua_sess, ust::app *app)
{
	int ret = 0;
	struct ust_app_channel *metadata;
	struct consumer_socket *socket;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(get_consumer_output_ptr());
	ASSERT_RCU_READ_LOCKED();

	auto locked_registry = get_locked_session_registry(ua_sess->get_identifier());
	/* The UST app session is held registry shall not be null. */
	LTTNG_ASSERT(locked_registry);

	ASSERT_LOCKED(_session._lock);

	const auto& metadata_config =
		_session.get_domain(lttng::domain_class::USER_SPACE).metadata_channel();

	/* Metadata already exists for this registry or it was closed previously */
	if (locked_registry->_metadata_key || locked_registry->_metadata_closed) {
		ret = 0;
		goto error;
	}

	/* Allocate UST metadata */
	metadata = alloc_ust_app_metadata_channel(ua_sess, metadata_config);
	if (!metadata) {
		/* malloc() failed */
		ret = -ENOMEM;
		goto error;
	}

	{
		const auto default_attr = _default_metadata_channel_attr();
		copy_channel_attr_to_ustctl(&metadata->attr, &default_attr);
	}

	/* Need one fd for the channel. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 1);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon create metadata");
		goto error;
	}

	/* Get the right consumer socket for the application. */
	socket = consumer_find_socket_by_bitness(app->abi.bits_per_long, get_consumer_output_ptr());
	if (!socket) {
		ret = -EINVAL;
		goto error_consumer;
	}

	/*
	 * Keep metadata key so we can identify it on the consumer side. Assign it
	 * to the registry *before* we ask the consumer so we avoid the race of the
	 * consumer requesting the metadata and the ask_channel call on our side
	 * did not returned yet.
	 */
	locked_registry->_metadata_key = metadata->key;

	/*
	 * Ask the metadata channel creation to the consumer. The metadata object
	 * will be created by the consumer and kept their. However, the stream is
	 * never added or monitored until we do a first push metadata to the
	 * consumer.
	 */
	ret = ust_consumer_ask_channel(&ua_sess.get(),
				       metadata,
				       get_consumer_output_ptr(),
				       socket,
				       locked_registry.locked_ref().get(),
				       _session.current_trace_chunk,
				       _session.trace_format,
				       _session.output_traces,
				       _session.live_timer);
	if (ret < 0) {
		/* Nullify the metadata key so we don't try to close it later on. */
		locked_registry->_metadata_key = 0;
		goto error_consumer;
	}

	/*
	 * The setup command will make the metadata stream be sent to the relayd,
	 * if applicable, and the thread managing the metadatas. This is important
	 * because after this point, if an error occurs, the only way the stream
	 * can be deleted is to be monitored in the consumer.
	 */
	ret = consumer_setup_metadata(socket, metadata->key);
	if (ret < 0) {
		/* Nullify the metadata key so we don't try to close it later on. */
		locked_registry->_metadata_key = 0;
		goto error_consumer;
	}

	DBG2("UST metadata with key %" PRIu64 " created for app pid %d", metadata->key, app->pid);

error_consumer:
	lttng_fd_put(LTTNG_FD_APPS, 1);
	delete_ust_app_channel(-1, metadata, app, locked_registry.locked_ref());
error:
	return ret;
}

void ls::ust::domain_orchestrator::synchronize_app(ust::app& app)
{
	namespace lsc = lttng::sessiond::config;

	if (!app.compatible) {
		return;
	}

	const auto& domain = _session.user_space_domain;

	if (domain.virtual_process_id_tracker().is_tracked(app.pid) &&
	    domain.virtual_user_id_tracker().is_tracked(
		    lsc::resolved_process_attr_value<uid_t>(app.uid)) &&
	    domain.virtual_group_id_tracker().is_tracked(
		    lsc::resolved_process_attr_value<gid_t>(app.gid))) {
		ust::app_session *ua_sess = nullptr;
		const auto ret = _find_or_create_app_session(&app, &ua_sess);
		if (ret < 0) {
			/* Tracer is probably gone or ENOMEM. */
			return;
		}

		LTTNG_ASSERT(ua_sess);

		{
			const auto locked_ua_sess = ua_sess->lock();
			if (!locked_ua_sess->deleted) {
				const lttng::urcu::read_lock_guard read_lock;
				_synchronize_all_channels(locked_ua_sess, &app);

				/*
				 * Create the metadata for the application. This returns
				 * gracefully if a metadata was already set for the session.
				 *
				 * The metadata channel must be created after the data
				 * channels as the consumer daemon assumes this ordering.
				 * When interacting with a relay daemon, the consumer will
				 * use this assumption to send the "STREAMS_SENT" message
				 * to the relay daemon.
				 */
				const auto md_ret = _create_app_metadata(locked_ua_sess, &app);
				if (md_ret < 0) {
					ERR("Metadata creation failed for app sock %d for session id %" PRIu64,
					    app.command_socket.fd(),
					    _session_id());
				}
			}
		}

		if (_active) {
			_start_app_trace(&app);
		}
	} else {
		if (_find_app_session(app)) {
			on_app_departure(app);
		}
	}
}

unsigned int ls::ust::domain_orchestrator::on_app_departure(
	ust::app& app, const nonstd::optional<uint32_t>& owner_id_to_reclaim)
{
	const auto it = _app_sessions.find(&app);
	if (it == _app_sessions.end()) {
		return 0;
	}

	/*
	 * Destroy the app_session. For per-PID buffers, flush all
	 * application streams before teardown to ensure proper
	 * data_pending behavior.
	 *
	 * The unique_ptr destruction runs the app_session's RAII token
	 * destructor, which deregisters the session objd from
	 * app.objd_registry. Channel tokens are destroyed when their
	 * channels are destroyed during delete_ust_app_session().
	 */
	auto owned_session = std::move(it->second);
	_app_sessions.erase(it);

	if (owned_session->buffer_type == LTTNG_BUFFER_PER_PID) {
		(void) _flush_app_session(app, *owned_session);
		_save_per_pid_stats_on_departure(*owned_session);
	}

	/*
	 * When reclaiming an owner ID, tell the consumer daemon before
	 * destroying the app session: the consumer needs the channels
	 * to still exist when processing the reclamation command.
	 */
	unsigned int pending_reclamations = 0;
	if (owner_id_to_reclaim) {
		pending_reclamations = consumer_reclaim_session_owner_id(
			*owned_session, *owner_id_to_reclaim);
	}

	delete_ust_app_session(app.command_socket.fd(), owned_session.release(), &app);

	if (buffer_type() == LTTNG_BUFFER_PER_PID) {
		_release_per_pid_stream_groups(app);
		_release_per_pid_trace_class(app);
	}

	return pending_reclamations;
}

void ls::ust::domain_orchestrator::_synchronize_all_apps()
{
	for (auto *app : lttng::urcu::lfht_iteration_adapter<ust::app,
							     decltype(ust::app::pid_n),
							     &ust::app::pid_n>(*ust_app_ht->ht)) {
		if (!ust_app_get(*app)) {
			DBG("Could not get application reference as it is being torn down; skipping application");
			continue;
		}

		const ust_app_reference app_ref(app);

		synchronize_app(*app);
	}
}

int ls::ust::domain_orchestrator::_start_app_trace(ust::app *app)
{
	ust::app_session *ua_sess;

	DBG("Starting tracing for ust app pid %d", app->pid);

	const lttng::urcu::read_lock_guard read_lock;
	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	if (!app->compatible) {
		return 0;
	}

	ua_sess = _find_app_session(*app);
	if (ua_sess == nullptr) {
		/* The session is in teardown process. Ignore and continue. */
		return 0;
	}

	auto locked_ua_sess = ua_sess->lock();

	if (locked_ua_sess->deleted) {
		return 0;
	}

	if (locked_ua_sess->enabled) {
		return 0;
	}

	/* This starts the UST tracing */
	try {
		app->command_socket.lock().start_session(ua_sess->handle);
	} catch (const ls::ust::app_communication_error&) {
		return 0;
	} catch (const lttng::runtime_error&) {
		return -1;
	}

	/* Indicate that the session has been started once */
	ua_sess->started = true;
	ua_sess->enabled = true;

	health_code_update();

	/* Quiescent wait after starting trace */
	try {
		app->command_socket.lock().wait_quiescent();
	} catch (const ls::ust::app_communication_error&) {
	} catch (const lttng::runtime_error&) {
	}

	return 0;
}

int ls::ust::domain_orchestrator::_stop_app_trace(ust::app *app)
{
	ust::app_session *ua_sess;

	DBG("Stopping tracing for ust app pid %d", app->pid);

	const lttng::urcu::read_lock_guard read_lock;
	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	if (!app->compatible) {
		return 0;
	}

	ua_sess = _find_app_session(*app);
	if (ua_sess == nullptr) {
		return 0;
	}

	auto locked_ua_sess = ua_sess->lock();

	if (ua_sess->deleted) {
		return 0;
	}

	/*
	 * If started = 0, it means that stop trace has been called for a session
	 * that was never started. It's possible since we can have a fail start
	 * from either the application manager thread or the command thread. Simply
	 * indicate that this is a stop error.
	 */
	if (!ua_sess->started) {
		return -1;
	}

	health_code_update();

	/* This inhibits UST tracing */
	try {
		app->command_socket.lock().stop_session(ua_sess->handle);
	} catch (const ls::ust::app_communication_error&) {
		return 0;
	} catch (const lttng::runtime_error&) {
		return -1;
	}

	health_code_update();
	ua_sess->enabled = false;

	/* Quiescent wait after stopping trace */
	try {
		app->command_socket.lock().wait_quiescent();
	} catch (const ls::ust::app_communication_error&) {
	} catch (const lttng::runtime_error&) {
	}

	health_code_update();

	{
		auto registry = ust_app_get_session_registry(locked_ua_sess->get_identifier());
		LTTNG_ASSERT(registry);
		auto locked_registry = registry->lock();
		if (!locked_registry->_metadata_closed) {
			const auto socket = consumer_find_socket_by_bitness(
				locked_registry->abi.bits_per_long, ua_sess->consumer);
			if (socket) {
				(void) ust_app_push_metadata(locked_registry, socket, 0);
			}
		}
	}

	return 0;
}

int ls::ust::domain_orchestrator::_flush_app_session(ust::app& app, ust::app_session& ua_sess)
{
	int ret, retval = 0;
	struct consumer_socket *socket;

	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	DBG("Flushing app session buffers for ust app pid %d", app.pid);

	if (!app.compatible) {
		return 0;
	}

	const auto locked_ua_sess = ua_sess.lock();
	if (locked_ua_sess->deleted) {
		return 0;
	}

	health_code_update();

	/* Flushing buffers */
	socket = consumer_find_socket_by_bitness(app.abi.bits_per_long, ua_sess.consumer);

	/* Flush buffers and push metadata. */
	switch (ua_sess.buffer_type) {
	case LTTNG_BUFFER_PER_PID:
	{
		for (auto *ua_chan :
		     lttng::urcu::lfht_iteration_adapter<ust_app_channel,
							 decltype(ust_app_channel::node),
							 &ust_app_channel::node>(
			     *ua_sess.channels->ht)) {
			health_code_update();
			ret = consumer_flush_channel(socket, ua_chan->key);
			if (ret) {
				ERR("Error flushing consumer channel");
				retval = -1;
				continue;
			}
		}

		break;
	}
	case LTTNG_BUFFER_PER_UID:
	default:
		abort();
		break;
	}

	return retval;
}

int ls::ust::domain_orchestrator::_clear_quiescent_app_session(ust::app *app,
							       ust::app_session *ua_sess)
{
	int ret = 0;
	struct consumer_socket *socket;

	DBG("Clearing stream quiescent state for ust app pid %d", app->pid);

	const lttng::urcu::read_lock_guard read_lock;
	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	if (!app->compatible) {
		return 0;
	}

	const auto locked_ua_sess = ua_sess->lock();
	if (locked_ua_sess->deleted) {
		return 0;
	}

	health_code_update();

	socket = consumer_find_socket_by_bitness(app->abi.bits_per_long, ua_sess->consumer);
	if (!socket) {
		ERR("Failed to find consumer (%" PRIu32 ") socket", app->abi.bits_per_long);
		return -1;
	}

	/* Clear quiescent state. */
	switch (ua_sess->buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		for (auto *ua_chan :
		     lttng::urcu::lfht_iteration_adapter<ust_app_channel,
							 decltype(ust_app_channel::node),
							 &ust_app_channel::node>(
			     *ua_sess->channels->ht)) {
			health_code_update();
			ret = consumer_clear_quiescent_channel(socket, ua_chan->key);
			if (ret) {
				ERR("Error clearing quiescent state for consumer channel");
				ret = -1;
				continue;
			}
		}
		break;
	case LTTNG_BUFFER_PER_UID:
	default:
		abort();
		ret = -1;
		break;
	}

	return ret;
}

void ls::ust::domain_orchestrator::start()
{
	if (_active) {
		return;
	}

	/*
	 * Set _active before iterating applications so that newly
	 * registering apps (via dispatch thread) see the session as
	 * active and are started by default.
	 */
	_active = true;

	/*
	 * In a start-stop-start use-case, clear the quiescent state of
	 * each channel so that a following stop or destroy grabs a
	 * timestamp_end near those operations, even if the packet is
	 * empty.
	 *
	 * Per-UID channels are handled by the orchestrator directly;
	 * per-PID channels are handled via the per-app iteration.
	 */
	if (buffer_type() == LTTNG_BUFFER_PER_UID) {
		_clear_quiescent_per_uid_channels();
	}

	if (buffer_type() == LTTNG_BUFFER_PER_PID) {
		const lttng::urcu::read_lock_guard read_lock;

		for (const auto& app_session_pair : _app_sessions) {
			auto *app = const_cast<ust::app *>(app_session_pair.first);

			if (!ust_app_get(*app)) {
				continue;
			}

			const ust_app_reference app_ref(app);
			(void) _clear_quiescent_app_session(app, app_session_pair.second.get());
		}
	}

	_synchronize_all_apps();
}

void ls::ust::domain_orchestrator::stop()
{
	if (!_active) {
		return;
	}

	/*
	 * Set _active before iterating applications so that newly
	 * registering apps (via dispatch thread) see the session as
	 * inactive and are not started.
	 */
	_active = false;

	/*
	 * Stop every running application. _app_sessions is complete at
	 * this point: start() synchronized all pre-existing apps, and
	 * the dispatch thread added any apps that registered since then.
	 */
	{
		const lttng::urcu::read_lock_guard read_lock;

		for (const auto& app_session_pair : _app_sessions) {
			auto *app = const_cast<ust::app *>(app_session_pair.first);

			if (!ust_app_get(*app)) {
				continue;
			}

			const ust_app_reference app_ref(app);

			(void) _stop_app_trace(app);
		}
	}

	/*
	 * Flush per-PID application buffers. Per-UID buffers are flushed
	 * below via _flush_per_uid_buffers().
	 */
	if (buffer_type() == LTTNG_BUFFER_PER_PID) {
		const lttng::urcu::read_lock_guard read_lock;
		for (const auto& app_session_pair : _app_sessions) {
			auto *app = const_cast<ust::app *>(app_session_pair.first);
			if (!ust_app_get(*app)) {
				continue;
			}
			const ust_app_reference app_ref(app);
			(void) _flush_app_session(*app, *app_session_pair.second);
		}
	}

	/*
	 * Flush per-UID consumer buffers and push pending metadata.
	 * Per-PID buffers were flushed per-application above.
	 */
	if (buffer_type() == LTTNG_BUFFER_PER_UID) {
		_flush_per_uid_buffers();
	}
}

void ls::ust::domain_orchestrator::_push_metadata(
	const ls::ust::trace_class::locked_ref& locked_trace_class) const
{
	if (locked_trace_class->_metadata_closed) {
		return;
	}

	const auto socket = consumer_find_socket_by_bitness(locked_trace_class->abi.bits_per_long,
							    get_consumer_output_ptr());
	if (!socket) {
		return;
	}

	(void) ust_app_push_metadata(locked_trace_class, socket, 0);
}

void ls::ust::domain_orchestrator::_flush_per_uid_buffers() const
{
	auto *consumer = get_consumer_output_ptr();

	_for_each_consumer_stream_group([this,
					 consumer](const _consumer_stream_group_descriptor& desc) {
		const lttng::urcu::read_lock_guard read_lock;

		const auto socket =
			consumer_find_socket_by_bitness(static_cast<int>(desc.abi), consumer);
		if (!socket) {
			return;
		}

		if (desc.is_metadata) {
			_push_metadata(desc.trace_class.lock());
		} else {
			(void) consumer_flush_channel(socket, desc.consumer_key);
		}
	});
}

void ls::ust::domain_orchestrator::_clear_quiescent_per_uid_channels() const
{
	_for_each_consumer_stream_group([this](const _consumer_stream_group_descriptor& desc) {
		if (desc.is_metadata) {
			return;
		}

		const lttng::urcu::read_lock_guard read_lock;

		const auto socket = consumer_find_socket_by_bitness(static_cast<int>(desc.abi),
								    get_consumer_output_ptr());
		if (!socket) {
			return;
		}

		(void) consumer_clear_quiescent_channel(socket, desc.consumer_key);
	});
}

void ls::ust::domain_orchestrator::rotate()
{
	auto result = LTTNG_OK;
	auto *consumer = get_consumer_output_ptr();

	_for_each_consumer_stream_group([this, consumer, &result](
						const _consumer_stream_group_descriptor& desc) {
		const lttng::urcu::read_lock_guard read_lock;

		if (result != LTTNG_OK) {
			return;
		}

		const auto socket =
			consumer_find_socket_by_bitness(static_cast<int>(desc.abi), consumer);
		if (!socket) {
			result = LTTNG_ERR_INVALID;
			return;
		}

		if (desc.is_metadata) {
			_push_metadata(desc.trace_class.lock());
		}

		const auto rotate_ret = consumer_rotate_channel(
			socket, desc.consumer_key, consumer, desc.is_metadata);
		if (rotate_ret < 0) {
			result = LTTNG_ERR_ROTATION_FAIL_CONSUMER;
		}
	});

	if (result != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to rotate UST session", result);
	}
}

void ls::ust::domain_orchestrator::clear()
{
	if (_active) {
		ERR("Expecting inactive session %s (%" PRIu64 ")", _session.name, _session.id);
		LTTNG_THROW_CTL("Failed to clear UST session", LTTNG_ERR_FATAL);
	}

	auto *consumer = get_consumer_output_ptr();
	const auto buf_type = buffer_type();
	auto result = LTTNG_OK;

	_for_each_consumer_stream_group([this, consumer, buf_type, &result](
						const _consumer_stream_group_descriptor& desc) {
		if (result != LTTNG_OK) {
			return;
		}

		/* Protect looked-up consumer socket. */
		const lttng::urcu::read_lock_guard read_lock;

		const auto consumer_socket =
			consumer_find_socket_by_bitness(static_cast<int>(desc.abi), consumer);

		if (desc.is_metadata) {
			_push_metadata(desc.trace_class.lock());
		}

		const auto clean_ret = consumer_clear_channel(consumer_socket, desc.consumer_key);
		if (clean_ret < 0) {
			if (clean_ret == -LTTCOMM_CONSUMERD_CHAN_NOT_FOUND &&
			    buf_type == LTTNG_BUFFER_PER_PID) {
				return;
			}

			if (clean_ret == -LTTCOMM_CONSUMERD_RELAYD_CLEAR_DISALLOWED) {
				result = LTTNG_ERR_CLEAR_RELAY_DISALLOWED;
				return;
			}

			result = LTTNG_ERR_CLEAR_FAIL_CONSUMER;
		}
	});

	if (result != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to clear UST session", result);
	}
}

/*
 * Open data channel packets for all consumer stream groups.
 *
 * Metadata channels are skipped: the begin/end timestamps of a metadata
 * packet are useless. Moreover, opening a packet after a "clear" would
 * introduce padding that was not part of the first trace chunk. The
 * relay daemon expects the content of the metadata stream of successive
 * metadata trace chunks to be strict supersets of one another.
 */
void ls::ust::domain_orchestrator::open_packets()
{
	auto *consumer = get_consumer_output_ptr();
	const auto buf_type = buffer_type();
	auto result = LTTNG_OK;

	_for_each_consumer_stream_group([consumer, buf_type, &result](
						const _consumer_stream_group_descriptor& desc) {
		if (result != LTTNG_OK || desc.is_metadata) {
			return;
		}

		/* Protect looked-up consumer socket. */
		const lttng::urcu::read_lock_guard read_lock;

		const auto socket =
			consumer_find_socket_by_bitness(static_cast<int>(desc.abi), consumer);

		const auto open_ret = consumer_open_channel_packets(socket, desc.consumer_key);
		if (open_ret < 0) {
			/* Per-PID buffer and application going away. */
			if (open_ret == -LTTCOMM_CONSUMERD_CHAN_NOT_FOUND &&
			    buf_type == LTTNG_BUFFER_PER_PID) {
				return;
			}

			result = LTTNG_ERR_UNK;
		}
	});

	if (result != LTTNG_OK) {
		LTTNG_THROW_CTL("Failed to open UST packets", result);
	}
}

void ls::ust::domain_orchestrator::_close_per_uid_metadata_on_consumer() const
{
	const lttng::urcu::read_lock_guard read_lock;

	for (const auto& tc_entry : _per_uid_trace_classes) {
		const auto& abi = tc_entry.first.abi;
		const auto& trace_class = *tc_entry.second;

		if (!trace_class._metadata_key) {
			continue;
		}

		auto *socket = consumer_find_socket_by_bitness(static_cast<int>(abi),
							       _consumer_output.get());
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
		_record_snapshot_per_pid(snapshot_consumer, nb_packets_per_stream);
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

void ls::ust::domain_orchestrator::_record_snapshot_per_pid(
	const struct consumer_output& snapshot_consumer, std::uint64_t nb_packets_per_stream) const
{
	for (const auto& tc_entry : _per_pid_trace_classes) {
		const auto *app = tc_entry.first;
		auto& trace_class = *tc_entry.second;

		if (!trace_class._metadata_key) {
			/* Skip since no metadata is present. */
			continue;
		}

		/*
		 * Skip entries whose trace class has been marked as
		 * closed. This happens when the application departs:
		 * ust_app_unregister() sets _metadata_closed and closes
		 * the channels on the consumer before the orchestrator
		 * maps are cleaned up.
		 */
		{
			const auto locked_tc = trace_class.lock();

			if (locked_tc->_metadata_closed) {
				continue;
			}
		}

		lttng::urcu::read_lock_guard read_lock;
		auto *socket = consumer_find_socket_by_bitness(
			static_cast<int>(app->abi.bits_per_long), _consumer_output.get());
		if (!socket) {
			LTTNG_THROW_CTL("Failed to find consumer socket for snapshot",
					LTTNG_ERR_INVALID);
		}

		/* Build per-PID trace path: pid/<name>-<pid>-<datetime>. */
		struct tm timeinfo_buf = {};
		const auto *timeinfo = localtime_r(&app->registration_time, &timeinfo_buf);
		char datetime[16];
		strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);

		const auto pid_path = lttng::format(
			DEFAULT_UST_TRACE_PID_PATH "/{}-{}-{}", app->name, app->pid, datetime);

		std::size_t consumer_path_offset = 0;
		const auto trace_path_raw = setup_channel_trace_path(
			_consumer_output.get(), pid_path.c_str(), &consumer_path_offset);
		if (!trace_path_raw) {
			LTTNG_THROW_CTL("Failed to setup channel trace path for snapshot",
					LTTNG_ERR_INVALID);
		}

		const auto free_trace_path = lttng::make_scope_exit(
			[trace_path_raw]() noexcept { free(trace_path_raw); });
		const auto *trace_path = &trace_path_raw[consumer_path_offset];

		/* Snapshot data channels. */
		for (const auto& sg_entry : _per_pid_stream_groups) {
			if (sg_entry.first.app != app) {
				continue;
			}

			const auto status =
				consumer_snapshot_channel(socket,
							  sg_entry.second->consumer_key(),
							  &snapshot_consumer,
							  0,
							  trace_path,
							  nb_packets_per_stream);
			switch (status) {
			case LTTNG_OK:
				break;
			case LTTNG_ERR_CHAN_NOT_FOUND:
				continue;
			default:
				LTTNG_THROW_SNAPSHOT_FAILURE(
					"Failed to snapshot UST per-PID data channel");
			}
		}

		/* Snapshot metadata channel. */
		const auto status = consumer_snapshot_channel(
			socket, trace_class._metadata_key, &snapshot_consumer, 1, trace_path, 0);
		switch (status) {
		case LTTNG_OK:
			break;
		case LTTNG_ERR_CHAN_NOT_FOUND:
			continue;
		default:
			LTTNG_THROW_SNAPSHOT_FAILURE(
				"Failed to snapshot UST per-PID metadata channel");
		}
	}
}

void ls::ust::domain_orchestrator::regenerate_metadata()
{
	if (buffer_type() == LTTNG_BUFFER_PER_PID) {
		LTTNG_THROW_CTL(
			"Metadata regeneration is not supported for per-PID buffering sessions",
			LTTNG_ERR_PER_PID_SESSION);
	}

	for (const auto& tc_entry : _per_uid_trace_classes) {
		tc_entry.second->regenerate_metadata();
	}
}

void ls::ust::domain_orchestrator::regenerate_statedump()
{
	DBG("Regenerating the statedump for all UST apps");

	const lttng::urcu::read_lock_guard read_lock;

	for (const auto& app_session_pair : _app_sessions) {
		auto *app = const_cast<ust::app *>(app_session_pair.first);
		auto *ua_sess = app_session_pair.second.get();

		if (!ust_app_get(*app)) {
			continue;
		}

		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			continue;
		}

		const auto locked_ua_sess = ua_sess->lock();
		if (locked_ua_sess->deleted) {
			continue;
		}

		try {
			app->command_socket.lock().regenerate_statedump(ua_sess->handle);
		} catch (const ls::ust::app_communication_error&) {
		} catch (const lttng::runtime_error&) {
		}
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

		/*
		 * Iterate the orchestrator's per-PID trace class map so that
		 * subdirectories are created for exactly the same set of
		 * applications that for_each_consumer_stream_group() will visit
		 * during rotation. Both maps are only mutated under the session
		 * lock, so there is no TOCTOU race between subdirectory creation
		 * and the subsequent rotation.
		 *
		 * Any app present in the map is guaranteed to still have its
		 * ua_sess accessible: the orchestrator entry is removed (under
		 * session lock) before the app session is torn down.
		 */
		for (const auto& tc_entry : _per_pid_trace_classes) {
			const auto *ua_sess = _find_app_session(*tc_entry.first);
			if (!ua_sess) {
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

namespace {
/*
 * Issue a memory reclamation request for the specified consumer channel keys
 * (effectively stream groups).
 *
 * The results are matched back to the stream group owners provided to
 * populate the result vector providing proper stream group ownership
 * information along with the reclaimed memory sizes (completed and pending).
 */
void issue_consumer_reclaim_channel_memory(
	consumer_socket& consumer_socket,
	const std::vector<ls::commands::stream_group_owner>& stream_group_owners,
	bool is_per_cpu_stream,
	const std::vector<std::uint64_t>& target_consumer_channel_keys,
	const nonstd::optional<std::chrono::microseconds>& reclaim_older_than_age,
	bool only_reclaim_consumed_data,
	std::uint64_t memory_reclaim_request_token,
	std::vector<ls::commands::stream_memory_reclamation_result_group>& result)
{
	if (target_consumer_channel_keys.empty()) {
		return;
	}

	std::size_t current_channel_index = 0;
	const auto channels_reclaimed_memory =
		ls::consumer::reclaim_channels_memory(consumer_socket,
						      target_consumer_channel_keys,
						      reclaim_older_than_age,
						      only_reclaim_consumed_data,
						      memory_reclaim_request_token);

	for (const auto& channel_reclaimed_memory : channels_reclaimed_memory) {
		const auto& group_owner = stream_group_owners.at(current_channel_index);

		std::uint64_t cpu_id = 0;
		std::vector<ls::commands::stream_memory_reclamation_result> streams_reclaimed_memory;
		for (const auto& stream_reclaimed_memory :
		     channel_reclaimed_memory.streams_reclaimed_memory) {
			const ls::commands::stream_identifier stream_identifier{
				is_per_cpu_stream ?
					decltype(ls::commands::stream_identifier::cpu_id)(
						cpu_id++) :
					nonstd::nullopt
			};

			streams_reclaimed_memory.emplace_back(
				stream_identifier,
				stream_reclaimed_memory.subbuffers_reclaimed,
				stream_reclaimed_memory.pending_subbuffers_to_reclaim);
		}

		result.emplace_back(group_owner, std::move(streams_reclaimed_memory));

		current_channel_index++;
	}
}

void append_consumer_channel_memory_usage(
	std::vector<ls::commands::stream_memory_usage_group>& result,
	const std::vector<std::uint64_t>& consumer_channel_keys,
	const std::vector<ls::commands::stream_group_owner>& stream_group_owners,
	bool is_per_cpu_stream,
	consumer_socket& consumer_socket)
{
	if (consumer_channel_keys.empty()) {
		return;
	}

	std::size_t current_channel_index = 0;
	const auto channels_memory_usage =
		ls::consumer::get_channels_memory_usage(consumer_socket, consumer_channel_keys);

	for (const auto& channel_usage : channels_memory_usage) {
		const auto& group_owner = stream_group_owners.at(current_channel_index);

		std::uint64_t cpu_id = 0;
		std::vector<ls::commands::stream_memory_usage> streams_memory_usage;
		for (const auto& stream_usage : channel_usage.streams_memory_usage) {
			const ls::commands::stream_identifier stream_identifier{
				is_per_cpu_stream ?
					decltype(ls::commands::stream_identifier::cpu_id)(
						cpu_id++) :
					nonstd::nullopt
			};

			streams_memory_usage.emplace_back(stream_identifier,
							  stream_usage.size_bytes.logical,
							  stream_usage.size_bytes.physical);
		}

		result.emplace_back(group_owner, std::move(streams_memory_usage));

		current_channel_index++;
	}
}

} /* namespace */

void ls::ust::domain_orchestrator::_collect_stream_group_keys_by_bitness(
	const lsc::recording_channel_configuration& target_channel_config,
	std::vector<std::uint64_t>& consumer32_channel_keys,
	std::vector<std::uint64_t>& consumer64_channel_keys,
	std::vector<ls::commands::stream_group_owner>& consumer32_owners,
	std::vector<ls::commands::stream_group_owner>& consumer64_owners) const
{
	_for_each_consumer_stream_group([&target_channel_config,
					 &consumer32_channel_keys,
					 &consumer64_channel_keys,
					 &consumer32_owners,
					 &consumer64_owners](
						const _consumer_stream_group_descriptor& desc) {
		/* Only consider data channels. */
		if (desc.is_metadata) {
			return;
		}

		/*
		 * Filter by channel configuration pointer identity: the
		 * orchestrator passes the actual recording_channel_configuration
		 * reference from the stream group key.
		 */
		if (&desc.channel_config != &target_channel_config) {
			return;
		}

		const auto owner = [&desc]() {
			if (desc.owner_uid) {
				return ls::commands::stream_group_owner(desc.abi, *desc.owner_uid);
			}

			return ls::commands::stream_group_owner(desc.abi, *desc.owner_pid);
		}();

		if (desc.abi == ls::ust::application_abi::ABI_32) {
			consumer32_channel_keys.emplace_back(desc.consumer_key);
			consumer32_owners.emplace_back(owner);
		} else {
			consumer64_channel_keys.emplace_back(desc.consumer_key);
			consumer64_owners.emplace_back(owner);
		}
	});
}

ls::commands::reclaim_channel_memory_result ls::ust::domain_orchestrator::reclaim_channel_memory(
	const config::recording_channel_configuration& target_channel,
	const nonstd::optional<std::chrono::microseconds>& reclaim_older_than_age,
	bool require_consumed,
	ls::commands::completion_callback_t on_complete,
	ls::commands::cancellation_callback_t on_cancel)
{
	const auto is_per_cpu_stream = target_channel.buffer_allocation_policy ==
		lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CPU;

	std::vector<std::uint64_t> consumer32_channel_keys, consumer64_channel_keys;
	std::vector<ls::commands::stream_group_owner> consumer32_owners, consumer64_owners;

	_collect_stream_group_keys_by_bitness(target_channel,
					      consumer32_channel_keys,
					      consumer64_channel_keys,
					      consumer32_owners,
					      consumer64_owners);

	const unsigned int consumer_count = (!consumer32_channel_keys.empty() ? 1 : 0) +
		(!consumer64_channel_keys.empty() ? 1 : 0);

	/*
	 * Create the completion tracking request before issuing reclaim operations.
	 * The consumers will signal completion on their own when they're done.
	 *
	 * The const_cast is needed because the pending reclamation registry
	 * mutates the session's pending reclamation state. The session lock
	 * is held by the caller.
	 */
	DBG_FMT("Creating completion tracking request: consumer_count={}", consumer_count);

	const auto token = ls::the_pending_memory_reclamation_registry.create_request(
		const_cast<ltt_session&>(_session),
		target_channel.name,
		consumer_count,
		std::move(on_complete),
		std::move(on_cancel));

	std::vector<ls::commands::stream_memory_reclamation_result_group> result;

	/* Handle 32-bit ABI stream groups. */
	if (!consumer32_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		try {
			issue_consumer_reclaim_channel_memory(
				*consumer_find_socket_by_bitness(32, _consumer_output.get()),
				consumer32_owners,
				is_per_cpu_stream,
				consumer32_channel_keys,
				reclaim_older_than_age,
				require_consumed,
				token,
				result);
		} catch (const std::exception& e) {
			ls::the_pending_memory_reclamation_registry.cancel_request(token);
			throw;
		}
	}

	/* Handle 64-bit ABI stream groups. */
	if (!consumer64_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		try {
			issue_consumer_reclaim_channel_memory(
				*consumer_find_socket_by_bitness(64, _consumer_output.get()),
				consumer64_owners,
				is_per_cpu_stream,
				consumer64_channel_keys,
				reclaim_older_than_age,
				require_consumed,
				token,
				result);
		} catch (const std::exception& e) {
			ls::the_pending_memory_reclamation_registry.cancel_request(token);
			throw;
		}
	}

	/* Log results. */
	for (const auto& stream_group : result) {
		const auto total_reclaimed = std::accumulate(
			stream_group.reclaimed_streams_memory.begin(),
			stream_group.reclaimed_streams_memory.end(),
			0ULL,
			[](std::uint64_t sum,
			   const ls::commands::stream_memory_reclamation_result& stream_result) {
				return sum + stream_result.subbuffers_reclaimed;
			});
		const auto total_pending = std::accumulate(
			stream_group.reclaimed_streams_memory.begin(),
			stream_group.reclaimed_streams_memory.end(),
			0ULL,
			[](std::uint64_t sum,
			   const ls::commands::stream_memory_reclamation_result& stream_result) {
				return sum + stream_result.pending_subbuffers_to_reclaim;
			});

		DBG_FMT("Reclaimed sub-buffers for streams in group: session_name=`{}`, channel_name=`{}`, "
			"owner_type={}, bitness={}, streams_count={}, total_reclaimed={}, total_pending={}",
			_session.name,
			target_channel.name,
			stream_group.owner.owner_type,
			stream_group.owner.bitness,
			stream_group.reclaimed_streams_memory.size(),
			total_reclaimed,
			total_pending);

		for (const auto& stream_result : stream_group.reclaimed_streams_memory) {
			DBG_FMT("Reclaimed stream sub-buffers: id={}, subbuffers_reclaimed={}, pending_subbuffers={}",
				stream_result.id,
				stream_result.subbuffers_reclaimed,
				stream_result.pending_subbuffers_to_reclaim);
		}
	}

	return { std::move(result), token };
}

std::vector<ls::commands::stream_memory_usage_group>
ls::ust::domain_orchestrator::get_channel_memory_usage(
	const config::recording_channel_configuration& target_channel) const
{
	const auto is_per_cpu_stream = target_channel.buffer_allocation_policy ==
		lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CPU;

	std::vector<std::uint64_t> consumer32_channel_keys, consumer64_channel_keys;
	std::vector<ls::commands::stream_group_owner> consumer32_owners, consumer64_owners;

	_collect_stream_group_keys_by_bitness(target_channel,
					      consumer32_channel_keys,
					      consumer64_channel_keys,
					      consumer32_owners,
					      consumer64_owners);

	std::vector<ls::commands::stream_memory_usage_group> result;

	if (!consumer32_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		append_consumer_channel_memory_usage(
			result,
			consumer32_channel_keys,
			consumer32_owners,
			is_per_cpu_stream,
			*consumer_find_socket_by_bitness(32, _consumer_output.get()));
	}

	if (!consumer64_channel_keys.empty()) {
		const lttng::urcu::read_lock_guard read_lock;

		append_consumer_channel_memory_usage(
			result,
			consumer64_channel_keys,
			consumer64_owners,
			is_per_cpu_stream,
			*consumer_find_socket_by_bitness(64, _consumer_output.get()));
	}

	/* Log results. */
	for (const auto& stream_group : result) {
		DBG_FMT("Stream group memory usage: session_name=`{}`, channel_name=`{}`, "
			"owner_type={}, bitness={}, streams_count={}, usage_ratio={:.3f}%",
			_session.name,
			target_channel.name,
			stream_group.owner.owner_type,
			stream_group.owner.bitness,
			stream_group.streams_memory_usage.size(),
			[&stream_group]() {
				if (stream_group.streams_memory_usage.empty()) {
					return 0.0;
				}

				std::uint64_t logical_size = 0, physical_size = 0;
				for (const auto& usage : stream_group.streams_memory_usage) {
					logical_size += usage.size_bytes.logical;
					physical_size += usage.size_bytes.physical;
				}

				if (logical_size == 0) {
					return 0.0;
				}

				return (static_cast<double>(physical_size) / logical_size) * 100.0;
			}());

		for (const auto& stream_usage : stream_group.streams_memory_usage) {
			DBG_FMT("Stream memory usage: id='{}', logical_size_bytes={}, "
				"physical_size_bytes={}",
				stream_usage.id,
				stream_usage.size_bytes.logical,
				stream_usage.size_bytes.physical);
		}
	}

	return result;
}

void ls::ust::domain_orchestrator::_save_per_pid_stats_on_departure(const ust::app_session& ua_sess)
{
	for (const auto *ua_chan :
	     lttng::urcu::lfht_iteration_adapter<ust_app_channel,
						 decltype(ust_app_channel::node),
						 &ust_app_channel::node>(*ua_sess.channels->ht)) {
		/* Metadata channels do not have discarded/lost counters. */
		if (ua_chan->attr.type == LTTNG_UST_ABI_CHAN_METADATA) {
			continue;
		}

		std::uint64_t discarded = 0, lost = 0;

		if (ua_chan->attr.overwrite) {
			consumer_get_lost_packets(ua_sess.recording_session_id,
						  ua_chan->key,
						  get_consumer_output_ptr(),
						  &lost);
		} else {
			consumer_get_discarded_events(ua_sess.recording_session_id,
						      ua_chan->key,
						      get_consumer_output_ptr(),
						      &discarded);
		}

		const auto& recording_config =
			static_cast<const lsc::recording_channel_configuration&>(
				ua_chan->channel_config);

		_accumulate_per_pid_closed_app_stats(recording_config, discarded, lost);
	}
}

void ls::ust::domain_orchestrator::_accumulate_per_pid_closed_app_stats(
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

void ls::ust::domain_orchestrator::_for_each_consumer_stream_group(
	const consumer_stream_group_visitor& visitor) const
{
	const auto& metadata_config = _session.user_space_domain.metadata_channel();

	if (_default_buffer_ownership ==
	    lsc::recording_channel_configuration::owership_model_t::PER_UID) {
		for (const auto& sg_entry : _per_uid_stream_groups) {
			visitor(_consumer_stream_group_descriptor{
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

			visitor(_consumer_stream_group_descriptor{
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

			visitor(_consumer_stream_group_descriptor{
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

			visitor(_consumer_stream_group_descriptor{
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
