/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "consumer.hpp"
#include "fd-limit.hpp"
#include "health-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "recording-channel-configuration.hpp"
#include "session.hpp"
#include "ust-app-channel.hpp"
#include "ust-app-ctx.hpp"
#include "ust-app-event.hpp"
#include "ust-app.hpp"
#include "ust-consumer.hpp"

#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/make-unique.hpp>
#include <common/scope-exit.hpp>
#include <common/urcu.hpp>

#include <inttypes.h>
#include <pthread.h>

namespace lsu = lttng::sessiond::ust;
namespace lsc = lttng::sessiond::config;

namespace {
/* Next available channel key. Access under next_channel_key_lock. */
uint64_t _next_channel_key;
pthread_mutex_t next_channel_key_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Return the incremented value of next_channel_key.
 */
uint64_t get_next_channel_key()
{
	uint64_t ret;

	pthread_mutex_lock(&next_channel_key_lock);
	ret = ++_next_channel_key;
	pthread_mutex_unlock(&next_channel_key_lock);
	return ret;
}

} /* namespace */

/* -- app_channel -- */

lsu::app_channel::app_channel(lsu::app_session& session_,
			      const lsc::channel_configuration& channel_config_) :
	enabled(true),
	handle(-1),
	key(get_next_channel_key()),
	session(session_),
	channel_config(channel_config_)
{
	/* By default, the channel is a per cpu channel. */
	attr.type = LTTNG_UST_ABI_CHAN_PER_CPU;

	DBG3("UST app channel %s allocated", channel_config.name.c_str());
}

lsu::app_channel::~app_channel()
{
	DBG3("UST app deleting channel %s", channel_config.name.c_str());

	/*
	 * Wipe streams first. Stream destructors access the app's
	 * command socket, which must still be reachable at this point.
	 */
	streams.clear();

	/* Wipe contexts. Destructors release UST objects. */
	contexts.clear();

	/* Wipe events. Destructors release UST tracer-side objects. */
	events.clear();

	if (obj != nullptr) {
		auto& app = session.app();
		int ret;

		/* Deregister objd from the app's registry via RAII token. */
		objd_token.reset();

		{
			const auto protocol = app.command_socket.lock();
			ret = lttng_ust_ctl_release_object(protocol.fd(), obj);
		}

		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app channel %s release failed. Application is dead: pid = %d, sock = %d",
				     channel_config.name.c_str(),
				     app.pid,
				     app.command_socket.fd());
			} else if (ret == -EAGAIN) {
				WARN("UST app channel %s release failed. Communication time out: pid = %d, sock = %d",
				     channel_config.name.c_str(),
				     app.pid,
				     app.command_socket.fd());
			} else {
				ERR("UST app channel %s release failed with ret %d: pid = %d, sock = %d",
				    channel_config.name.c_str(),
				    ret,
				    app.pid,
				    app.command_socket.fd());
			}
		}

		lttng_fd_put(LTTNG_FD_APPS, 1);
		free(obj);
	}
}

void lsu::app_channel::enable()
{
	health_code_update();
	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	auto& app = session.app();

	app.command_socket.lock().enable(obj);

	enabled = true;

	DBG2("UST app channel %s enabled successfully for app: pid = %d",
	     channel_config.name.c_str(),
	     app.pid);
}

void lsu::app_channel::disable()
{
	health_code_update();
	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	auto& app = session.app();

	app.command_socket.lock().disable(obj);

	enabled = false;

	DBG2("UST app channel %s disabled successfully for app: pid = %d",
	     channel_config.name.c_str(),
	     app.pid);
}

void lsu::app_channel::init_from_config()
{
	const auto& config =
		static_cast<const lsc::recording_channel_configuration&>(channel_config);

	DBG2("UST app initializing channel %s from config", channel_config.name.c_str());

	attr.subbuf_size = config.subbuffer_size_bytes;
	attr.num_subbuf = config.subbuffer_count;
	attr.overwrite = config.buffer_full_policy ==
			lsc::channel_configuration::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET ?
		1 :
		0;
	attr.switch_timer_interval = config.switch_timer_period_us.value_or(0);
	attr.read_timer_interval = config.read_timer_period_us.value_or(0);

	attr.output = config.buffer_consumption_backend ==
			lsc::channel_configuration::buffer_consumption_backend_t::MMAP ?
		LTTNG_UST_ABI_MMAP :
		static_cast<lttng_ust_abi_output>(-1);

	switch (config.consumption_blocking_policy_.mode_) {
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::NONE:
		attr.blocking_timeout = 0;
		break;
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::UNBOUNDED:
		attr.blocking_timeout = -1;
		break;
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::TIMED:
		attr.blocking_timeout = *config.consumption_blocking_policy_.timeout_us;
		break;
	}

	enabled = config.is_enabled;

	DBG3("UST app channel %s initialized from config", channel_config.name.c_str());
}

void lsu::app_channel::create_context(const lsc::context_configuration& context_config,
				      const lttng_ust_context_attr *uctx)
{
	DBG2("UST app adding context to channel %s", channel_config.name.c_str());

	if (contexts.find(&context_config) != contexts.end()) {
		return;
	}

	auto app_context = lttng::make_unique<lsu::app_context>(*this, context_config, uctx);
	auto& app = session.app();

	health_code_update();
	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	app.command_socket.lock().add_context(&app_context->ctx, obj, &app_context->obj);

	if (!app_context->obj) {
		LTTNG_THROW_ERROR(lttng::format(
			"Failed to add UST context: no context object returned: channel_name=`{}`, pid={}, "
			"sock={}",
			channel_config.name,
			app.pid,
			app.command_socket.fd()));
	}

	app_context->handle = app_context->obj->header.handle;

	DBG2("UST app context handle %d created successfully for channel %s",
	     app_context->handle,
	     channel_config.name.c_str());

	contexts.emplace(&context_config, std::move(app_context));
}

void lsu::app_channel::send_to_app_per_pid()
{
	auto& app = session.app();

	health_code_update();

	DBG("UST app sending channel %s to UST app sock %d",
	    channel_config.name.c_str(),
	    app.command_socket.fd());

	/* Send channel to the application. */
	const auto channel_send_ret = ust_consumer_send_channel_to_ust(&app, &session, this);
	if (channel_send_ret < 0) {
		LTTNG_THROW_ERROR(lttng::format(
			"Failed to send UST channel to application: channel_name=`{}`, pid={}, sock={}, "
			"session_id={}, channel_key={}, status={}",
			channel_config.name,
			app.pid,
			app.command_socket.fd(),
			session.recording_session_id,
			key,
			channel_send_ret));
	}

	health_code_update();

	/* Send all streams to application. */
	for (auto& stream_ptr : streams) {
		const auto stream_send_ret =
			ust_consumer_send_stream_to_ust(&app, this, stream_ptr.get());
		if (stream_send_ret < 0) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to send UST stream to application: channel_name=`{}`, pid={}, "
				"sock={}, session_id={}, channel_key={}, status={}",
				channel_config.name,
				app.pid,
				app.command_socket.fd(),
				session.recording_session_id,
				key,
				stream_send_ret));
		}

		/*
		 * The stream has been sent to the tracer; discard the local
		 * resources without sending a release command to the tracer
		 * (it now owns the handle).
		 */
		stream_ptr->discard_locally();
	}

	streams.clear();
}

void lsu::app_channel::send_to_app_per_uid(lsu::stream_group& stream_group)
{
	auto& app = session.app();

	DBG("UST app sending stream group channel to ust sock %d", app.command_socket.fd());

	/* Duplicate the master channel object for this application. */
	{
		try {
			auto duplicated_channel = stream_group.duplicate_channel_object();
			obj = duplicated_channel.release();
		} catch (const std::exception& ex) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to duplicate UST channel object for per-UID send: channel_name=`{}`, "
				"pid={}, sock={}, session_id={}, channel_key={}, error={}",
				channel_config.name,
				app.pid,
				app.command_socket.fd(),
				session.recording_session_id,
				key,
				ex.what()));
		}

		handle = obj->header.handle;
	}

	/* Send channel to the application. */
	const auto channel_send_ret = ust_consumer_send_channel_to_ust(&app, &session, this);
	if (channel_send_ret < 0) {
		LTTNG_THROW_ERROR(lttng::format(
			"Failed to send per-UID UST channel to application: channel_name=`{}`, pid={}, "
			"sock={}, session_id={}, channel_key={}, status={}",
			channel_config.name,
			app.pid,
			app.command_socket.fd(),
			session.recording_session_id,
			key,
			channel_send_ret));
	}

	health_code_update();

	/* Send all streams to application by duplicating from the stream group. */
	for (const auto& stream_ptr : stream_group.streams()) {
		lsu::app_stream tmp_stream(*this);

		try {
			auto duplicated_stream = stream_ptr->handle.duplicate();
			tmp_stream.obj = duplicated_stream.release();
		} catch (const std::exception& ex) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to duplicate UST stream object for per-UID send: channel_name=`{}`, "
				"pid={}, sock={}, session_id={}, channel_key={}, error={}",
				channel_config.name,
				app.pid,
				app.command_socket.fd(),
				session.recording_session_id,
				key,
				ex.what()));
		}

		tmp_stream.handle = tmp_stream.obj->header.handle;

		const auto stream_send_ret =
			ust_consumer_send_stream_to_ust(&app, this, &tmp_stream);
		if (stream_send_ret < 0) {
			/*
			 * discard_locally releases the local resources without
			 * notifying the tracer (the send may have failed).
			 * The destructor will then be a no-op.
			 */
			tmp_stream.discard_locally();
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to send per-UID UST stream to application: channel_name=`{}`, "
				"pid={}, sock={}, session_id={}, channel_key={}, status={}",
				channel_config.name,
				app.pid,
				app.command_socket.fd(),
				session.recording_session_id,
				key,
				stream_send_ret));
		}

		/*
		 * The stream was sent successfully. Release local resources
		 * without sending a release command to the tracer.
		 */
		tmp_stream.discard_locally();
	}
}

/* -- app_stream -- */

lsu::app_stream::app_stream(lsu::app_channel& channel) : _channel(channel)
{
}

lsu::app_stream::app_stream(app_stream&& other) noexcept :
	handle(other.handle), obj(other.obj), _channel(other._channel)
{
	other.obj = nullptr;
	other.handle = -1;
}

lsu::app_stream::~app_stream()
{
	if (!obj) {
		return;
	}

	auto& app = _channel.session.app();
	int ret;

	{
		const auto protocol = app.command_socket.lock();
		ret = lttng_ust_ctl_release_object(protocol.fd(), obj);
	}

	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app release stream failed. Application is dead: pid = %d, sock = %d",
			     app.pid,
			     app.command_socket.fd());
		} else if (ret == -EAGAIN) {
			WARN("UST app release stream failed. Communication time out: pid = %d, sock = %d",
			     app.pid,
			     app.command_socket.fd());
		} else {
			ERR("UST app release stream obj failed with ret %d: pid = %d, sock = %d",
			    ret,
			    app.pid,
			    app.command_socket.fd());
		}
	}

	lttng_fd_put(LTTNG_FD_APPS, 2);
	free(obj);
}

lttng_ust_abi_object_data *lsu::app_stream::release_obj() noexcept
{
	auto *ret = obj;
	obj = nullptr;
	return ret;
}

void lsu::app_stream::discard_locally() noexcept
{
	if (!obj) {
		return;
	}

	auto& app = _channel.session.app();

	{
		const auto protocol = app.command_socket.lock();
		(void) lttng_ust_ctl_release_object(-1, obj);
	}

	lttng_fd_put(LTTNG_FD_APPS, 2);
	free(obj);
	obj = nullptr;
}

/* -- channel allocation/deallocation -- */

lsc::recording_channel_configuration::buffer_allocation_policy_t
ust_channel_type_to_allocation_policy(enum lttng_ust_abi_chan_type type)
{
	switch (type) {
	case LTTNG_UST_ABI_CHAN_PER_CPU:
		return lttng::sessiond::config::recording_channel_configuration::
			buffer_allocation_policy_t::PER_CPU;
	case LTTNG_UST_ABI_CHAN_METADATA:
		/* fall-through  */
	case LTTNG_UST_ABI_CHAN_PER_CHANNEL:
		return lttng::sessiond::config::recording_channel_configuration::
			buffer_allocation_policy_t::PER_CHANNEL;
	default:
		abort();
	}
}

enum lttng_ust_abi_chan_type allocation_policy_to_ust_channel_type(
	lsc::recording_channel_configuration::buffer_allocation_policy_t policy)
{
	namespace lsc = lttng::sessiond::config;

	switch (policy) {
	case lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CPU:
		return LTTNG_UST_ABI_CHAN_PER_CPU;
	case lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CHANNEL:
		return LTTNG_UST_ABI_CHAN_PER_CHANNEL;
	default:
		abort();
	}
}

/*
 * Ask the consumer to create a channel and get it if successful.
 *
 * Called with UST app session lock held.
 *
 * Return 0 on success or else a negative value.
 */
int do_consumer_create_channel(struct consumer_output *consumer,
			       lsu::app_session *ua_sess,
			       lsu::app_channel *ua_chan,
			       int bitness,
			       lsu::trace_class *registry,
			       struct lttng_trace_chunk *current_trace_chunk,
			       enum lttng_trace_format trace_format,
			       unsigned int output_traces,
			       unsigned int live_timer_interval)
{
	int ret;
	unsigned int nb_fd = 0;
	struct consumer_socket *socket;

	LTTNG_ASSERT(consumer);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(registry);

	const lttng::urcu::read_lock_guard read_lock;
	health_code_update();

	/* Get the right consumer socket for the application. */
	socket = consumer_find_socket_by_bitness(bitness, consumer);
	if (!socket) {
		ret = -EINVAL;
		goto error;
	}

	health_code_update();

	/* Need one fd for the channel. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 1);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon create channel");
		goto error;
	}

	/*
	 * Ask consumer to create channel. The consumer will return the number of
	 * stream we have to expect.
	 */
	ret = ust_consumer_ask_channel(ua_sess,
				       ua_chan,
				       consumer,
				       socket,
				       registry,
				       current_trace_chunk,
				       trace_format,
				       output_traces,
				       live_timer_interval);
	if (ret < 0) {
		goto error_ask;
	}

	/*
	 * Compute the number of fd needed before receiving them. It must be 2 per
	 * stream (2 being the default value here).
	 */
	nb_fd = DEFAULT_UST_STREAM_FD_NUM * ua_chan->expected_stream_count;

	/* Reserve the amount of file descriptor we need. */
	ret = lttng_fd_get(LTTNG_FD_APPS, nb_fd);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon create channel");
		goto error_fd_get_stream;
	}

	health_code_update();

	/*
	 * Now get the channel from the consumer. This call will populate the stream
	 * vector of that channel and set the ust objects.
	 */
	if (consumer->enabled) {
		ret = ust_consumer_get_channel(socket, ua_chan);
		if (ret < 0) {
			goto error_destroy;
		}
	}

	return 0;

error_destroy:
	lttng_fd_put(LTTNG_FD_APPS, nb_fd);
error_fd_get_stream:
	/*
	 * Initiate a destroy channel on the consumer since we had an error
	 * handling it on our side. The return value is of no importance since we
	 * already have a ret value set by the previous error that we need to
	 * return.
	 */
	(void) ust_consumer_destroy_channel(socket, ua_chan);
error_ask:
	lttng_fd_put(LTTNG_FD_APPS, 1);
error:
	health_code_update();
	return ret;
}
