/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "consumer.hpp"
#include "health-sessiond.hpp"
#include "lttng-sessiond.hpp"
#include "recording-channel-configuration.hpp"
#include "session.hpp"
#include "ust-app-channel.hpp"
#include "ust-consumer.hpp"
#include "ust-trace-class-index.hpp"
#include "ust-trace-class.hpp"

#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/defaults.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/make-unique.hpp>

#include <lttng/ust-ctl.h>
#include <lttng/ust-error.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace lsc = lttng::sessiond::config;
namespace lsu = lttng::sessiond::ust;

/*
 * Send a single channel to the consumer using command ASK_CHANNEL_CREATION.
 *
 * Consumer socket lock MUST be acquired before calling this.
 */
static int ask_channel_creation(lsu::app_session *ua_sess,
				lsu::app_channel *ua_chan,
				struct consumer_output *consumer,
				struct consumer_socket *socket,
				lsu::trace_class *trace_class,
				std::uint32_t chan_id,
				struct lttng_trace_chunk *trace_chunk,
				enum lttng_trace_format trace_format,
				unsigned int output_traces,
				unsigned int live_timer_interval)
{
	int ret, output;
	uint64_t key;
	struct lttcomm_consumer_msg msg;
	char shm_path[PATH_MAX] = "";
	char root_shm_path[PATH_MAX] = "";
	bool is_local_trace;
	size_t consumer_path_offset = 0;

	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(socket);
	LTTNG_ASSERT(consumer);
	LTTNG_ASSERT(trace_class);

	DBG2("Asking UST consumer for channel");

	is_local_trace = consumer->net_seq_index == -1ULL;
	/* Format the channel's path (relative to the current trace chunk). */
	std::string pathname;
	{
		const auto raw_pathname = lttng::make_unique_wrapper<char, lttng::memory::free>(
			setup_channel_trace_path(
				consumer, ua_sess->path.c_str(), &consumer_path_offset));
		if (!raw_pathname) {
			return -1;
		}

		pathname = raw_pathname.get();
	}

	if (is_local_trace && trace_chunk) {
		const std::string pathname_index = fmt::format("{}/" DEFAULT_INDEX_DIR, pathname);

		/*
		 * Create the index subdirectory which will take care
		 * of implicitly creating the channel's path.
		 */
		const auto chunk_status =
			lttng_trace_chunk_create_subdirectory(trace_chunk, pathname_index.c_str());
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			return -1;
		}
	}

	const auto is_metadata = ua_chan->channel_config.channel_type() ==
		lsc::channel_configuration::channel_type_t::METADATA;

	if (!is_metadata) {
		if (!ua_sess->shm_path.empty()) {
			const auto shm_path_str =
				ua_sess->shm_path + "/" + ua_chan->channel_config.name + "_";

			strncpy(shm_path, shm_path_str.c_str(), sizeof(shm_path));
			shm_path[sizeof(shm_path) - 1] = '\0';
		}
		strncpy(root_shm_path, ua_sess->root_shm_path.c_str(), sizeof(root_shm_path));
		root_shm_path[sizeof(root_shm_path) - 1] = '\0';
	}

	switch (ua_chan->channel_config.buffer_consumption_backend) {
	case lsc::channel_configuration::buffer_consumption_backend_t::MMAP:
	default:
		output = LTTNG_EVENT_MMAP;
		break;
	}

	/*
	 * Recording channel configuration fields are only meaningful for data
	 * channels. Metadata channels use default values (zero/unset).
	 */
	const auto *recording_config = !is_metadata ?
		&static_cast<const lsc::recording_channel_configuration&>(ua_chan->channel_config) :
		nullptr;

	const auto reclamation_age = recording_config ?
		recording_config->automatic_memory_reclamation_maximal_age :
		nonstd::optional<std::chrono::microseconds>{};

	/*
	 * A reclamation policy with an age of zero effectively means that buffers should be
	 * continuously reclaimed. In that case, set the continuously_reclaimed flag to true
	 * and disable the periodic evaluation of the age of buffers.
	 */
	const bool continuously_reclaimed = reclamation_age.has_value() &&
		reclamation_age->count() == 0;
	const auto automatic_memory_reclamation_maximal_age =
		continuously_reclaimed ? nonstd::nullopt : reclamation_age;

	const auto monitor_timer_interval = recording_config ?
		recording_config->monitor_timer_period_us.value_or(0) :
		uint64_t(0);

	const auto watchdog_timer_interval = recording_config &&
			recording_config->watchdog_timer_period_us ?
		nonstd::optional<uint64_t>(*recording_config->watchdog_timer_period_us) :
		nonstd::optional<uint64_t>{};

	const auto tracefile_size = recording_config ?
		recording_config->trace_file_size_limit_bytes.value_or(0) :
		uint64_t(0);

	const auto tracefile_count =
		recording_config ? recording_config->trace_file_count_limit.value_or(0) : 0u;

	const auto preallocation_policy = recording_config ?
		recording_config->buffer_preallocation_policy :
		lsc::recording_channel_configuration::buffer_preallocation_policy_t::PREALLOCATE;

	const auto& chan_config = ua_chan->channel_config;

	const auto overwrite = chan_config.buffer_full_policy ==
		lsc::channel_configuration::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET;

	int channel_type;
	if (is_metadata) {
		channel_type = LTTNG_UST_ABI_CHAN_METADATA;
	} else {
		channel_type = static_cast<int>(allocation_policy_to_ust_channel_type(
			recording_config->buffer_allocation_policy));
	}

	int64_t blocking_timeout = 0;
	if (recording_config) {
		switch (recording_config->consumption_blocking_policy_.mode_) {
		case lsc::recording_channel_configuration::consumption_blocking_policy::mode::NONE:
			blocking_timeout = 0;
			break;
		case lsc::recording_channel_configuration::consumption_blocking_policy::mode::
			UNBOUNDED:
			blocking_timeout = -1;
			break;
		case lsc::recording_channel_configuration::consumption_blocking_policy::mode::TIMED:
			blocking_timeout =
				*recording_config->consumption_blocking_policy_.timeout_us;
			break;
		}
	}

	consumer_init_ask_channel_comm_msg(&msg,
					   chan_config.subbuffer_size_bytes,
					   chan_config.subbuffer_count,
					   overwrite ? 1 : 0,
					   chan_config.switch_timer_period_us.value_or(0),
					   chan_config.read_timer_period_us.value_or(0),
					   live_timer_interval,
					   live_timer_interval != 0,
					   continuously_reclaimed,
					   monitor_timer_interval,
					   watchdog_timer_interval,
					   output,
					   channel_type,
					   ua_sess->recording_session_id,
					   &(pathname.c_str()[consumer_path_offset]),
					   ua_chan->channel_config.name.c_str(),
					   consumer->net_seq_index,
					   ua_chan->key,
					   trace_class->uuid,
					   chan_id,
					   tracefile_size,
					   tracefile_count,
					   ua_sess->app_session_id,
					   output_traces,
					   lttng_credentials_get_uid(&ua_sess->real_credentials),
					   blocking_timeout,
					   preallocation_policy,
					   automatic_memory_reclamation_maximal_age,
					   root_shm_path,
					   shm_path,
					   trace_chunk,
					   &ua_sess->effective_credentials,
					   trace_format);

	health_code_update();

	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	ret = consumer_socket_send(socket, &msg, sizeof(msg));
	if (ret < 0) {
		return ret;
	}

	ret = consumer_recv_status_channel(socket, &key, &ua_chan->expected_stream_count);
	if (ret < 0) {
		return ret;
	}
	/* Communication protocol error. */
	LTTNG_ASSERT(key == ua_chan->key);
	/* We need at least one where 1 stream for 1 cpu. */
	if (output_traces) {
		LTTNG_ASSERT(ua_chan->expected_stream_count > 0);
	}

	DBG2("UST ask channel %" PRIu64 " successfully done with %u stream(s)",
	     key,
	     ua_chan->expected_stream_count);

	return ret;
}

/*
 * Ask consumer to create a channel for a given session.
 *
 * Session list and rcu read side locks must be held by the caller.
 *
 * Returns 0 on success else a negative value.
 */
int ust_consumer_ask_channel(lsu::app_session *ua_sess,
			     lsu::app_channel *ua_chan,
			     struct consumer_output *consumer,
			     struct consumer_socket *socket,
			     lsu::trace_class *trace_class,
			     struct lttng_trace_chunk *trace_chunk,
			     enum lttng_trace_format trace_format,
			     unsigned int output_traces,
			     unsigned int live_timer_interval)
{
	int ret;

	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(consumer);
	LTTNG_ASSERT(socket);
	LTTNG_ASSERT(trace_class);

	if (!consumer->enabled) {
		ret = -LTTNG_ERR_NO_CONSUMER;
		DBG3("Consumer is disabled");
		goto error;
	}

	/*
	 * Extract the channel id from the trace class before acquiring
	 * the consumer socket lock to follow the established convention
	 * (see the circular-dependency note in ust_app_push_metadata()):
	 * the trace class lock must never be acquired while a consumer
	 * socket lock is held.
	 */
	std::uint32_t chan_id;
	{
		const auto is_metadata = ua_chan->channel_config.channel_type() ==
			lsc::channel_configuration::channel_type_t::METADATA;

		if (is_metadata) {
			chan_id = -1U;
		} else {
			const auto trace_class_channel_key = ua_sess->buffer_type ==
					LTTNG_BUFFER_PER_UID ?
				ua_chan->trace_class_stream_class_handle :
				ua_chan->key;
			auto locked_trace_class = trace_class->lock();
			auto& trace_class_channel =
				locked_trace_class->channel(trace_class_channel_key);

			chan_id = trace_class_channel.id;
		}
	}

	pthread_mutex_lock(socket->lock);
	ret = ask_channel_creation(ua_sess,
				   ua_chan,
				   consumer,
				   socket,
				   trace_class,
				   chan_id,
				   trace_chunk,
				   trace_format,
				   output_traces,
				   live_timer_interval);
	pthread_mutex_unlock(socket->lock);
	if (ret < 0) {
		ERR("ask_channel_creation consumer command failed");
		goto error;
	}

error:
	return ret;
}

/*
 * Send a get channel command to consumer using the given channel key.  The
 * channel object is populated and the stream list.
 *
 * Return 0 on success else a negative value.
 */
int ust_consumer_get_channel(struct consumer_socket *socket, lsu::app_channel *ua_chan)
{
	int ret;
	struct lttcomm_consumer_msg msg;

	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(socket);

	memset(&msg, 0, sizeof(msg));
	msg.cmd_type = LTTNG_CONSUMER_GET_CHANNEL;
	msg.u.get_channel.key = ua_chan->key;

	/*
	 * Pre-allocate the streams vector so push_back() below is
	 * effectively noexcept (std::unique_ptr move is noexcept). This
	 * must happen outside the consumer socket lock: the only way an
	 * app_stream destructor could run while that lock is held is if
	 * push_back() reallocated and threw, and ~app_stream acquires
	 * the app's command socket lock. That would reverse the lock
	 * order used in other places (see the circular-dependency note in
	 * ust_app_push_metadata()).
	 */
	try {
		ua_chan->streams.reserve(ua_chan->expected_stream_count);
	} catch (const std::bad_alloc&) {
		return -ENOMEM;
	}

	pthread_mutex_lock(socket->lock);
	health_code_update();

	/* Send command and wait for OK reply. */
	ret = consumer_send_msg(socket, &msg);
	if (ret < 0) {
		goto error;
	}

	/* First, get the channel from consumer. */
	ret = lttng_ust_ctl_recv_channel_from_consumer(*socket->fd_ptr, &ua_chan->obj);
	if (ret < 0) {
		if (ret != -EPIPE) {
			ERR("Error recv channel from consumer %d with ret %d",
			    *socket->fd_ptr,
			    ret);
		} else {
			DBG3("UST app recv channel from consumer. Consumer is dead.");
		}
		goto error;
	}

	/* Next, get all streams. */
	while (true) {
		auto stream = lttng::make_unique<lsu::app_stream>(*ua_chan);

		/* Stream object is populated by this call if successful. */
		ret = lttng_ust_ctl_recv_stream_from_consumer(*socket->fd_ptr, &stream->obj);
		if (ret < 0) {
			/*
			 * lttng_ust_ctl_recv_stream_from_consumer() only
			 * populates ->obj on success, but defensively clear
			 * it so that ~app_stream remains a no-op in error
			 * paths -- acquiring the app command socket lock
			 * while socket->lock is held would reverse the
			 * lock order used elsewhere.
			 */
			stream->obj = nullptr;
			if (ret == -LTTNG_UST_ERR_NOENT) {
				DBG3("UST app consumer has no more stream available");
				break;
			}
			if (ret != -EPIPE) {
				ERR("Recv stream from consumer %d with ret %d",
				    *socket->fd_ptr,
				    ret);
			} else {
				DBG3("UST app recv stream from consumer. Consumer is dead.");
			}
			goto error;
		}

		ua_chan->streams.push_back(std::move(stream));

		DBG2("UST app stream %zu received successfully", ua_chan->streams.size());
	}

	/* This MUST match or else we have a synchronization problem. */
	LTTNG_ASSERT(ua_chan->expected_stream_count == ua_chan->streams.size());

	/* Wait for confirmation that we can proceed with the streams. */
	ret = consumer_recv_status_reply(socket);
	if (ret < 0) {
		goto error;
	}

error:
	health_code_update();
	pthread_mutex_unlock(socket->lock);
	return ret;
}

/*
 * Send a destroy channel command to consumer using the given channel key.
 *
 * Note that this command MUST be used prior to a successful
 * LTTNG_CONSUMER_GET_CHANNEL because once this command is done successfully,
 * the streams are dispatched to the consumer threads and MUST be teardown
 * through the hang up process.
 *
 * Return 0 on success else a negative value.
 */
int ust_consumer_destroy_channel(struct consumer_socket *socket, lsu::app_channel *ua_chan)
{
	int ret;
	struct lttcomm_consumer_msg msg;

	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(socket);

	memset(&msg, 0, sizeof(msg));
	msg.cmd_type = LTTNG_CONSUMER_DESTROY_CHANNEL;
	msg.u.destroy_channel.key = ua_chan->key;

	pthread_mutex_lock(socket->lock);
	health_code_update();

	ret = consumer_send_msg(socket, &msg);
	if (ret < 0) {
		goto error;
	}

error:
	health_code_update();
	pthread_mutex_unlock(socket->lock);
	return ret;
}

/*
 * Send a given stream to UST tracer.
 *
 * On success return 0 else a negative value.
 */
int ust_consumer_send_stream_to_ust(lsu::app *app,
				    lsu::app_channel *channel,
				    lsu::app_stream *stream)
{
	int ret = 0;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(stream);
	LTTNG_ASSERT(channel);

	DBG2("UST consumer send stream to app %d", app->command_socket.fd());

	/* Relay stream to application. */
	try {
		app->command_socket.lock().send_stream_to_ust(channel->obj, stream->obj);
	} catch (const lsu::app_communication_error&) {
		ret = -ENOTCONN;
		goto error;
	} catch (const lttng::runtime_error&) {
		ret = -1;
		goto error;
	}

	channel->handle = channel->obj->header.handle;

error:
	return ret;
}

/*
 * Send channel previously received from the consumer to the UST tracer.
 *
 * On success return 0 else a negative value.
 */
int ust_consumer_send_channel_to_ust(lsu::app *app,
				     lsu::app_session *ua_sess,
				     lsu::app_channel *channel)
{
	int ret = 0;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(channel);
	LTTNG_ASSERT(channel->obj);

	DBG2("UST app send channel to sock %d pid %d (name: %s, key: %" PRIu64 ")",
	     app->command_socket.fd(),
	     app->pid,
	     channel->channel_config.name.c_str(),
	     channel->trace_class_stream_class_handle);

	/*
	 * This effectively transmits the owner-id to the application by storing
	 * it in the channel.
	 */
	lttng_ust_ctl_set_channel_owner_id(channel->obj, app->owner_id_n.key);

	/* Send channel to application. */
	try {
		app->command_socket.lock().send_channel_to_ust(ua_sess->handle, channel->obj);
	} catch (const lsu::app_communication_error&) {
		ret = -ENOTCONN;
		goto error;
	} catch (const lttng::runtime_error&) {
		ret = -1;
		goto error;
	}

error:
	return ret;
}

/*
 * Handle the metadata requests from the UST consumer
 *
 * Return 0 on success else a negative value.
 */
int ust_consumer_metadata_request(struct consumer_socket *socket)
{
	int ret;
	ssize_t ret_push;
	struct lttcomm_metadata_request_msg request;
	std::shared_ptr<lsu::trace_class> trace;
	struct lttcomm_consumer_msg msg;

	LTTNG_ASSERT(socket);

	const lttng::urcu::read_lock_guard read_lock;
	health_code_update();

	/* Wait for a metadata request */
	pthread_mutex_lock(socket->lock);
	ret = consumer_socket_recv(socket, &request, sizeof(request));
	pthread_mutex_unlock(socket->lock);
	if (ret < 0) {
		goto end;
	}

	DBG("Metadata request received for session %" PRIu64 ", key %" PRIu64,
	    request.session_id,
	    request.key);

	trace = the_trace_class_index->find_per_uid(
		request.session_id, request.bits_per_long, request.uid);
	if (!trace) {
		trace = the_trace_class_index->find_per_pid(request.session_id_per_pid);
	}
	if (!trace) {
		DBG("Trace class not found for session id %" PRIu64 ", per-pid %" PRIu64,
		    request.session_id,
		    request.session_id_per_pid);

		memset(&msg, 0, sizeof(msg));
		msg.cmd_type = LTTNG_ERR_UND;
		pthread_mutex_lock(socket->lock);
		(void) consumer_send_msg(socket, &msg);
		pthread_mutex_unlock(socket->lock);
		/*
		 * This is possible since the session might have been destroyed
		 * during a consumer metadata request. So here, return gracefully
		 * because the destroy session will push the remaining metadata to
		 * the consumer.
		 */
		ret = 0;
		goto end;
	}
	LTTNG_ASSERT(trace);

	{
		auto locked_ust_reg = trace->lock();
		ret_push = ust_app_push_metadata(locked_ust_reg, socket, 1);
	}
	if (ret_push == -EPIPE) {
		DBG("Application or relay closed while pushing metadata");
	} else if (ret_push < 0) {
		ERR("Pushing metadata");
		ret = -1;
		goto end;
	} else {
		DBG("UST Consumer metadata pushed successfully");
	}
	ret = 0;

end:
	return ret;
}
