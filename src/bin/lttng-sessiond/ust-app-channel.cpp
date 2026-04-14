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

void delete_ust_app_channel_rcu(struct rcu_head *head)
{
	struct ust_app_channel *ua_chan =
		lttng::utils::container_of(head, &ust_app_channel::rcu_head);

	delete ua_chan;
}

/*
 * Common initialization for ust_app_channel. Used by both the recording
 * channel and metadata channel allocation paths.
 */
void init_ust_app_channel(struct ust_app_channel *ua_chan, struct lttng_ust_abi_channel_attr *attr)
{
	ua_chan->enabled = true;
	ua_chan->handle = -1;
	ua_chan->key = get_next_channel_key();

	/* By default, the channel is a per cpu channel. */
	ua_chan->attr.type = LTTNG_UST_ABI_CHAN_PER_CPU;

	/* Copy attributes */
	if (attr) {
		/* Translate from lttng_ust_channel to lttng_ust_ctl_consumer_channel_attr. */
		ua_chan->attr.subbuf_size = attr->subbuf_size;
		ua_chan->attr.num_subbuf = attr->num_subbuf;
		ua_chan->attr.overwrite = attr->overwrite;
		ua_chan->attr.switch_timer_interval = attr->switch_timer_interval;
		ua_chan->attr.read_timer_interval = attr->read_timer_interval;
		ua_chan->attr.output = (lttng_ust_abi_output) attr->output;
		ua_chan->attr.blocking_timeout = attr->blocking_timeout;
		ua_chan->attr.type = static_cast<enum lttng_ust_abi_chan_type>(attr->type);
	}

	DBG3("UST app channel %s allocated", ua_chan->channel_config.name.c_str());
}
} /* namespace */

/* -- ust_app_channel -- */

ust_app_channel::~ust_app_channel() = default;

int ust_app_channel::enable()
{
	int ret = 0;

	health_code_update();

	auto& app = session.app();

	try {
		app.command_socket.lock().enable(obj);
	} catch (const lsu::app_communication_error&) {
		goto error;
	} catch (const lttng::runtime_error&) {
		ret = -1;
		goto error;
	}

	enabled = true;

	DBG2("UST app channel %s enabled successfully for app: pid = %d",
	     channel_config.name.c_str(),
	     app.pid);

error:
	health_code_update();
	return ret;
}

int ust_app_channel::disable()
{
	int ret = 0;

	health_code_update();

	auto& app = session.app();

	try {
		app.command_socket.lock().disable(obj);
	} catch (const lsu::app_communication_error&) {
		goto error;
	} catch (const lttng::runtime_error&) {
		ret = -1;
		goto error;
	}

	enabled = false;

	DBG2("UST app channel %s disabled successfully for app: pid = %d",
	     channel_config.name.c_str(),
	     app.pid);

error:
	health_code_update();
	return ret;
}

void ust_app_channel::init_from_config()
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

int ust_app_channel::send_to_app_per_pid()
{
	int ret;

	auto& app = session.app();

	health_code_update();

	DBG("UST app sending channel %s to UST app sock %d",
	    channel_config.name.c_str(),
	    app.command_socket.fd());

	/* Send channel to the application. */
	ret = ust_consumer_send_channel_to_ust(&app, &session, this);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Send all streams to application. */
	for (auto& stream_ptr : streams) {
		ret = ust_consumer_send_stream_to_ust(&app, this, stream_ptr.get());
		if (ret < 0) {
			goto error;
		}

		/*
		 * The stream has been sent to the tracer; discard the local
		 * resources without sending a release command to the tracer
		 * (it now owns the handle).
		 */
		stream_ptr->discard_locally();
	}

	streams.clear();

error:
	health_code_update();
	return ret;
}

int ust_app_channel::send_to_app_per_uid(lsu::stream_group& stream_group)
{
	int ret;

	auto& app = session.app();

	DBG("UST app sending stream group channel to ust sock %d", app.command_socket.fd());

	/* Duplicate the master channel object for this application. */
	{
		try {
			auto duplicated_channel = stream_group.duplicate_channel_object();
			obj = duplicated_channel.release();
		} catch (const std::exception& ex) {
			ERR("Failed to duplicate channel object for app pid %d: %s",
			    app.pid,
			    ex.what());
			ret = -ENOMEM;
			goto error;
		}

		handle = obj->header.handle;
	}

	/* Send channel to the application. */
	ret = ust_consumer_send_channel_to_ust(&app, &session, this);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Send all streams to application by duplicating from the stream group. */
	for (const auto& stream_ptr : stream_group.streams()) {
		lsu::app_stream tmp_stream(*this);

		try {
			auto duplicated_stream = stream_ptr->handle.duplicate();
			tmp_stream.obj = duplicated_stream.release();
		} catch (const std::exception& ex) {
			ERR("Failed to duplicate stream object for app pid %d: %s",
			    app.pid,
			    ex.what());
			ret = -ENOMEM;
			goto error;
		}

		tmp_stream.handle = tmp_stream.obj->header.handle;

		ret = ust_consumer_send_stream_to_ust(&app, this, &tmp_stream);
		if (ret < 0) {
			/*
			 * discard_locally releases the local resources without
			 * notifying the tracer (the send may have failed).
			 * The destructor will then be a no-op.
			 */
			tmp_stream.discard_locally();
			goto error;
		}

		/*
		 * The stream was sent successfully. Release local resources
		 * without sending a release command to the tracer.
		 */
		tmp_stream.discard_locally();
	}

error:
	return ret;
}

/* -- app_stream -- */

lsu::app_stream::app_stream(ust_app_channel& channel) : _channel(channel)
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
 * Allocate a recording channel with an associated config reference.
 */
struct ust_app_channel *
alloc_ust_app_channel(lsu::app_session& ua_sess,
		      struct lttng_ust_abi_channel_attr *attr,
		      const lttng::sessiond::config::recording_channel_configuration& config)
{
	struct ust_app_channel *ua_chan;

	try {
		ua_chan = new ust_app_channel(ua_sess, config);
	} catch (const std::bad_alloc&) {
		PERROR("ust_app_channel allocation");
		return nullptr;
	}

	init_ust_app_channel(ua_chan, attr);
	return ua_chan;
}

/*
 * Allocate a metadata channel (no recording_channel_configuration).
 */
struct ust_app_channel *alloc_ust_app_metadata_channel(
	lsu::app_session& ua_sess,
	const lttng::sessiond::config::metadata_channel_configuration& metadata_config)
{
	struct ust_app_channel *ua_chan;

	try {
		ua_chan = new ust_app_channel(ua_sess, metadata_config);
	} catch (const std::bad_alloc&) {
		PERROR("ust_app_channel allocation");
		return nullptr;
	}

	init_ust_app_channel(ua_chan, nullptr);
	return ua_chan;
}

/*
 * Delete ust app channel safely. RCU read lock must be held before calling
 * this function.
 *
 * The session list lock must be held by the caller.
 */
void delete_ust_app_channel(int sock,
			    struct ust_app_channel *ua_chan,
			    lsu::app *app,
			    const lsu::trace_class::locked_ref& locked_registry)
{
	int ret;

	LTTNG_ASSERT(ua_chan);
	ASSERT_RCU_READ_LOCKED();

	DBG3("UST app deleting channel %s", ua_chan->channel_config.name.c_str());

	/*
	 * Wipe streams before scheduling the channel for RCU reclamation.
	 * Stream destructors access the app's command socket, which must
	 * still be reachable at this point.
	 */
	ua_chan->streams.clear();

	/* Wipe context */
	for (auto& ctx_pair : ua_chan->contexts) {
		delete_ust_app_ctx(sock, ctx_pair.second, app);
	}
	ua_chan->contexts.clear();

	/* Wipe events */
	for (auto& event_pair : ua_chan->events) {
		delete_ust_app_event(sock, event_pair.second, app);
	}
	ua_chan->events.clear();

	if (ua_chan->session.buffer_type == LTTNG_BUFFER_PER_PID) {
		/* Wipe and free registry from session registry. */
		if (locked_registry) {
			try {
				locked_registry->remove_channel(ua_chan->key, sock >= 0);
			} catch (const std::exception& ex) {
				DBG("Could not find channel for removal: %s", ex.what());
			}
		}
	}

	if (ua_chan->obj != nullptr) {
		/* Deregister objd from the app's registry via RAII token. */
		ua_chan->objd_token.reset();

		{
			const auto protocol = app->command_socket.lock();
			ret = lttng_ust_ctl_release_object(sock, ua_chan->obj);
		}
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app channel %s release failed. Application is dead: pid = %d, sock = %d",
				     ua_chan->channel_config.name.c_str(),
				     app->pid,
				     app->command_socket.fd());
			} else if (ret == -EAGAIN) {
				WARN("UST app channel %s release failed. Communication time out: pid = %d, sock = %d",
				     ua_chan->channel_config.name.c_str(),
				     app->pid,
				     app->command_socket.fd());
			} else {
				ERR("UST app channel %s release failed with ret %d: pid = %d, sock = %d",
				    ua_chan->channel_config.name.c_str(),
				    ret,
				    app->pid,
				    app->command_socket.fd());
			}
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
		free(ua_chan->obj);
	}
	call_rcu(&ua_chan->rcu_head, delete_ust_app_channel_rcu);
}

/*
 * Lookup ust app channel for session and enable it on the tracer side. This
 * MUST be called with a RCU read side lock acquired.
 */
int enable_ust_app_channel(lsu::app_session& ua_sess, lttng::c_string_view channel_name)
{
	int ret = 0;

	const auto it = ua_sess.channels.find(channel_name.data());
	if (it == ua_sess.channels.end()) {
		DBG2("Unable to find channel %s in ust session id %" PRIu64,
		     channel_name.data(),
		     ua_sess.recording_session_id);
		goto error;
	}

	ret = it->second->enable();
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
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
			       struct ust_app_channel *ua_chan,
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
