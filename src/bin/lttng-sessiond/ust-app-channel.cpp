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
#include "ust-domain-orchestrator.hpp"

#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
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

/*
 * Release ust data object of the given stream.
 *
 * Return 0 on success or else a negative value.
 */
int release_ust_app_stream(int sock, lsu::app_stream *stream, lsu::app *app)
{
	int ret = 0;

	LTTNG_ASSERT(stream);

	if (stream->obj) {
		pthread_mutex_lock(&app->sock_lock);
		ret = lttng_ust_ctl_release_object(sock, stream->obj);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release stream failed. Application is dead: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app release stream failed. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else {
				ERR("UST app release stream obj failed with ret %d: pid = %d, sock = %d",
				    ret,
				    app->pid,
				    app->sock);
			}
		}
		lttng_fd_put(LTTNG_FD_APPS, 2);
		free(stream->obj);
	}

	return ret;
}

/*
 * Delete ust app stream safely. RCU read lock must be held before calling
 * this function.
 */
void delete_ust_app_stream(int sock, lsu::app_stream *stream, lsu::app *app)
{
	LTTNG_ASSERT(stream);
	ASSERT_RCU_READ_LOCKED();

	(void) release_ust_app_stream(sock, stream, app);
	free(stream);
}

void delete_ust_app_channel_rcu(struct rcu_head *head)
{
	struct ust_app_channel *ua_chan =
		lttng::utils::container_of(head, &ust_app_channel::rcu_head);

	lttng_ht_destroy(ua_chan->ctx);
	delete ua_chan;
}

/*
 * Extract the lost packet or discarded events counter when a per-PID
 * channel is being deleted and accumulate the values in the UST domain
 * orchestrator so they can be included in runtime statistics after the
 * application has exited.
 *
 * The session list lock must be held by the caller.
 */
void save_per_pid_lost_discarded_counters(struct ust_app_channel *ua_chan)
{
	uint64_t discarded = 0, lost = 0;

	/* Metadata channels do not have discarded counters. */
	switch (ua_chan->attr.type) {
	case LTTNG_UST_ABI_CHAN_METADATA:
		return;
	default:
		break;
	}

	const lttng::urcu::read_lock_guard read_lock;

	try {
		const auto session =
			ltt_session::find_session(ua_chan->session->recording_session_id);

		if (!session->ust_orchestrator) {
			/*
			 * Not finding the session is not an error because there are
			 * multiple ways the channels can be torn down.
			 *
			 * 1) The session daemon can initiate the destruction of the
			 *    ust app session after receiving a destroy command or
			 *    during its shutdown/teardown.
			 * 2) The application, since we are in per-pid tracing, is
			 *    unregistering and tearing down its ust app session.
			 *
			 * Both paths are protected by the session list lock which
			 * ensures that the accounting of lost packets and discarded
			 * events is done exactly once. The session is then unpublished
			 * from the session list, resulting in this condition.
			 */
			return;
		}

		auto& orchestrator =
			static_cast<lsu::domain_orchestrator&>(session->get_ust_orchestrator());

		if (ua_chan->attr.overwrite) {
			consumer_get_lost_packets(ua_chan->session->recording_session_id,
						  ua_chan->key,
						  orchestrator.get_consumer_output_ptr(),
						  &lost);
		} else {
			consumer_get_discarded_events(ua_chan->session->recording_session_id,
						      ua_chan->key,
						      orchestrator.get_consumer_output_ptr(),
						      &discarded);
		}
		const auto& recording_config =
			static_cast<const lttng::sessiond::config::recording_channel_configuration&>(
				ua_chan->channel_config);

		orchestrator.accumulate_per_pid_closed_app_stats(recording_config, discarded, lost);
	} catch (const lttng::sessiond::exceptions::session_not_found_error& ex) {
		DBG_FMT("Failed to save per-pid lost/discarded counters: {}, location='{}'",
			ex.what(),
			ex.source_location);
		return;
	}
}

/*
 * Common initialization for ust_app_channel. Used by both the recording
 * channel and metadata channel allocation paths.
 */
void init_ust_app_channel(struct ust_app_channel *ua_chan,
			  const char *name,
			  const lsu::app_session::locked_weak_ref& ua_sess,
			  struct lttng_ust_abi_channel_attr *attr)
{
	strncpy(ua_chan->name, name, sizeof(ua_chan->name));
	ua_chan->name[sizeof(ua_chan->name) - 1] = '\0';

	ua_chan->enabled = true;
	ua_chan->handle = -1;
	ua_chan->session = &ua_sess.get();
	ua_chan->key = get_next_channel_key();
	ua_chan->ctx = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	lttng_ht_node_init_str(&ua_chan->node, ua_chan->name);

	CDS_INIT_LIST_HEAD(&ua_chan->streams.head);

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

	DBG3("UST app channel %s allocated", ua_chan->name);
}
} /* namespace */

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
alloc_ust_app_channel(const char *name,
		      const lsu::app_session::locked_weak_ref& ua_sess,
		      struct lttng_ust_abi_channel_attr *attr,
		      const lttng::sessiond::config::recording_channel_configuration& config)
{
	struct ust_app_channel *ua_chan;

	try {
		ua_chan = new ust_app_channel(config);
	} catch (const std::bad_alloc&) {
		PERROR("ust_app_channel allocation");
		return nullptr;
	}

	init_ust_app_channel(ua_chan, name, ua_sess, attr);
	return ua_chan;
}

/*
 * Allocate a metadata channel (no recording_channel_configuration).
 */
struct ust_app_channel *alloc_ust_app_metadata_channel(
	const char *name,
	const lsu::app_session::locked_weak_ref& ua_sess,
	const lttng::sessiond::config::metadata_channel_configuration& metadata_config)
{
	struct ust_app_channel *ua_chan;

	try {
		ua_chan = new ust_app_channel(metadata_config);
	} catch (const std::bad_alloc&) {
		PERROR("ust_app_channel allocation");
		return nullptr;
	}

	init_ust_app_channel(ua_chan, name, ua_sess, nullptr);
	return ua_chan;
}

/*
 * Allocate and initialize a UST app stream.
 *
 * Return newly allocated stream pointer or NULL on error.
 */
lsu::app_stream *ust_app_alloc_stream()
{
	lsu::app_stream *stream = nullptr;

	stream = zmalloc<lsu::app_stream>();
	if (stream == nullptr) {
		PERROR("zmalloc ust app stream");
		goto error;
	}

	/* Zero could be a valid value for a handle so flag it to -1. */
	stream->handle = -1;

error:
	return stream;
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

	DBG3("UST app deleting channel %s", ua_chan->name);

	/* Wipe stream */
	for (auto *stream :
	     lttng::urcu::list_iteration_adapter<lsu::app_stream, &lsu::app_stream::list>(
		     ua_chan->streams.head)) {
		cds_list_del(&stream->list);
		delete_ust_app_stream(sock, stream, app);
	}

	/* Wipe context */
	for (auto ua_ctx :
	     lttng::urcu::lfht_iteration_adapter<ust_app_ctx,
						 decltype(ust_app_ctx::node),
						 &ust_app_ctx::node>(*ua_chan->ctx->ht)) {
		ret = cds_lfht_del(ua_chan->ctx->ht, &ua_ctx->node.node);
		LTTNG_ASSERT(!ret);
		delete_ust_app_ctx(sock, ua_ctx, app);
	}

	/* Wipe events */
	for (auto& event_pair : ua_chan->events) {
		delete_ust_app_event(sock, event_pair.second, app);
	}
	ua_chan->events.clear();

	if (ua_chan->session->buffer_type == LTTNG_BUFFER_PER_PID) {
		/* Wipe and free registry from session registry. */
		if (locked_registry) {
			try {
				locked_registry->remove_channel(ua_chan->key, sock >= 0);
			} catch (const std::exception& ex) {
				DBG("Could not find channel for removal: %s", ex.what());
			}
		}

		/*
		 * A negative socket can be used by the caller when
		 * cleaning-up a ua_chan in an error path. Skip the
		 * accounting in this case.
		 */
		if (sock >= 0) {
			save_per_pid_lost_discarded_counters(ua_chan);
		}
	}

	if (ua_chan->obj != nullptr) {
		lttng_ht_iter iter;

		/* Remove channel from application UST object descriptor. */
		iter.iter.node = &ua_chan->ust_objd_node.node;
		ret = lttng_ht_del(app->ust_objd, &iter);
		LTTNG_ASSERT(!ret);
		pthread_mutex_lock(&app->sock_lock);
		ret = lttng_ust_ctl_release_object(sock, ua_chan->obj);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app channel %s release failed. Application is dead: pid = %d, sock = %d",
				     ua_chan->name,
				     app->pid,
				     app->sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app channel %s release failed. Communication time out: pid = %d, sock = %d",
				     ua_chan->name,
				     app->pid,
				     app->sock);
			} else {
				ERR("UST app channel %s release failed with ret %d: pid = %d, sock = %d",
				    ua_chan->name,
				    ret,
				    app->pid,
				    app->sock);
			}
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
		free(ua_chan->obj);
	}
	call_rcu(&ua_chan->rcu_head, delete_ust_app_channel_rcu);
}

/*
 * Disable the specified channel on to UST tracer for the UST session.
 */
int disable_ust_channel(lsu::app *app,
			const lsu::app_session::locked_weak_ref& ua_sess,
			struct ust_app_channel *ua_chan)
{
	int ret;

	health_code_update();

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_disable(app->sock, ua_chan->obj);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app disable channel failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app disable channel failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app channel %s disable failed, session handle %d, with ret %d: pid = %d, sock = %d",
			    ua_chan->name,
			    ua_sess->handle,
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error;
	}

	DBG2("UST app channel %s disabled successfully for app: pid = %d", ua_chan->name, app->pid);

error:
	health_code_update();
	return ret;
}

/*
 * Enable the specified channel on to UST tracer for the UST session.
 */
int enable_ust_channel(lsu::app *app,
		       const lsu::app_session::locked_weak_ref& ua_sess,
		       struct ust_app_channel *ua_chan)
{
	int ret;

	health_code_update();

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_enable(app->sock, ua_chan->obj);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app channel %s enable failed. Application is dead: pid = %d, sock = %d",
			     ua_chan->name,
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app channel %s enable failed. Communication time out: pid = %d, sock = %d",
			     ua_chan->name,
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app channel %s enable failed, session handle %d, with ret %d: pid = %d, sock = %d",
			    ua_chan->name,
			    ua_sess->handle,
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error;
	}

	ua_chan->enabled = true;

	DBG2("UST app channel %s enabled successfully for app: pid = %d", ua_chan->name, app->pid);

error:
	health_code_update();
	return ret;
}

/*
 * Lookup ust app channel for session and disable it on the tracer side.
 */
int disable_ust_app_channel(const lsu::app_session::locked_weak_ref& ua_sess,
			    struct ust_app_channel *ua_chan,
			    lsu::app *app)
{
	int ret;

	ret = disable_ust_channel(app, ua_sess, ua_chan);
	if (ret < 0) {
		goto error;
	}

	ua_chan->enabled = false;

error:
	return ret;
}

/*
 * Lookup ust app channel for session and enable it on the tracer side. This
 * MUST be called with a RCU read side lock acquired.
 */
int enable_ust_app_channel(const lsu::app_session::locked_weak_ref& ua_sess,
			   lttng::c_string_view channel_name,
			   lsu::app *app)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app_channel *ua_chan;

	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(ua_sess->channels, (void *) channel_name.data(), &iter);
	ua_chan_node = lttng_ht_iter_get_node<lttng_ht_node_str>(&iter);
	if (ua_chan_node == nullptr) {
		DBG2("Unable to find channel %s in ust session id %" PRIu64,
		     channel_name.data(),
		     ua_sess->recording_session_id);
		goto error;
	}

	ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

	ret = enable_ust_channel(app, ua_sess, ua_chan);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Initialize per-app channel attributes from its recording_channel_configuration.
 *
 * This replaces the former shadow_copy_channel which copied from ltt_ust_channel.
 * The trace_class_stream_class_handle and channel type are set by the caller.
 */
void init_ust_app_channel_from_config(struct ust_app_channel *ua_chan)
{
	namespace lsc = lttng::sessiond::config;
	const auto& config =
		static_cast<const lsc::recording_channel_configuration&>(ua_chan->channel_config);

	DBG2("UST app initializing channel %s from config", ua_chan->name);

	ua_chan->attr.subbuf_size = config.subbuffer_size_bytes;
	ua_chan->attr.num_subbuf = config.subbuffer_count;
	ua_chan->attr.overwrite = config.buffer_full_policy ==
			lsc::channel_configuration::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET ?
		1 :
		0;
	ua_chan->attr.switch_timer_interval = config.switch_timer_period_us.value_or(0);
	ua_chan->attr.read_timer_interval = config.read_timer_period_us.value_or(0);

	ua_chan->attr.output = config.buffer_consumption_backend ==
			lsc::channel_configuration::buffer_consumption_backend_t::MMAP ?
		LTTNG_UST_ABI_MMAP :
		static_cast<lttng_ust_abi_output>(-1);

	switch (config.consumption_blocking_policy_.mode_) {
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::NONE:
		ua_chan->attr.blocking_timeout = 0;
		break;
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::UNBOUNDED:
		ua_chan->attr.blocking_timeout = -1;
		break;
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::TIMED:
		ua_chan->attr.blocking_timeout = *config.consumption_blocking_policy_.timeout_us;
		break;
	}

	ua_chan->enabled = config.is_enabled;

	DBG3("UST app channel %s initialized from config", ua_chan->name);
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
	 * list of that channel and set the ust objects.
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

/*
 * Send channel and stream buffer to application.
 *
 * Return 0 on success. On error, a negative value is returned.
 */
int send_channel_pid_to_ust(lsu::app *app,
			    lsu::app_session *ua_sess,
			    struct ust_app_channel *ua_chan)
{
	int ret;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);

	health_code_update();

	DBG("UST app sending channel %s to UST app sock %d", ua_chan->name, app->sock);

	/* Send channel to the application. */
	ret = ust_consumer_send_channel_to_ust(app, ua_sess, ua_chan);
	if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
		ret = -ENOTCONN; /* Caused by app exiting. */
		goto error;
	} else if (ret == -EAGAIN) {
		/* Caused by timeout. */
		WARN("Communication with application %d timed out on send_channel for channel \"%s\" of session \"%" PRIu64
		     "\".",
		     app->pid,
		     ua_chan->name,
		     ua_sess->recording_session_id);
		/* Treat this the same way as an application that is exiting. */
		ret = -ENOTCONN;
		goto error;
	} else if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Send all streams to application. */
	for (auto *stream :
	     lttng::urcu::list_iteration_adapter<lsu::app_stream, &lsu::app_stream::list>(
		     ua_chan->streams.head)) {
		ret = ust_consumer_send_stream_to_ust(app, ua_chan, stream);
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = -ENOTCONN; /* Caused by app exiting. */
			goto error;
		} else if (ret == -EAGAIN) {
			/* Caused by timeout. */
			WARN("Communication with application %d timed out on send_stream for stream \"%s\" of channel \"%s\" of session \"%" PRIu64
			     "\".",
			     app->pid,
			     stream->name,
			     ua_chan->name,
			     ua_sess->recording_session_id);
			/*
			 * Treat this the same way as an application that is
			 * exiting.
			 */
			ret = -ENOTCONN;
		} else if (ret < 0) {
			goto error;
		}
		/* We don't need the stream anymore once sent to the tracer. */
		cds_list_del(&stream->list);
		delete_ust_app_stream(-1, stream, app);
	}

error:
	health_code_update();
	return ret;
}

/*
 * Send a per-UID stream group's channel and streams to the application by
 * duplicating the master objects held by the stream group.
 *
 * In per-UID mode, the stream group holds the "master" channel and stream
 * objects obtained from the consumer daemon when the first application
 * created the shared buffers. Each subsequent application receives
 * duplicated copies of these objects.
 *
 * Return 0 on success else a negative value.
 */
int send_channel_uid_to_ust(lsu::stream_group& stream_group,
			    lsu::app *app,
			    lsu::app_session *ua_sess,
			    struct ust_app_channel *ua_chan)
{
	int ret;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);

	DBG("UST app sending stream group channel to ust sock %d", app->sock);

	/* Duplicate the master channel object for this application. */
	{
		try {
			auto duplicated_channel = stream_group.duplicate_channel_object();
			ua_chan->obj = duplicated_channel.release();
		} catch (const std::exception& ex) {
			ERR("Failed to duplicate channel object for app pid %d: %s",
			    app->pid,
			    ex.what());
			ret = -ENOMEM;
			goto error;
		}

		ua_chan->handle = ua_chan->obj->header.handle;
	}

	/* Send channel to the application. */
	ret = ust_consumer_send_channel_to_ust(app, ua_sess, ua_chan);
	if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
		ret = -ENOTCONN; /* Caused by app exiting. */
		goto error;
	} else if (ret == -EAGAIN) {
		/* Caused by timeout. */
		WARN("Communication with application %d timed out on send_channel for channel \"%s\" of session \"%" PRIu64
		     "\".",
		     app->pid,
		     ua_chan->name,
		     ua_sess->recording_session_id);
		/* Treat this the same way as an application that is exiting. */
		ret = -ENOTCONN;
		goto error;
	} else if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Send all streams to application by duplicating from the stream group. */
	for (const auto& stream_ptr : stream_group.streams()) {
		lsu::app_stream app_stream = {};

		try {
			auto duplicated_stream = stream_ptr->handle.duplicate();
			app_stream.obj = duplicated_stream.release();
		} catch (const std::exception& ex) {
			ERR("Failed to duplicate stream object for app pid %d: %s",
			    app->pid,
			    ex.what());
			ret = -ENOMEM;
			goto error;
		}

		app_stream.handle = app_stream.obj->header.handle;

		ret = ust_consumer_send_stream_to_ust(app, ua_chan, &app_stream);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				ret = -ENOTCONN; /* Caused by app exiting. */
			} else if (ret == -EAGAIN) {
				WARN("Communication with application %d timed out on send_stream for stream of channel \"%s\" of session \"%" PRIu64
				     "\".",
				     app->pid,
				     ua_chan->name,
				     ua_sess->recording_session_id);
				ret = -ENOTCONN;
			}
			(void) release_ust_app_stream(-1, &app_stream, app);
			goto error;
		}

		(void) release_ust_app_stream(-1, &app_stream, app);
	}

error:
	return ret;
}
