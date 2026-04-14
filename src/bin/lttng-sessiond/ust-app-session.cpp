/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "consumer.hpp"
#include "health-sessiond.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "session.hpp"
#include "ust-app-channel.hpp"
#include "ust-app-session.hpp"
#include "ust-app.hpp"
#include "ust-trace-class-index.hpp"
#include "ust-trace-class.hpp"

#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/exception.hpp>
#include <common/scope-exit.hpp>
#include <common/urcu.hpp>

#include <inttypes.h>
#include <mutex>
#include <pthread.h>

namespace lsu = lttng::sessiond::ust;
namespace lsc = lttng::sessiond::config;

namespace {

/* Next available session ID. Access under next_session_id_lock. */
uint64_t _next_session_id;
pthread_mutex_t next_session_id_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Bundles a shared_ptr (ownership) with a locked_ref (lock) so that
 * the trace_class cannot be destroyed while the lock is held.
 *
 * Callers that need a `const locked_ref&` (e.g. push_metadata) should
 * use the locked_ref() accessor.
 */
struct owned_locked_registry {
	std::shared_ptr<lsu::trace_class> _ownership;
	lsu::trace_class::locked_ref _lock;

	explicit operator bool() const noexcept
	{
		return _ownership != nullptr;
	}

	lsu::trace_class *operator->() const noexcept
	{
		return _ownership.get();
	}

	lsu::trace_class& operator*() const noexcept
	{
		return *_ownership;
	}

	lsu::trace_class::locked_ref& locked_ref() noexcept
	{
		return _lock;
	}

	const lsu::trace_class::locked_ref& locked_ref() const noexcept
	{
		return _lock;
	}

	void reset() noexcept
	{
		_lock.reset();
		_ownership.reset();
	}
};

owned_locked_registry get_locked_session_registry(const lsu::app_session::identifier& identifier)
{
	auto session = ust_app_get_session_registry(identifier);
	lsu::trace_class::locked_ref lock;

	if (session) {
		pthread_mutex_lock(&session->_lock);
		lock = lsu::trace_class::locked_ref{ session.get() };
	}

	return { std::move(session), std::move(lock) };
}

/*
 * For a given application and session, push metadata to consumer.
 * Either sock or consumer is required : if sock is NULL, the default
 * socket to send the metadata is retrieved from consumer, if sock
 * is not NULL we use it to send the metadata.
 * RCU read-side lock must be held while calling this function,
 * therefore ensuring existence of registry. It also ensures existence
 * of socket throughout this function.
 *
 * Return 0 on success else a negative error.
 * Returning a -EPIPE return value means we could not send the metadata,
 * but it can be caused by recoverable errors (e.g. the application has
 * terminated concurrently).
 */
int push_metadata(const lsu::trace_class::locked_ref& locked_registry,
		  struct consumer_output *consumer)
{
	int ret_val;
	ssize_t ret;
	struct consumer_socket *socket;

	LTTNG_ASSERT(locked_registry);
	LTTNG_ASSERT(consumer);
	ASSERT_RCU_READ_LOCKED();

	if (locked_registry->_metadata_closed) {
		ret_val = -EPIPE;
		goto error;
	}

	/* Get consumer socket to use to push the metadata. */
	socket = consumer_find_socket_by_bitness(locked_registry->abi.bits_per_long, consumer);
	if (!socket) {
		ret_val = -1;
		goto error;
	}

	ret = ust_app_push_metadata(locked_registry, socket, 0);
	if (ret < 0) {
		ret_val = ret;
		goto error;
	}
	return 0;

error:
	return ret_val;
}

void delete_ust_app_session_rcu(struct rcu_head *head)
{
	lsu::app_session *ua_sess = lttng::utils::container_of(head, &lsu::app_session::rcu_head);

	lttng_ht_destroy(ua_sess->channels);
	delete ua_sess;
}

/*
 * Delete the session from the application ht and delete the data structure by
 * freeing every object inside and releasing them.
 *
 * The session list lock must be held by the caller.
 */
} /* namespace */

/*
 * Return the atomically incremented value of next_session_id.
 */
uint64_t get_next_session_id()
{
	uint64_t ret;

	pthread_mutex_lock(&next_session_id_lock);
	ret = ++_next_session_id;
	pthread_mutex_unlock(&next_session_id_lock);
	return ret;
}

/*
 * Return the session registry according to the buffer type of the given
 * session.
 *
 * A registry per UID object MUST exists before calling this function or else
 * it LTTNG_ASSERT() if not found. RCU read side lock must be acquired.
 */
std::shared_ptr<lsu::trace_class>
ust_app_get_session_registry(const lsu::app_session::identifier& ua_sess_id)
{
	switch (ua_sess_id.allocation_policy) {
	case lsu::app_session::identifier::buffer_allocation_policy::PER_PID:
		return the_trace_class_index->find_per_pid(ua_sess_id.app_session_id);
	case lsu::app_session::identifier::buffer_allocation_policy::PER_UID:
	{
		const std::uint32_t bits_per_long = ua_sess_id.abi ==
				lsu::app_session::identifier::application_abi::ABI_32 ?
			32 :
			64;

		return the_trace_class_index->find_per_uid(
			ua_sess_id.recording_session_id,
			bits_per_long,
			lttng_credentials_get_uid(&ua_sess_id.app_credentials));
	}
	default:
		abort();
	};
}

/*
 * Send to the consumer a close metadata command for the given session. Once
 * done, the metadata channel is deleted and the session metadata pointer is
 * nullified. The session lock MUST be held unless the application is
 * in the destroy path.
 *
 * Do not hold the registry lock while communicating with the consumerd, because
 * doing so causes inter-process deadlocks between consumerd and sessiond with
 * the metadata request notification.
 *
 * Return 0 on success else a negative value.
 */
int close_metadata(uint64_t metadata_key,
		   unsigned int consumer_bitness,
		   struct consumer_output *consumer)
{
	int ret;
	struct consumer_socket *socket;
	const lttng::urcu::read_lock_guard read_lock_guard;

	LTTNG_ASSERT(consumer);

	/* Get consumer socket to use to push the metadata. */
	socket = consumer_find_socket_by_bitness(consumer_bitness, consumer);
	if (!socket) {
		ret = -1;
		goto end;
	}

	ret = consumer_close_metadata(socket, metadata_key);
	if (ret < 0) {
		goto end;
	}

end:
	return ret;
}

/*
 * Delete ust app session safely. RCU read lock must be held before calling
 * this function.
 *
 * The session list lock must be held by the caller.
 */
void delete_ust_app_session(int sock, lsu::app_session *ua_sess, lsu::app *app)
{
	LTTNG_ASSERT(ua_sess);
	ASSERT_RCU_READ_LOCKED();

	/* Locked for the duration of the function. */
	auto locked_ua_sess = ua_sess->lock();

	LTTNG_ASSERT(!ua_sess->deleted);
	ua_sess->deleted = true;

	auto locked_registry = get_locked_session_registry(locked_ua_sess->get_identifier());
	/* Registry can be null on error path during initialization. */
	if (locked_registry) {
		/* Push metadata for application before freeing the application. */
		(void) push_metadata(locked_registry.locked_ref(), ua_sess->consumer);
	}

	for (auto *ua_chan :
	     lttng::urcu::lfht_iteration_adapter<ust_app_channel,
						 decltype(ust_app_channel::node),
						 &ust_app_channel::node>(*ua_sess->channels->ht)) {
		const auto ret = cds_lfht_del(ua_sess->channels->ht, &ua_chan->node.node);
		LTTNG_ASSERT(ret == 0);
		delete_ust_app_channel(sock, ua_chan, app, locked_registry.locked_ref());
	}

	if (locked_registry) {
		/*
		 * Don't ask to close metadata for global per UID buffers. Close
		 * metadata only on destroy trace session in this case. Also, the
		 * previous push metadata could have flag the metadata registry to
		 * close so don't send a close command if closed.
		 */
		if (ua_sess->buffer_type != LTTNG_BUFFER_PER_UID) {
			const auto metadata_key = locked_registry->_metadata_key;
			const auto consumer_bitness = locked_registry->abi.bits_per_long;

			if (!locked_registry->_metadata_closed && metadata_key != 0) {
				locked_registry->_metadata_closed = true;
			}

			/* Release lock before communication, see comments in close_metadata(). */
			locked_registry.reset();
			(void) close_metadata(metadata_key, consumer_bitness, ua_sess->consumer);
		}
	}

	if (ua_sess->handle != -1) {
		int ret;
		{
			const auto protocol = app->command_socket.lock();
			ret = lttng_ust_ctl_release_handle(sock, ua_sess->handle);
		}
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release session handle failed. Application is dead: pid = %d, sock = %d",
				     app->pid,
				     app->command_socket.fd());
			} else if (ret == -EAGAIN) {
				WARN("UST app release session handle failed. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->command_socket.fd());
			} else {
				ERR("UST app release session handle failed with ret %d: pid = %d, sock = %d",
				    ret,
				    app->pid,
				    app->command_socket.fd());
			}
		}
	}

	consumer_output_put(ua_sess->consumer);
	call_rcu(&ua_sess->rcu_head, delete_ust_app_session_rcu);
}

/*
 * Alloc new UST app session.
 */
lsu::app_session *alloc_ust_app_session()
{
	auto *ua_sess = new lsu::app_session;

	ua_sess->handle = -1;
	ua_sess->channels = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);

	return ua_sess;
}

int ust_app_flush_app_session(lsu::app& app, lsu::app_session& ua_sess)
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
