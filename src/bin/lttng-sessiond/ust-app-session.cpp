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

#include <lttng/ust-ctl.h>
#include <lttng/ust-error.h>

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
struct owned_locked_trace_class {
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

owned_locked_trace_class get_locked_trace_class(const lsu::app_session::identifier& identifier)
{
	auto session = lsu::app_session::get_trace_class(identifier);
	lsu::trace_class::locked_ref lock;

	if (session) {
		pthread_mutex_lock(&session->_lock);
		lock = lsu::trace_class::locked_ref{ session.get() };
	}

	return { std::move(session), std::move(lock) };
}

/*
 * For a given application and session, push metadata to consumer.
 * The consumer socket is retrieved from the consumer output.
 *
 * The RCU read-side lock is acquired internally to look up the consumer
 * socket and kept held while the socket is used, ensuring it is not
 * freed concurrently.
 *
 * Return 0 on success else a negative error.
 * Returning a -EPIPE return value means we could not send the metadata,
 * but it can be caused by recoverable errors (e.g. the application has
 * terminated concurrently).
 */
int push_metadata(const lsu::trace_class::locked_ref& locked_trace_class,
		  struct consumer_output *consumer)
{
	int ret_val;
	ssize_t ret;
	struct consumer_socket *socket;

	LTTNG_ASSERT(locked_trace_class);
	LTTNG_ASSERT(consumer);

	if (locked_trace_class->_metadata_closed) {
		ret_val = -EPIPE;
		goto error;
	}

	{
		const lttng::urcu::read_lock_guard read_lock;

		/* Get consumer socket to use to push the metadata. */
		socket = consumer_find_socket_by_bitness(locked_trace_class->abi.bits_per_long,
							 consumer);
		if (!socket) {
			ret_val = -1;
			goto error;
		}

		ret = ust_app_push_metadata(locked_trace_class, socket, 0);
		if (ret < 0) {
			ret_val = ret;
			goto error;
		}
	}

	return 0;

error:
	return ret_val;
}

} /* anonymous namespace */

lsu::app_session::app_session(lsu::app& app,
			      std::uint64_t recording_session_id_,
			      std::uint64_t app_session_id_,
			      lttng_credentials real_credentials_,
			      lttng_credentials effective_credentials_,
			      lttng_buffer_type buffer_type_,
			      std::uint32_t bits_per_long_,
			      std::string path_,
			      std::string root_shm_path_,
			      std::string shm_path_,
			      consumer_output *consumer_) :
	recording_session_id(recording_session_id_),
	app_session_id(app_session_id_),
	path(std::move(path_)),
	real_credentials(real_credentials_),
	effective_credentials(effective_credentials_),
	consumer(consumer_),
	buffer_type(buffer_type_),
	bits_per_long(bits_per_long_),
	root_shm_path(std::move(root_shm_path_)),
	shm_path(std::move(shm_path_)),
	_app(app)
{
	LTTNG_ASSERT(consumer);
}

lsu::app_session::~app_session()
{
	LTTNG_ASSERT(!deleted);
	deleted = true;

	auto locked_trace_class = get_locked_trace_class(get_identifier());
	/* Trace class can be null on error path during initialization. */
	if (locked_trace_class) {
		/* Push metadata for application before freeing the application. */
		(void) push_metadata(locked_trace_class.locked_ref(), consumer);
	}

	/* Remove per-PID channels from the trace class while it is locked. */
	if (buffer_type == LTTNG_BUFFER_PER_PID && locked_trace_class) {
		for (const auto& chan_pair : channels) {
			try {
				locked_trace_class->remove_channel(chan_pair.second->key, true);
			} catch (const std::exception& ex) {
				DBG("Could not find channel for removal: %s", ex.what());
			}
		}
	}

	if (locked_trace_class) {
		/*
		 * Don't ask to close metadata for global per UID buffers. Close
		 * metadata only on destroy trace session in this case. Also, the
		 * previous push metadata could have flagged the metadata trace class to
		 * close so don't send a close command if closed.
		 */
		if (buffer_type != LTTNG_BUFFER_PER_UID) {
			const auto metadata_key = locked_trace_class->_metadata_key;
			const auto consumer_bitness = locked_trace_class->abi.bits_per_long;

			if (!locked_trace_class->_metadata_closed && metadata_key != 0) {
				locked_trace_class->_metadata_closed = true;
			}

			/* Release lock before communication, see comments in close_metadata(). */
			locked_trace_class.reset();
			(void) close_metadata(metadata_key, consumer_bitness, consumer);
		}
	}

	/*
	 * Channel destructors handle UST object release,
	 * event/context/stream teardown.
	 */
	channels.clear();

	if (handle != -1) {
		int ret;
		{
			const auto protocol = _app.command_socket.lock();
			ret = lttng_ust_ctl_release_handle(protocol.fd(), handle);
		}

		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release session handle failed. Application is dead: pid = %d, sock = %d",
				     _app.pid,
				     _app.command_socket.fd());
			} else if (ret == -EAGAIN) {
				WARN("UST app release session handle failed. Communication time out: pid = %d, sock = %d",
				     _app.pid,
				     _app.command_socket.fd());
			} else {
				ERR("UST app release session handle failed with ret %d: pid = %d, sock = %d",
				    ret,
				    _app.pid,
				    _app.command_socket.fd());
			}
		}
	}

	consumer_output_put(consumer);
}

/*
 * Return the atomically incremented value of next_session_id.
 */
uint64_t lsu::app_session::next_id()
{
	uint64_t ret;

	pthread_mutex_lock(&next_session_id_lock);
	ret = ++_next_session_id;
	pthread_mutex_unlock(&next_session_id_lock);
	return ret;
}

/*
 * Return the session trace class according to the buffer type of the given
 * session.
 *
 * A per-UID trace class object MUST exist before calling this function or else
 * it LTTNG_ASSERT() if not found. RCU read side lock must be acquired.
 */
std::shared_ptr<lsu::trace_class>
lsu::app_session::get_trace_class(const lsu::app_session::identifier& ua_sess_id)
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
 * Do not hold the trace class lock while communicating with the consumerd, because
 * doing so causes inter-process deadlocks between consumerd and sessiond with
 * the metadata request notification.
 *
 * Return 0 on success else a negative value.
 */
int lsu::app_session::close_metadata(uint64_t metadata_key,
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

void lsu::app_session::flush()
{
	int ret;
	struct consumer_socket *socket;

	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	DBG("Flushing app session buffers for ust app pid %d", _app.pid);

	if (!_app.compatible) {
		return;
	}

	if (deleted) {
		return;
	}

	health_code_update();

	/* Flushing buffers */
	socket = consumer_find_socket_by_bitness(_app.abi.bits_per_long, consumer);

	/* Flush buffers and push metadata. */
	switch (buffer_type) {
	case LTTNG_BUFFER_PER_PID:
	{
		for (auto& chan_pair : channels) {
			health_code_update();
			ret = consumer_flush_channel(socket, chan_pair.second->key);
			if (ret) {
				ERR("Error flushing consumer channel");
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
}
