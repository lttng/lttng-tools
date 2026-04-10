/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APP_SESSION_HPP
#define LTTNG_SESSIOND_UST_APP_SESSION_HPP

#include "ust-application-abi.hpp"

#include <common/credentials.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/macros.hpp>
#include <common/reference.hpp>

#include <lttng/domain.h>

#include <limits.h>
#include <memory>
#include <pthread.h>
#include <stdint.h>

struct consumer_output;

namespace lttng {
namespace sessiond {
namespace ust {
class trace_class;
struct app;
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

namespace lttng {
namespace sessiond {
namespace ust {

struct app_session {
private:
	static void _session_unlock(app_session *session)
	{
		_const_session_unlock(session);
	}

	static void _const_session_unlock(const app_session *session)
	{
		pthread_mutex_unlock(&session->_lock);
	}

public:
	using locked_weak_ref = lttng::non_copyable_reference<
		app_session,
		lttng::memory::create_deleter_class<app_session,
						    app_session::_session_unlock>::deleter>;
	using const_locked_weak_ref = lttng::non_copyable_reference<
		const app_session,
		lttng::memory::create_deleter_class<const app_session,
						    app_session::_const_session_unlock>::deleter>;

	static locked_weak_ref make_locked_weak_ref(app_session& ua_session)
	{
		return lttng::make_non_copyable_reference<locked_weak_ref::referenced_type,
							  locked_weak_ref::deleter>(ua_session);
	}

	static const_locked_weak_ref make_locked_weak_ref(const app_session& ua_session)
	{
		return lttng::make_non_copyable_reference<const_locked_weak_ref::referenced_type,
							  const_locked_weak_ref::deleter>(
			ua_session);
	}

	app_session::const_locked_weak_ref lock() const noexcept
	{
		pthread_mutex_lock(&_lock);
		return app_session::make_locked_weak_ref(*this);
	}

	app_session::locked_weak_ref lock() noexcept
	{
		pthread_mutex_lock(&_lock);
		return app_session::make_locked_weak_ref(*this);
	}

	struct identifier {
		using application_abi = lttng::sessiond::ust::application_abi;
		enum class buffer_allocation_policy : std::uint8_t { PER_PID, PER_UID };

		/* Unique identifier of the app_session. */
		std::uint64_t app_session_id;
		/* Unique identifier of the ltt_session (recording session). */
		std::uint64_t recording_session_id;
		/* Credentials of the application which owns the app_session. */
		lttng_credentials app_credentials;
		application_abi abi;
		buffer_allocation_policy allocation_policy;
	};

	identifier get_identifier() const noexcept
	{
		/*
		 * To work around synchro design issues, this method allows the sampling
		 * of an app_session's identifying properties without taking its lock.
		 *
		 * Since those properties are immutable, it is safe to sample them without
		 * holding the lock (as long as the existence of the instance is somehow
		 * guaranteed).
		 *
		 * The locking issue that motivates this method is that the application
		 * notitication handling thread needs to access the trace_class in response to
		 * a message from the application. The app_session's ID is needed to look-up the
		 * registry session.
		 *
		 * The application's message can be emited in response to a command from the
		 * session daemon that is emited by the client thread.
		 *
		 * During that command, the client thread holds the app_session lock until
		 * the application replies to the command. This causes the notification thread
		 * to block when it attempts to sample the app_session's ID properties.
		 */
		LTTNG_ASSERT(bits_per_long == 32 || bits_per_long == 64);
		LTTNG_ASSERT(buffer_type == LTTNG_BUFFER_PER_PID ||
			     buffer_type == LTTNG_BUFFER_PER_UID);

		return { .app_session_id = app_session_id,
			 .recording_session_id = recording_session_id,
			 .app_credentials = real_credentials,
			 .abi = bits_per_long == 32 ? identifier::application_abi::ABI_32 :
						      identifier::application_abi::ABI_64,
			 .allocation_policy = buffer_type == LTTNG_BUFFER_PER_PID ?
				 identifier::buffer_allocation_policy::PER_PID :
				 identifier::buffer_allocation_policy::PER_UID };
	}

	bool enabled = false;
	/* started: has the session been in started state at any time ? */
	bool started = false; /* allows detection of start vs restart. */
	int handle = 0; /* used has unique identifier for app session */

	bool deleted = false; /* Session deleted flag. Check with lock held. */

	/*
	 * Recording session ID (ltt_session::id). Multiple app_sessions
	 * can share the same recording_session_id since each application
	 * gets its own app_session for the same recording session.
	 */
	uint64_t recording_session_id = 0;
	/* Unique app_session identifier, allocated by sessiond. */
	uint64_t app_session_id = 0;
	::lttng_ht *channels = nullptr; /* Registered channels */
	lttng_ht_node_u64 node = {};
	/*
	 * Node indexed by UST session object descriptor (handle). Stored in the
	 * ust_sessions_objd hash table in the app object.
	 */
	lttng_ht_node_ulong ust_objd_node = {};
	/* Starts with 'ust'; no leading slash. */
	char path[PATH_MAX] = {};
	/* UID/GID of the application owning the session */
	lttng_credentials real_credentials = {};
	/* Effective UID and GID. Same as the tracing session. */
	lttng_credentials effective_credentials = {};
	/*
	 * Once at least *one* session is created onto the application, the
	 * corresponding consumer is set so we can use it on unregistration.
	 */
	::consumer_output *consumer = nullptr;
	enum lttng_buffer_type buffer_type = LTTNG_BUFFER_PER_PID;
	/* ABI of the session. Same value as the application. */
	uint32_t bits_per_long = 0;
	/* For delayed reclaim */
	::rcu_head rcu_head = {};

	char root_shm_path[PATH_MAX] = {};
	char shm_path[PATH_MAX] = {};

private:
	/*
	 * Lock protecting this session's ust app interaction. Held
	 * across command send/recv to/from app. Never nests within the
	 * session registry lock.
	 */
	mutable pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#ifdef HAVE_LIBLTTNG_UST_CTL

lttng::sessiond::ust::app_session *ust_app_lookup_app_session(std::uint64_t session_id,
							      const lttng::sessiond::ust::app *app);
std::shared_ptr<lttng::sessiond::ust::trace_class>
ust_app_get_session_registry(const lttng::sessiond::ust::app_session::identifier& identifier);

lttng::sessiond::ust::app_session *alloc_ust_app_session();
void delete_ust_app_session(int sock,
			    lttng::sessiond::ust::app_session *ua_sess,
			    lttng::sessiond::ust::app *app);
std::uint64_t get_next_session_id();

int ust_app_destroy_trace_all(std::uint64_t session_id);
void ust_app_global_destroy(std::uint64_t session_id, lttng::sessiond::ust::app *app);

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_SESSIOND_UST_APP_SESSION_HPP */
