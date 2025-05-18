/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "buffer-registry.hpp"
#include "cmd.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "session.hpp"
#include "timer.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/ctl/format.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/trace-chunk.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

#include <lttng/location-internal.hpp>

#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <urcu.h>

namespace {
struct ltt_session_destroy_notifier_element {
	ltt_session_destroy_notifier notifier;
	void *user_data;
};

struct ltt_session_clear_notifier_element {
	ltt_session_clear_notifier notifier;
	void *user_data;
};

namespace ls = lttng::sessiond;

/*
 * NOTES:
 *
 * No ltt_session.lock is taken here because those data structure are widely
 * spread across the lttng-tools code base so before calling functions below
 * that can read/write a session, the caller MUST acquire the session lock
 * using session_lock() and session_unlock().
 */

/* These characters are forbidden in a session name. Used by validate_name. */
const char *forbidden_name_chars = "/";

/* Global hash table to keep the sessions, indexed by id. */
struct lttng_ht *ltt_sessions_ht_by_id = nullptr;
/* Global hash table to keep the sessions, indexed by name. */
struct lttng_ht *ltt_sessions_ht_by_name = nullptr;

/*
 * Init tracing session list.
 *
 * Please see session.h for more explanation and correct usage of the list.
 */
struct ltt_session_list the_session_list;

/*
 * Return a ltt_session structure ptr that matches name. If no session found,
 * NULL is returned. This must be called with the session list lock held using
 * session_lock_list and session_unlock_list.
 * A reference to the session is implicitly acquired by this function.
 */
struct ltt_session *session_find_by_name(const char *name)
{
	struct ltt_session *session_to_return;

	LTTNG_ASSERT(name);
	ASSERT_SESSION_LIST_LOCKED();

	DBG2("Trying to find session by name %s", name);

	for (auto session : lttng::urcu::list_iteration_adapter<ltt_session, &ltt_session::list>(
		     the_session_list.head)) {
		if (!strncmp(session->name, name, NAME_MAX) && !session->destroyed) {
			session_to_return = session;
			goto found;
		}
	}

	return nullptr;
found:
	return session_get(session_to_return) ? session_to_return : nullptr;
}

/*
 * Return an ltt_session that matches the id. If no session is found,
 * NULL is returned. This must be called with rcu_read_lock and
 * session list lock held (to guarantee the lifetime of the session).
 */
struct ltt_session *session_find_by_id(uint64_t id)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct ltt_session *ls;

	ASSERT_RCU_READ_LOCKED();
	ASSERT_SESSION_LIST_LOCKED();

	if (!ltt_sessions_ht_by_id) {
		goto end;
	}

	lttng_ht_lookup(ltt_sessions_ht_by_id, &id, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (node == nullptr) {
		goto end;
	}
	ls = lttng::utils::container_of(node, &ltt_session::node);

	DBG3("Session %" PRIu64 " found by id.", id);
	return session_get(ls) ? ls : nullptr;

end:
	DBG3("Session %" PRIu64 " NOT found by id", id);
	return nullptr;
}
} /* namespace */

/*
 * Validate the session name for forbidden characters.
 *
 * Return 0 on success else -1 meaning a forbidden char. has been found.
 */
static int validate_name(const char *name)
{
	int ret;
	char *tok, *tmp_name;

	LTTNG_ASSERT(name);

	tmp_name = strdup(name);
	if (!tmp_name) {
		/* ENOMEM here. */
		ret = -1;
		goto error;
	}

	tok = strpbrk(tmp_name, forbidden_name_chars);
	if (tok) {
		DBG("Session name %s contains a forbidden character", name);
		/* Forbidden character has been found. */
		ret = -1;
		goto error;
	}
	ret = 0;

error:
	free(tmp_name);
	return ret;
}

/*
 * Add a ltt_session structure to the global list.
 *
 * The caller MUST acquire the session list lock before.
 * Returns the unique identifier for the session.
 */
static uint64_t add_session_list(struct ltt_session *ls)
{
	LTTNG_ASSERT(ls);

	cds_list_add(&ls->list, &the_session_list.head);
	return the_session_list.next_uuid++;
}

/*
 * Delete a ltt_session structure to the global list.
 *
 * The caller MUST acquire the session list lock before.
 */
static void del_session_list(struct ltt_session *ls)
{
	LTTNG_ASSERT(ls);

	cds_list_del(&ls->list);
}

/*
 * Return a pointer to the session list.
 */
struct ltt_session_list *session_get_list()
{
	return &the_session_list;
}

/*
 * Returns once the session list is empty.
 */
void session_list_wait_empty(std::unique_lock<std::mutex> list_lock)
{
	/* Keep waiting until the session list is empty. */
	the_session_list.removal_cond.wait(list_lock,
					   [] { return cds_list_empty(&the_session_list.head); });
}

/*
 * Try to acquire session list lock
 */
int session_trylock_list() noexcept
{
	/* Return 0 if successfully acquired. */
	return the_session_list.lock.try_lock() ? 0 : 1;
}

/*
 * Get the session's consumer destination type.
 */
enum consumer_dst_type session_get_consumer_destination_type(const ltt_session::locked_ref& session)
{
	/*
	 * The output information is duplicated in both of those session types.
	 * Hence, it doesn't matter from which it is retrieved. However, it is
	 * possible for only one of them to be set.
	 */
	return session->kernel_session ? session->kernel_session->consumer->type :
					 session->ust_session->consumer->type;
}

/*
 * Get the session's consumer network hostname.
 * The caller must ensure that the destination is of type "net".
 */
const char *session_get_net_consumer_hostname(const ltt_session::locked_ref& session)
{
	const char *hostname = nullptr;
	const struct consumer_output *output;

	output = session->kernel_session ? session->kernel_session->consumer :
					   session->ust_session->consumer;

	/*
	 * hostname is assumed to be the same for both control and data
	 * connections.
	 */
	switch (output->dst.net.control.dtype) {
	case LTTNG_DST_IPV4:
		hostname = output->dst.net.control.dst.ipv4;
		break;
	case LTTNG_DST_IPV6:
		hostname = output->dst.net.control.dst.ipv6;
		break;
	default:
		abort();
	}
	return hostname;
}

/*
 * Get the session's consumer network control and data ports.
 * The caller must ensure that the destination is of type "net".
 */
void session_get_net_consumer_ports(const ltt_session::locked_ref& session,
				    uint16_t *control_port,
				    uint16_t *data_port)
{
	const struct consumer_output *output;

	output = session->kernel_session ? session->kernel_session->consumer :
					   session->ust_session->consumer;
	*control_port = output->dst.net.control.port;
	*data_port = output->dst.net.data.port;
}

/*
 * Get the location of the latest trace archive produced by a rotation.
 */
struct lttng_trace_archive_location *
session_get_trace_archive_location(const ltt_session::locked_ref& session)
{
	int ret;
	struct lttng_trace_archive_location *location = nullptr;
	char *chunk_path = nullptr;

	if (session->rotation_state != LTTNG_ROTATION_STATE_COMPLETED ||
	    !session->last_archived_chunk_name) {
		goto end;
	}

	switch (session_get_consumer_destination_type(session)) {
	case CONSUMER_DST_LOCAL:
		ret = asprintf(&chunk_path,
			       "%s/" DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY "/%s",
			       session_get_base_path(session),
			       session->last_archived_chunk_name);
		if (ret == -1) {
			goto end;
		}
		location = lttng_trace_archive_location_local_create(chunk_path);
		break;
	case CONSUMER_DST_NET:
	{
		const char *hostname;
		uint16_t control_port, data_port;

		hostname = session_get_net_consumer_hostname(session);
		session_get_net_consumer_ports(session, &control_port, &data_port);
		location = lttng_trace_archive_location_relay_create(
			hostname,
			LTTNG_TRACE_ARCHIVE_LOCATION_RELAY_PROTOCOL_TYPE_TCP,
			control_port,
			data_port,
			session->last_chunk_path);
		break;
	}
	default:
		abort();
	}
end:
	free(chunk_path);
	return location;
}

/*
 * Allocate the ltt_sessions_ht_by_id and ltt_sessions_ht_by_name HT.
 *
 * The session list lock must be held.
 */
static int ltt_sessions_ht_alloc()
{
	int ret = 0;

	DBG("Allocating ltt_sessions_ht_by_id");
	ltt_sessions_ht_by_id = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!ltt_sessions_ht_by_id) {
		ret = -1;
		ERR("Failed to allocate ltt_sessions_ht_by_id");
		goto end;
	}

	DBG("Allocating ltt_sessions_ht_by_name");
	ltt_sessions_ht_by_name = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!ltt_sessions_ht_by_name) {
		ret = -1;
		ERR("Failed to allocate ltt_sessions_ht_by_name");
		goto end;
	}

end:
	return ret;
}

/*
 * Destroy the ltt_sessions_ht_by_id HT.
 *
 * The session list lock must be held.
 */
static void ltt_sessions_ht_destroy()
{
	if (ltt_sessions_ht_by_id) {
		lttng_ht_destroy(ltt_sessions_ht_by_id);
		ltt_sessions_ht_by_id = nullptr;
	}

	if (ltt_sessions_ht_by_name) {
		lttng_ht_destroy(ltt_sessions_ht_by_name);
		ltt_sessions_ht_by_name = nullptr;
	}

	return;
}

/*
 * Add a ltt_session to the ltt_sessions_ht_by_id and ltt_sessions_ht_by_name.
 * If unallocated, the ltt_sessions_ht_by_id and ltt_sessions_ht_by_name. HTs
 * are allocated. The session list lock must be held.
 */
static void add_session_ht(struct ltt_session *ls)
{
	int ret;

	LTTNG_ASSERT(ls);

	if (!ltt_sessions_ht_by_id) {
		ret = ltt_sessions_ht_alloc();
		if (ret) {
			ERR("Error allocating the sessions HT");
			goto end;
		}
	}

	/* Should always be present with ltt_sessions_ht_by_id. */
	LTTNG_ASSERT(ltt_sessions_ht_by_name);

	lttng_ht_node_init_u64(&ls->node, ls->id);
	lttng_ht_add_unique_u64(ltt_sessions_ht_by_id, &ls->node);

	lttng_ht_node_init_str(&ls->node_by_name, ls->name);
	lttng_ht_add_unique_str(ltt_sessions_ht_by_name, &ls->node_by_name);

end:
	return;
}

/*
 * Test if ltt_sessions_ht_by_id/name are empty.
 * Return `false` if hash table objects are null.
 * The session list lock must be held.
 */
static bool ltt_sessions_ht_empty()
{
	bool empty = false;

	if (!ltt_sessions_ht_by_id) {
		/* The hash tables do not exist yet. */
		goto end;
	}

	LTTNG_ASSERT(ltt_sessions_ht_by_name);

	if (lttng_ht_get_count(ltt_sessions_ht_by_id) != 0) {
		/* Not empty.*/
		goto end;
	}

	/*
	 * At this point it is expected that the `ltt_sessions_ht_by_name` ht is
	 * empty.
	 *
	 * The removal from both hash tables is done in two different
	 * places:
	 *   - removal from `ltt_sessions_ht_by_name` is done during
	 *     `session_destroy()`
	 *   - removal from `ltt_sessions_ht_by_id` is done later
	 *     in `session_release()` on the last reference put.
	 *
	 * This means that it is possible for `ltt_sessions_ht_by_name` to be
	 * empty but for `ltt_sessions_ht_by_id` to still contain objects when
	 * multiple sessions exists. The reverse is false, hence this sanity
	 * check.
	 */
	LTTNG_ASSERT(lttng_ht_get_count(ltt_sessions_ht_by_name) == 0);
	empty = true;
end:
	return empty;
}

/*
 * Remove a ltt_session from the ltt_sessions_ht_by_id.
 * If empty, the ltt_sessions_ht_by_id/name HTs are freed.
 * The session list lock must be held.
 */
static void del_session_ht(struct ltt_session *ls)
{
	struct lttng_ht_iter iter;
	int ret;

	LTTNG_ASSERT(ls);
	LTTNG_ASSERT(ltt_sessions_ht_by_id);
	LTTNG_ASSERT(ltt_sessions_ht_by_name);

	iter.iter.node = &ls->node.node;
	ret = lttng_ht_del(ltt_sessions_ht_by_id, &iter);
	LTTNG_ASSERT(!ret);

	if (ltt_sessions_ht_empty()) {
		DBG("Empty ltt_sessions_ht_by_id/name, destroying hash tables");
		ltt_sessions_ht_destroy();
	}
}

/*
 * Acquire session lock
 */
void session_lock(const ltt_session *session)
{
	LTTNG_ASSERT(session);
	session->lock();
}

void ltt_session::lock() const noexcept
{
	pthread_mutex_lock(&_lock);
}

void ltt_session::unlock() const noexcept
{
	ltt_session::_const_session_unlock(*this);
}

ls::domain& ltt_session::get_domain(ls::domain_class domain)
{
	switch (domain) {
	case ls::domain_class::LOG4J:
	case ls::domain_class::LOG4J2:
	case ls::domain_class::JAVA_UTIL_LOGGING:
	case ls::domain_class::PYTHON_LOGGING:
	case ls::domain_class::USER_SPACE:
		return user_space_domain;
	case ls::domain_class::KERNEL_SPACE:
		return kernel_space_domain;
	}

	std::abort();
}

const ls::domain& ltt_session::get_domain(ls::domain_class domain) const
{
	/* NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) */
	return const_cast<ltt_session *>(this)->get_domain(domain);
}

/*
 * Release session lock
 */
void session_unlock(const ltt_session *session)
{
	LTTNG_ASSERT(session);
	session->unlock();
}

void ltt_session::_const_session_unlock(const ltt_session& session)
{
	pthread_mutex_unlock(&session._lock);
}

static int _session_set_trace_chunk_no_lock_check(const ltt_session::locked_ref& session,
						  struct lttng_trace_chunk *new_trace_chunk,
						  struct lttng_trace_chunk **_current_trace_chunk)
{
	int ret = 0;
	unsigned int i, refs_to_acquire = 0, refs_acquired = 0, refs_to_release = 0;
	struct lttng_trace_chunk *current_trace_chunk;
	uint64_t chunk_id;
	enum lttng_trace_chunk_status chunk_status;

	const lttng::urcu::read_lock_guard read_lock;
	/*
	 * Ownership of current trace chunk is transferred to
	 * `current_trace_chunk`.
	 */
	current_trace_chunk = session->current_trace_chunk;
	session->current_trace_chunk = nullptr;
	if (session->ust_session) {
		lttng_trace_chunk_put(session->ust_session->current_trace_chunk);
		session->ust_session->current_trace_chunk = nullptr;
	}
	if (session->kernel_session) {
		lttng_trace_chunk_put(session->kernel_session->current_trace_chunk);
		session->kernel_session->current_trace_chunk = nullptr;
	}
	if (!new_trace_chunk) {
		ret = 0;
		goto end;
	}
	chunk_status = lttng_trace_chunk_get_id(new_trace_chunk, &chunk_id);
	LTTNG_ASSERT(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);

	refs_to_acquire = 1;
	refs_to_acquire += !!session->ust_session;
	refs_to_acquire += !!session->kernel_session;

	for (refs_acquired = 0; refs_acquired < refs_to_acquire; refs_acquired++) {
		if (!lttng_trace_chunk_get(new_trace_chunk)) {
			ERR("Failed to acquire reference to new trace chunk of session \"%s\"",
			    session->name);
			goto error;
		}
	}

	if (session->ust_session) {
		const uint64_t relayd_id = session->ust_session->consumer->net_seq_index;
		const bool is_local_trace = session->ust_session->consumer->type ==
			CONSUMER_DST_LOCAL;

		session->ust_session->current_trace_chunk = new_trace_chunk;
		if (is_local_trace) {
			enum lttng_error_code ret_error_code;

			ret_error_code =
				ust_app_create_channel_subdirectories(session->ust_session);
			if (ret_error_code != LTTNG_OK) {
				goto error;
			}
		}

		for (auto *socket :
		     lttng::urcu::lfht_iteration_adapter<consumer_socket,
							 decltype(consumer_socket::node),
							 &consumer_socket::node>(
			     *session->ust_session->consumer->socks->ht)) {
			pthread_mutex_lock(socket->lock);
			ret = consumer_create_trace_chunk(socket,
							  relayd_id,
							  session->id,
							  new_trace_chunk,
							  DEFAULT_UST_TRACE_DIR);
			pthread_mutex_unlock(socket->lock);
			if (ret) {
				goto error;
			}
		}
	}

	if (session->kernel_session) {
		const uint64_t relayd_id = session->kernel_session->consumer->net_seq_index;
		const bool is_local_trace = session->kernel_session->consumer->type ==
			CONSUMER_DST_LOCAL;

		session->kernel_session->current_trace_chunk = new_trace_chunk;
		if (is_local_trace) {
			enum lttng_error_code ret_error_code;

			ret_error_code =
				kernel_create_channel_subdirectories(session->kernel_session);
			if (ret_error_code != LTTNG_OK) {
				goto error;
			}
		}

		for (auto *socket :
		     lttng::urcu::lfht_iteration_adapter<consumer_socket,
							 decltype(consumer_socket::node),
							 &consumer_socket::node>(
			     *session->kernel_session->consumer->socks->ht)) {
			pthread_mutex_lock(socket->lock);
			ret = consumer_create_trace_chunk(socket,
							  relayd_id,
							  session->id,
							  new_trace_chunk,
							  DEFAULT_KERNEL_TRACE_DIR);
			pthread_mutex_unlock(socket->lock);
			if (ret) {
				goto error;
			}
		}
	}

	/*
	 * Update local current trace chunk state last, only if all remote
	 * creations succeeded.
	 */
	session->current_trace_chunk = new_trace_chunk;
	LTTNG_OPTIONAL_SET(&session->most_recent_chunk_id, chunk_id);
end:
	if (_current_trace_chunk) {
		*_current_trace_chunk = current_trace_chunk;
		current_trace_chunk = nullptr;
	}
end_no_move:
	lttng_trace_chunk_put(current_trace_chunk);
	return ret;
error:
	if (session->ust_session) {
		session->ust_session->current_trace_chunk = nullptr;
	}
	if (session->kernel_session) {
		session->kernel_session->current_trace_chunk = nullptr;
	}
	/*
	 * Release references taken in the case where all references could not
	 * be acquired.
	 */
	refs_to_release = refs_to_acquire - refs_acquired;
	for (i = 0; i < refs_to_release; i++) {
		lttng_trace_chunk_put(new_trace_chunk);
	}
	ret = -1;
	goto end_no_move;
}

struct lttng_trace_chunk *
session_create_new_trace_chunk(const ltt_session::locked_ref& session,
			       const struct consumer_output *consumer_output_override,
			       const char *session_base_path_override,
			       const char *chunk_name_override)
{
	int ret;
	struct lttng_trace_chunk *trace_chunk = nullptr;
	enum lttng_trace_chunk_status chunk_status;
	const time_t chunk_creation_ts = time(nullptr);
	bool is_local_trace;
	const char *base_path;
	struct lttng_directory_handle *session_output_directory = nullptr;
	const struct lttng_credentials session_credentials = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(session->uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE(session->gid),
	};
	uint64_t next_chunk_id;
	const struct consumer_output *output;
	const char *new_path;

	if (consumer_output_override) {
		output = consumer_output_override;
	} else {
		LTTNG_ASSERT(session->ust_session || session->kernel_session);
		output = session->ust_session ? session->ust_session->consumer :
						session->kernel_session->consumer;
	}

	is_local_trace = output->type == CONSUMER_DST_LOCAL;
	base_path = session_base_path_override ?: consumer_output_get_base_path(output);

	if (chunk_creation_ts == (time_t) -1) {
		PERROR("Failed to sample time while creation session \"%s\" trace chunk",
		       session->name);
		goto error;
	}

	next_chunk_id =
		session->most_recent_chunk_id.is_set ? session->most_recent_chunk_id.value + 1 : 0;

	if (session->current_trace_chunk &&
	    !lttng_trace_chunk_get_name_overridden(session->current_trace_chunk)) {
		chunk_status = lttng_trace_chunk_rename_path(session->current_trace_chunk,
							     DEFAULT_CHUNK_TMP_OLD_DIRECTORY);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			goto error;
		}
	}
	if (!session->current_trace_chunk) {
		if (!session->rotated) {
			new_path = "";
		} else {
			new_path = nullptr;
		}
	} else {
		new_path = DEFAULT_CHUNK_TMP_NEW_DIRECTORY;
	}

	trace_chunk = lttng_trace_chunk_create(next_chunk_id, chunk_creation_ts, new_path);
	if (!trace_chunk) {
		goto error;
	}

	if (chunk_name_override) {
		chunk_status = lttng_trace_chunk_override_name(trace_chunk, chunk_name_override);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			goto error;
		}
	}

	if (!is_local_trace) {
		/*
		 * No need to set crendentials and output directory
		 * for remote trace chunks.
		 */
		goto end;
	}

	chunk_status = lttng_trace_chunk_set_credentials(trace_chunk, &session_credentials);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		goto error;
	}

	DBG("Creating base output directory of session \"%s\" at %s", session->name, base_path);
	ret = utils_mkdir_recursive(base_path, S_IRWXU | S_IRWXG, session->uid, session->gid);
	if (ret) {
		goto error;
	}
	session_output_directory = lttng_directory_handle_create(base_path);
	if (!session_output_directory) {
		goto error;
	}
	chunk_status = lttng_trace_chunk_set_as_owner(trace_chunk, session_output_directory);
	lttng_directory_handle_put(session_output_directory);
	session_output_directory = nullptr;
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		goto error;
	}
end:
	return trace_chunk;
error:
	lttng_directory_handle_put(session_output_directory);
	lttng_trace_chunk_put(trace_chunk);
	trace_chunk = nullptr;
	goto end;
}

int session_close_trace_chunk(const ltt_session::locked_ref& session,
			      struct lttng_trace_chunk *trace_chunk,
			      enum lttng_trace_chunk_command_type close_command,
			      char *closed_trace_chunk_path)
{
	int ret = 0;
	bool error_occurred = false;
	enum lttng_trace_chunk_status chunk_status;
	const time_t chunk_close_timestamp = time(nullptr);
	const char *new_path;

	chunk_status = lttng_trace_chunk_set_close_command(trace_chunk, close_command);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = -1;
		goto end;
	}

	if (chunk_close_timestamp == (time_t) -1) {
		ERR("Failed to sample the close timestamp of the current trace chunk of session \"%s\"",
		    session->name);
		ret = -1;
		goto end;
	}

	if (close_command == LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE && !session->rotated) {
		/* New chunk stays in session output directory. */
		new_path = "";
	} else {
		/* Use chunk name for new chunk. */
		new_path = nullptr;
	}
	if (session->current_trace_chunk &&
	    !lttng_trace_chunk_get_name_overridden(session->current_trace_chunk)) {
		/* Rename new chunk path. */
		chunk_status =
			lttng_trace_chunk_rename_path(session->current_trace_chunk, new_path);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret = -1;
			goto end;
		}
	}
	if (!lttng_trace_chunk_get_name_overridden(trace_chunk) &&
	    close_command == LTTNG_TRACE_CHUNK_COMMAND_TYPE_NO_OPERATION) {
		const char *old_path;

		if (!session->rotated) {
			old_path = "";
		} else {
			old_path = nullptr;
		}
		/* We need to move back the .tmp_old_chunk to its rightful place. */
		chunk_status = lttng_trace_chunk_rename_path(trace_chunk, old_path);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret = -1;
			goto end;
		}
	}
	if (close_command == LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED) {
		session->rotated = true;
	}
	chunk_status = lttng_trace_chunk_set_close_timestamp(trace_chunk, chunk_close_timestamp);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ERR("Failed to set the close timestamp of the current trace chunk of session \"%s\"",
		    session->name);
		ret = -1;
		goto end;
	}

	if (session->ust_session) {
		const uint64_t relayd_id = session->ust_session->consumer->net_seq_index;

		for (auto *socket :
		     lttng::urcu::lfht_iteration_adapter<consumer_socket,
							 decltype(consumer_socket::node),
							 &consumer_socket::node>(
			     *session->ust_session->consumer->socks->ht)) {
			pthread_mutex_lock(socket->lock);
			ret = consumer_close_trace_chunk(socket,
							 relayd_id,
							 session->id,
							 trace_chunk,
							 closed_trace_chunk_path);
			pthread_mutex_unlock(socket->lock);
			if (ret) {
				ERR("Failed to close trace chunk on user space consumer");
				error_occurred = true;
			}
		}
	}
	if (session->kernel_session) {
		const uint64_t relayd_id = session->kernel_session->consumer->net_seq_index;

		for (auto *socket :
		     lttng::urcu::lfht_iteration_adapter<consumer_socket,
							 decltype(consumer_socket::node),
							 &consumer_socket::node>(
			     *session->kernel_session->consumer->socks->ht)) {
			pthread_mutex_lock(socket->lock);
			ret = consumer_close_trace_chunk(socket,
							 relayd_id,
							 session->id,
							 trace_chunk,
							 closed_trace_chunk_path);
			pthread_mutex_unlock(socket->lock);
			if (ret) {
				ERR("Failed to close trace chunk on kernel consumer");
				error_occurred = true;
			}
		}
	}
	ret = error_occurred ? -1 : 0;
end:
	return ret;
}

/*
 * This function skips the metadata channel as the begin/end timestamps of a
 * metadata packet are useless.
 *
 * Moreover, opening a packet after a "clear" will cause problems for live
 * sessions as it will introduce padding that was not part of the first trace
 * chunk. The relay daemon expects the content of the metadata stream of
 * successive metadata trace chunks to be strict supersets of one another.
 *
 * For example, flushing a packet at the beginning of the metadata stream of
 * a trace chunk resulting from a "clear" session command will cause the
 * size of the metadata stream of the new trace chunk to not match the size of
 * the metadata stream of the original chunk. This will confuse the relay
 * daemon as the same "offset" in a metadata stream will no longer point
 * to the same content.
 */
static enum lttng_error_code session_kernel_open_packets(const ltt_session::locked_ref& session)
{
	enum lttng_error_code ret = LTTNG_OK;
	struct lttng_ht_iter iter;
	struct cds_lfht_node *node;

	const lttng::urcu::read_lock_guard read_lock;

	cds_lfht_first(session->kernel_session->consumer->socks->ht, &iter.iter);
	node = cds_lfht_iter_get_node(&iter.iter);
	auto *socket = lttng_ht_node_container_of(node, &consumer_socket::node);

	for (auto chan :
	     lttng::urcu::list_iteration_adapter<ltt_kernel_channel, &ltt_kernel_channel::list>(
		     session->kernel_session->channel_list.head)) {
		int open_ret;

		DBG("Open packet of kernel channel: channel key = %" PRIu64
		    ", session name = %s, session_id = %" PRIu64,
		    chan->key,
		    session->name,
		    session->id);

		open_ret = consumer_open_channel_packets(socket, chan->key);
		if (open_ret < 0) {
			/* General error (no known error expected). */
			ret = LTTNG_ERR_UNK;
			goto end;
		}
	}

end:
	return ret;
}

enum lttng_error_code session_open_packets(const ltt_session::locked_ref& session)
{
	enum lttng_error_code ret = LTTNG_OK;

	DBG("Opening packets of session channels: session name = %s, session id = %" PRIu64,
	    session->name,
	    session->id);

	if (session->ust_session) {
		ret = ust_app_open_packets(session);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	if (session->kernel_session) {
		ret = session_kernel_open_packets(session);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

end:
	return ret;
}

/*
 * Set a session's current trace chunk.
 *
 * Must be called with the session lock held.
 */
int session_set_trace_chunk(const ltt_session::locked_ref& session,
			    struct lttng_trace_chunk *new_trace_chunk,
			    struct lttng_trace_chunk **current_trace_chunk)
{
	ASSERT_LOCKED(session->_lock);
	return _session_set_trace_chunk_no_lock_check(
		session, new_trace_chunk, current_trace_chunk);
}

static void session_notify_destruction(const ltt_session::locked_ref& session)
{
	size_t i;
	const auto count = lttng_dynamic_array_get_count(&session->destroy_notifiers);

	for (i = 0; i < count; i++) {
		const struct ltt_session_destroy_notifier_element *element =
			(ltt_session_destroy_notifier_element *) lttng_dynamic_array_get_element(
				&session->destroy_notifiers, i);

		element->notifier(session, element->user_data);
	}
}

/*
 * Fire each clear notifier once, and remove them from the array.
 */
void session_notify_clear(const ltt_session::locked_ref& session)
{
	size_t i;
	const auto count = lttng_dynamic_array_get_count(&session->clear_notifiers);

	for (i = 0; i < count; i++) {
		const struct ltt_session_clear_notifier_element *element =
			(ltt_session_clear_notifier_element *) lttng_dynamic_array_get_element(
				&session->clear_notifiers, i);

		element->notifier(session, element->user_data);
	}
	lttng_dynamic_array_clear(&session->clear_notifiers);
}

static void session_release(struct urcu_ref *ref)
{
	int ret;
	struct ltt_ust_session *usess;
	struct ltt_kernel_session *ksess;
	struct ltt_session *session = lttng::utils::container_of(ref, &ltt_session::ref_count);
	const bool session_published = session->published;

	LTTNG_ASSERT(!session->chunk_being_archived);

	usess = session->ust_session;
	ksess = session->kernel_session;

	/* Clean kernel session teardown, keeping data for destroy notifier. */
	kernel_destroy_session(ksess);

	/* UST session teardown, keeping data for destroy notifier. */
	if (usess) {
		/* Close any relayd session */
		consumer_output_send_destroy_relayd(usess->consumer);

		/* Destroy every UST application related to this session. */
		ret = ust_app_destroy_trace_all(usess);
		if (ret) {
			ERR("Error in ust_app_destroy_trace_all");
		}

		/* Clean up the rest, keeping destroy notifier data. */
		trace_ust_destroy_session(usess);
	}

	/*
	 * Must notify the kernel thread here to update it's poll set in order to
	 * remove the channel(s)' fd just destroyed.
	 */
	ret = notify_thread_pipe(the_kernel_poll_pipe[1]);
	if (ret < 0) {
		PERROR("write kernel poll pipe");
	}

	DBG("Destroying session %s (id %" PRIu64 ")", session->name, session->id);

	snapshot_destroy(&session->snapshot);

	if (session_published) {
		ASSERT_SESSION_LIST_LOCKED();
		del_session_list(session);
		del_session_ht(session);
	}

	/*
	 * The notifiers make use of free-functions that expect a locked reference to a session.
	 * To create such a reference, we need to acquire the lock and acquire a reference (increase
	 * the ref-count). To ensure the release of the reference does not re-cross the zero value,
	 * set the refcount to a tombstone value.
	 *
	 * The value is arbitrary, but must not trigger a second destruction once the temporary
	 * reference is 'put' and must be positive as to not trigger the underflow checks in the
	 * urcu refcount implementation.
	 */
	session->ref_count.refcount = 0xDEAD1;
	session_notify_destruction([session]() {
		session_lock(session);
		session_get(session);
		return ltt_session::make_locked_ref(*session);
	}());

	pthread_mutex_destroy(&session->_lock);

	consumer_output_put(session->consumer);
	kernel_free_session(ksess);
	session->kernel_session = nullptr;
	if (usess) {
		trace_ust_free_session(usess);
		session->ust_session = nullptr;
	}

	lttng_dynamic_array_reset(&session->destroy_notifiers);
	lttng_dynamic_array_reset(&session->clear_notifiers);
	free(session->last_archived_chunk_name);
	free(session->base_path);
	lttng_trigger_put(session->rotate_trigger);

	delete session;

	if (session_published) {
		/*
		 * Notify after free-ing to ensure the memory is
		 * reclaimed before the main thread exits (and prevent memory leak
		 * reports).
		 */
		ASSERT_SESSION_LIST_LOCKED();
		the_session_list.removal_cond.notify_all();
	}
}

/*
 * Acquire a reference to a session.
 * This function may fail (return false); its return value must be checked.
 */
bool session_get(struct ltt_session *session)
{
	return urcu_ref_get_unless_zero(&session->ref_count);
}

/*
 * Release a reference to a session.
 */
void session_put(struct ltt_session *session)
{
	if (!session) {
		return;
	}
	/*
	 * The session list lock must be held as any session_put()
	 * may cause the removal of the session from the session_list.
	 */
	ASSERT_SESSION_LIST_LOCKED();
	LTTNG_ASSERT(session->ref_count.refcount);
	urcu_ref_put(&session->ref_count, session_release);
}

/*
 * Destroy a session.
 *
 * This method does not immediately release/free the session as other
 * components may still hold a reference to the session. However,
 * the session should no longer be presented to the user.
 *
 * Releases the session list's reference to the session
 * and marks it as destroyed. Iterations on the session list should be
 * mindful of the "destroyed" flag.
 */
void session_destroy(struct ltt_session *session)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(!session->destroyed);
	session->destroyed = true;

	/*
	 * Remove immediately from the "session by name" hash table. Only one
	 * session is expected to exist with a given name for at any given time.
	 *
	 * Even if a session still technically exists for a little while longer,
	 * there is no point in performing action on a "destroyed" session.
	 */
	iter.iter.node = &session->node_by_name.node;
	ret = lttng_ht_del(ltt_sessions_ht_by_name, &iter);
	LTTNG_ASSERT(!ret);

	session_put(session);
}

int session_add_destroy_notifier(const ltt_session::locked_ref& session,
				 ltt_session_destroy_notifier notifier,
				 void *user_data)
{
	const struct ltt_session_destroy_notifier_element element = { .notifier = notifier,
								      .user_data = user_data };

	return lttng_dynamic_array_add_element(&session->destroy_notifiers, &element);
}

int session_add_clear_notifier(const ltt_session::locked_ref& session,
			       ltt_session_clear_notifier notifier,
			       void *user_data)
{
	const struct ltt_session_clear_notifier_element element = { .notifier = notifier,
								    .user_data = user_data };

	return lttng_dynamic_array_add_element(&session->clear_notifiers, &element);
}

/*
 * Create a new session and add it to the session list.
 * Session list lock must be held by the caller.
 */
enum lttng_error_code
session_create(const char *name, uid_t uid, gid_t gid, struct ltt_session **out_session)
{
	int ret;
	enum lttng_error_code ret_code;
	struct ltt_session *new_session = nullptr;

	ASSERT_SESSION_LIST_LOCKED();
	if (name) {
		struct ltt_session *clashing_session;

		clashing_session = session_find_by_name(name);
		if (clashing_session) {
			session_put(clashing_session);
			ret_code = LTTNG_ERR_EXIST_SESS;
			goto error;
		}
	}

	try {
		new_session = new ltt_session;
	} catch (std::bad_alloc& ex) {
		ERR_FMT("Failed to allocate an ltt_session: {}", ex.what());
		ret_code = LTTNG_ERR_NOMEM;
		goto error;
	}

	lttng_dynamic_array_init(&new_session->destroy_notifiers,
				 sizeof(struct ltt_session_destroy_notifier_element),
				 nullptr);
	lttng_dynamic_array_init(&new_session->clear_notifiers,
				 sizeof(struct ltt_session_clear_notifier_element),
				 nullptr);
	urcu_ref_init(&new_session->ref_count);
	pthread_mutex_init(&new_session->_lock, nullptr);

	new_session->creation_time = time(nullptr);
	if (new_session->creation_time == (time_t) -1) {
		PERROR("Failed to sample session creation time");
		ret_code = LTTNG_ERR_SESSION_FAIL;
		goto error;
	}

	/* Create default consumer output. */
	new_session->consumer = consumer_create_output(CONSUMER_DST_LOCAL);
	if (new_session->consumer == nullptr) {
		ret_code = LTTNG_ERR_NOMEM;
		goto error;
	}

	if (name) {
		ret = lttng_strncpy(new_session->name, name, sizeof(new_session->name));
		if (ret) {
			ret_code = LTTNG_ERR_SESSION_INVALID_CHAR;
			goto error;
		}
		ret = validate_name(name);
		if (ret < 0) {
			ret_code = LTTNG_ERR_SESSION_INVALID_CHAR;
			goto error;
		}
	} else {
		int i = 0;
		bool found_name = false;
		char datetime[16];
		struct tm *timeinfo;

		timeinfo = localtime(&new_session->creation_time);
		if (!timeinfo) {
			ret_code = LTTNG_ERR_SESSION_FAIL;
			goto error;
		}
		strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);
		for (i = 0; i < INT_MAX; i++) {
			struct ltt_session *clashing_session;

			if (i == 0) {
				ret = snprintf(new_session->name,
					       sizeof(new_session->name),
					       "%s-%s",
					       DEFAULT_SESSION_NAME,
					       datetime);
			} else {
				ret = snprintf(new_session->name,
					       sizeof(new_session->name),
					       "%s%d-%s",
					       DEFAULT_SESSION_NAME,
					       i,
					       datetime);
			}
			new_session->name_contains_creation_time = true;
			if (ret == -1 || ret >= sizeof(new_session->name)) {
				/*
				 * Null-terminate in case the name is used
				 * in logging statements.
				 */
				new_session->name[sizeof(new_session->name) - 1] = '\0';
				ret_code = LTTNG_ERR_SESSION_FAIL;
				goto error;
			}

			clashing_session = session_find_by_name(new_session->name);
			session_put(clashing_session);
			if (!clashing_session) {
				found_name = true;
				break;
			}
		}
		if (found_name) {
			DBG("Generated session name \"%s\"", new_session->name);
			new_session->has_auto_generated_name = true;
		} else {
			ERR("Failed to auto-generate a session name");
			ret_code = LTTNG_ERR_SESSION_FAIL;
			goto error;
		}
	}

	ret = gethostname(new_session->hostname, sizeof(new_session->hostname));
	if (ret < 0) {
		if (errno == ENAMETOOLONG) {
			new_session->hostname[sizeof(new_session->hostname) - 1] = '\0';
			ERR("Hostname exceeds the maximal permitted length and has been truncated to %s",
			    new_session->hostname);
		} else {
			ret_code = LTTNG_ERR_SESSION_FAIL;
			goto error;
		}
	}

	new_session->uid = uid;
	new_session->gid = gid;

	ret = snapshot_init(&new_session->snapshot);
	if (ret < 0) {
		ret_code = LTTNG_ERR_NOMEM;
		goto error;
	}

	new_session->rotation_state = LTTNG_ROTATION_STATE_NO_ROTATION;

	/* Add new session to the session list. */
	new_session->id = add_session_list(new_session);

	/*
	 * Add the new session to the ltt_sessions_ht_by_id.
	 * No ownership is taken by the hash table; it is merely
	 * a wrapper around the session list used for faster access
	 * by session id.
	 */
	add_session_ht(new_session);
	new_session->published = true;

	/*
	 * Consumer is left to NULL since the create_session_uri command will
	 * set it up and, if valid, assign it to the session.
	 */
	DBG("Tracing session %s created with ID %" PRIu64 " by uid = %d, gid = %d",
	    new_session->name,
	    new_session->id,
	    new_session->uid,
	    new_session->gid);
	ret_code = LTTNG_OK;
end:
	if (new_session) {
		(void) session_get(new_session);
		*out_session = new_session;
	}
	return ret_code;
error:
	session_put(new_session);
	new_session = nullptr;
	goto end;
}

/*
 * Check if the UID matches the session. Root user has access to all
 * sessions.
 */
bool session_access_ok(const ltt_session::locked_ref& session, uid_t uid)
{
	return (uid == session->uid) || uid == 0;
}

/*
 * Set a session's rotation state and reset all associated state.
 *
 * This function resets the rotation state (check timers, pending
 * flags, etc.) and sets the result of the last rotation. The result
 * can be queries by a liblttng-ctl client.
 *
 * Be careful of the result passed to this function. For instance,
 * on failure to launch a rotation, a client will expect the rotation
 * state to be set to "NO_ROTATION". If an error occurred while the
 * rotation was "ONGOING", result should be set to "ERROR", which will
 * allow a client to report it.
 *
 * Must be called with the session and session_list locks held.
 */
int session_reset_rotation_state(const ltt_session::locked_ref& session,
				 enum lttng_rotation_state result)
{
	int ret = 0;

	ASSERT_SESSION_LIST_LOCKED();

	session->rotation_state = result;
	if (session->rotation_pending_check_timer_enabled) {
		ret = timer_session_rotation_pending_check_stop(session);
	}
	if (session->chunk_being_archived) {
		uint64_t chunk_id;
		enum lttng_trace_chunk_status chunk_status;

		chunk_status = lttng_trace_chunk_get_id(session->chunk_being_archived, &chunk_id);
		LTTNG_ASSERT(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);
		LTTNG_OPTIONAL_SET(&session->last_archived_chunk_id, chunk_id);
		lttng_trace_chunk_put(session->chunk_being_archived);
		session->chunk_being_archived = nullptr;
		/*
		 * Fire the clear reply notifiers if we are completing a clear
		 * rotation.
		 */
		session_notify_clear(session);
	}
	return ret;
}

/*
 * Sample the id of a session looked up via its name.
 * Here the term "sampling" hint the caller that this return the id at a given
 * point in time with no guarantee that the session for which the id was
 * sampled still exist at that point.
 *
 * Return 0 when the session is not found,
 * Return 1 when the session is found and set `id`.
 */
bool sample_session_id_by_name(const char *name, uint64_t *id)
{
	bool found = false;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct ltt_session *ls;

	const lttng::urcu::read_lock_guard read_lock;

	if (!ltt_sessions_ht_by_name) {
		found = false;
		goto end;
	}

	lttng_ht_lookup(ltt_sessions_ht_by_name, name, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_str>(&iter);
	if (node == nullptr) {
		found = false;
		goto end;
	}

	ls = lttng::utils::container_of(node, &ltt_session::node_by_name);
	*id = ls->id;
	found = true;

	DBG3("Session id `%" PRIu64 "` sampled for session `%s", *id, name);
end:
	return found;
}

void ltt_session::_locked_session_release(ltt_session *session)
{
	if (!session) {
		return;
	}

	session_unlock(session);
	session_put(session);
}

void ltt_session::_locked_const_session_release(const ltt_session *session)
{
	if (!session) {
		return;
	}

	ltt_session::_const_session_unlock(*session);
	ltt_session::_const_session_put(session);
}

ltt_session::locked_ref ltt_session::find_locked_session(ltt_session::id_t id)
{
	const lttng::urcu::read_lock_guard rcu_lock;
	auto session = session_find_by_id(id);

	if (!session) {
		LTTNG_THROW_SESSION_NOT_FOUND_BY_ID_ERROR(id);
	}

	/*
	 * The pointer falling out of scope will unlock and release the reference to the
	 * session.
	 */
	session_lock(session);
	return ltt_session::make_locked_ref(*session);
}

ltt_session::locked_ref ltt_session::find_locked_session(lttng::c_string_view name)
{
	const lttng::urcu::read_lock_guard rcu_lock;
	auto session = session_find_by_name(name.data());

	if (!session) {
		LTTNG_THROW_SESSION_NOT_FOUND_BY_NAME_ERROR(name.data());
	}

	session_lock(session);
	return ltt_session::make_locked_ref(*session);
}

ltt_session::const_locked_ref ltt_session::find_locked_const_session(ltt_session::id_t id)
{
	const lttng::urcu::read_lock_guard rcu_lock;
	const auto *session = session_find_by_id(id);

	if (!session) {
		LTTNG_THROW_SESSION_NOT_FOUND_BY_ID_ERROR(id);
	}

	session_lock(session);
	return ltt_session::make_locked_ref(*session);
}

ltt_session::const_locked_ref ltt_session::find_locked_const_session(lttng::c_string_view name)
{
	const lttng::urcu::read_lock_guard rcu_lock;
	const auto *session = session_find_by_name(name.data());

	if (!session) {
		LTTNG_THROW_SESSION_NOT_FOUND_BY_NAME_ERROR(name.data());
	}

	session_lock(session);
	return ltt_session::make_locked_ref(*session);
}

ltt_session::ref ltt_session::find_session(ltt_session::id_t id)
{
	const lttng::urcu::read_lock_guard rcu_lock;
	auto session = session_find_by_id(id);

	if (!session) {
		LTTNG_THROW_SESSION_NOT_FOUND_BY_ID_ERROR(id);
	}

	return ltt_session::make_ref(*session);
}

ltt_session::ref ltt_session::find_session(lttng::c_string_view name)
{
	const lttng::urcu::read_lock_guard rcu_lock;
	auto session = session_find_by_name(name.data());

	if (!session) {
		LTTNG_THROW_SESSION_NOT_FOUND_BY_NAME_ERROR(name.data());
	}

	return ltt_session::make_ref(*session);
}

ltt_session::const_ref ltt_session::find_const_session(ltt_session::id_t id)
{
	const lttng::urcu::read_lock_guard rcu_lock;
	const auto *session = session_find_by_id(id);

	if (!session) {
		LTTNG_THROW_SESSION_NOT_FOUND_BY_ID_ERROR(id);
	}

	return ltt_session::make_ref(*session);
}

ltt_session::const_ref ltt_session::find_const_session(lttng::c_string_view name)
{
	const lttng::urcu::read_lock_guard rcu_lock;
	const auto *session = session_find_by_name(name.data());

	if (!session) {
		LTTNG_THROW_SESSION_NOT_FOUND_BY_NAME_ERROR(name.data());
	}

	return ltt_session::make_ref(*session);
}

void ltt_session::_const_session_put(const ltt_session *session)
{
	/*
	 * The session list lock must be held as any session_put()
	 * may cause the removal of the session from the session_list.
	 */
	ASSERT_SESSION_LIST_LOCKED();
	LTTNG_ASSERT(session->ref_count.refcount);
	urcu_ref_put(&session->ref_count, session_release);
}

std::unique_lock<std::mutex> ls::lock_session_list()
{
	return std::unique_lock<std::mutex>(the_session_list.lock);
}

lttng::sessiond::user_space_consumer_channel_keys
ltt_session::user_space_consumer_channel_keys() const
{
	switch (ust_session->buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		return lttng::sessiond::user_space_consumer_channel_keys(*ust_session,
									 *ust_app_get_all());
	case LTTNG_BUFFER_PER_UID:
		return lttng::sessiond::user_space_consumer_channel_keys(
			*ust_session, ust_session->buffer_reg_uid_list);
	default:
		abort();
	}
}

ls::user_space_consumer_channel_keys::iterator
ls::user_space_consumer_channel_keys::begin() const noexcept
{
	return ls::user_space_consumer_channel_keys::iterator(_creation_context);
}

ls::user_space_consumer_channel_keys::iterator
ls::user_space_consumer_channel_keys::end() const noexcept
{
	return ls::user_space_consumer_channel_keys::iterator(_creation_context, true);
}

ls::user_space_consumer_channel_keys::iterator&
ls::user_space_consumer_channel_keys::iterator::operator++()
{
	if (_is_end) {
		LTTNG_THROW_OUT_OF_RANGE(fmt::format(
			"Attempted to advance channel key iterator past the end of channel keys: iteration_mode={}",
			_creation_context._session.buffer_type));
	}

	switch (_creation_context._session.buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		_advance_one_per_pid();
		break;
	case LTTNG_BUFFER_PER_UID:
		_advance_one_per_uid();
		break;
	default:
		abort();
	}

	return *this;
}

namespace {
bool is_list_empty(const cds_list_head *head)
{
	return head == head->next;
}
} /* namespace */

ls::user_space_consumer_channel_keys::iterator::iterator(
	const _iterator_creation_context& creation_context, bool is_end) :
	_creation_context(creation_context), _is_end(is_end)
{
	if (_is_end) {
		return;
	}

	switch (_creation_context._mode) {
	case _iteration_mode::PER_PID:
		_init_per_pid();
		break;
	case _iteration_mode::PER_UID:
		_init_per_uid();
		break;
	}
}

void ls::user_space_consumer_channel_keys::iterator::_skip_to_next_app_per_pid(
	bool try_current) noexcept
{
	auto& position = _position._per_pid;

	while (true) {
		if (!try_current) {
			lttng_ht_get_next(_creation_context._container.apps,
					  &position.app_iterator);
		} else {
			try_current = false;
		}

		const auto app_node =
			lttng_ht_iter_get_node<lttng_ht_node_ulong>(&position.app_iterator);
		if (!app_node) {
			_is_end = true;
			return;
		}

		const auto& app = *lttng::utils::container_of(app_node, &ust_app::pid_n);
		auto app_session = ust_app_lookup_app_session(&_creation_context._session, &app);

		if (!app_session) {
			/* This app is not traced by the target session. */
			continue;
		}

		position.current_app_session = app_session->lock();

		auto *registry = ust_app_get_session_registry(
			(*_position._per_pid.current_app_session)->get_identifier());
		if (!registry) {
			DBG_FMT("Application session is being torn down: skipping application: app={}",
				app);
			continue;
		}

		position.current_registry_session = registry;
		lttng_ht_get_first((*position.current_app_session)->channels,
				   &_position.channel_iterator);
		break;
	}
}

void ls::user_space_consumer_channel_keys::iterator::_init_per_pid() noexcept
{
	auto& position = _position._per_pid;

	lttng_ht_get_first(_creation_context._container.apps, &position.app_iterator);
	_skip_to_next_app_per_pid(true);
}

void ls::user_space_consumer_channel_keys::iterator::_init_per_uid() noexcept
{
	auto& position = _position._per_uid;

	/* Start the iteration: get the first registry and point to its first channel. */
	if (is_list_empty(&_creation_context._session.buffer_reg_uid_list)) {
		_is_end = true;
		return;
	}

	position.registry_list_head = &_creation_context._session.buffer_reg_uid_list;
	position.current_registry = lttng::utils::container_of(
		_creation_context._session.buffer_reg_uid_list.next, &buffer_reg_uid::lnode);
	lttng_ht_get_first(position.current_registry->registry->channels,
			   &_position.channel_iterator);
}

void ls::user_space_consumer_channel_keys::iterator::_advance_one_per_pid()
{
	auto& position = _position._per_pid;

	if (!cds_lfht_iter_get_node(&_position.channel_iterator.iter)) {
		/* Reached the last channel. Move on to the next app. */
		_skip_to_next_app_per_pid(false);
		return;
	}

	const auto current_app_node =
		lttng_ht_iter_get_node<lttng_ht_node_ulong>(&position.app_iterator);
	LTTNG_ASSERT(current_app_node);

	lttng_ht_get_next((*position.current_app_session)->channels, &_position.channel_iterator);
}

void ls::user_space_consumer_channel_keys::iterator::_advance_one_per_uid()
{
	auto& position = _position._per_uid;

	if (!cds_lfht_iter_get_node(&_position.channel_iterator.iter)) {
		/* Reached the last channel of the registry. Move on to the next registry. */
		if (position.current_registry->lnode.next == position.registry_list_head) {
			_is_end = true;
			return;
		}

		position.current_registry = lttng::utils::container_of(
			position.current_registry->lnode.next, &buffer_reg_uid::lnode);
		cds_lfht_first(position.current_registry->registry->channels->ht,
			       &_position.channel_iterator.iter);

		/* Assumes a registry can't be empty. */
		LTTNG_ASSERT(cds_lfht_iter_get_node(&_position.channel_iterator.iter));
	}

	cds_lfht_next(position.current_registry->registry->channels->ht,
		      &_position.channel_iterator.iter);
}

bool ls::user_space_consumer_channel_keys::iterator::operator==(const iterator& other) const noexcept
{
	if (_is_end && other._is_end) {
		return true;
	}

	/* Channel keys are unique; use them to compare the iterators. */
	return !_is_end && !other._is_end && **this == *other;
}

bool ls::user_space_consumer_channel_keys::iterator::operator!=(const iterator& other) const noexcept
{
	return !(*this == other);
}

ls::user_space_consumer_channel_keys::iterator::key
ls::user_space_consumer_channel_keys::iterator::_get_current_value_per_pid() const noexcept
{
	auto& position = _position._per_pid;

	const auto *channel_node =
		lttng_ht_iter_get_node<lttng_ht_node_str>(&_position.channel_iterator);
	const auto current_app_node =
		lttng_ht_iter_get_node<lttng_ht_node_ulong>(&position.app_iterator);
	LTTNG_ASSERT(current_app_node);

	const auto& app = *lttng::utils::container_of(current_app_node, &ust_app::pid_n);

	if (channel_node) {
		const auto& channel =
			*lttng::utils::container_of(channel_node, &ust_app_channel::node);

		return { static_cast<consumer_bitness>(app.abi.bits_per_long),
			 channel.key,
			 ls::user_space_consumer_channel_keys::channel_type::DATA };
	} else {
		LTTNG_ASSERT(position.current_registry_session);

		/*
		 * Once the last data channel is delivered (iter points to the 'end' of the ht),
		 * deliver the metadata channel's key.
		 */
		return { static_cast<consumer_bitness>(app.abi.bits_per_long),
			 position.current_registry_session->_metadata_key,
			 ls::user_space_consumer_channel_keys::channel_type::METADATA };
	}
}

ls::user_space_consumer_channel_keys::iterator::key
ls::user_space_consumer_channel_keys::iterator::_get_current_value_per_uid() const noexcept
{
	const auto *channel_node =
		lttng_ht_iter_get_node<lttng_ht_node_u64>(&_position.channel_iterator);

	if (channel_node) {
		const auto& channel =
			*lttng::utils::container_of(channel_node, &buffer_reg_channel::node);

		return { static_cast<consumer_bitness>(
				 _position._per_uid.current_registry->bits_per_long),
			 channel.consumer_key,
			 ls::user_space_consumer_channel_keys::channel_type::DATA };
	} else {
		/*
		 * Once the last data channel is delivered (iter points to the 'end' of the ht),
		 * deliver the metadata channel's key.
		 */
		return { static_cast<consumer_bitness>(
				 _position._per_uid.current_registry->bits_per_long),
			 _position._per_uid.current_registry->registry->reg.ust->_metadata_key,
			 ls::user_space_consumer_channel_keys::channel_type::METADATA };
	}
}

ls::user_space_consumer_channel_keys::iterator::key
ls::user_space_consumer_channel_keys::iterator::operator*() const
{
	if (_is_end) {
		LTTNG_THROW_OUT_OF_RANGE(
			"Attempt to use operator* on user_space_consumer_channel_keys iterator at the end position");
	}

	switch (_creation_context._mode) {
	case _iteration_mode::PER_PID:
		return _get_current_value_per_pid();
	case _iteration_mode::PER_UID:
		return _get_current_value_per_uid();
	}

	std::abort();
}

ls::ust::registry_session *ls::user_space_consumer_channel_keys::iterator::get_registry_session()
{
	if (_is_end) {
		LTTNG_THROW_OUT_OF_RANGE(
			"Attempt to get registry session on user_space_consumer_channel_keys iterator at the end position");
	}

	switch (_creation_context._mode) {
	case _iteration_mode::PER_PID:
		return _get_registry_session_per_pid();
	case _iteration_mode::PER_UID:
		return _get_registry_session_per_uid();
	}

	std::abort();
}

ls::ust::registry_session *
ls::user_space_consumer_channel_keys::iterator::_get_registry_session_per_pid()
{
	return _position._per_pid.current_registry_session;
}

ls::ust::registry_session *
ls::user_space_consumer_channel_keys::iterator::_get_registry_session_per_uid()
{
	return _position._per_uid.current_registry->registry->reg.ust;
}
