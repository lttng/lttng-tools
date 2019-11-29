/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <urcu.h>
#include <dirent.h>
#include <sys/types.h>
#include <pthread.h>

#include <common/common.h>
#include <common/utils.h>
#include <common/trace-chunk.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <lttng/location-internal.h>
#include "lttng-sessiond.h"
#include "kernel.h"

#include "session.h"
#include "utils.h"
#include "trace-ust.h"
#include "timer.h"
#include "cmd.h"

struct ltt_session_destroy_notifier_element {
	ltt_session_destroy_notifier notifier;
	void *user_data;
};

/*
 * NOTES:
 *
 * No ltt_session.lock is taken here because those data structure are widely
 * spread across the lttng-tools code base so before caling functions below
 * that can read/write a session, the caller MUST acquire the session lock
 * using session_lock() and session_unlock().
 */

/*
 * Init tracing session list.
 *
 * Please see session.h for more explanation and correct usage of the list.
 */
static struct ltt_session_list ltt_session_list = {
	.head = CDS_LIST_HEAD_INIT(ltt_session_list.head),
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.removal_cond = PTHREAD_COND_INITIALIZER,
	.next_uuid = 0,
};

/* These characters are forbidden in a session name. Used by validate_name. */
static const char *forbidden_name_chars = "/";

/* Global hash table to keep the sessions, indexed by id. */
static struct lttng_ht *ltt_sessions_ht_by_id = NULL;

/*
 * Validate the session name for forbidden characters.
 *
 * Return 0 on success else -1 meaning a forbidden char. has been found.
 */
static int validate_name(const char *name)
{
	int ret;
	char *tok, *tmp_name;

	assert(name);

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
	assert(ls);

	cds_list_add(&ls->list, &ltt_session_list.head);
	return ltt_session_list.next_uuid++;
}

/*
 * Delete a ltt_session structure to the global list.
 *
 * The caller MUST acquire the session list lock before.
 */
static void del_session_list(struct ltt_session *ls)
{
	assert(ls);

	cds_list_del(&ls->list);
}

/*
 * Return a pointer to the session list.
 */
struct ltt_session_list *session_get_list(void)
{
	return &ltt_session_list;
}

/*
 * Returns once the session list is empty.
 */
void session_list_wait_empty(void)
{
	pthread_mutex_lock(&ltt_session_list.lock);
	while (!cds_list_empty(&ltt_session_list.head)) {
		pthread_cond_wait(&ltt_session_list.removal_cond,
				&ltt_session_list.lock);
	}
	pthread_mutex_unlock(&ltt_session_list.lock);
}

/*
 * Acquire session list lock
 */
void session_lock_list(void)
{
	pthread_mutex_lock(&ltt_session_list.lock);
}

/*
 * Try to acquire session list lock
 */
int session_trylock_list(void)
{
	return pthread_mutex_trylock(&ltt_session_list.lock);
}

/*
 * Release session list lock
 */
void session_unlock_list(void)
{
	pthread_mutex_unlock(&ltt_session_list.lock);
}

/*
 * Get the session's consumer destination type.
 *
 * The caller must hold the session lock.
 */
enum consumer_dst_type session_get_consumer_destination_type(
		const struct ltt_session *session)
{
	/*
	 * The output information is duplicated in both of those session types.
	 * Hence, it doesn't matter from which it is retrieved. However, it is
	 * possible for only one of them to be set.
	 */
	return session->kernel_session ?
			session->kernel_session->consumer->type :
			session->ust_session->consumer->type;
}

/*
 * Get the session's consumer network hostname.
 * The caller must ensure that the destination is of type "net".
 *
 * The caller must hold the session lock.
 */
const char *session_get_net_consumer_hostname(const struct ltt_session *session)
{
	const char *hostname = NULL;
	const struct consumer_output *output;

	output = session->kernel_session ?
			session->kernel_session->consumer :
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
 *
 * The caller must hold the session lock.
 */
void session_get_net_consumer_ports(const struct ltt_session *session,
		uint16_t *control_port, uint16_t *data_port)
{
	const struct consumer_output *output;

	output = session->kernel_session ?
			session->kernel_session->consumer :
			session->ust_session->consumer;
	*control_port = output->dst.net.control.port;
	*data_port = output->dst.net.data.port;
}

/*
 * Get the location of the latest trace archive produced by a rotation.
 *
 * The caller must hold the session lock.
 */
struct lttng_trace_archive_location *session_get_trace_archive_location(
		const struct ltt_session *session)
{
	int ret;
	struct lttng_trace_archive_location *location = NULL;
	char *chunk_path = NULL;

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
		location = lttng_trace_archive_location_local_create(
				chunk_path);
		break;
	case CONSUMER_DST_NET:
	{
		const char *hostname;
		uint16_t control_port, data_port;

		hostname = session_get_net_consumer_hostname(session);
		session_get_net_consumer_ports(session,
				&control_port,
				&data_port);
		location = lttng_trace_archive_location_relay_create(
				hostname,
				LTTNG_TRACE_ARCHIVE_LOCATION_RELAY_PROTOCOL_TYPE_TCP,
				control_port, data_port, session->last_chunk_path);
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
 * Allocate the ltt_sessions_ht_by_id HT.
 *
 * The session list lock must be held.
 */
static int ltt_sessions_ht_alloc(void)
{
	int ret = 0;

	DBG("Allocating ltt_sessions_ht_by_id");
	ltt_sessions_ht_by_id = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!ltt_sessions_ht_by_id) {
		ret = -1;
		ERR("Failed to allocate ltt_sessions_ht_by_id");
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
static void ltt_sessions_ht_destroy(void)
{
	if (!ltt_sessions_ht_by_id) {
		return;
	}
	ht_cleanup_push(ltt_sessions_ht_by_id);
	ltt_sessions_ht_by_id = NULL;
}

/*
 * Add a ltt_session to the ltt_sessions_ht_by_id.
 * If unallocated, the ltt_sessions_ht_by_id HT is allocated.
 * The session list lock must be held.
 */
static void add_session_ht(struct ltt_session *ls)
{
	int ret;

	assert(ls);

	if (!ltt_sessions_ht_by_id) {
		ret = ltt_sessions_ht_alloc();
		if (ret) {
			ERR("Error allocating the sessions HT");
			goto end;
		}
	}
	lttng_ht_node_init_u64(&ls->node, ls->id);
	lttng_ht_add_unique_u64(ltt_sessions_ht_by_id, &ls->node);

end:
	return;
}

/*
 * Test if ltt_sessions_ht_by_id is empty.
 * Return 1 if empty, 0 if not empty.
 * The session list lock must be held.
 */
static int ltt_sessions_ht_empty(void)
{
	int ret;

	if (!ltt_sessions_ht_by_id) {
		ret = 1;
		goto end;
	}

	ret = lttng_ht_get_count(ltt_sessions_ht_by_id) ? 0 : 1;
end:
	return ret;
}

/*
 * Remove a ltt_session from the ltt_sessions_ht_by_id.
 * If empty, the ltt_sessions_ht_by_id HT is freed.
 * The session list lock must be held.
 */
static void del_session_ht(struct ltt_session *ls)
{
	struct lttng_ht_iter iter;
	int ret;

	assert(ls);
	assert(ltt_sessions_ht_by_id);

	iter.iter.node = &ls->node.node;
	ret = lttng_ht_del(ltt_sessions_ht_by_id, &iter);
	assert(!ret);

	if (ltt_sessions_ht_empty()) {
		DBG("Empty ltt_sessions_ht_by_id, destroying it");
		ltt_sessions_ht_destroy();
	}
}

/*
 * Acquire session lock
 */
void session_lock(struct ltt_session *session)
{
	assert(session);

	pthread_mutex_lock(&session->lock);
}

/*
 * Release session lock
 */
void session_unlock(struct ltt_session *session)
{
	assert(session);

	pthread_mutex_unlock(&session->lock);
}

static
int _session_set_trace_chunk_no_lock_check(struct ltt_session *session,
		struct lttng_trace_chunk *new_trace_chunk,
		struct lttng_trace_chunk **_current_trace_chunk)
{
	int ret = 0;
	unsigned int i, refs_to_acquire = 0, refs_acquired = 0, refs_to_release = 0;
	struct cds_lfht_iter iter;
	struct consumer_socket *socket;
	struct lttng_trace_chunk *current_trace_chunk;
	uint64_t chunk_id;
	enum lttng_trace_chunk_status chunk_status;

	rcu_read_lock();
	/*
	 * Ownership of current trace chunk is transferred to
	 * `current_trace_chunk`.
	 */
	current_trace_chunk = session->current_trace_chunk;
	session->current_trace_chunk = NULL;
	if (session->ust_session) {
		lttng_trace_chunk_put(
				session->ust_session->current_trace_chunk);
		session->ust_session->current_trace_chunk = NULL;
	}
	if (session->kernel_session) {
		lttng_trace_chunk_put(
				session->kernel_session->current_trace_chunk);
		session->kernel_session->current_trace_chunk = NULL;
	}
	if (!new_trace_chunk) {
		ret = 0;
		goto end;
	}
	chunk_status = lttng_trace_chunk_get_id(new_trace_chunk, &chunk_id);
	assert(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);

	refs_to_acquire = 1;
	refs_to_acquire += !!session->ust_session;
	refs_to_acquire += !!session->kernel_session;

	for (refs_acquired = 0; refs_acquired < refs_to_acquire;
			refs_acquired++) {
		if (!lttng_trace_chunk_get(new_trace_chunk)) {
			ERR("Failed to acquire reference to new trace chunk of session \"%s\"",
					session->name);
			goto error;
		}
	}

	if (session->ust_session) {
		const uint64_t relayd_id =
				session->ust_session->consumer->net_seq_index;
		const bool is_local_trace =
				session->ust_session->consumer->type ==
				CONSUMER_DST_LOCAL;

		session->ust_session->current_trace_chunk = new_trace_chunk;
                if (is_local_trace) {
			enum lttng_error_code ret_error_code;

			ret_error_code = ust_app_create_channel_subdirectories(
					session->ust_session);
			if (ret_error_code != LTTNG_OK) {
				goto error;
			}
                }
		cds_lfht_for_each_entry(
				session->ust_session->consumer->socks->ht,
				&iter, socket, node.node) {
			pthread_mutex_lock(socket->lock);
			ret = consumer_create_trace_chunk(socket,
					relayd_id,
					session->id, new_trace_chunk);
			pthread_mutex_unlock(socket->lock);
                        if (ret) {
				goto error;
                        }
                }
        }
	if (session->kernel_session) {
		const uint64_t relayd_id =
				session->kernel_session->consumer->net_seq_index;
		const bool is_local_trace =
				session->kernel_session->consumer->type ==
				CONSUMER_DST_LOCAL;

		session->kernel_session->current_trace_chunk = new_trace_chunk;
		if (is_local_trace) {
			enum lttng_error_code ret_error_code;

			ret_error_code = kernel_create_channel_subdirectories(
					session->kernel_session);
			if (ret_error_code != LTTNG_OK) {
				goto error;
			}
                }
		cds_lfht_for_each_entry(
				session->kernel_session->consumer->socks->ht,
				&iter, socket, node.node) {
			pthread_mutex_lock(socket->lock);
			ret = consumer_create_trace_chunk(socket,
					relayd_id,
					session->id, new_trace_chunk);
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
		current_trace_chunk = NULL;
	}
end_no_move:
	rcu_read_unlock();
	lttng_trace_chunk_put(current_trace_chunk);
	return ret;
error:
	if (session->ust_session) {
		session->ust_session->current_trace_chunk = NULL;
	}
	if (session->kernel_session) {
		session->kernel_session->current_trace_chunk = NULL;
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

struct lttng_trace_chunk *session_create_new_trace_chunk(
		const struct ltt_session *session,
		const struct consumer_output *consumer_output_override,
		const char *session_base_path_override,
		const char *chunk_name_override)
{
	int ret;
	struct lttng_trace_chunk *trace_chunk = NULL;
	enum lttng_trace_chunk_status chunk_status;
	const time_t chunk_creation_ts = time(NULL);
	bool is_local_trace;
	const char *base_path;
	struct lttng_directory_handle *session_output_directory = NULL;
	const struct lttng_credentials session_credentials = {
		.uid = session->uid,
		.gid = session->gid,
	};
	uint64_t next_chunk_id;
	const struct consumer_output *output;

	if (consumer_output_override) {
		output = consumer_output_override;
	} else {
		assert(session->ust_session || session->kernel_session);
		output = session->ust_session ?
					 session->ust_session->consumer :
					 session->kernel_session->consumer;
	}

	is_local_trace = output->type == CONSUMER_DST_LOCAL;
	base_path = session_base_path_override ? :
			consumer_output_get_base_path(output);

	if (chunk_creation_ts == (time_t) -1) {
		PERROR("Failed to sample time while creation session \"%s\" trace chunk",
				session->name);
		goto error;
	}

	next_chunk_id = session->most_recent_chunk_id.is_set ?
			session->most_recent_chunk_id.value + 1 : 0;

	trace_chunk = lttng_trace_chunk_create(next_chunk_id,
			chunk_creation_ts);
	if (!trace_chunk) {
		goto error;
	}

	if (chunk_name_override) {
		chunk_status = lttng_trace_chunk_override_name(trace_chunk,
				chunk_name_override);
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

	chunk_status = lttng_trace_chunk_set_credentials(trace_chunk,
			&session_credentials);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		goto error;
	}

	DBG("Creating base output directory of session \"%s\" at %s",
			session->name, base_path);
	ret = utils_mkdir_recursive(base_path, S_IRWXU | S_IRWXG,
			session->uid, session->gid);
	if (ret) {
		goto error;
	}
	session_output_directory = lttng_directory_handle_create(base_path);
	if (!session_output_directory) {
		goto error;
	}
	chunk_status = lttng_trace_chunk_set_as_owner(trace_chunk,
			session_output_directory);
	lttng_directory_handle_put(session_output_directory);
	session_output_directory = NULL;
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		goto error;
	}
end:
	return trace_chunk;
error:
	lttng_directory_handle_put(session_output_directory);
	lttng_trace_chunk_put(trace_chunk);
	trace_chunk = NULL;
	goto end;
}

int session_close_trace_chunk(const struct ltt_session *session,
		struct lttng_trace_chunk *trace_chunk,
		const enum lttng_trace_chunk_command_type *close_command,
		char *closed_trace_chunk_path)
{
	int ret = 0;
	bool error_occurred = false;
	struct cds_lfht_iter iter;
	struct consumer_socket *socket;
	enum lttng_trace_chunk_status chunk_status;
	const time_t chunk_close_timestamp = time(NULL);

	if (close_command) {
		chunk_status = lttng_trace_chunk_set_close_command(
				trace_chunk, *close_command);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret = -1;
			goto end;
		}
	}

	if (chunk_close_timestamp == (time_t) -1) {
		ERR("Failed to sample the close timestamp of the current trace chunk of session \"%s\"",
				session->name);
		ret = -1;
		goto end;
	}
	chunk_status = lttng_trace_chunk_set_close_timestamp(trace_chunk,
			chunk_close_timestamp);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ERR("Failed to set the close timestamp of the current trace chunk of session \"%s\"",
				session->name);
		ret = -1;
		goto end;
	}

	if (session->ust_session) {
		const uint64_t relayd_id =
				session->ust_session->consumer->net_seq_index;

		cds_lfht_for_each_entry(
				session->ust_session->consumer->socks->ht,
				&iter, socket, node.node) {
			pthread_mutex_lock(socket->lock);
			ret = consumer_close_trace_chunk(socket,
					relayd_id,
					session->id,
					trace_chunk, closed_trace_chunk_path);
			pthread_mutex_unlock(socket->lock);
			if (ret) {
				ERR("Failed to close trace chunk on user space consumer");
				error_occurred = true;
			}
		}
	}
	if (session->kernel_session) {
		const uint64_t relayd_id =
				session->kernel_session->consumer->net_seq_index;

		cds_lfht_for_each_entry(
				session->kernel_session->consumer->socks->ht,
				&iter, socket, node.node) {
			pthread_mutex_lock(socket->lock);
			ret = consumer_close_trace_chunk(socket,
					relayd_id,
					session->id,
					trace_chunk, closed_trace_chunk_path);
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
 * Set a session's current trace chunk.
 *
 * Must be called with the session lock held.
 */
int session_set_trace_chunk(struct ltt_session *session,
		struct lttng_trace_chunk *new_trace_chunk,
		struct lttng_trace_chunk **current_trace_chunk)
{
	ASSERT_LOCKED(session->lock);
	return _session_set_trace_chunk_no_lock_check(session, new_trace_chunk,
			current_trace_chunk);
}

static
void session_notify_destruction(const struct ltt_session *session)
{
	size_t i;
	const size_t count = lttng_dynamic_array_get_count(
			&session->destroy_notifiers);

	for (i = 0; i < count; i++) {
		const struct ltt_session_destroy_notifier_element *element =
			lttng_dynamic_array_get_element(
					&session->destroy_notifiers, i);

		element->notifier(session, element->user_data);
	}
}

static
void session_release(struct urcu_ref *ref)
{
	int ret;
	struct ltt_ust_session *usess;
	struct ltt_kernel_session *ksess;
	struct ltt_session *session = container_of(ref, typeof(*session), ref);
	const bool session_published = session->published;

	assert(!session->chunk_being_archived);

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
	ret = notify_thread_pipe(kernel_poll_pipe[1]);
	if (ret < 0) {
		PERROR("write kernel poll pipe");
	}

	DBG("Destroying session %s (id %" PRIu64 ")", session->name, session->id);

	snapshot_destroy(&session->snapshot);

	pthread_mutex_destroy(&session->lock);

	if (session_published) {
		ASSERT_LOCKED(ltt_session_list.lock);
		del_session_list(session);
		del_session_ht(session);
	}
	session_notify_destruction(session);

	consumer_output_put(session->consumer);
	kernel_free_session(ksess);
	session->kernel_session = NULL;
	if (usess) {
		trace_ust_free_session(usess);
		session->ust_session = NULL;
	}
	lttng_dynamic_array_reset(&session->destroy_notifiers);
	free(session->last_archived_chunk_name);
	free(session->base_path);
	free(session);
	if (session_published) {
		/*
		 * Broadcast after free-ing to ensure the memory is
		 * reclaimed before the main thread exits.
		 */
		pthread_cond_broadcast(&ltt_session_list.removal_cond);
	}
}

/*
 * Acquire a reference to a session.
 * This function may fail (return false); its return value must be checked.
 */
bool session_get(struct ltt_session *session)
{
	return urcu_ref_get_unless_zero(&session->ref);
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
	ASSERT_LOCKED(ltt_session_list.lock);
	assert(session->ref.refcount);
	urcu_ref_put(&session->ref, session_release);
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
	assert(!session->destroyed);
	session->destroyed = true;
	session_put(session);
}

int session_add_destroy_notifier(struct ltt_session *session,
		ltt_session_destroy_notifier notifier, void *user_data)
{
	const struct ltt_session_destroy_notifier_element element = {
		.notifier = notifier,
		.user_data = user_data
	};

	return lttng_dynamic_array_add_element(&session->destroy_notifiers,
			&element);
}

/*
 * Return a ltt_session structure ptr that matches name. If no session found,
 * NULL is returned. This must be called with the session list lock held using
 * session_lock_list and session_unlock_list.
 * A reference to the session is implicitly acquired by this function.
 */
struct ltt_session *session_find_by_name(const char *name)
{
	struct ltt_session *iter;

	assert(name);
	ASSERT_LOCKED(ltt_session_list.lock);

	DBG2("Trying to find session by name %s", name);

	cds_list_for_each_entry(iter, &ltt_session_list.head, list) {
		if (!strncmp(iter->name, name, NAME_MAX) &&
				!iter->destroyed) {
			goto found;
		}
	}

	return NULL;
found:
	return session_get(iter) ? iter : NULL;
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

	ASSERT_LOCKED(ltt_session_list.lock);

	if (!ltt_sessions_ht_by_id) {
		goto end;
	}

	lttng_ht_lookup(ltt_sessions_ht_by_id, &id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node == NULL) {
		goto end;
	}
	ls = caa_container_of(node, struct ltt_session, node);

	DBG3("Session %" PRIu64 " found by id.", id);
	return session_get(ls) ? ls : NULL;

end:
	DBG3("Session %" PRIu64 " NOT found by id", id);
	return NULL;
}

/*
 * Create a new session and add it to the session list.
 * Session list lock must be held by the caller.
 */
enum lttng_error_code session_create(const char *name, uid_t uid, gid_t gid,
		struct ltt_session **out_session)
{
	int ret;
	enum lttng_error_code ret_code;
	struct ltt_session *new_session = NULL;

	ASSERT_LOCKED(ltt_session_list.lock);
	if (name) {
		struct ltt_session *clashing_session;

		clashing_session = session_find_by_name(name);
		if (clashing_session) {
			session_put(clashing_session);
			ret_code = LTTNG_ERR_EXIST_SESS;
			goto error;
		}
	}
	new_session = zmalloc(sizeof(struct ltt_session));
	if (!new_session) {
		PERROR("Failed to allocate an ltt_session structure");
		ret_code = LTTNG_ERR_NOMEM;
		goto error;
	}

	lttng_dynamic_array_init(&new_session->destroy_notifiers,
			sizeof(struct ltt_session_destroy_notifier_element),
			NULL);
	urcu_ref_init(&new_session->ref);
	pthread_mutex_init(&new_session->lock, NULL);

	new_session->creation_time = time(NULL);
	if (new_session->creation_time == (time_t) -1) {
		PERROR("Failed to sample session creation time");
		ret_code = LTTNG_ERR_SESSION_FAIL;
		goto error;
	}

	/* Create default consumer output. */
	new_session->consumer = consumer_create_output(CONSUMER_DST_LOCAL);
	if (new_session->consumer == NULL) {
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
						DEFAULT_SESSION_NAME, i,
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

			clashing_session =
					session_find_by_name(new_session->name);
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
			new_session->name, new_session->id, new_session->uid,
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
	new_session = NULL;
	goto end;
}

/*
 * Check if the UID or GID match the session. Root user has access to all
 * sessions.
 */
int session_access_ok(struct ltt_session *session, uid_t uid, gid_t gid)
{
	assert(session);

	if (uid != session->uid && gid != session->gid && uid != 0) {
		return 0;
	} else {
		return 1;
	}
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
int session_reset_rotation_state(struct ltt_session *session,
		enum lttng_rotation_state result)
{
	int ret = 0;

	ASSERT_LOCKED(ltt_session_list.lock);
	ASSERT_LOCKED(session->lock);

	session->rotation_state = result;
	if (session->rotation_pending_check_timer_enabled) {
		ret = timer_session_rotation_pending_check_stop(session);
	}
	if (session->chunk_being_archived) {
		uint64_t chunk_id;
		enum lttng_trace_chunk_status chunk_status;

		chunk_status = lttng_trace_chunk_get_id(
				session->chunk_being_archived,
				&chunk_id);
		assert(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);
		LTTNG_OPTIONAL_SET(&session->last_archived_chunk_id,
				chunk_id);
		lttng_trace_chunk_put(session->chunk_being_archived);
		session->chunk_being_archived = NULL;
	}
	return ret;
}
