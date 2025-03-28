/*
 * SPDX-FileCopyrightText: 2013 Julien Desfossez <jdesfossez@efficios.com>
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 * SPDX-FileCopyrightText: 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "ctf-trace.hpp"
#include "lttng-relayd.hpp"
#include "session.hpp"
#include "sessiond-trace-chunks.hpp"
#include "stream.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/compat/path.hpp>
#include <common/defaults.hpp>
#include <common/fd-tracker/utils.hpp>
#include <common/time.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>
#include <common/uuid.hpp>

#include <sys/stat.h>
#include <urcu/rculist.h>

/* Global session id used in the session creation. */
static uint64_t last_relay_session_id;
static pthread_mutex_t last_relay_session_id_lock = PTHREAD_MUTEX_INITIALIZER;

static int init_session_output_path_group_by_host(struct relay_session *session)
{
	/*
	 * session_directory:
	 *
	 * if base_path is \0'
	 *   hostname/session_name
	 * else
	 *   hostname/base_path
	 */
	char *session_directory = nullptr;
	int ret = 0;

	if (session->output_path[0] != '\0') {
		goto end;
	}
	/*
	 * If base path is set, it overrides the session name for the
	 * session relative base path. No timestamp is appended if the
	 * base path is overridden.
	 *
	 * If the session name already contains the creation time (e.g.
	 * auto-<timestamp>, don't append yet another timestamp after
	 * the session name in the generated path.
	 *
	 * Otherwise, generate the path with session_name-<timestamp>.
	 */
	if (session->base_path[0] != '\0') {
		ret = asprintf(&session_directory, "%s/%s", session->hostname, session->base_path);
	} else if (session->session_name_contains_creation_time) {
		ret = asprintf(
			&session_directory, "%s/%s", session->hostname, session->session_name);
	} else {
		char session_creation_datetime[DATETIME_STR_LEN];

		ret = time_to_datetime_str(LTTNG_OPTIONAL_GET(session->creation_time),
					   session_creation_datetime,
					   sizeof(session_creation_datetime));
		if (ret) {
			ERR("Failed to format session creation timestamp while initializing session output directory handle");
			ret = -1;
			goto end;
		}

		ret = asprintf(&session_directory,
			       "%s/%s-%s",
			       session->hostname,
			       session->session_name,
			       session_creation_datetime);
	}
	if (ret < 0) {
		PERROR("Failed to format session directory name");
		goto end;
	}

	if (strlen(session_directory) >= LTTNG_PATH_MAX) {
		ERR("Session output directory exceeds maximal length");
		ret = -1;
		goto end;
	}
	strcpy(session->output_path, session_directory);
	ret = 0;

end:
	free(session_directory);
	return ret;
}

static int init_session_output_path_group_by_session(struct relay_session *session)
{
	/*
	 * session_directory:
	 *
	 *   session_name/hostname-creation_time/base_path
	 *
	 * For session name including the datetime, use it as the complete name
	 * since. Do not perform modification on it since the datetime is an
	 * integral part of the name and how a user identify a session.
	 */
	int ret = 0;
	char *session_directory = nullptr;
	char creation_datetime[DATETIME_STR_LEN];

	if (session->output_path[0] != '\0') {
		/* output_path as been generated already */
		goto end;
	}

	ret = time_to_datetime_str(LTTNG_OPTIONAL_GET(session->creation_time),
				   creation_datetime,
				   sizeof(creation_datetime));
	if (ret) {
		ERR("Failed to format session creation timestamp while initializing session output directory handle");
		ret = -1;
		goto end;
	}

	ret = asprintf(&session_directory,
		       "%s/%s-%s%s%s",
		       session->session_name,
		       session->hostname,
		       creation_datetime,
		       session->base_path[0] != '\0' ? "/" : "",
		       session->base_path);
	if (ret < 0) {
		PERROR("Failed to format session directory name");
		goto end;
	}

	if (strlen(session_directory) >= LTTNG_PATH_MAX) {
		ERR("Session output directory exceeds maximal length");
		ret = -1;
		goto end;
	}

	strcpy(session->output_path, session_directory);
	ret = 0;

end:
	free(session_directory);
	return ret;
}

static int init_session_output_path(struct relay_session *session)
{
	int ret;

	switch (opt_group_output_by) {
	case RELAYD_GROUP_OUTPUT_BY_HOST:
		ret = init_session_output_path_group_by_host(session);
		break;
	case RELAYD_GROUP_OUTPUT_BY_SESSION:
		ret = init_session_output_path_group_by_session(session);
		break;
	case RELAYD_GROUP_OUTPUT_BY_UNKNOWN:
	default:
		abort();
		break;
	}

	return ret;
}

static struct lttng_directory_handle *
session_create_output_directory_handle(struct relay_session *session)
{
	int ret;
	/*
	 * relayd_output_path/session_directory
	 * e.g. /home/user/lttng-traces/hostname/session_name
	 */
	char *full_session_path = nullptr;
	struct lttng_directory_handle *handle = nullptr;

	pthread_mutex_lock(&session->lock);
	full_session_path = create_output_path(session->output_path);
	if (!full_session_path) {
		goto end;
	}

	ret = utils_mkdir_recursive(full_session_path, S_IRWXU | S_IRWXG, -1, -1);
	if (ret) {
		ERR("Failed to create session output path \"%s\"", full_session_path);
		goto end;
	}

	handle = fd_tracker_create_directory_handle(the_fd_tracker, full_session_path);
end:
	pthread_mutex_unlock(&session->lock);
	free(full_session_path);
	return handle;
}

static int session_set_anonymous_chunk(struct relay_session *session)
{
	int ret = 0;
	struct lttng_trace_chunk *chunk = nullptr;
	enum lttng_trace_chunk_status status;
	struct lttng_directory_handle *output_directory;

	output_directory = session_create_output_directory_handle(session);
	if (!output_directory) {
		goto end;
	}

	chunk = lttng_trace_chunk_create_anonymous();
	if (!chunk) {
		goto end;
	}

	lttng_trace_chunk_set_fd_tracker(chunk, the_fd_tracker);
	status = lttng_trace_chunk_set_credentials_current_user(chunk);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = -1;
		goto end;
	}

	status = lttng_trace_chunk_set_as_owner(chunk, output_directory);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		ret = -1;
		goto end;
	}

	session->current_trace_chunk = chunk;
	chunk = nullptr;
end:
	lttng_trace_chunk_put(chunk);
	lttng_directory_handle_put(output_directory);
	return ret;
}

/*
 * Check if a name is safe to use in a path.
 *
 * A name that is deemed "path-safe":
 *   - Does not contains a path separator (/ or \, platform dependant),
 *   - Does not start with a '.' (hidden file/folder),
 *   - Is not empty.
 */
static bool is_name_path_safe(const char *name)
{
	const size_t name_len = strlen(name);

	/* Not empty. */
	if (name_len == 0) {
		WARN("An empty name is not allowed to be used in a path");
		return false;
	}
	/* Does not start with '.'. */
	if (name[0] == '.') {
		WARN("Name \"%s\" is not allowed to be used in a path since it starts with '.'",
		     name);
		return false;
	}
	/* Does not contain a path-separator. */
	if (strchr(name, LTTNG_PATH_SEPARATOR)) {
		WARN("Name \"%s\" is not allowed to be used in a path since it contains a path separator",
		     name);
		return false;
	}

	return true;
}

/*
 * Create a new session by assigning a new session ID.
 *
 * Return allocated session or else NULL.
 */
struct relay_session *session_create(const char *session_name,
				     const char *hostname,
				     const char *base_path,
				     uint32_t live_timer,
				     bool snapshot,
				     const lttng_uuid& sessiond_uuid,
				     const uint64_t *id_sessiond,
				     const uint64_t *current_chunk_id,
				     const time_t *creation_time,
				     uint32_t major,
				     uint32_t minor,
				     bool session_name_contains_creation_time)
{
	int ret;
	struct relay_session *session = nullptr;

	LTTNG_ASSERT(session_name);
	LTTNG_ASSERT(hostname);
	LTTNG_ASSERT(base_path);

	if (!is_name_path_safe(session_name)) {
		ERR("Refusing to create session as the provided session name is not path-safe");
		goto error;
	}
	if (!is_name_path_safe(hostname)) {
		ERR("Refusing to create session as the provided hostname is not path-safe");
		goto error;
	}
	if (strstr(base_path, "../")) {
		ERR("Invalid session base path walks up the path hierarchy: \"%s\"", base_path);
		goto error;
	}

	session = zmalloc<relay_session>();
	if (!session) {
		PERROR("Failed to allocate session");
		goto error;
	}

	pthread_mutex_lock(&last_relay_session_id_lock);
	session->id = ++last_relay_session_id;
	pthread_mutex_unlock(&last_relay_session_id_lock);

	lttng_ht_node_init_u64(&session->session_n, session->id);
	urcu_ref_init(&session->ref);
	CDS_INIT_LIST_HEAD(&session->recv_list);
	pthread_mutex_init(&session->lock, nullptr);
	pthread_mutex_init(&session->recv_list_lock, nullptr);

	if (lttng_strncpy(session->session_name, session_name, sizeof(session->session_name))) {
		WARN("Session name exceeds maximal allowed length");
		goto error;
	}
	if (lttng_strncpy(session->hostname, hostname, sizeof(session->hostname))) {
		WARN("Hostname exceeds maximal allowed length");
		goto error;
	}
	if (lttng_strncpy(session->base_path, base_path, sizeof(session->base_path))) {
		WARN("Base path exceeds maximal allowed length");
		goto error;
	}
	if (creation_time) {
		LTTNG_OPTIONAL_SET(&session->creation_time, *creation_time);
	} else {
		LTTNG_OPTIONAL_SET(&session->creation_time, time(nullptr));
		if (session->creation_time.value == (time_t) -1) {
			PERROR("Failed to sample session creation time");
			goto error;
		}
	}
	session->session_name_contains_creation_time = session_name_contains_creation_time;

	session->ctf_traces_ht = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!session->ctf_traces_ht) {
		goto error;
	}

	session->major = major;
	session->minor = minor;

	session->live_timer = live_timer;
	session->snapshot = snapshot;
	session->sessiond_uuid = sessiond_uuid;

	if (id_sessiond) {
		LTTNG_OPTIONAL_SET(&session->id_sessiond, *id_sessiond);
	}

	if (major == 2 && minor >= 11) {
		/* Only applies for 2.11+ peers using trace chunks. */
		ret = init_session_output_path(session);
		if (ret) {
			goto error;
		}
	}

	ret = sessiond_trace_chunk_registry_session_created(sessiond_trace_chunk_registry,
							    sessiond_uuid);
	if (ret) {
		goto error;
	}

	if (id_sessiond && current_chunk_id) {
		enum lttng_trace_chunk_status chunk_status;
		struct lttng_directory_handle *session_output_directory;

		session->current_trace_chunk =
			sessiond_trace_chunk_registry_get_chunk(sessiond_trace_chunk_registry,
								session->sessiond_uuid,
								session->id_sessiond.value,
								*current_chunk_id);
		if (!session->current_trace_chunk) {
			char uuid_str[LTTNG_UUID_STR_LEN];

			lttng_uuid_to_str(sessiond_uuid, uuid_str);
			ERR("Could not find trace chunk: sessiond = {%s}, sessiond session id = %" PRIu64
			    ", trace chunk id = %" PRIu64,
			    uuid_str,
			    *id_sessiond,
			    *current_chunk_id);
			goto error;
		}

		chunk_status = lttng_trace_chunk_get_session_output_directory_handle(
			session->current_trace_chunk, &session_output_directory);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			goto error;
		}

		LTTNG_ASSERT(session_output_directory);
		session->output_directory = session_output_directory;
	} else if (!id_sessiond) {
		/*
		 * Pre-2.11 peers will not announce trace chunks. An
		 * anonymous trace chunk which will remain set for the
		 * duration of the session is created.
		 */
		ret = session_set_anonymous_chunk(session);
		if (ret) {
			goto error;
		}
	} else {
		session->output_directory = session_create_output_directory_handle(session);
		if (!session->output_directory) {
			goto error;
		}
	}

	lttng_ht_add_unique_u64(sessions_ht, &session->session_n);
	return session;

error:
	session_put(session);
	return nullptr;
}

/* Should be called with RCU read-side lock held. */
bool session_get(struct relay_session *session)
{
	return urcu_ref_get_unless_zero(&session->ref);
}

/*
 * Lookup a session within the session hash table using the session id
 * as key. A session reference is taken when a session is returned.
 * session_put() must be called on that session.
 *
 * Return session or NULL if not found.
 */
struct relay_session *session_get_by_id(uint64_t id)
{
	struct relay_session *session = nullptr;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;

	const lttng::urcu::read_lock_guard read_lock;
	lttng_ht_lookup(sessions_ht, &id, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (!node) {
		DBG("Session find by ID %" PRIu64 " id NOT found", id);
		goto end;
	}
	session = lttng::utils::container_of(node, &relay_session::session_n);
	DBG("Session find by ID %" PRIu64 " id found", id);
	if (!session_get(session)) {
		session = nullptr;
	}
end:
	return session;
}

/*
 * Check if any of the relay sessions originating from the same
 * session daemon session have the 'ongoing_rotation' state set.
 *
 * The caller must hold the lock of session.
 */
bool session_has_ongoing_rotation(const struct relay_session *session)
{
	bool ongoing_rotation = false;

	ASSERT_LOCKED(session->lock);

	if (!session->id_sessiond.is_set) {
		/*
		 * The peer that created this session is too old to
		 * support rotations; we can assume no rotations are ongoing.
		 */
		goto end;
	}

	if (session->ongoing_rotation) {
		ongoing_rotation = true;
		goto end;
	}

	/*
	 * Sample the 'ongoing_rotation' status of all relay sessions that
	 * originate from the same session daemon session.
	 */
	for (auto *iterated_session :
	     lttng::urcu::lfht_iteration_adapter<relay_session,
						 decltype(relay_session::session_n),
						 &relay_session::session_n>(*sessions_ht->ht)) {
		if (!session_get(iterated_session)) {
			continue;
		}

		if (session == iterated_session) {
			/* Skip this session. */
			goto next_session_no_unlock;
		}

		pthread_mutex_lock(&iterated_session->lock);

		if (!iterated_session->id_sessiond.is_set) {
			/*
			 * Session belongs to a peer that doesn't support
			 * rotations.
			 */
			goto next_session;
		}

		if (session->sessiond_uuid != iterated_session->sessiond_uuid) {
			/* Sessions do not originate from the same sessiond. */
			goto next_session;
		}

		if (LTTNG_OPTIONAL_GET(session->id_sessiond) !=
		    LTTNG_OPTIONAL_GET(iterated_session->id_sessiond)) {
			/*
			 * Sessions do not originate from the same sessiond
			 * session.
			 */
			goto next_session;
		}

		ongoing_rotation = iterated_session->ongoing_rotation;

	next_session:
		pthread_mutex_unlock(&iterated_session->lock);
	next_session_no_unlock:
		session_put(iterated_session);

		if (ongoing_rotation) {
			break;
		}
	}

end:
	return ongoing_rotation;
}

static void rcu_destroy_session(struct rcu_head *rcu_head)
{
	auto *session = lttng::utils::container_of(rcu_head, &relay_session::rcu_node);
	/*
	 * Since each trace has a reference on the session, it means
	 * that if we are at the point where we teardown the session, no
	 * trace belonging to that session exist at this point.
	 * Calling lttng_ht_destroy in call_rcu worker thread so we
	 * don't hold the RCU read-side lock while calling it.
	 */
	lttng_ht_destroy(session->ctf_traces_ht);
	free(session);
}

/*
 * Delete session from the given hash table.
 *
 * Return lttng ht del error code being 0 on success and 1 on failure.
 */
static int session_delete(struct relay_session *session)
{
	struct lttng_ht_iter iter;

	iter.iter.node = &session->session_n.node;
	return lttng_ht_del(sessions_ht, &iter);
}

static void destroy_session(struct relay_session *session)
{
	int ret;

	ret = session_delete(session);
	LTTNG_ASSERT(!ret);
	lttng_trace_chunk_put(session->current_trace_chunk);
	session->current_trace_chunk = nullptr;
	lttng_trace_chunk_put(session->pending_closure_trace_chunk);
	session->pending_closure_trace_chunk = nullptr;
	ret = sessiond_trace_chunk_registry_session_destroyed(sessiond_trace_chunk_registry,
							      session->sessiond_uuid);
	LTTNG_ASSERT(!ret);
	lttng_directory_handle_put(session->output_directory);
	session->output_directory = nullptr;
	call_rcu(&session->rcu_node, rcu_destroy_session);
}

static void session_release(struct urcu_ref *ref)
{
	struct relay_session *session = lttng::utils::container_of(ref, &relay_session::ref);

	destroy_session(session);
}

void session_put(struct relay_session *session)
{
	if (!session) {
		return;
	}
	const lttng::urcu::read_lock_guard read_lock;
	urcu_ref_put(&session->ref, session_release);
}

int session_close(struct relay_session *session)
{
	int ret = 0;

	pthread_mutex_lock(&session->lock);
	DBG("closing session %" PRIu64 ": is conn already closed %d",
	    session->id,
	    session->connection_closed);
	session->connection_closed = true;
	pthread_mutex_unlock(&session->lock);

	for (auto *trace :
	     lttng::urcu::lfht_iteration_adapter<ctf_trace,
						 decltype(ctf_trace::node),
						 &ctf_trace::node>(*session->ctf_traces_ht->ht)) {
		ret = ctf_trace_close(trace);
		if (ret) {
			goto end;
		}
	}

	for (auto *stream :
	     lttng::urcu::rcu_list_iteration_adapter<relay_stream, &relay_stream::recv_node>(
		     session->recv_list)) {
		/* Close streams which have not been published yet. */
		try_stream_close(stream);
	}

end:
	if (ret) {
		return ret;
	}

	/* Put self-reference from create. */
	session_put(session);
	return ret;
}

int session_abort(struct relay_session *session)
{
	const int ret = 0;

	if (!session) {
		return 0;
	}

	pthread_mutex_lock(&session->lock);
	DBG("aborting session %" PRIu64, session->id);
	session->aborted = true;
	pthread_mutex_unlock(&session->lock);
	return ret;
}

void print_sessions()
{
	if (!sessions_ht) {
		return;
	}

	for (auto *session :
	     lttng::urcu::lfht_iteration_adapter<relay_session,
						 decltype(relay_session::session_n),
						 &relay_session::session_n>(*sessions_ht->ht)) {
		if (!session_get(session)) {
			continue;
		}
		DBG("session %p refcount %ld session %" PRIu64,
		    session,
		    session->ref.refcount,
		    session->id);
		session_put(session);
	}
}
