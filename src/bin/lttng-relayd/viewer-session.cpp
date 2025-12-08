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
#include "live.hpp"
#include "lttng-relayd.hpp"
#include "session.hpp"
#include "stream.hpp"
#include "viewer-session.hpp"
#include "viewer-stream.hpp"

#include <common/common.hpp>
#include <common/urcu.hpp>

#include <urcu/rculist.h>

/* Global session id used in the session creation. */
static uint64_t last_viewer_session_id;
static pthread_mutex_t last_viewer_session_id_lock = PTHREAD_MUTEX_INITIALIZER;

struct relay_viewer_session *viewer_session_create()
{
	struct relay_viewer_session *vsession;

	vsession = zmalloc<relay_viewer_session>();
	if (!vsession) {
		goto end;
	}
	pthread_mutex_lock(&last_viewer_session_id_lock);
	vsession->id = ++last_viewer_session_id;
	pthread_mutex_unlock(&last_viewer_session_id_lock);
	CDS_INIT_LIST_HEAD(&vsession->session_list);
	CDS_INIT_LIST_HEAD(&vsession->unannounced_stream_list);
	pthread_mutex_init(&vsession->unannounced_stream_list_lock, nullptr);
	lttng_ht_node_init_u64(&vsession->viewer_session_n, vsession->id);
	lttng_ht_add_unique_u64(viewer_sessions_ht, &vsession->viewer_session_n);
end:
	return vsession;
}

int viewer_session_set_trace_chunk_copy(struct relay_viewer_session *vsession,
					struct lttng_trace_chunk *relay_session_trace_chunk)
{
	int ret = 0;
	struct lttng_trace_chunk *viewer_chunk;

	lttng_trace_chunk_put(vsession->current_trace_chunk);
	vsession->current_trace_chunk = nullptr;

	DBG("Copying relay session's current trace chunk to the viewer session");
	if (!relay_session_trace_chunk) {
		goto end;
	}

	viewer_chunk = lttng_trace_chunk_copy(relay_session_trace_chunk);
	if (!viewer_chunk) {
		ERR("Failed to create a viewer trace chunk from the relay session's current chunk");
		ret = -1;
		goto end;
	}

	vsession->current_trace_chunk = viewer_chunk;
end:
	return ret;
}

/* The existence of session must be guaranteed by the caller. */
enum lttng_viewer_attach_return_code viewer_session_attach(struct relay_viewer_session *vsession,
							   struct relay_session *session,
							   enum lttng_viewer_seek seek_type)
{
	enum lttng_viewer_attach_return_code viewer_attach_status = LTTNG_VIEWER_ATTACH_OK;

	ASSERT_LOCKED(session->lock);

	/* Will not fail, as per the ownership guarantee. */
	if (!session_get(session)) {
		viewer_attach_status = LTTNG_VIEWER_ATTACH_UNK;
		goto end;
	}
	if (session->viewer_attached) {
		viewer_attach_status = LTTNG_VIEWER_ATTACH_ALREADY;
	} else {
		int ret;

		session->viewer_attached = true;

		ret = viewer_session_set_trace_chunk_copy(vsession, session->current_trace_chunk);
		if (ret) {
			/*
			 * The live protocol does not define a generic error
			 * value for the "attach" command. The "unknown"
			 * status is used so that the viewer may handle this
			 * failure as if the session didn't exist anymore.
			 */
			DBG("Failed to create a viewer trace chunk from the current trace chunk of session \"%s\", returning LTTNG_VIEWER_ATTACH_UNK",
			    session->session_name);
			viewer_attach_status = LTTNG_VIEWER_ATTACH_UNK;
		}
	}

	if (viewer_attach_status == LTTNG_VIEWER_ATTACH_OK) {
		pthread_mutex_lock(&vsession->session_list_lock);
		/* Ownership is transfered to the list. */
		cds_list_add_rcu(&session->viewer_session_node, &vsession->session_list);
		pthread_mutex_unlock(&vsession->session_list_lock);

		/*
		 * Immediately create new viewer streams for the attached session
		 * so that the viewer streams hold a reference on the any relay
		 * streams that could be unpublished between now and the next
		 * GET_NEW_STREAMS command from the live viewer.
		 */
		uint32_t created = 0;
		uint32_t total = 0;
		uint32_t unsent = 0;
		bool closed = false;
		const int make_viewer_streams_ret = make_viewer_streams(
			session, vsession, seek_type, &total, &unsent, &created, &closed);

		if (make_viewer_streams_ret == 0) {
			DBG("Created %d new viewer streams while attaching to relay session %" PRIu64,
			    created,
			    session->id);
		} else {
			/*
			 * Warning, since the creation of the streams will be retried when
			 * the viewer next sends the GET_NEW_STREAMS commands.
			 */
			WARN("Failed to create new viewer streams while attaching to relay session %" PRIu64
			     ", ret=%d, total=%d, unsent=%d, created=%d, closed=%d",
			     session->id,
			     make_viewer_streams_ret,
			     total,
			     unsent,
			     created,
			     closed);
		}
	} else {
		/* Put our local ref. */
		session_put(session);
	}
end:
	return viewer_attach_status;
}

/* The existence of session must be guaranteed by the caller. */
static int viewer_session_detach(struct relay_viewer_session *vsession,
				 struct relay_session *session)
{
	int ret = 0;

	pthread_mutex_lock(&session->lock);
	if (!session->viewer_attached) {
		ret = -1;
	} else {
		session->viewer_attached = false;
	}

	if (!ret) {
		pthread_mutex_lock(&vsession->session_list_lock);
		cds_list_del_rcu(&session->viewer_session_node);
		pthread_mutex_unlock(&vsession->session_list_lock);
		/* Release reference held by the list. */
		session_put(session);
	}

	/* Safe since we know the session exists. */
	pthread_mutex_unlock(&session->lock);
	return ret;
}

void viewer_session_destroy(struct relay_viewer_session *vsession)
{
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(cds_list_empty(&vsession->unannounced_stream_list));

	iter.iter.node = &vsession->viewer_session_n.node;
	lttng_ht_del(viewer_sessions_ht, &iter);
	lttng_trace_chunk_put(vsession->current_trace_chunk);
	free(vsession);
}

/*
 * Release ownership of all the streams of one session and detach the viewer.
 */
void viewer_session_close_one_session(struct relay_viewer_session *vsession,
				      struct relay_session *session)
{
	/*
	 * TODO: improvement: create more efficient list of
	 * vstream per session.
	 */
	for (auto *vstream :
	     lttng::urcu::lfht_iteration_adapter<relay_viewer_stream,
						 decltype(relay_viewer_stream::stream_n),
						 &relay_viewer_stream::stream_n>(
		     *viewer_streams_ht->ht)) {
		if (!viewer_stream_get(vstream)) {
			continue;
		}

		if (vstream->stream->trace->session != session) {
			viewer_stream_put(vstream);
			continue;
		}
		/* Put local reference. */
		viewer_stream_put(vstream);
		/*
		 * We have reached one of the viewer stream's lifetime
		 * end condition. This "put" will cause the proper
		 * teardown of the viewer stream.
		 */
		viewer_stream_put(vstream);
	}

	for (auto *vstream :
	     lttng::urcu::rcu_list_iteration_adapter<relay_viewer_stream,
						     &relay_viewer_stream::viewer_stream_node>(
		     vsession->unannounced_stream_list)) {
		if (!viewer_stream_get(vstream)) {
			continue;
		}
		if (vstream->stream->trace->session != session) {
			viewer_stream_put(vstream);
			continue;
		}
		pthread_mutex_lock(&vsession->unannounced_stream_list_lock);
		cds_list_del_rcu(&vstream->viewer_stream_node);
		pthread_mutex_unlock(&vsession->unannounced_stream_list_lock);
		/* Local reference */
		viewer_stream_put(vstream);
		/* Reference from unannounced_stream_list */
		viewer_stream_put(vstream);
	}

	lttng_trace_chunk_put(vsession->current_trace_chunk);
	vsession->current_trace_chunk = nullptr;
	viewer_session_detach(vsession, session);
}

void viewer_session_close(struct relay_viewer_session *vsession)
{
	for (auto *session :
	     lttng::urcu::rcu_list_iteration_adapter<relay_session,
						     &relay_session::viewer_session_node>(
		     vsession->session_list)) {
		viewer_session_close_one_session(vsession, session);
	}
}

/*
 * Check if a connection is attached to a session.
 * Return 1 if attached, 0 if not attached, a negative value on error.
 */
int viewer_session_is_attached(struct relay_viewer_session *vsession, struct relay_session *session)
{
	int found = 0;

	pthread_mutex_lock(&session->lock);
	if (!vsession) {
		goto end;
	}
	if (!session->viewer_attached) {
		goto end;
	}

	for (auto *session_it :
	     lttng::urcu::rcu_list_iteration_adapter<relay_session,
						     &relay_session::viewer_session_node>(
		     vsession->session_list)) {
		if (session == session_it) {
			found = 1;
			break;
		}
	}

end:
	pthread_mutex_unlock(&session->lock);
	return found;
}
