/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#define _LGPL_SOURCE
#include <common/common.h>
#include <urcu/rculist.h>

#include "lttng-relayd.h"
#include "ctf-trace.h"
#include "session.h"
#include "viewer-session.h"
#include "viewer-stream.h"
#include "stream.h"

struct relay_viewer_session *viewer_session_create(void)
{
	struct relay_viewer_session *vsession;

	vsession = zmalloc(sizeof(*vsession));
	if (!vsession) {
		goto end;
	}
	CDS_INIT_LIST_HEAD(&vsession->session_list);
end:
	return vsession;
}

int viewer_session_attach(struct relay_viewer_session *vsession,
		struct relay_session *session)
{
	int ret = 0;

	if (!session_get(session)) {
		ret = -1;
		goto end;
	}
	pthread_mutex_lock(&session->lock);
	if (session->viewer_attached) {
		ret = -1;
	} else {
		session->viewer_attached = true;
	}
	pthread_mutex_unlock(&session->lock);

	if (!ret) {
		pthread_mutex_lock(&vsession->session_list_lock);
		cds_list_add_rcu(&session->viewer_session_node,
				&vsession->session_list);
		pthread_mutex_unlock(&vsession->session_list_lock);
	} else {
		session_put(session);
	}
end:
	return ret;
}

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
	pthread_mutex_unlock(&session->lock);

	if (!ret) {
		pthread_mutex_lock(&vsession->session_list_lock);
		cds_list_del_rcu(&session->viewer_session_node);
		pthread_mutex_unlock(&vsession->session_list_lock);
		session_put(session);
	}
	return ret;
}

void viewer_session_destroy(struct relay_viewer_session *vsession)
{
	free(vsession);
}

void viewer_session_close(struct relay_viewer_session *vsession)
{
	struct relay_session *session;

	rcu_read_lock();
	cds_list_for_each_entry_rcu(session,
			&vsession->session_list, viewer_session_node) {
		struct lttng_ht_iter iter;
		struct relay_viewer_stream *vstream;

		/*
		 * TODO: improvement: create more efficient list of
		 * vstream per session.
		 */
		cds_lfht_for_each_entry(viewer_streams_ht->ht, &iter.iter,
				vstream, stream_n.node) {
			if (!viewer_stream_get(vstream)) {
				continue;
			}
			if (vstream->stream->trace->session != session) {
				viewer_stream_put(vstream);
				continue;
			}
			viewer_stream_put(vstream);	/* put local ref */
			viewer_stream_put(vstream);	/* release ownership */
		}

		viewer_session_detach(vsession, session);
	}
	rcu_read_unlock();
}

/*
 * Check if a connection is attached to a session.
 * Return 1 if attached, 0 if not attached, a negative value on error.
 */
int viewer_session_is_attached(struct relay_viewer_session *vsession,
		struct relay_session *session)
{
	struct relay_session *iter;
	int found = 0;

	pthread_mutex_lock(&session->lock);
	if (!vsession) {
		goto end;
	}
	if (!session->viewer_attached) {
		goto end;
	}
	rcu_read_lock();
	cds_list_for_each_entry_rcu(iter,
			&vsession->session_list,
			viewer_session_node) {
		if (session == iter) {
			found = 1;
			goto end;
		}
	}
end:
	pthread_mutex_unlock(&session->lock);
	rcu_read_unlock();
	return found;
}

