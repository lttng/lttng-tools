/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
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

#ifndef _CONNECTION_H
#define _CONNECTION_H

#include <limits.h>
#include <inttypes.h>
#include <pthread.h>
#include <urcu.h>
#include <urcu/wfcqueue.h>
#include <urcu/list.h>

#include <common/hashtable/hashtable.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "session.h"

enum connection_type {
	RELAY_DATA                  = 1,
	RELAY_CONTROL               = 2,
	RELAY_VIEWER_COMMAND        = 3,
	RELAY_VIEWER_NOTIFICATION   = 4,
};

/*
 * Internal structure to map a socket with the corresponding session.
 * A hashtable indexed on the socket FD is used for the lookups.
 */
struct relay_connection {
	struct lttcomm_sock *sock;
	struct relay_session *session;
	struct relay_viewer_session *viewer_session;
	struct cds_wfcq_node qnode;
	struct lttng_ht_node_ulong sock_n;
	struct rcu_head rcu_node;
	enum connection_type type;
	/* Protocol version to use for this connection. */
	uint32_t major;
	uint32_t minor;
	uint64_t session_id;

	/*
	 * This contains streams that are received on that connection. It's used to
	 * store them until we get the streams sent command where they are removed
	 * and flagged ready for the viewer. This is ONLY used by the control
	 * thread thus any action on it should happen in that thread.
	 */
	struct cds_list_head recv_head;
	unsigned int version_check_done:1;

	/* Pointer to the sessions HT that this connection can use. */
	struct lttng_ht *sessions_ht;
};

struct relay_connection *connection_find_by_sock(struct lttng_ht *ht,
		int sock);
struct relay_connection *connection_create(void);
void connection_init(struct relay_connection *conn);
void connection_delete(struct lttng_ht *ht, struct relay_connection *conn);
void connection_destroy(struct relay_connection *conn);
void connection_free(struct relay_connection *conn);

#endif /* _CONNECTION_H */
