#ifndef _CONNECTION_H
#define _CONNECTION_H

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
	RELAY_CONNECTION_UNKNOWN    = 0,
	RELAY_DATA                  = 1,
	RELAY_CONTROL               = 2,
	RELAY_VIEWER_COMMAND        = 3,
	RELAY_VIEWER_NOTIFICATION   = 4,
};

/*
 * Internal structure to map a socket with the corresponding session.
 * A hashtable indexed on the socket FD is used for the lookups.
 *
 * Connections are assumed to be accessed from a single thread. Live
 * connections between the relay and a live client are only accessed
 * from the live worker thread.
 *
 * The connections between the consumerd/sessiond and the relayd are only
 * handled by the "main" worker thread (as in, the worker thread in main.c).
 *
 * This is why there are no back references to connections from the
 * sessions and session list.
 */
struct relay_connection {
	struct lttcomm_sock *sock;
	struct cds_wfcq_node qnode;

	enum connection_type type;
	/*
	 * session is only ever set for RELAY_CONTROL connection type.
	 */
	struct relay_session *session;
	/*
	 * viewer_session is only ever set for RELAY_VIEWER_COMMAND
	 * connection type.
	 */
	struct relay_viewer_session *viewer_session;

	/*
	 * Protocol version to use for this connection. Only valid for
	 * RELAY_CONTROL connection type.
	 */
	uint32_t major;
	uint32_t minor;

	struct urcu_ref ref;

	bool version_check_done;

	/*
	 * Node member of connection within global socket hash table.
	 */
	struct lttng_ht_node_ulong sock_n;
	bool in_socket_ht;
	struct lttng_ht *socket_ht;	/* HACK: Contained within this hash table. */
	struct rcu_head rcu_node;	/* For call_rcu teardown. */
};

struct relay_connection *connection_create(struct lttcomm_sock *sock,
		enum connection_type type);
struct relay_connection *connection_get_by_sock(struct lttng_ht *relay_connections_ht,
		int sock);
bool connection_get(struct relay_connection *connection);
void connection_put(struct relay_connection *connection);
void connection_ht_add(struct lttng_ht *relay_connections_ht,
		struct relay_connection *conn);

#endif /* _CONNECTION_H */
