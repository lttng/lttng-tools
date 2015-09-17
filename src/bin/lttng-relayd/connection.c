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

#define _LGPL_SOURCE
#include <common/common.h>
#include <urcu/rculist.h>

#include "connection.h"
#include "stream.h"
#include "viewer-session.h"

bool connection_get(struct relay_connection *conn)
{
	return urcu_ref_get_unless_zero(&conn->ref);
}

struct relay_connection *connection_get_by_sock(struct lttng_ht *relay_connections_ht,
		int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct relay_connection *conn = NULL;

	assert(sock >= 0);

	rcu_read_lock();
	lttng_ht_lookup(relay_connections_ht, (void *)((unsigned long) sock),
			&iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (!node) {
		DBG2("Relay connection by sock %d not found", sock);
		goto end;
	}
	conn = caa_container_of(node, struct relay_connection, sock_n);
	if (!connection_get(conn)) {
		conn = NULL;
	}
end:
	rcu_read_unlock();
	return conn;
}

struct relay_connection *connection_create(struct lttcomm_sock *sock,
		enum connection_type type)
{
	struct relay_connection *conn;

	conn = zmalloc(sizeof(*conn));
	if (!conn) {
		PERROR("zmalloc relay connection");
		goto end;
	}
	urcu_ref_init(&conn->ref);
	conn->type = type;
	conn->sock = sock;
	lttng_ht_node_init_ulong(&conn->sock_n, (unsigned long) conn->sock->fd);
end:
	return conn;
}

static void rcu_free_connection(struct rcu_head *head)
{
	struct relay_connection *conn =
		caa_container_of(head, struct relay_connection, rcu_node);

	lttcomm_destroy_sock(conn->sock);
	if (conn->viewer_session) {
		viewer_session_destroy(conn->viewer_session);
		conn->viewer_session = NULL;
	}
	free(conn);
}

static void destroy_connection(struct relay_connection *conn)
{
	call_rcu(&conn->rcu_node, rcu_free_connection);
}

static void connection_release(struct urcu_ref *ref)
{
	struct relay_connection *conn =
		caa_container_of(ref, struct relay_connection, ref);

	if (conn->in_socket_ht) {
		struct lttng_ht_iter iter;
		int ret;

		iter.iter.node = &conn->sock_n.node;
		ret = lttng_ht_del(conn->socket_ht, &iter);
		assert(!ret);
	}

	if (conn->session) {
		if (session_close(conn->session)) {
			ERR("session_close");
		}
		conn->session = NULL;
	}
	if (conn->viewer_session) {
		viewer_session_close(conn->viewer_session);
	}
	destroy_connection(conn);
}

void connection_put(struct relay_connection *conn)
{
	rcu_read_lock();
	urcu_ref_put(&conn->ref, connection_release);
	rcu_read_unlock();
}

void connection_ht_add(struct lttng_ht *relay_connections_ht,
		struct relay_connection *conn)
{
	assert(!conn->in_socket_ht);
	lttng_ht_add_unique_ulong(relay_connections_ht, &conn->sock_n);
	conn->in_socket_ht = 1;
	conn->socket_ht = relay_connections_ht;
}
