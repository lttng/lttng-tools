/*
 * SPDX-FileCopyrightText: 2013 Julien Desfossez <jdesfossez@efficios.com>
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 * SPDX-FileCopyrightText: 2015 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "connection.hpp"
#include "stream.hpp"
#include "viewer-session.hpp"

#include <common/common.hpp>
#include <common/urcu.hpp>

#include <urcu/rculist.h>

bool connection_get(struct relay_connection *conn)
{
	return urcu_ref_get_unless_zero(&conn->ref);
}

struct relay_connection *connection_get_by_sock(struct lttng_ht *relay_connections_ht, int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct relay_connection *conn = nullptr;

	LTTNG_ASSERT(sock >= 0);

	const lttng::urcu::read_lock_guard read_lock;
	lttng_ht_lookup(relay_connections_ht, (void *) ((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_ulong>(&iter);
	if (!node) {
		DBG2("Relay connection by sock %d not found", sock);
		goto end;
	}
	conn = lttng::utils::container_of(node, &relay_connection::sock_n);
	if (!connection_get(conn)) {
		conn = nullptr;
	}
end:
	return conn;
}

int connection_reset_protocol_state(struct relay_connection *connection)
{
	int ret = 0;

	switch (connection->type) {
	case RELAY_DATA:
		connection->protocol.data.state_id = DATA_CONNECTION_STATE_RECEIVE_HEADER;
		memset(&connection->protocol.data.state.receive_header,
		       0,
		       sizeof(connection->protocol.data.state.receive_header));
		connection->protocol.data.state.receive_header.left_to_receive =
			sizeof(struct lttcomm_relayd_data_hdr);
		break;
	case RELAY_CONTROL:
		connection->protocol.ctrl.state_id = CTRL_CONNECTION_STATE_RECEIVE_HEADER;
		memset(&connection->protocol.ctrl.state.receive_header,
		       0,
		       sizeof(connection->protocol.ctrl.state.receive_header));
		connection->protocol.data.state.receive_header.left_to_receive =
			sizeof(struct lttcomm_relayd_hdr);
		ret = lttng_dynamic_buffer_set_size(&connection->protocol.ctrl.reception_buffer,
						    sizeof(struct lttcomm_relayd_hdr));
		if (ret) {
			ERR("Failed to reinitialize control connection reception buffer size to %zu bytes.",
			    sizeof(struct lttcomm_relayd_hdr));
			goto end;
		}
		break;
	default:
		goto end;
	}
	DBG("Reset communication state of relay connection (fd = %i)", connection->sock->fd);
end:
	return ret;
}

struct relay_connection *connection_create(struct lttcomm_sock *sock, enum connection_type type)
{
	struct relay_connection *conn;

	conn = zmalloc<relay_connection>();
	if (!conn) {
		PERROR("zmalloc relay connection");
		goto end;
	}
	urcu_ref_init(&conn->ref);
	conn->type = type;
	conn->sock = sock;
	lttng_ht_node_init_ulong(&conn->sock_n, (unsigned long) conn->sock->fd);
	if (conn->type == RELAY_CONTROL) {
		lttng_dynamic_buffer_init(&conn->protocol.ctrl.reception_buffer);
	}
	connection_reset_protocol_state(conn);
end:
	return conn;
}

static void rcu_free_connection(struct rcu_head *head)
{
	struct relay_connection *conn =
		lttng::utils::container_of(head, &relay_connection::rcu_node);

	lttcomm_destroy_sock(conn->sock);
	if (conn->viewer_session) {
		viewer_session_destroy(conn->viewer_session);
		conn->viewer_session = nullptr;
	}
	if (conn->type == RELAY_CONTROL) {
		lttng_dynamic_buffer_reset(&conn->protocol.ctrl.reception_buffer);
	}
	free(conn);
}

static void destroy_connection(struct relay_connection *conn)
{
	call_rcu(&conn->rcu_node, rcu_free_connection);
}

static void connection_release(struct urcu_ref *ref)
{
	struct relay_connection *conn = lttng::utils::container_of(ref, &relay_connection::ref);

	if (conn->in_socket_ht) {
		struct lttng_ht_iter iter;
		int ret;

		iter.iter.node = &conn->sock_n.node;
		ret = lttng_ht_del(conn->socket_ht, &iter);
		LTTNG_ASSERT(!ret);
	}

	if (conn->session) {
		if (session_close(conn->session)) {
			ERR("session_close");
		}
		conn->session = nullptr;
	}
	if (conn->viewer_session) {
		viewer_session_close(conn->viewer_session);
	}
	destroy_connection(conn);
}

void connection_put(struct relay_connection *conn)
{
	const lttng::urcu::read_lock_guard read_lock;
	urcu_ref_put(&conn->ref, connection_release);
}

void connection_ht_add(struct lttng_ht *relay_connections_ht, struct relay_connection *conn)
{
	LTTNG_ASSERT(!conn->in_socket_ht);
	lttng_ht_add_unique_ulong(relay_connections_ht, &conn->sock_n);
	conn->in_socket_ht = true;
	conn->socket_ht = relay_connections_ht;
}

int connection_set_session(struct relay_connection *conn, struct relay_session *session)
{
	int ret = 0;

	LTTNG_ASSERT(conn);
	LTTNG_ASSERT(session);
	LTTNG_ASSERT(!conn->session);

	if (connection_get(conn)) {
		if (session_get(session)) {
			conn->session = session;
		} else {
			ERR("Failed to get session reference in connection_set_session()");
			ret = -1;
		}
		connection_put(conn);
	} else {
		ERR("Failed to get connection reference in connection_set_session()");
		ret = -1;
	}
	return ret;
}
