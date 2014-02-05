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

#define _GNU_SOURCE
#include <common/common.h>

#include "connection.h"
#include "stream.h"

static void rcu_free_connection(struct rcu_head *head)
{
	struct relay_connection *conn =
		caa_container_of(head, struct relay_connection, rcu_node);

	lttcomm_destroy_sock(conn->sock);
	connection_free(conn);
}

struct relay_connection *connection_find_by_sock(struct lttng_ht *ht, int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct relay_connection *conn = NULL;

	assert(ht);
	assert(sock >= 0);

	lttng_ht_lookup(ht, (void *)((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (!node) {
		DBG2("Relay connection by sock %d not found", sock);
		goto end;
	}
	conn = caa_container_of(node, struct relay_connection, sock_n);

end:
	return conn;
}

void connection_delete(struct lttng_ht *ht, struct relay_connection *conn)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(ht);
	assert(conn);

	iter.iter.node = &conn->sock_n.node;
	ret = lttng_ht_del(ht, &iter);
	assert(!ret);
}

void connection_destroy(struct relay_connection *conn)
{
	struct relay_stream *stream, *tmp_stream;

	assert(conn);

	/* Clean up recv list of this connection if any. */
	cds_list_for_each_entry_safe(stream, tmp_stream, &conn->recv_head,
			recv_list) {
		cds_list_del(&stream->recv_list);
	}

	call_rcu(&conn->rcu_node, rcu_free_connection);
}

struct relay_connection *connection_create(void)
{
	struct relay_connection *conn;

	conn = zmalloc(sizeof(*conn));
	if (!conn) {
		PERROR("zmalloc relay connection");
		goto error;
	}

error:
	return conn;
}

void connection_init(struct relay_connection *conn)
{
	assert(conn);
	assert(conn->sock);

	CDS_INIT_LIST_HEAD(&conn->recv_head);
	lttng_ht_node_init_ulong(&conn->sock_n, (unsigned long) conn->sock->fd);
}

void connection_free(struct relay_connection *conn)
{
	assert(conn);

	free(conn->viewer_session);
	free(conn);
}
