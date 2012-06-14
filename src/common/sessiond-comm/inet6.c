/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <common/defaults.h>
#include <common/error.h>

#include "inet6.h"

/*
 * INET protocol operations.
 */
static const struct lttcomm_proto_ops inet6_ops = {
	.bind = lttcomm_bind_inet6_sock,
	.close = lttcomm_close_inet6_sock,
	.connect = lttcomm_connect_inet6_sock,
	.accept = lttcomm_accept_inet6_sock,
	.listen = lttcomm_listen_inet6_sock,
	.recvmsg = lttcomm_recvmsg_inet6_sock,
	.sendmsg = lttcomm_sendmsg_inet6_sock,
};

/*
 * Creates an PF_INET socket.
 */
int lttcomm_create_inet6_sock(struct lttcomm_sock *sock, int type, int proto)
{
	int val, ret;

	/* Create server socket */
	if ((sock->fd = socket(PF_INET, type, proto)) < 0) {
		PERROR("socket inet6");
		goto error;
	}

	sock->ops = &inet6_ops;

	/*
	 * Set socket option to reuse the address.
	 */
	ret = setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int));
	if (ret < 0) {
		PERROR("setsockopt inet6");
		goto error;
	}

	return 0;

error:
	return -1;
}

/*
 * Bind socket and return.
 */
int lttcomm_bind_inet6_sock(struct lttcomm_sock *sock)
{
	int ret;

	ret = bind(sock->fd, &sock->sockaddr.addr.sin6,
			sizeof(sock->sockaddr.addr.sin6));
	if (ret < 0) {
		PERROR("bind inet6");
	}

	return ret;
}

/*
 * Connect PF_INET socket.
 */
int lttcomm_connect_inet6_sock(struct lttcomm_sock *sock)
{
	int ret, closeret;

	ret = connect(sock->fd, (struct sockaddr *) &sock->sockaddr.addr.sin6,
			sizeof(sock->sockaddr.addr.sin6));
	if (ret < 0) {
		/*
		 * Don't print message on connect error, because connect is used in
		 * normal execution to detect if sessiond is alive.
		 */
		goto error_connect;
	}

	return ret;

error_connect:
	closeret = close(sock->fd);
	if (closeret) {
		PERROR("close inet6");
	}

	return ret;
}

/*
 * Do an accept(2) on the sock and return the new lttcomm socket. The socket
 * MUST be bind(2) before.
 */
struct lttcomm_sock *lttcomm_accept_inet6_sock(struct lttcomm_sock *sock)
{
	int new_fd;
	socklen_t len = 0;
	struct lttcomm_sock *new_sock;

	if (sock->proto == LTTCOMM_SOCK_UDP) {
		/*
		 * accept(2) does not exist for UDP so simply return the passed socket.
		 */
		new_sock = sock;
		goto end;
	}

	new_sock = lttcomm_alloc_sock(LTTCOMM_INET, sock->proto);
	if (new_sock == NULL) {
		goto error;
	}

	/* Blocking call */
	new_fd = accept(sock->fd,
			(struct sockaddr *) &new_sock->sockaddr.addr.sin6, &len);
	if (new_fd < 0) {
		PERROR("accept inet6");
		goto error;
	}

	new_sock->fd = new_fd;

end:
	return new_sock;

error:
	free(new_sock);
	return NULL;
}

/*
 * Make the socket listen using LTTNG_SESSIOND_COMM_MAX_LISTEN.
 */
int lttcomm_listen_inet6_sock(struct lttcomm_sock *sock, int backlog)
{
	int ret;

	if (sock->proto == LTTCOMM_SOCK_UDP) {
		/* listen(2) does not exist for UDP so simply return success. */
		ret = 0;
		goto end;
	}

	/* Default listen backlog */
	if (backlog <= 0) {
		backlog = LTTNG_SESSIOND_COMM_MAX_LISTEN;
	}

	ret = listen(sock->fd, backlog);
	if (ret < 0) {
		PERROR("listen inet6");
	}

end:
	return ret;
}

/*
 * Receive data of size len in put that data into the buf param. Using recvmsg
 * API.
 *
 * Return the size of received data.
 */
ssize_t lttcomm_recvmsg_inet6_sock(struct lttcomm_sock *sock, void *buf,
		size_t len, int flags)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	msg.msg_name = (struct sockaddr *) &sock->sockaddr.addr.sin6;
	msg.msg_namelen = sizeof(sock->sockaddr.addr.sin6);

	if (flags == 0) {
		flags = MSG_WAITALL;
	}

	do {
		ret = recvmsg(sock->fd, &msg, flags);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		PERROR("recvmsg inet6");
	}

	return ret;
}

/*
 * Send buf data of size len. Using sendmsg API.
 *
 * Return the size of sent data.
 */
ssize_t lttcomm_sendmsg_inet6_sock(struct lttcomm_sock *sock, void *buf,
		size_t len, int flags)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	switch (sock->proto) {
	case LTTCOMM_SOCK_UDP:
		msg.msg_name = (struct sockaddr *) &sock->sockaddr.addr.sin6;
		msg.msg_namelen = sizeof(sock->sockaddr.addr.sin6);
		break;
	default:
		break;
	}

	do {
		ret = sendmsg(sock->fd, &msg, flags);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		/*
		 * Only warn about EPIPE when quiet mode is deactivated.
		 * We consider EPIPE as expected.
		 */
		if (errno != EPIPE || !lttng_opt_quiet) {
			PERROR("sendmsg inet6");
		}
	}

	return ret;
}

/*
 * Shutdown cleanly and close.
 */
int lttcomm_close_inet6_sock(struct lttcomm_sock *sock)
{
	int ret, closeret;

	/* Don't try to close an invalid mark socket */
	if (sock->fd == -1) {
		return 0;
	}

	closeret = close(sock->fd);
	if (closeret) {
		PERROR("close inet6");
	}

	/* Mark socket */
	sock->fd = -1;

	return ret;
}
