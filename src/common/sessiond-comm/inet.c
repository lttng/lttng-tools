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
#include <fcntl.h>

#include <common/common.h>

#include "inet.h"

/*
 * INET protocol operations.
 */
static const struct lttcomm_proto_ops inet_ops = {
	.bind = lttcomm_bind_inet_sock,
	.close = lttcomm_close_inet_sock,
	.connect = lttcomm_connect_inet_sock,
	.accept = lttcomm_accept_inet_sock,
	.listen = lttcomm_listen_inet_sock,
	.recvmsg = lttcomm_recvmsg_inet_sock,
	.sendmsg = lttcomm_sendmsg_inet_sock,
};

unsigned long lttcomm_inet_tcp_timeout;

/*
 * Creates an PF_INET socket.
 */
LTTNG_HIDDEN
int lttcomm_create_inet_sock(struct lttcomm_sock *sock, int type, int proto)
{
	int val = 1, ret;

	/* Create server socket */
	if ((sock->fd = socket(PF_INET, type, proto)) < 0) {
		PERROR("socket inet");
		goto error;
	}

	sock->ops = &inet_ops;

	/*
	 * Set socket option to reuse the address.
	 */
	ret = setsockopt(sock->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int));
	if (ret < 0) {
		PERROR("setsockopt inet");
		goto error;
	}

	return 0;

error:
	return -1;
}

/*
 * Bind socket and return.
 */
LTTNG_HIDDEN
int lttcomm_bind_inet_sock(struct lttcomm_sock *sock)
{
	int ret;

	ret = bind(sock->fd, &sock->sockaddr.addr.sin,
			sizeof(sock->sockaddr.addr.sin));
	if (ret < 0) {
		PERROR("bind inet");
	}

	return ret;
}

/*
 * Connect PF_INET socket.
 */
LTTNG_HIDDEN
int lttcomm_connect_inet_sock(struct lttcomm_sock *sock)
{
	int ret, closeret;

	ret = connect(sock->fd, (struct sockaddr *) &sock->sockaddr.addr.sin,
			sizeof(sock->sockaddr.addr.sin));
	if (ret < 0) {
		PERROR("connect");
		goto error_connect;
	}

	return ret;

error_connect:
	closeret = close(sock->fd);
	if (closeret) {
		PERROR("close inet");
	}

	return ret;
}

/*
 * Do an accept(2) on the sock and return the new lttcomm socket. The socket
 * MUST be bind(2) before.
 */
LTTNG_HIDDEN
struct lttcomm_sock *lttcomm_accept_inet_sock(struct lttcomm_sock *sock)
{
	int new_fd;
	socklen_t len;
	struct lttcomm_sock *new_sock;

	if (sock->proto == LTTCOMM_SOCK_UDP) {
		/*
		 * accept(2) does not exist for UDP so simply return the passed socket.
		 */
		new_sock = sock;
		goto end;
	}

	new_sock = lttcomm_alloc_sock(sock->proto);
	if (new_sock == NULL) {
		goto error;
	}

	len = sizeof(new_sock->sockaddr.addr.sin);

	/* Blocking call */
	new_fd = accept(sock->fd, (struct sockaddr *) &new_sock->sockaddr.addr.sin,
			&len);
	if (new_fd < 0) {
		PERROR("accept inet");
		goto error;
	}

	new_sock->fd = new_fd;
	new_sock->ops = &inet_ops;

end:
	return new_sock;

error:
	free(new_sock);
	return NULL;
}

/*
 * Make the socket listen using LTTNG_SESSIOND_COMM_MAX_LISTEN.
 */
LTTNG_HIDDEN
int lttcomm_listen_inet_sock(struct lttcomm_sock *sock, int backlog)
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
		PERROR("listen inet");
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
LTTNG_HIDDEN
ssize_t lttcomm_recvmsg_inet_sock(struct lttcomm_sock *sock, void *buf,
		size_t len, int flags)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;
	size_t len_last;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	msg.msg_name = (struct sockaddr *) &sock->sockaddr.addr.sin;
	msg.msg_namelen = sizeof(sock->sockaddr.addr.sin);

	do {
		len_last = iov[0].iov_len;
		ret = recvmsg(sock->fd, &msg, flags);
		if (ret > 0) {
			iov[0].iov_base += ret;
			iov[0].iov_len -= ret;
			assert(ret <= len_last);
		}
	} while ((ret > 0 && ret < len_last) || (ret < 0 && errno == EINTR));
	if (ret < 0) {
		PERROR("recvmsg inet");
	} else if (ret > 0) {
		ret = len;
	}
	/* Else ret = 0 meaning an orderly shutdown. */

	return ret;
}

/*
 * Send buf data of size len. Using sendmsg API.
 *
 * Return the size of sent data.
 */
LTTNG_HIDDEN
ssize_t lttcomm_sendmsg_inet_sock(struct lttcomm_sock *sock, void *buf,
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
		msg.msg_name = (struct sockaddr *) &sock->sockaddr.addr.sin;
		msg.msg_namelen = sizeof(sock->sockaddr.addr.sin);
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
			PERROR("sendmsg inet");
		}
	}

	return ret;
}

/*
 * Shutdown cleanly and close.
 */
LTTNG_HIDDEN
int lttcomm_close_inet_sock(struct lttcomm_sock *sock)
{
	int ret;

	/* Don't try to close an invalid marked socket */
	if (sock->fd == -1) {
		return 0;
	}

	ret = close(sock->fd);
	if (ret) {
		PERROR("close inet");
	}

	/* Mark socket */
	sock->fd = -1;

	return ret;
}

/*
 * Return value read from /proc or else 0 if value is not found.
 */
static unsigned long read_proc_value(const char *path)
{
	int ret, fd;
	long r_val;
	unsigned long val = 0;
	char buf[64];

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		goto error;
	}

	ret = read(fd, buf, sizeof(buf));
	if (ret < 0) {
		PERROR("read proc failed");
		goto error_close;
	}

	errno = 0;
	r_val = strtol(buf, NULL, 10);
	if (errno != 0 || r_val < -1L) {
		val = 0;
		goto error_close;
	} else {
		if (r_val > 0) {
			val = r_val;
		}
	}

error_close:
	ret = close(fd);
	if (ret) {
		PERROR("close /proc value");
	}
error:
	return val;
}

LTTNG_HIDDEN
void lttcomm_inet_init(void)
{
	unsigned long syn_retries, fin_timeout, syn_timeout;

	/* Assign default value and see if we can change it. */
	lttcomm_inet_tcp_timeout = DEFAULT_INET_TCP_TIMEOUT;

	syn_retries = read_proc_value(LTTCOMM_INET_PROC_SYN_RETRIES_PATH);
	fin_timeout = read_proc_value(LTTCOMM_INET_PROC_FIN_TIMEOUT_PATH);

	syn_timeout = syn_retries * LTTCOMM_INET_SYN_TIMEOUT_FACTOR;

	/*
	 * Get the maximum between the two possible timeout value and use that to
	 * get the maximum with the default timeout.
	 */
	lttcomm_inet_tcp_timeout = max_t(unsigned long,
			max_t(unsigned long, syn_timeout, fin_timeout),
			lttcomm_inet_tcp_timeout);

	DBG("TCP inet operation timeout set to %lu sec", lttcomm_inet_tcp_timeout);
}
