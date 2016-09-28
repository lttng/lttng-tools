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

#define _LGPL_SOURCE
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
#include <common/compat/time.h>
#include <poll.h>

#include <common/common.h>
#include <common/time.h>

#include "inet6.h"

#define RECONNECT_DELAY	200	/* ms */

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
LTTNG_HIDDEN
int lttcomm_create_inet6_sock(struct lttcomm_sock *sock, int type, int proto)
{
	int val = 1, ret;
	unsigned long timeout;

	/* Create server socket */
	if ((sock->fd = socket(PF_INET6, type, proto)) < 0) {
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
	timeout = lttcomm_get_network_timeout();
	if (timeout) {
		ret = lttcomm_setsockopt_rcv_timeout(sock->fd, timeout);
		if (ret) {
			goto error;
		}
		ret = lttcomm_setsockopt_snd_timeout(sock->fd, timeout);
		if (ret) {
			goto error;
		}
	}

	return 0;

error:
	return -1;
}

/*
 * Bind socket and return.
 */
LTTNG_HIDDEN
int lttcomm_bind_inet6_sock(struct lttcomm_sock *sock)
{
	int ret;

	ret = bind(sock->fd, (const struct sockaddr *) &sock->sockaddr.addr.sin6,
			sizeof(sock->sockaddr.addr.sin6));
	if (ret < 0) {
		PERROR("bind inet6");
	}

	return ret;
}

static
int connect_no_timeout(struct lttcomm_sock *sock)
{
	return connect(sock->fd, (struct sockaddr *) &sock->sockaddr.addr.sin6,
			sizeof(sock->sockaddr.addr.sin6));
}

/*
 * Return time_a - time_b  in milliseconds.
 */
static
unsigned long time_diff_ms(struct timespec *time_a,
		struct timespec *time_b)
{
	time_t sec_diff;
	long nsec_diff;
	unsigned long result_ms;

	sec_diff = time_a->tv_sec - time_b->tv_sec;
	nsec_diff = time_a->tv_nsec - time_b->tv_nsec;

	result_ms = sec_diff * MSEC_PER_SEC;
	result_ms += nsec_diff / NSEC_PER_MSEC;
	return result_ms;
}

static
int connect_with_timeout(struct lttcomm_sock *sock)
{
	unsigned long timeout = lttcomm_get_network_timeout();
	int ret, flags, connect_ret;
	struct timespec orig_time, cur_time;

	ret = fcntl(sock->fd, F_GETFL, 0);
	if (ret == -1) {
		PERROR("fcntl");
		return -1;
	}
	flags = ret;

	/* Set socket to nonblock */
	ret = fcntl(sock->fd, F_SETFL, flags | O_NONBLOCK);
	if (ret == -1) {
		PERROR("fcntl");
		return -1;
	}

	ret = lttng_clock_gettime(CLOCK_MONOTONIC, &orig_time);
	if (ret == -1) {
		PERROR("clock_gettime");
		return -1;
	}

	connect_ret = connect(sock->fd,
		(struct sockaddr *) &sock->sockaddr.addr.sin6,
		sizeof(sock->sockaddr.addr.sin6));
	if (connect_ret == -1 && errno != EAGAIN
			&& errno != EWOULDBLOCK
			&& errno != EINPROGRESS) {
		goto error;
	} else if (!connect_ret) {
		/* Connect succeeded */
		goto success;
	}

	/*
	 * Perform poll loop following EINPROGRESS recommendation from
	 * connect(2) man page.
	 */
	do {
		struct pollfd fds;

		fds.fd = sock->fd;
		fds.events = POLLOUT;
		fds.revents = 0;
		ret = poll(&fds, 1, RECONNECT_DELAY);
		if (ret < 0) {
			goto error;
		} else if (ret > 0) {
			int optval;
			socklen_t optval_len = sizeof(optval);

			if (!(fds.revents & POLLOUT)) {
				/* Either hup or error */
				errno = EPIPE;
				goto error;
			}
			/* got something */
			ret = getsockopt(sock->fd, SOL_SOCKET,
				SO_ERROR, &optval, &optval_len);
			if (ret) {
				goto error;
			}
			if (!optval) {
				connect_ret = 0;
				goto success;
			} else {
				goto error;
			}
		}
		/* ret == 0: timeout */
		ret = lttng_clock_gettime(CLOCK_MONOTONIC, &cur_time);
		if (ret == -1) {
			PERROR("clock_gettime");
			connect_ret = ret;
			goto error;
		}
	} while (time_diff_ms(&cur_time, &orig_time) < timeout);

	/* Timeout */
	errno = ETIMEDOUT;
	connect_ret = -1;

success:
	/* Restore initial flags */
	ret = fcntl(sock->fd, F_SETFL, flags);
	if (ret == -1) {
		PERROR("fcntl");
		/* Continue anyway */
	}
error:
	return connect_ret;
}

/*
 * Connect PF_INET socket.
 */
LTTNG_HIDDEN
int lttcomm_connect_inet6_sock(struct lttcomm_sock *sock)
{
	int ret, closeret;

	if (lttcomm_get_network_timeout()) {
		ret = connect_with_timeout(sock);
	} else {
		ret = connect_no_timeout(sock);
	}
	if (ret < 0) {
		PERROR("connect inet6");
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
LTTNG_HIDDEN
struct lttcomm_sock *lttcomm_accept_inet6_sock(struct lttcomm_sock *sock)
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

	len = sizeof(new_sock->sockaddr.addr.sin6);

	/* Blocking call */
	new_fd = accept(sock->fd,
			(struct sockaddr *) &new_sock->sockaddr.addr.sin6, &len);
	if (new_fd < 0) {
		PERROR("accept inet6");
		goto error;
	}

	new_sock->fd = new_fd;
	new_sock->ops = &inet6_ops;

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
LTTNG_HIDDEN
ssize_t lttcomm_recvmsg_inet6_sock(struct lttcomm_sock *sock, void *buf,
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

	msg.msg_name = (struct sockaddr *) &sock->sockaddr.addr.sin6;
	msg.msg_namelen = sizeof(sock->sockaddr.addr.sin6);

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
ssize_t lttcomm_sendmsg_inet6_sock(struct lttcomm_sock *sock, const void *buf,
		size_t len, int flags)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (void *) buf;
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
LTTNG_HIDDEN
int lttcomm_close_inet6_sock(struct lttcomm_sock *sock)
{
	int ret;

	/* Don't try to close an invalid marked socket */
	if (sock->fd == -1) {
		return 0;
	}

	ret = close(sock->fd);
	if (ret) {
		PERROR("close inet6");
	}

	/* Mark socket */
	sock->fd = -1;

	return ret;
}
