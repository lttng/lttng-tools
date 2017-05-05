/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>

#include "unix.h"

/*
 * Connect to unix socket using the path name.
 */
LTTNG_HIDDEN
int lttcomm_connect_unix_sock(const char *pathname)
{
	struct sockaddr_un s_un;
	int fd, ret, closeret;

	if (strlen(pathname) >= sizeof(s_un.sun_path)) {
		ERR("unix socket address (\"%s\") is longer than the platform's limit (%zu > %zu).",
				pathname, strlen(pathname) + 1,
				sizeof(s_un.sun_path));
		ret = -ENAMETOOLONG;
		goto error;
	}

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		PERROR("socket");
		ret = fd;
		goto error;
	}

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strncpy(s_un.sun_path, pathname, sizeof(s_un.sun_path));
	s_un.sun_path[sizeof(s_un.sun_path) - 1] = '\0';

	ret = connect(fd, (struct sockaddr *) &s_un, sizeof(s_un));
	if (ret < 0) {
		/*
		 * Don't print message on connect error, because connect is used in
		 * normal execution to detect if sessiond is alive.
		 */
		goto error_connect;
	}

	return fd;

error_connect:
	closeret = close(fd);
	if (closeret) {
		PERROR("close");
	}
error:
	return ret;
}

/*
 * Do an accept(2) on the sock and return the new file descriptor. The socket
 * MUST be bind(2) before.
 */
LTTNG_HIDDEN
int lttcomm_accept_unix_sock(int sock)
{
	int new_fd;
	struct sockaddr_un s_un;
	socklen_t len = sizeof(s_un);

	/* Blocking call */
	new_fd = accept(sock, (struct sockaddr *) &s_un, &len);
	if (new_fd < 0) {
		PERROR("accept");
	}

	return new_fd;
}

LTTNG_HIDDEN
int lttcomm_create_anon_unix_socketpair(int *fds)
{
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		PERROR("socketpair");
		return -1;
	}
	return 0;
}

/*
 * Creates a AF_UNIX local socket using pathname bind the socket upon creation
 * and return the fd.
 */
LTTNG_HIDDEN
int lttcomm_create_unix_sock(const char *pathname)
{
	struct sockaddr_un s_un;
	int fd = -1;
	int ret = -1;

	if (strlen(pathname) >= sizeof(s_un.sun_path)) {
		ERR("unix socket address (\"%s\") is longer than the platform's limit (%zu > %zu).",
				pathname, strlen(pathname) + 1,
				sizeof(s_un.sun_path));
		ret = -ENAMETOOLONG;
		goto error;
	}

	/* Create server socket */
	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		PERROR("socket");
		goto error;
	}

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strncpy(s_un.sun_path, pathname, sizeof(s_un.sun_path));
	s_un.sun_path[sizeof(s_un.sun_path) - 1] = '\0';

	/* Unlink the old file if present */
	(void) unlink(pathname);
	ret = bind(fd, (struct sockaddr *) &s_un, sizeof(s_un));
	if (ret < 0) {
		PERROR("bind");
		goto error;
	}

	return fd;

error:
	if (fd >= 0) {
		if (close(fd) < 0) {
			PERROR("close create unix sock");
		}
	}
	return ret;
}

/*
 * Make the socket listen using LTTNG_SESSIOND_COMM_MAX_LISTEN.
 */
LTTNG_HIDDEN
int lttcomm_listen_unix_sock(int sock)
{
	int ret;

	ret = listen(sock, LTTNG_SESSIOND_COMM_MAX_LISTEN);
	if (ret < 0) {
		PERROR("listen");
	}

	return ret;
}

/*
 * Receive data of size len in put that data into the buf param. Using recvmsg
 * API.
 *
 * Return the size of received data.
 */
LTTNG_HIDDEN
ssize_t lttcomm_recv_unix_sock(int sock, void *buf, size_t len)
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

	do {
		len_last = iov[0].iov_len;
		ret = lttng_recvmsg_nosigpipe(sock, &msg);
		if (ret > 0) {
			iov[0].iov_base += ret;
			iov[0].iov_len -= ret;
			assert(ret <= len_last);
		}
	} while ((ret > 0 && ret < len_last) || (ret < 0 && errno == EINTR));
	if (ret < 0) {
		PERROR("recvmsg");
	} else if (ret > 0) {
		ret = len;
	}
	/* Else ret = 0 meaning an orderly shutdown. */

	return ret;
}

/*
 * Receive data of size len in put that data into the buf param. Using recvmsg
 * API. Only use with sockets set in non-blocking mode.
 *
 * Return the size of received data.
 */
LTTNG_HIDDEN
ssize_t lttcomm_recv_unix_sock_non_block(int sock, void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

retry:
	ret = lttng_recvmsg_nosigpipe(sock, &msg);
	if (ret < 0) {
		if (errno == EINTR) {
			goto retry;
		} else {
			/*
			 * Only warn about EPIPE when quiet mode is
			 * deactivated.
			 * We consider EPIPE as expected.
			 */
			if (errno != EPIPE || !lttng_opt_quiet) {
				PERROR("recvmsg");
			}
			goto end;
		}
	}
	ret = len;
end:
	return ret;
}

/*
 * Send buf data of size len. Using sendmsg API.
 *
 * Return the size of sent data.
 */
LTTNG_HIDDEN
ssize_t lttcomm_send_unix_sock(int sock, const void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (void *) buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	while (iov[0].iov_len) {
		ret = sendmsg(sock, &msg, 0);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				/*
				 * Only warn about EPIPE when quiet mode is
				 * deactivated.
				 * We consider EPIPE as expected.
				 */
				if (errno != EPIPE || !lttng_opt_quiet) {
					PERROR("sendmsg");
				}
				goto end;
			}
		}
		iov[0].iov_len -= ret;
		iov[0].iov_base += ret;
	}
	ret = len;
end:
	return ret;
}

/*
 * Send buf data of size len. Using sendmsg API.
 * Only use with non-blocking sockets. The difference with the blocking version
 * of the function is that this one does not retry to send on partial sends,
 * except if the interruption was caused by a signal (EINTR).
 *
 * Return the size of sent data.
 */
LTTNG_HIDDEN
ssize_t lttcomm_send_unix_sock_non_block(int sock, const void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = (void *) buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

retry:
	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		if (errno == EINTR) {
			goto retry;
		} else {
			/*
			 * Only warn about EPIPE when quiet mode is
			 * deactivated.
			 * We consider EPIPE as expected.
			 */
			if (errno != EPIPE || !lttng_opt_quiet) {
				PERROR("sendmsg");
			}
			goto end;
		}
	}
	ret = len;
end:
	return ret;
}

/*
 * Shutdown cleanly a unix socket.
 */
LTTNG_HIDDEN
int lttcomm_close_unix_sock(int sock)
{
	int ret, closeret;

	/* Shutdown receptions and transmissions */
	ret = shutdown(sock, SHUT_RDWR);
	if (ret < 0) {
		PERROR("shutdown");
	}

	closeret = close(sock);
	if (closeret) {
		PERROR("close");
	}

	return ret;
}

/*
 * Send a message accompanied by fd(s) over a unix socket.
 *
 * Returns the size of data sent, or negative error value.
 */
LTTNG_HIDDEN
ssize_t lttcomm_send_fds_unix_sock(int sock, int *fds, size_t nb_fd)
{
	struct msghdr msg;
	struct cmsghdr *cmptr;
	struct iovec iov[1];
	ssize_t ret = -1;
	unsigned int sizeof_fds = nb_fd * sizeof(int);
	char tmp[CMSG_SPACE(sizeof_fds)];
	char dummy = 0;

	memset(&msg, 0, sizeof(msg));
	memset(tmp, 0, CMSG_SPACE(sizeof_fds) * sizeof(char));

	if (nb_fd > LTTCOMM_MAX_SEND_FDS)
		return -EINVAL;

	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof_fds);

	cmptr = CMSG_FIRSTHDR(&msg);
	if (!cmptr) {
		return -1;
	}
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = SCM_RIGHTS;
	cmptr->cmsg_len = CMSG_LEN(sizeof_fds);
	memcpy(CMSG_DATA(cmptr), fds, sizeof_fds);
	/* Sum of the length of all control messages in the buffer: */
	msg.msg_controllen = cmptr->cmsg_len;

	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	do {
		ret = sendmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		/*
		 * Only warn about EPIPE when quiet mode is deactivated.
		 * We consider EPIPE as expected.
		 */
		if (errno != EPIPE || !lttng_opt_quiet) {
			PERROR("sendmsg");
		}
	}
	return ret;
}

/*
 * Recv a message accompanied by fd(s) from a unix socket.
 *
 * Returns the size of received data, or negative error value.
 *
 * Expect at most "nb_fd" file descriptors. Returns the number of fd
 * actually received in nb_fd.
 */
LTTNG_HIDDEN
ssize_t lttcomm_recv_fds_unix_sock(int sock, int *fds, size_t nb_fd)
{
	struct iovec iov[1];
	ssize_t ret = 0;
	struct cmsghdr *cmsg;
	size_t sizeof_fds = nb_fd * sizeof(int);
	char recv_fd[CMSG_SPACE(sizeof_fds)];
	struct msghdr msg;
	char dummy;

	memset(&msg, 0, sizeof(msg));

	/* Prepare to receive the structures */
	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = recv_fd;
	msg.msg_controllen = sizeof(recv_fd);

	do {
		ret = recvmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		PERROR("recvmsg fds");
		goto end;
	}
	if (ret != 1) {
		fprintf(stderr, "Error: Received %zd bytes, expected %d\n",
				ret, 1);
		goto end;
	}
	if (msg.msg_flags & MSG_CTRUNC) {
		fprintf(stderr, "Error: Control message truncated.\n");
		ret = -1;
		goto end;
	}
	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg) {
		fprintf(stderr, "Error: Invalid control message header\n");
		ret = -1;
		goto end;
	}
	if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "Didn't received any fd\n");
		ret = -1;
		goto end;
	}
	if (cmsg->cmsg_len != CMSG_LEN(sizeof_fds)) {
		fprintf(stderr, "Error: Received %zu bytes of ancillary data, expected %zu\n",
				(size_t) cmsg->cmsg_len, (size_t) CMSG_LEN(sizeof_fds));
		ret = -1;
		goto end;
	}
	memcpy(fds, CMSG_DATA(cmsg), sizeof_fds);
	ret = sizeof_fds;
end:
	return ret;
}

/*
 * Send a message with credentials over a unix socket.
 *
 * Returns the size of data sent, or negative error value.
 */
LTTNG_HIDDEN
ssize_t lttcomm_send_creds_unix_sock(int sock, void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;
#ifdef __linux__
	struct cmsghdr *cmptr;
	size_t sizeof_cred = sizeof(lttng_sock_cred);
	char anc_buf[CMSG_SPACE(sizeof_cred)];
	lttng_sock_cred *creds;

	memset(anc_buf, 0, CMSG_SPACE(sizeof_cred) * sizeof(char));
#endif /* __linux__ */

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

#ifdef __linux__
	msg.msg_control = (caddr_t) anc_buf;
	msg.msg_controllen = CMSG_LEN(sizeof_cred);

	cmptr = CMSG_FIRSTHDR(&msg);
	if (!cmptr) {
		return -1;
	}
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = LTTNG_SOCK_CREDS;
	cmptr->cmsg_len = CMSG_LEN(sizeof_cred);

	creds = (lttng_sock_cred*) CMSG_DATA(cmptr);

	LTTNG_SOCK_SET_UID_CRED(creds, geteuid());
	LTTNG_SOCK_SET_GID_CRED(creds, getegid());
	LTTNG_SOCK_SET_PID_CRED(creds, getpid());
#endif /* __linux__ */

	do {
		ret = sendmsg(sock, &msg, 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		/*
		 * Only warn about EPIPE when quiet mode is deactivated.
		 * We consider EPIPE as expected.
		 */
		if (errno != EPIPE || !lttng_opt_quiet) {
			PERROR("sendmsg");
		}
	}
	return ret;
}

/*
 * Recv a message accompanied with credentials from a unix socket.
 *
 * Returns the size of received data, or negative error value.
 */
LTTNG_HIDDEN
ssize_t lttcomm_recv_creds_unix_sock(int sock, void *buf, size_t len,
		lttng_sock_cred *creds)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;
	size_t len_last;
#ifdef __linux__
	struct cmsghdr *cmptr;
	size_t sizeof_cred = sizeof(lttng_sock_cred);
	char anc_buf[CMSG_SPACE(sizeof_cred)];
#endif	/* __linux__ */

	memset(&msg, 0, sizeof(msg));

	/* Not allowed */
	if (creds == NULL) {
		ret = -1;
		goto end;
	}

	/* Prepare to receive the structures */
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

#ifdef __linux__
	msg.msg_control = anc_buf;
	msg.msg_controllen = sizeof(anc_buf);
#endif /* __linux__ */

	do {
		len_last = iov[0].iov_len;
		ret = recvmsg(sock, &msg, 0);
		if (ret > 0) {
			iov[0].iov_base += ret;
			iov[0].iov_len -= ret;
			assert(ret <= len_last);
		}
	} while ((ret > 0 && ret < len_last) || (ret < 0 && errno == EINTR));
	if (ret < 0) {
		PERROR("recvmsg fds");
		goto end;
	} else if (ret > 0) {
		ret = len;
	}
	/* Else ret = 0 meaning an orderly shutdown. */

#ifdef __linux__
	if (msg.msg_flags & MSG_CTRUNC) {
		fprintf(stderr, "Error: Control message truncated.\n");
		ret = -1;
		goto end;
	}

	cmptr = CMSG_FIRSTHDR(&msg);
	if (cmptr == NULL) {
		fprintf(stderr, "Error: Invalid control message header\n");
		ret = -1;
		goto end;
	}

	if (cmptr->cmsg_level != SOL_SOCKET ||
			cmptr->cmsg_type != LTTNG_SOCK_CREDS) {
		fprintf(stderr, "Didn't received any credentials\n");
		ret = -1;
		goto end;
	}

	if (cmptr->cmsg_len != CMSG_LEN(sizeof_cred)) {
		fprintf(stderr, "Error: Received %zu bytes of ancillary data, expected %zu\n",
				(size_t) cmptr->cmsg_len, (size_t) CMSG_LEN(sizeof_cred));
		ret = -1;
		goto end;
	}

	memcpy(creds, CMSG_DATA(cmptr), sizeof_cred);
#elif (defined(__FreeBSD__) || defined(__CYGWIN__) || defined(__sun__) || defined(__APPLE__))
	{
		int peer_ret;

		peer_ret = getpeereid(sock, &creds->uid, &creds->gid);
		if (peer_ret != 0) {
			return peer_ret;
		}
	}
#else
#error "Please implement credential support for your OS."
#endif	/* __linux__ */

end:
	return ret;
}

/*
 * Set socket option to use credentials passing.
 */
#ifdef __linux__
LTTNG_HIDDEN
int lttcomm_setsockopt_creds_unix_sock(int sock)
{
	int ret, on = 1;

	/* Set socket for credentials retrieval */
	ret = setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &on, sizeof(on));
	if (ret < 0) {
		PERROR("setsockopt creds unix sock");
	}
	return ret;
}
#elif (defined(__FreeBSD__) || defined(__CYGWIN__) || defined(__sun__) || defined(__APPLE__))
LTTNG_HIDDEN
int lttcomm_setsockopt_creds_unix_sock(int sock)
{
	return 0;
}
#else
#error "Please implement credential support for your OS."
#endif /* __linux__ */
