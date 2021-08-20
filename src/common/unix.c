/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/common.h>
#include <common/compat/errno.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/fd-handle.h>

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

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(buf);
	LTTNG_ASSERT(len > 0);

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
			LTTNG_ASSERT(ret <= len_last);
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
 * NOTE: EPIPE errors are NOT reported. This call expects the socket to be in a
 * poll set. The poll loop will handle the EPIPE original cause.
 *
 * Return the size of received data.
 */
LTTNG_HIDDEN
ssize_t lttcomm_recv_unix_sock_non_block(int sock, void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(buf);
	LTTNG_ASSERT(len > 0);

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
			 * We consider EPIPE and EAGAIN/EWOULDBLOCK as expected.
			 */
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
					errno == EPIPE) {
				/*
				 * Nothing was recv.
				 */
				ret = 0;
				goto end;
			}

			/* Unexpected error */
			PERROR("recvmsg");
			ret = -1;
			goto end;
		}
	}

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

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(buf);
	LTTNG_ASSERT(len > 0);

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
 * NOTE: EPIPE errors are NOT reported. This call expects the socket to be in a
 * poll set. The poll loop will handle the EPIPE original cause.
 *
 * Return the size of sent data.
 */
LTTNG_HIDDEN
ssize_t lttcomm_send_unix_sock_non_block(int sock, const void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(buf);
	LTTNG_ASSERT(len > 0);

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
			 * We consider EPIPE and EAGAIN/EWOULDBLOCK as expected.
			 */
			if (errno == EAGAIN || errno == EWOULDBLOCK ||
					errno == EPIPE) {
				/*
				 * This can happen in non blocking mode.
				 * Nothing was sent.
				 */
				ret = 0;
				goto end;
			}

			/* Unexpected error */
			PERROR("sendmsg");
			ret = -1;
			goto end;
		}
	}
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
ssize_t lttcomm_send_fds_unix_sock(int sock, const int *fds, size_t nb_fd)
{
	struct msghdr msg;
	struct cmsghdr *cmptr;
	struct iovec iov[1];
	ssize_t ret = -1;
	unsigned int sizeof_fds = nb_fd * sizeof(int);
	char tmp[CMSG_SPACE(sizeof_fds)];
	char dummy = 0;

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(fds);
	LTTNG_ASSERT(nb_fd > 0);

	memset(&msg, 0, sizeof(msg));
	memset(tmp, 0, sizeof(tmp));

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
 * Send the fd(s) of a payload view over a unix socket.
 *
 * Returns the size of data sent, or negative error value.
 */
static
ssize_t _lttcomm_send_payload_view_fds_unix_sock(int sock,
		struct lttng_payload_view *view,
		bool blocking)
{
	int i;
	ssize_t ret;
	struct lttng_dynamic_array raw_fds;
	const int fd_count = lttng_payload_view_get_fd_handle_count(view);

	lttng_dynamic_array_init(&raw_fds, sizeof(int), NULL);

	if (fd_count < 0) {
		ret = -LTTNG_ERR_INVALID;
		goto end;
	}

	/*
	 * Prepare a contiguous array of file descriptors to send them.
	 *
	 * Note that the reference to each fd is released during the iteration;
	 * we're just getting the numerical value of the fds to conform to the
	 * syscall's interface. We rely on the fact that "view" must remain
	 * valid for the duration of the call and that the underlying payload
	 * owns a reference to the fd_handles.
	 */
	for (i = 0; i < fd_count; i++) {
		struct fd_handle *handle =
				lttng_payload_view_pop_fd_handle(view);
		const int raw_fd = fd_handle_get_fd(handle);
		const int add_ret = lttng_dynamic_array_add_element(
				&raw_fds, &raw_fd);

		fd_handle_put(handle);
		if (add_ret) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	if (blocking) {
		ret = lttcomm_send_fds_unix_sock(sock,
				(const int *) raw_fds.buffer.data, fd_count);
	} else {
		ret = lttcomm_send_fds_unix_sock_non_block(sock,
				(const int *) raw_fds.buffer.data, fd_count);
	}

end:
	lttng_dynamic_array_reset(&raw_fds);
	return ret;
}

LTTNG_HIDDEN
ssize_t lttcomm_send_payload_view_fds_unix_sock(int sock,
		struct lttng_payload_view *view)
{
	return _lttcomm_send_payload_view_fds_unix_sock(sock, view, true);
}

LTTNG_HIDDEN
ssize_t lttcomm_send_payload_view_fds_unix_sock_non_block(int sock,
		struct lttng_payload_view *view)
{
	return _lttcomm_send_payload_view_fds_unix_sock(sock, view, false);
}

/*
 * Send a message accompanied by fd(s) over a unix socket.
 * Only use for non blocking socket.
 *
 * Returns the size of data sent, or negative error value.
 */
LTTNG_HIDDEN
ssize_t lttcomm_send_fds_unix_sock_non_block(int sock, const int *fds, size_t nb_fd)
{
	struct msghdr msg;
	struct cmsghdr *cmptr;
	struct iovec iov[1];
	ssize_t ret = -1;
	unsigned int sizeof_fds = nb_fd * sizeof(int);
	char tmp[CMSG_SPACE(sizeof_fds)];
	char dummy = 0;

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(fds);
	LTTNG_ASSERT(nb_fd > 0);

	memset(&msg, 0, sizeof(msg));
	memset(tmp, 0, sizeof(tmp));

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

retry:
	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		if (errno == EINTR) {
			goto retry;
		} else {
			/*
			 * We consider EPIPE and EAGAIN/EWOULDBLOCK as expected.
			 */
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/*
				 * This can happen in non blocking mode.
				 * Nothing was sent.
				 */
				ret = 0;
				goto end;
			}

			if (errno == EPIPE) {
				/* Expected error, pass error to caller */
				DBG3("EPIPE on sendmsg");
				ret = -1;
				goto end;
			}

			/* Unexpected error */
			PERROR("sendmsg");
			ret = -1;
			goto end;
		}
	}

end:
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

#ifdef __linux__
/* Account for the struct ucred cmsg in the buffer size */
#define LTTNG_SOCK_RECV_FDS_BUF_SIZE CMSG_SPACE(sizeof_fds) + CMSG_SPACE(sizeof(struct ucred))
#else
#define LTTNG_SOCK_RECV_FDS_BUF_SIZE CMSG_SPACE(sizeof_fds)
#endif /* __linux__ */

	char recv_buf[LTTNG_SOCK_RECV_FDS_BUF_SIZE];
	struct msghdr msg;
	char dummy;

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(fds);
	LTTNG_ASSERT(nb_fd > 0);

	memset(&msg, 0, sizeof(msg));

	/* Prepare to receive the structures */
	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	cmsg = (struct cmsghdr *) recv_buf;
	cmsg->cmsg_len = CMSG_LEN(sizeof_fds);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	msg.msg_control = cmsg;
	msg.msg_controllen = CMSG_LEN(sizeof(recv_buf));
	msg.msg_flags = 0;

retry:
	ret = lttng_recvmsg_nosigpipe(sock, &msg);
	if (ret < 0) {
		if (errno == EINTR) {
			goto retry;
		} else {
			/* We consider EPIPE and EAGAIN as expected. */
			if (!lttng_opt_quiet &&
					(errno != EPIPE && errno != EAGAIN)) {
				PERROR("recvmsg");
			}
			goto end;
		}
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

	/*
	 * If the socket was configured with SO_PASSCRED, the kernel will add a
	 * control message (cmsg) to the ancillary data of the unix socket. We
	 * need to expect a cmsg of the SCM_CREDENTIALS as the first control
	 * message.
	 */
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET) {
			fprintf(stderr, "Error: The socket needs to be of type SOL_SOCKET\n");
			ret = -1;
			goto end;
		}
		if (cmsg->cmsg_type == SCM_RIGHTS) {
			/*
			 * We found the controle message for file descriptors,
			 * now copy the fds to the fds ptr and return success.
			 */
			if (cmsg->cmsg_len != CMSG_LEN(sizeof_fds)) {
				fprintf(stderr, "Error: Received %zu bytes of"
					"ancillary data for FDs, expected %zu\n",
					(size_t) cmsg->cmsg_len,
					(size_t) CMSG_LEN(sizeof_fds));
				ret = -1;
				goto end;
			}
			memcpy(fds, CMSG_DATA(cmsg), sizeof_fds);
			ret = sizeof_fds;
			goto end;
		}
#ifdef __linux__
		if (cmsg->cmsg_type == SCM_CREDENTIALS) {
			/*
			 * Expect credentials to be sent when expecting fds even
			 * if no credential were include in the send(). The
			 * kernel adds them...
			 */
			ret = -1;
		}
#endif /* __linux__ */
	}
end:
	return ret;
}

static
void close_raw_fd(void *ptr)
{
	const int raw_fd = *((const int *) ptr);

	if (raw_fd >= 0) {
		const int ret = close(raw_fd);

		if (ret) {
			PERROR("Failed to close file descriptor %d", raw_fd);
		}
	}
}

static
enum lttng_error_code add_fds_to_payload(struct lttng_dynamic_array *raw_fds,
		struct lttng_payload *payload)
{
	int i;
	enum lttng_error_code ret_code = LTTNG_OK;
	const int fd_count = lttng_dynamic_array_get_count(raw_fds);

	for (i = 0; i < fd_count; i++) {
		int ret;
		struct fd_handle *handle;
		int *raw_fd = (int *) lttng_dynamic_array_get_element(
			raw_fds, i);

		LTTNG_ASSERT(*raw_fd != -1);

		handle = fd_handle_create(*raw_fd);
		if (!handle) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}

		/* FD ownership transferred to the handle. */
		*raw_fd = -1;

		ret = lttng_payload_push_fd_handle(payload, handle);
		fd_handle_put(handle);
		if (ret) {
			ret_code = LTTNG_ERR_NOMEM;
			goto end;
		}
	}

end:
	return ret_code;
}

static
ssize_t _lttcomm_recv_payload_fds_unix_sock(int sock, size_t nb_fd,
		struct lttng_payload *payload, bool blocking)
{
	int i = 0;
	enum lttng_error_code add_ret;
	ssize_t ret;
	int default_value = -1;
	struct lttng_dynamic_array raw_fds;

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(payload);
	LTTNG_ASSERT(nb_fd > 0);

	lttng_dynamic_array_init(&raw_fds, sizeof(int), close_raw_fd);

	for (i = 0; i < nb_fd; i++) {
		if (lttng_dynamic_array_add_element(&raw_fds, &default_value)) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	if (blocking) {
		ret = lttcomm_recv_fds_unix_sock(
				sock, (int *) raw_fds.buffer.data, nb_fd);
	} else {
		ret = lttcomm_recv_fds_unix_sock_non_block(
				sock, (int *) raw_fds.buffer.data, nb_fd);
	}

	if (ret <= 0) {
		goto end;
	}

	add_ret = add_fds_to_payload(&raw_fds, payload);
	if (add_ret != LTTNG_OK) {
		ret = - (int) add_ret;
		goto end;
	}

end:
	lttng_dynamic_array_reset(&raw_fds);
	return ret;
}

LTTNG_HIDDEN
ssize_t lttcomm_recv_payload_fds_unix_sock(int sock, size_t nb_fd,
			   struct lttng_payload *payload)
{
	return _lttcomm_recv_payload_fds_unix_sock(sock, nb_fd, payload, true);
}

LTTNG_HIDDEN
ssize_t lttcomm_recv_payload_fds_unix_sock_non_block(int sock, size_t nb_fd,
			   struct lttng_payload *payload)
{
	return _lttcomm_recv_payload_fds_unix_sock(sock, nb_fd, payload, false);
}

/*
 * Recv a message accompanied by fd(s) from a non-blocking unix socket.
 * Only use with non-blocking sockets.
 *
 * Returns the size of received data, or negative error value.
 *
 * Expect at most "nb_fd" file descriptors.
 *
 * Note that based on our comprehension, partial reception of fds is not
 * possible since the FDs are actually in the control message. It is all or
 * nothing, still the sender side can send the wrong number of fds.
 */
LTTNG_HIDDEN
ssize_t lttcomm_recv_fds_unix_sock_non_block(int sock, int *fds, size_t nb_fd)
{
	struct iovec iov[1];
	ssize_t ret = 0;
	struct cmsghdr *cmsg;
	size_t sizeof_fds = nb_fd * sizeof(int);

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(fds);
	LTTNG_ASSERT(nb_fd > 0);

#ifdef __linux__
/* Account for the struct ucred cmsg in the buffer size */
#define LTTNG_SOCK_RECV_FDS_BUF_SIZE CMSG_SPACE(sizeof_fds) + CMSG_SPACE(sizeof(struct ucred))
#else
#define LTTNG_SOCK_RECV_FDS_BUF_SIZE CMSG_SPACE(sizeof_fds)
#endif /* __linux__ */

	char recv_buf[LTTNG_SOCK_RECV_FDS_BUF_SIZE];
	struct msghdr msg;
	char dummy;

	memset(&msg, 0, sizeof(msg));

	/* Prepare to receive the structures */
	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	cmsg = (struct cmsghdr *) recv_buf;
	cmsg->cmsg_len = CMSG_LEN(sizeof_fds);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	msg.msg_control = cmsg;
	msg.msg_controllen = CMSG_LEN(sizeof(recv_buf));
	msg.msg_flags = 0;

retry:
	ret = lttng_recvmsg_nosigpipe(sock, &msg);
	if (ret < 0) {
		if (errno == EINTR) {
			goto retry;
		} else {
			/*
			 * We consider EPIPE and EAGAIN/EWOULDBLOCK as expected.
			 */
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/*
				 * This can happen in non blocking mode.
				 * Nothing was recv.
				 */
				ret = 0;
				goto end;
			}

			if (errno == EPIPE) {
				/* Expected error, pass error to caller */
				DBG3("EPIPE on recvmsg");
				ret = -1;
				goto end;
			}

			/* Unexpected error */
			PERROR("recvmsg");
			ret = -1;
			goto end;
		}
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

	/*
	 * If the socket was configured with SO_PASSCRED, the kernel will add a
	 * control message (cmsg) to the ancillary data of the unix socket. We
	 * need to expect a cmsg of the SCM_CREDENTIALS as the first control
	 * message.
	 */
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_SOCKET) {
			fprintf(stderr, "Error: The socket needs to be of type SOL_SOCKET\n");
			ret = -1;
			goto end;
		}
		if (cmsg->cmsg_type == SCM_RIGHTS) {
			/*
			 * We found the controle message for file descriptors,
			 * now copy the fds to the fds ptr and return success.
			 */
			if (cmsg->cmsg_len != CMSG_LEN(sizeof_fds)) {
				fprintf(stderr, "Error: Received %zu bytes of"
					"ancillary data for FDs, expected %zu\n",
					(size_t) cmsg->cmsg_len,
					(size_t) CMSG_LEN(sizeof_fds));
				ret = -1;
				goto end;
			}
			memcpy(fds, CMSG_DATA(cmsg), sizeof_fds);
			ret = sizeof_fds;
			goto end;
		}
#ifdef __linux__
		if (cmsg->cmsg_type == SCM_CREDENTIALS) {
			/*
			 * Expect credentials to be sent when expecting fds even
			 * if no credential were include in the send(). The
			 * kernel adds them...
			 */
			ret = -1;
		}
#endif /* __linux__ */
	}
end:
	return ret;
}

/*
 * Send a message with credentials over a unix socket.
 *
 * Returns the size of data sent, or negative error value.
 */
LTTNG_HIDDEN
ssize_t lttcomm_send_creds_unix_sock(int sock, const void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;
#if defined(__linux__) || defined(__CYGWIN__)
	struct cmsghdr *cmptr;
	size_t sizeof_cred = sizeof(lttng_sock_cred);
	char anc_buf[CMSG_SPACE(sizeof_cred)];
	lttng_sock_cred *creds;

	memset(anc_buf, 0, CMSG_SPACE(sizeof_cred) * sizeof(char));
#endif /* __linux__, __CYGWIN__ */

	memset(&msg, 0, sizeof(msg));

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(buf);
	LTTNG_ASSERT(len > 0);

	iov[0].iov_base = (void *) buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

#if defined(__linux__) || defined(__CYGWIN__)
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
#endif /* __linux__, __CYGWIN__ */

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
#if defined(__linux__) || defined(__CYGWIN__)
	struct cmsghdr *cmptr;
	size_t sizeof_cred = sizeof(lttng_sock_cred);
	char anc_buf[CMSG_SPACE(sizeof_cred)];
#endif	/* __linux__, __CYGWIN__ */

	LTTNG_ASSERT(sock);
	LTTNG_ASSERT(buf);
	LTTNG_ASSERT(len > 0);
	LTTNG_ASSERT(creds);

	memset(&msg, 0, sizeof(msg));

	/* Prepare to receive the structures */
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

#if defined(__linux__) || defined(__CYGWIN__)
	msg.msg_control = anc_buf;
	msg.msg_controllen = sizeof(anc_buf);
#endif /* __linux__, __CYGWIN__ */

	do {
		len_last = iov[0].iov_len;
		ret = recvmsg(sock, &msg, 0);
		if (ret > 0) {
			iov[0].iov_base += ret;
			iov[0].iov_len -= ret;
			LTTNG_ASSERT(ret <= len_last);
		}
	} while ((ret > 0 && ret < len_last) || (ret < 0 && errno == EINTR));
	if (ret < 0) {
		PERROR("recvmsg fds");
		goto end;
	} else if (ret > 0) {
		ret = len;
	}
	/* Else ret = 0 meaning an orderly shutdown. */

#if defined(__linux__) || defined(__CYGWIN__)
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
#elif (defined(__FreeBSD__) || defined(__sun__) || defined(__APPLE__))
	if (lttng_get_unix_socket_peer_creds(sock, creds)) {
		fprintf(stderr, "ARG\n");
		ret = -1;
		goto end;
	}
#else
#error "Please implement credential support for your OS."
#endif	/* __linux__, __CYGWIN__ */

end:
	return ret;
}

/*
 * Set socket option to use credentials passing.
 */
#if defined(__linux__) || defined(__CYGWIN__)
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
#elif (defined(__FreeBSD__) || defined(__sun__) || defined(__APPLE__))
LTTNG_HIDDEN
int lttcomm_setsockopt_creds_unix_sock(int sock)
{
	return 0;
}
#else
#error "Please implement credential support for your OS."
#endif /* __linux__ */
