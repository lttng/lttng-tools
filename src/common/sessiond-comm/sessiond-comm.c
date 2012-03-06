/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
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

#include "sessiond-comm.h"

/*
 * Human readable error message.
 */
static const char *lttcomm_readable_code[] = {
	[ LTTCOMM_ERR_INDEX(LTTCOMM_OK) ] = "Success",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_ERR) ] = "Unknown error",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UND) ] = "Undefined command",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NOT_IMPLEMENTED) ] = "Not implemented",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UNKNOWN_DOMAIN) ] = "Unknown tracing domain",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_SESSION) ] = "No session found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_LIST_FAIL) ] = "Unable to list traceable apps",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_APPS) ] = "No traceable apps found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_SESS_NOT_FOUND) ] = "Session name not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_TRACE) ] = "No trace found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_FATAL) ] = "Fatal error of the session daemon",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CREATE_DIR_FAIL) ] = "Create directory failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_START_FAIL) ] = "Start trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_STOP_FAIL) ] = "Stop trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_TRACEABLE) ] = "App is not traceable",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_SELECT_SESS) ] = "A session MUST be selected",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_EXIST_SESS) ] = "Session name already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONNECT_FAIL) ] = "Unable to connect to Unix socket",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_APP_NOT_FOUND) ] = "Application not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_EPERM) ] = "Permission denied",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_NA) ] = "Kernel tracer not available",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_VERSION) ] = "Kernel tracer version is not compatible",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_EVENT_EXIST) ] = "Kernel event already exists",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_SESS_FAIL) ] = "Kernel create session failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CHAN_FAIL) ] = "Kernel create channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CHAN_NOT_FOUND) ] = "Kernel channel not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CHAN_DISABLE_FAIL) ] = "Disable kernel channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CHAN_ENABLE_FAIL) ] = "Enable kernel channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CONTEXT_FAIL) ] = "Add kernel context failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_ENABLE_FAIL) ] = "Enable kernel event failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_DISABLE_FAIL) ] = "Disable kernel event failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_META_FAIL) ] = "Opening metadata failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_START_FAIL) ] = "Starting kernel trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_STOP_FAIL) ] = "Stoping kernel trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CONSUMER_FAIL) ] = "Kernel consumer start failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_STREAM_FAIL) ] = "Kernel create stream failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_DIR_FAIL) ] = "Kernel trace directory creation failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_DIR_EXIST) ] = "Kernel trace directory already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_NO_SESSION) ] = "No kernel session found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_LIST_FAIL) ] = "Listing kernel events failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CALIBRATE_FAIL) ] = "UST calibration failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_VERSION) ] = "UST tracer version is not compatible",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_SESS_FAIL) ] = "UST create session failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_FAIL) ] = "UST create channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_EXIST) ] = "UST channel already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_NOT_FOUND) ] = "UST channel not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_DISABLE_FAIL) ] = "Disable UST channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_ENABLE_FAIL) ] = "Enable UST channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONTEXT_FAIL) ] = "Add UST context failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_ENABLE_FAIL) ] = "Enable UST event failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_DISABLE_FAIL) ] = "Disable UST event failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_META_FAIL) ] = "Opening metadata failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_START_FAIL) ] = "Starting UST trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_STOP_FAIL) ] = "Stoping UST trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONSUMER64_FAIL) ] = "64-bit UST consumer start failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONSUMER32_FAIL) ] = "32-bit UST consumer start failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_STREAM_FAIL) ] = "UST create stream failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_DIR_FAIL) ] = "UST trace directory creation failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_DIR_EXIST) ] = "UST trace directory already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_NO_SESSION) ] = "No UST session found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_LIST_FAIL) ] = "Listing UST events failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_EVENT_EXIST) ] = "UST event already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_EVENT_NOT_FOUND)] = "UST event not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONTEXT_EXIST)] = "UST context already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONTEXT_INVAL)] = "UST invalid context",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NEED_ROOT_SESSIOND) ] = "Tracing the kernel requires a root lttng-sessiond daemon and \"tracing\" group user membership",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_TRACE_ALREADY_STARTED) ] = "Tracing already started",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_TRACE_ALREADY_STOPPED) ] = "Tracing already stopped",

	[ LTTCOMM_ERR_INDEX(CONSUMERD_COMMAND_SOCK_READY) ] = "consumerd command socket ready",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SUCCESS_RECV_FD) ] = "consumerd success on receiving fds",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_ERROR_RECV_FD) ] = "consumerd error on receiving fds",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_ERROR_RECV_CMD) ] = "consumerd error on receiving command",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_POLL_ERROR) ] = "consumerd error in polling thread",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_POLL_NVAL) ] = "consumerd polling on closed fd",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_POLL_HUP) ] = "consumerd all fd hung up",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_EXIT_SUCCESS) ] = "consumerd exiting normally",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_EXIT_FAILURE) ] = "consumerd exiting on error",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_OUTFD_ERROR) ] = "consumerd error opening the tracefile",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SPLICE_EBADF) ] = "consumerd splice EBADF",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SPLICE_EINVAL) ] = "consumerd splice EINVAL",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SPLICE_ENOMEM) ] = "consumerd splice ENOMEM",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SPLICE_ESPIPE) ] = "consumerd splice ESPIPE",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_EVENT) ] = "Event not found",
};

/*
 * Return ptr to string representing a human readable error code from the
 * lttcomm_return_code enum.
 *
 * These code MUST be negative in other to treat that as an error value.
 */
const char *lttcomm_get_readable_code(enum lttcomm_return_code code)
{
	int tmp_code = -code;

	if (tmp_code >= LTTCOMM_OK && tmp_code < LTTCOMM_NR) {
		return lttcomm_readable_code[LTTCOMM_ERR_INDEX(tmp_code)];
	}

	return "Unknown error code";
}

/*
 * Connect to unix socket using the path name.
 */
int lttcomm_connect_unix_sock(const char *pathname)
{
	struct sockaddr_un sun;
	int fd, ret, closeret;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		PERROR("socket");
		ret = fd;
		goto error;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, pathname, sizeof(sun.sun_path));
	sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';

	ret = connect(fd, (struct sockaddr *) &sun, sizeof(sun));
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
int lttcomm_accept_unix_sock(int sock)
{
	int new_fd;
	struct sockaddr_un sun;
	socklen_t len = 0;

	/* Blocking call */
	new_fd = accept(sock, (struct sockaddr *) &sun, &len);
	if (new_fd < 0) {
		PERROR("accept");
	}

	return new_fd;
}

/*
 * Creates a AF_UNIX local socket using pathname bind the socket upon creation
 * and return the fd.
 */
int lttcomm_create_unix_sock(const char *pathname)
{
	struct sockaddr_un sun;
	int fd;
	int ret = -1;

	/* Create server socket */
	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		PERROR("socket");
		goto error;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, pathname, sizeof(sun.sun_path));
	sun.sun_path[sizeof(sun.sun_path) - 1] = '\0';

	/* Unlink the old file if present */
	(void) unlink(pathname);
	ret = bind(fd, (struct sockaddr *) &sun, sizeof(sun));
	if (ret < 0) {
		PERROR("bind");
		goto error;
	}

	return fd;

error:
	return ret;
}

/*
 * Make the socket listen using LTTNG_SESSIOND_COMM_MAX_LISTEN.
 */
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
ssize_t lttcomm_recv_unix_sock(int sock, void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ret = recvmsg(sock, &msg, MSG_WAITALL);
	if (ret < 0) {
		PERROR("recvmsg");
	}

	return ret;
}

/*
 * Send buf data of size len. Using sendmsg API.
 *
 * Return the size of sent data.
 */
ssize_t lttcomm_send_unix_sock(int sock, void *buf, size_t len)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret = -1;

	memset(&msg, 0, sizeof(msg));

	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(sock, &msg, 0);
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
 * Shutdown cleanly a unix socket.
 */
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

	if (nb_fd > LTTCOMM_MAX_SEND_FDS)
		return -EINVAL;

	msg.msg_control = (caddr_t)tmp;
	msg.msg_controllen = CMSG_LEN(sizeof_fds);

	cmptr = CMSG_FIRSTHDR(&msg);
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

	ret = sendmsg(sock, &msg, 0);
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

	ret = recvmsg(sock, &msg, 0);
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
	cmptr->cmsg_level = SOL_SOCKET;
	cmptr->cmsg_type = LTTNG_SOCK_CREDS;
	cmptr->cmsg_len = CMSG_LEN(sizeof_cred);

	creds = (lttng_sock_cred*) CMSG_DATA(cmptr);

	LTTNG_SOCK_SET_UID_CRED(creds, geteuid());
	LTTNG_SOCK_SET_GID_CRED(creds, getegid());
	LTTNG_SOCK_SET_PID_CRED(creds, getpid());
#endif /* __linux__ */

	ret = sendmsg(sock, &msg, 0);
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
ssize_t lttcomm_recv_creds_unix_sock(int sock, void *buf, size_t len,
		lttng_sock_cred *creds)
{
	struct msghdr msg;
	struct iovec iov[1];
	ssize_t ret;
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

	ret = recvmsg(sock, &msg, 0);
	if (ret < 0) {
		PERROR("recvmsg fds");
		goto end;
	}

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
#elif defined(__FreeBSD__)
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
#elif defined(__FreeBSD__)
int lttcomm_setsockopt_creds_unix_sock(int sock)
{
	return 0;
}
#else
#error "Please implement credential support for your OS."
#endif /* __linux__ */
