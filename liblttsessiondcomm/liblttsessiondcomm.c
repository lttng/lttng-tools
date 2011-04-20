/*
 * Copyright (C)  2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "liblttsessiondcomm.h"

/*
 * Human readable error message.
 */
static const char *lttcomm_readable_code[] = {
	[ LTTCOMM_ERR_INDEX(LTTCOMM_OK) ] = "Success",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_ERR) ] = "Unknown error",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UND) ] = "Undefined command",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_SESSION) ] = "No session found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_LIST_FAIL) ] = "Unable to list traceable apps",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_APPS) ] = "No traceable apps found",
};

/*
 *  lttcom_get_readable_code
 *
 *  Return ptr to string representing a human readable
 *  error code from the lttcomm_return_code enum.
 *
 *  These code MUST be negative in other to treat that
 *  as an error value.
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
 * 	lttcomm_connect_unix_sock
 *
 * 	Connect to unix socket using the path name.
 */
int lttcomm_connect_unix_sock(const char *pathname)
{
	struct sockaddr_un sun;
	int fd;
	int ret = 1;

	fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		goto error;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, pathname, sizeof(sun.sun_path));

	ret = connect(fd, (struct sockaddr *) &sun, sizeof(sun));
	if (ret < 0) {
		perror("connect");
		goto error;
	}

	return fd;

error:
	return -1;
}

/*
 * 	lttcomm_accept_unix_sock
 *
 *	Do an accept(2) on the sock and return the
 *	new file descriptor. The socket MUST be bind(2) before.
 */
int lttcomm_accept_unix_sock(int sock)
{
	int new_fd;
	struct sockaddr_un sun;
	socklen_t len = 0;

	/* Blocking call */
	new_fd = accept(sock, (struct sockaddr *) &sun, &len);
	if (new_fd < 0) {
		perror("accept");
		goto error;
	}

	return new_fd;

error:
	return -1;
}

/*
 * 	lttcomm_create_unix_sock
 *
 * 	Creates a AF_UNIX local socket using pathname
 * 	bind the socket upon creation and return the fd.
 */
int lttcomm_create_unix_sock(const char *pathname)
{
	struct sockaddr_un sun;
	int fd;
	int ret = -1;

	/* Create server socket */
	if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		goto error;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strncpy(sun.sun_path, pathname, strlen(pathname));

	ret = bind(fd, (struct sockaddr *) &sun, sizeof(sun));
	if (ret < 0) {
		perror("bind");
		goto error;
	}

	return fd;

error:
	return ret;
}

/*
 * 	lttcomm_listen_unix_sock
 *
 * 	Make the socket listen using MAX_LISTEN.
 */
int lttcomm_listen_unix_sock(int sock)
{
	int ret;

	ret = listen(sock, MAX_LISTEN);
	if (ret < 0) {
		perror("listen");
	}

	return ret;
}

/*
 * 	lttcomm_recv_unix_sock
 *
 *  Receive data of size len in put that data into
 *  the buf param. Using recvmsg API.
 *  Return the size of received data.
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

	ret = recvmsg(sock, &msg, 0);
	if (ret < 0) {
		perror("recvmsg");
	}

	return ret;
}

/*
 * 	lttcomm_send_unix_sock
 *
 * 	Send buf data of size len. Using sendmsg API.
 * 	Return the size of sent data.
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
		perror("sendmsg");
	}

	return ret;
}
