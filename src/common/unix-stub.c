/*
 * Copyright (C) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
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

#ifndef _UNIX_STUB_H
#define _UNIX_STUB_H

#include <stddef.h>
#include <stdlib.h>
#include <common/compat/socket.h>

int lttcomm_create_unix_sock(const char *pathname)
{
	return -1;
}
int lttcomm_create_anon_unix_socketpair(int *fds)
{
	return -1;
}
int lttcomm_connect_unix_sock(const char *pathname)
{
	return -1;
}
int lttcomm_accept_unix_sock(int sock)
{
	return -1;
}
int lttcomm_listen_unix_sock(int sock)
{
	return -1;
}
int lttcomm_close_unix_sock(int sock)
{
	return -1;
}
ssize_t lttcomm_send_fds_unix_sock(int sock, const int *fds, size_t nb_fd)
{
	return -1;
}
ssize_t lttcomm_recv_fds_unix_sock(int sock, int *fds, size_t nb_fd)
{
	return -1;
}
ssize_t lttcomm_recv_unix_sock(int sock, void *buf, size_t len)
{
	return -1;
}
ssize_t lttcomm_recv_unix_sock_non_block(int sock, void *buf, size_t len)
{
	return -1;
}
ssize_t lttcomm_send_unix_sock(int sock, const void *buf, size_t len)
{
	return -1;
}
ssize_t lttcomm_send_unix_sock_non_block(int sock, const void *buf, size_t len)
{
	return -1;
}
ssize_t lttcomm_send_creds_unix_sock(int sock, void *buf, size_t len)
{
	return -1;
}
ssize_t lttcomm_recv_creds_unix_sock(int sock, void *buf, size_t len,
		lttng_sock_cred *creds)
{
	return -1;
}
int lttcomm_setsockopt_creds_unix_sock(int sock)
{
	return -1;
}
#endif	/* _UNIX_STUB_H */
