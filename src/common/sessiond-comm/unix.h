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

#ifndef _LTTCOMM_UNIX_H
#define _LTTCOMM_UNIX_H

#define _GNU_SOURCE
#include <limits.h>
#include <sys/un.h>

#include <common/compat/socket.h>

#include "sessiond-comm.h"

extern int lttcomm_create_unix_sock(const char *pathname);
extern int lttcomm_connect_unix_sock(const char *pathname);
extern int lttcomm_accept_unix_sock(int sock);
extern int lttcomm_listen_unix_sock(int sock);
extern int lttcomm_close_unix_sock(int sock);

/* Send a message accompanied by fd(s) over a unix socket. */
extern ssize_t lttcomm_send_fds_unix_sock(int sock, int *fds, size_t nb_fd);
/* Recv a message accompanied by fd(s) from a unix socket */
extern ssize_t lttcomm_recv_fds_unix_sock(int sock, int *fds, size_t nb_fd);

extern ssize_t lttcomm_recv_unix_sock(int sock, void *buf, size_t len);
extern ssize_t lttcomm_send_unix_sock(int sock, void *buf, size_t len);

extern ssize_t lttcomm_send_creds_unix_sock(int sock, void *buf, size_t len);
extern ssize_t lttcomm_recv_creds_unix_sock(int sock, void *buf, size_t len,
		lttng_sock_cred *creds);

extern int lttcomm_setsockopt_creds_unix_sock(int sock);

#endif	/* _LTTCOMM_UNIX_H */
