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

#ifndef _LTTCOMM_INET6_H
#define _LTTCOMM_INET6_H

#include <limits.h>

#include "sessiond-comm.h"

/* Stub */
struct lttcomm_sock;

/* Net family callback */
extern int lttcomm_create_inet6_sock(struct lttcomm_sock *sock, int type,
		int proto);

extern struct lttcomm_sock *lttcomm_accept_inet6_sock(
		struct lttcomm_sock *sock);
extern int lttcomm_bind_inet6_sock(struct lttcomm_sock *sock);
extern int lttcomm_close_inet6_sock(struct lttcomm_sock *sock);
extern int lttcomm_connect_inet6_sock(struct lttcomm_sock *sock);
extern int lttcomm_listen_inet6_sock(struct lttcomm_sock *sock, int backlog);

extern ssize_t lttcomm_recvmsg_inet6_sock(struct lttcomm_sock *sock, void *buf,
		size_t len, int flags);
extern ssize_t lttcomm_sendmsg_inet6_sock(struct lttcomm_sock *sock,
		const void *buf, size_t len, int flags);

#endif	/* _LTTCOMM_INET6_H */
