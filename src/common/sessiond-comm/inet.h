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

#ifndef _LTTCOMM_INET_H
#define _LTTCOMM_INET_H

#include <limits.h>

#include "sessiond-comm.h"

/* See man tcp(7) for more detail about this value. */
#define LTTCOMM_INET_PROC_SYN_RETRIES_PATH "/proc/sys/net/ipv4/tcp_syn_retries"
#define LTTCOMM_INET_PROC_FIN_TIMEOUT_PATH "/proc/sys/net/ipv4/tcp_fin_timeout"

/*
 * The timeout value of a connect() is computed with an algorithm inside the
 * kernel using the defined TCP SYN retries so the end value in time is
 * approximative. According to tcp(7) man page, a value of 5 is roughly 180
 * seconds of timeout. With that information, we've computed a factor of 36
 * (180/5) by considering that it grows linearly. This is of course uncertain
 * but this is the best approximation we can do at runtime.
 */
#define LTTCOMM_INET_SYN_TIMEOUT_FACTOR		36

/*
 * Maximum timeout value in seconds of a TCP connection for both send/recv and
 * connect operations.
 */
extern unsigned long lttcomm_inet_tcp_timeout;

/* Stub */
struct lttcomm_sock;

/* Net family callback */
extern int lttcomm_create_inet_sock(struct lttcomm_sock *sock, int type,
		int proto);

extern struct lttcomm_sock *lttcomm_accept_inet_sock(struct lttcomm_sock *sock);
extern int lttcomm_bind_inet_sock(struct lttcomm_sock *sock);
extern int lttcomm_close_inet_sock(struct lttcomm_sock *sock);
extern int lttcomm_connect_inet_sock(struct lttcomm_sock *sock);
extern int lttcomm_listen_inet_sock(struct lttcomm_sock *sock, int backlog);

extern ssize_t lttcomm_recvmsg_inet_sock(struct lttcomm_sock *sock, void *buf,
		size_t len, int flags);
extern ssize_t lttcomm_sendmsg_inet_sock(struct lttcomm_sock *sock,
		const void *buf, size_t len, int flags);

/* Initialize inet communication layer. */
extern void lttcomm_inet_init(void);

#endif	/* _LTTCOMM_INET_H */
