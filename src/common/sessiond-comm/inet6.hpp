/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTCOMM_INET6_H
#define _LTTCOMM_INET6_H

#include "sessiond-comm.hpp"

#include <limits.h>
#include <sys/types.h>

/* Stub */
struct lttcomm_sock;

/* Net family callback */
extern int lttcomm_create_inet6_sock(struct lttcomm_sock *sock, int type, int proto);

extern struct lttcomm_sock *lttcomm_accept_inet6_sock(struct lttcomm_sock *sock);
extern int lttcomm_bind_inet6_sock(struct lttcomm_sock *sock);
extern int lttcomm_close_inet6_sock(struct lttcomm_sock *sock);
extern int lttcomm_connect_inet6_sock(struct lttcomm_sock *sock);
extern int lttcomm_listen_inet6_sock(struct lttcomm_sock *sock, int backlog);

extern ssize_t
lttcomm_recvmsg_inet6_sock(struct lttcomm_sock *sock, void *buf, size_t len, int flags);
extern ssize_t
lttcomm_sendmsg_inet6_sock(struct lttcomm_sock *sock, const void *buf, size_t len, int flags);

#endif /* _LTTCOMM_INET6_H */
