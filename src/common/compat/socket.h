/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _COMPAT_SOCKET_H
#define _COMPAT_SOCKET_H

#include <sys/socket.h>
#include <sys/un.h>

#include <common/macros.h>

#ifdef __linux__

#define LTTNG_SOCK_CREDS SCM_CREDENTIALS

typedef struct ucred lttng_sock_cred;

#define LTTNG_SOCK_SET_UID_CRED(c, u) LTTNG_REF(c)->uid = u
#define LTTNG_SOCK_SET_GID_CRED(c, g) LTTNG_REF(c)->gid = g
#define LTTNG_SOCK_SET_PID_CRED(c, p) LTTNG_REF(c)->pid = p

#define LTTNG_SOCK_GET_UID_CRED(c) LTTNG_REF(c)->uid
#define LTTNG_SOCK_GET_GID_CRED(c) LTTNG_REF(c)->gid
#define LTTNG_SOCK_GET_PID_CRED(c) LTTNG_REF(c)->pid

#elif defined(__FreeBSD__)

struct lttng_sock_cred {
	uid_t uid;
	gid_t gid;
};

typedef struct lttng_sock_cred lttng_sock_cred;

#define LTTNG_SOCK_GET_UID_CRED(c) LTTNG_REF(c)->uid
#define LTTNG_SOCK_GET_GID_CRED(c) LTTNG_REF(c)->gid
#define LTTNG_SOCK_GET_PID_CRED(c) -1

#else
#error "Please add support for your OS."
#endif /* __linux__ , __FreeBSD__ */

#endif /* _COMPAT_SOCKET_H */
