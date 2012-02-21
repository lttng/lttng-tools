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
#define LTTNG_SOCK_FDS   SCM_RIGHTS

typedef struct ucred lttng_sock_cred;

#define LTTNG_SOCK_SET_UID_CRED(c, u) LTTNG_REF(c)->uid = u;
#define LTTNG_SOCK_SET_GID_CRED(c, g) LTTNG_REF(c)->gid = g;
#define LTTNG_SOCK_SET_PID_CRED(c, p) LTTNG_REF(c)->pid = p;

#elif __FreeBSD__

#undef SO_PASSCRED
#define SO_PASSCRED 0

#define LTTNG_SOCK_CREDS SCM_CREDS
#define LTTNG_SOCK_FDS   SCM_RIGHTS

typedef struct cmsgcred lttng_sock_cred;

#define LTTNG_SOCK_SET_UID_CRED(c, uid) LTTNG_REF(c)->cmcred_uid = uid;
#define LTTNG_SOCK_SET_GID_CRED(c, gid) LTTNG_REF(c)->cmcred_gid = gid;
#define LTTNG_SOCK_SET_PID_CRED(c, pid) LTTNG_REF(c)->cmcred_pid = pid;

#else
#error "Please add support for your OS into lttng/ust-endian.h."
#endif /* __linux__ , __FreeBSD__ */

#endif /* _COMPAT_SOCKET_H */
