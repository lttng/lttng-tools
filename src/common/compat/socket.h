/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

#elif (defined(__FreeBSD__) || defined(__CYGWIN__) || defined(__sun__))

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


#ifdef __sun__

# ifndef CMSG_ALIGN
#  ifdef _CMSG_DATA_ALIGN
#   define CMSG_ALIGN(len) _CMSG_DATA_ALIGN(len)
#  else
    /* aligning to sizeof (long) is assumed to be portable (fd.o#40235) */
#   define CMSG_ALIGN(len) (((len) + sizeof (long) - 1) & ~(sizeof (long) - 1))
#  endif
#  ifndef CMSG_SPACE
#    define CMSG_SPACE(len) (CMSG_ALIGN (sizeof (struct cmsghdr)) + CMSG_ALIGN (len))
#  endif
#  ifndef CMSG_LEN
#    define CMSG_LEN(len) (CMSG_ALIGN (sizeof (struct cmsghdr)) + (len))
#  endif
# endif


#include <ucred.h>
static int
getpeereid(int s, uid_t *euid, gid_t *gid)
{
	ucred_t *ucred = NULL;
	int ret = 0;

	if (getpeerucred(s, &ucred) == -1) {
		ret = -1;
		goto end;
	}

	if ((*euid = ucred_geteuid(ucred)) == -1) {
		ret = -1;
		goto free;
	}

	if ((*gid = ucred_getrgid(ucred)) == -1) {
		ret = -1;
		goto free;
	}

free:
	ucred_free(ucred);
end:
	return ret;
}

#endif /* __sun__ */

#endif /* _COMPAT_SOCKET_H */
