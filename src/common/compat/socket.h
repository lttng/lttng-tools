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

#ifndef MSG_NOSIGNAL
# ifdef SO_NOSIGPIPE
#   define MSG_NOSIGNAL SO_NOSIGPIPE
# endif
#endif

#if defined(MSG_NOSIGNAL)
static inline
ssize_t lttng_recvmsg_nosigpipe(int sockfd, struct msghdr *msg)
{
	return recvmsg(sockfd, msg, MSG_NOSIGNAL);
}
#else

#include <signal.h>
#include <errno.h>

static inline
ssize_t lttng_recvmsg_nosigpipe(int sockfd, struct msghdr *msg)
{
	ssize_t received;
	int saved_err;
	sigset_t sigpipe_set, pending_set, old_set;
	int sigpipe_was_pending;

	/*
	 * Discard the SIGPIPE from send(), not disturbing any SIGPIPE
	 * that might be already pending. If a bogus SIGPIPE is sent to
	 * the entire process concurrently by a malicious user, it may
	 * be simply discarded.
	 */
	if (sigemptyset(&pending_set)) {
		return -1;
	}
	/*
	 * sigpending returns the mask of signals that are _both_
	 * blocked for the thread _and_ pending for either the thread or
	 * the entire process.
	 */
	if (sigpending(&pending_set)) {
		return -1;
	}
	sigpipe_was_pending = sigismember(&pending_set, SIGPIPE);
	/*
	 * If sigpipe was pending, it means it was already blocked, so
	 * no need to block it.
	 */
	if (!sigpipe_was_pending) {
		if (sigemptyset(&sigpipe_set)) {
			return -1;
		}
		if (sigaddset(&sigpipe_set, SIGPIPE)) {
			return -1;
		}
		if (pthread_sigmask(SIG_BLOCK, &sigpipe_set, &old_set)) {
			return -1;
		}
	}

	/* Send and save errno. */
	received = recvmsg(sockfd, msg, 0);
	saved_err = errno;

	if (received == -1 && errno == EPIPE && !sigpipe_was_pending) {
		struct timespec timeout = { 0, 0 };
		int ret;

		do {
			ret = sigtimedwait(&sigpipe_set, NULL,
				&timeout);
		} while (ret == -1 && errno == EINTR);
	}
	if (!sigpipe_was_pending) {
		if (pthread_sigmask(SIG_SETMASK, &old_set, NULL)) {
			return -1;
		}
	}
	/* Restore send() errno */
	errno = saved_err;

	return received;
}
#endif


#ifdef __linux__

#define LTTNG_SOCK_CREDS SCM_CREDENTIALS

typedef struct ucred lttng_sock_cred;

#define LTTNG_SOCK_SET_UID_CRED(c, u) LTTNG_REF(c)->uid = u
#define LTTNG_SOCK_SET_GID_CRED(c, g) LTTNG_REF(c)->gid = g
#define LTTNG_SOCK_SET_PID_CRED(c, p) LTTNG_REF(c)->pid = p

#define LTTNG_SOCK_GET_UID_CRED(c) LTTNG_REF(c)->uid
#define LTTNG_SOCK_GET_GID_CRED(c) LTTNG_REF(c)->gid
#define LTTNG_SOCK_GET_PID_CRED(c) LTTNG_REF(c)->pid

#elif (defined(__FreeBSD__) || defined(__CYGWIN__) || defined(__sun__) || defined(__APPLE__))

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

static inline
int getpeereid(int s, uid_t *euid, gid_t *gid)
{
	int ret = 0;
	ucred_t *ucred = NULL;

	ret = getpeerucred(s, &ucred);
	if (ret == -1) {
		goto end;
	}

	ret = ucred_geteuid(ucred);
	if (ret == -1) {
		goto free;
	}
	*euid = ret;

	ret = ucred_getrgid(ucred);
	if (ret == -1) {
		goto free;
	}
	*gid = ret;
	ret = 0;
free:
	ucred_free(ucred);
end:
	return ret;
}

#endif /* __sun__ */

#endif /* _COMPAT_SOCKET_H */
