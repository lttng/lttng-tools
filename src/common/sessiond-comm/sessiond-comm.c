/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <common/common.h>

#include "sessiond-comm.h"

/* For Unix socket */
#include <common/unix.h>
/* For Inet socket */
#include "inet.h"
/* For Inet6 socket */
#include "inet6.h"

#define NETWORK_TIMEOUT_ENV	"LTTNG_NETWORK_SOCKET_TIMEOUT"

static struct lttcomm_net_family net_families[] = {
	{ LTTCOMM_INET, lttcomm_create_inet_sock },
	{ LTTCOMM_INET6, lttcomm_create_inet6_sock },
};

/*
 * Human readable error message.
 */
static const char *lttcomm_readable_code[] = {
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_COMMAND_SOCK_READY) ] = "consumerd command socket ready",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SUCCESS_RECV_FD) ] = "consumerd success on receiving fds",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_ERROR_RECV_FD) ] = "consumerd error on receiving fds",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_ERROR_RECV_CMD) ] = "consumerd error on receiving command",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_POLL_ERROR) ] = "consumerd error in polling thread",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_POLL_NVAL) ] = "consumerd polling on closed fd",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_POLL_HUP) ] = "consumerd all fd hung up",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_EXIT_SUCCESS) ] = "consumerd exiting normally",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_EXIT_FAILURE) ] = "consumerd exiting on error",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_OUTFD_ERROR) ] = "consumerd error opening the tracefile",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SPLICE_EBADF) ] = "consumerd splice EBADF",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SPLICE_EINVAL) ] = "consumerd splice EINVAL",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SPLICE_ENOMEM) ] = "consumerd splice ENOMEM",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_SPLICE_ESPIPE) ] = "consumerd splice ESPIPE",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_ENOMEM) ] = "Consumer is out of memory",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_ERROR_METADATA) ] = "Error with metadata",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_FATAL) ] = "Fatal error",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONSUMERD_RELAYD_FAIL) ] = "Error on remote relayd",

	/* Last element */
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NR) ] = "Unknown error code"
};

static unsigned long network_timeout;

/*
 * Return ptr to string representing a human readable error code from the
 * lttcomm_return_code enum.
 *
 * These code MUST be negative in other to treat that as an error value.
 */
LTTNG_HIDDEN
const char *lttcomm_get_readable_code(enum lttcomm_return_code code)
{
	code = -code;

	if (code < LTTCOMM_CONSUMERD_COMMAND_SOCK_READY || code > LTTCOMM_NR) {
		code = LTTCOMM_NR;
	}

	return lttcomm_readable_code[LTTCOMM_ERR_INDEX(code)];
}

/*
 * Create socket from an already allocated lttcomm socket structure and init
 * sockaddr in the lttcomm sock.
 */
LTTNG_HIDDEN
int lttcomm_create_sock(struct lttcomm_sock *sock)
{
	int ret, _sock_type, _sock_proto, domain;

	assert(sock);

	domain = sock->sockaddr.type;
	if (domain != LTTCOMM_INET && domain != LTTCOMM_INET6) {
		ERR("Create socket of unknown domain %d", domain);
		ret = -1;
		goto error;
	}

	switch (sock->proto) {
	case LTTCOMM_SOCK_UDP:
		_sock_type = SOCK_DGRAM;
		_sock_proto = IPPROTO_UDP;
		break;
	case LTTCOMM_SOCK_TCP:
		_sock_type = SOCK_STREAM;
		_sock_proto = IPPROTO_TCP;
		break;
	default:
		ret = -1;
		goto error;
	}

	ret = net_families[domain].create(sock, _sock_type, _sock_proto);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Return allocated lttcomm socket structure.
 */
LTTNG_HIDDEN
struct lttcomm_sock *lttcomm_alloc_sock(enum lttcomm_sock_proto proto)
{
	struct lttcomm_sock *sock;

	sock = zmalloc(sizeof(struct lttcomm_sock));
	if (sock == NULL) {
		PERROR("zmalloc create sock");
		goto end;
	}

	sock->proto = proto;
	sock->fd = -1;

end:
	return sock;
}

/*
 * Return an allocated lttcomm socket structure and copy src content into
 * the newly created socket.
 *
 * This is mostly useful when lttcomm_sock are passed between process where the
 * fd and ops have to be changed within the correct address space.
 */
LTTNG_HIDDEN
struct lttcomm_sock *lttcomm_alloc_copy_sock(struct lttcomm_sock *src)
{
	struct lttcomm_sock *sock;

	/* Safety net */
	assert(src);

	sock = lttcomm_alloc_sock(src->proto);
	if (sock == NULL) {
		goto alloc_error;
	}

	lttcomm_copy_sock(sock, src);

alloc_error:
	return sock;
}

/*
 * Create and copy socket from an allocated lttcomm socket structure.
 *
 * This is mostly useful when lttcomm_sock are passed between process where the
 * fd and ops have to be changed within the correct address space.
 */
LTTNG_HIDDEN
void lttcomm_copy_sock(struct lttcomm_sock *dst, struct lttcomm_sock *src)
{
	/* Safety net */
	assert(dst);
	assert(src);

	dst->proto = src->proto;
	dst->fd = src->fd;
	dst->ops = src->ops;
	/* Copy sockaddr information from original socket */
	memcpy(&dst->sockaddr, &src->sockaddr, sizeof(dst->sockaddr));
}

/*
 * Init IPv4 sockaddr structure.
 */
LTTNG_HIDDEN
int lttcomm_init_inet_sockaddr(struct lttcomm_sockaddr *sockaddr,
		const char *ip, unsigned int port)
{
	int ret;

	assert(sockaddr);
	assert(ip);
	assert(port > 0 && port <= 65535);

	memset(sockaddr, 0, sizeof(struct lttcomm_sockaddr));

	sockaddr->type = LTTCOMM_INET;
	sockaddr->addr.sin.sin_family = AF_INET;
	sockaddr->addr.sin.sin_port = htons(port);
	ret = inet_pton(sockaddr->addr.sin.sin_family, ip,
			&sockaddr->addr.sin.sin_addr);
	if (ret < 1) {
		ret = -1;
		ERR("%s with port %d: unrecognized IPv4 address", ip, port);
		goto error;
	}
	memset(sockaddr->addr.sin.sin_zero, 0, sizeof(sockaddr->addr.sin.sin_zero));

error:
	return ret;
}

/*
 * Init IPv6 sockaddr structure.
 */
LTTNG_HIDDEN
int lttcomm_init_inet6_sockaddr(struct lttcomm_sockaddr *sockaddr,
		const char *ip, unsigned int port)
{
	int ret;

	assert(sockaddr);
	assert(ip);
	assert(port > 0 && port <= 65535);

	memset(sockaddr, 0, sizeof(struct lttcomm_sockaddr));

	sockaddr->type = LTTCOMM_INET6;
	sockaddr->addr.sin6.sin6_family = AF_INET6;
	sockaddr->addr.sin6.sin6_port = htons(port);
	ret = inet_pton(sockaddr->addr.sin6.sin6_family, ip,
			&sockaddr->addr.sin6.sin6_addr);
	if (ret < 1) {
		ret = -1;
		goto error;
	}

error:
	return ret;
}

/*
 * Return allocated lttcomm socket structure from lttng URI.
 */
LTTNG_HIDDEN
struct lttcomm_sock *lttcomm_alloc_sock_from_uri(struct lttng_uri *uri)
{
	int ret;
	int _sock_proto;
	struct lttcomm_sock *sock = NULL;

	/* Safety net */
	assert(uri);

	/* Check URI protocol */
	if (uri->proto == LTTNG_TCP) {
		_sock_proto = LTTCOMM_SOCK_TCP;
	} else {
		ERR("Relayd invalid URI proto: %d", uri->proto);
		goto alloc_error;
	}

	sock = lttcomm_alloc_sock(_sock_proto);
	if (sock == NULL) {
		goto alloc_error;
	}

	/* Check destination type */
	if (uri->dtype == LTTNG_DST_IPV4) {
		ret = lttcomm_init_inet_sockaddr(&sock->sockaddr, uri->dst.ipv4,
				uri->port);
		if (ret < 0) {
			goto error;
		}
	} else if (uri->dtype == LTTNG_DST_IPV6) {
		ret = lttcomm_init_inet6_sockaddr(&sock->sockaddr, uri->dst.ipv6,
				uri->port);
		if (ret < 0) {
			goto error;
		}
	} else {
		/* Command URI is invalid */
		ERR("Relayd invalid URI dst type: %d", uri->dtype);
		goto error;
	}

	return sock;

error:
	lttcomm_destroy_sock(sock);
alloc_error:
	return NULL;
}

/*
 * Destroy and free lttcomm socket.
 */
LTTNG_HIDDEN
void lttcomm_destroy_sock(struct lttcomm_sock *sock)
{
	free(sock);
}

/*
 * Allocate and return a relayd socket object using a given URI to initialize
 * it and the major/minor version of the supported protocol.
 *
 * On error, NULL is returned.
 */
LTTNG_HIDDEN
struct lttcomm_relayd_sock *lttcomm_alloc_relayd_sock(struct lttng_uri *uri,
		uint32_t major, uint32_t minor)
{
	int ret;
	struct lttcomm_sock *tmp_sock = NULL;
	struct lttcomm_relayd_sock *rsock = NULL;

	assert(uri);

	rsock = zmalloc(sizeof(*rsock));
	if (!rsock) {
		PERROR("zmalloc relayd sock");
		goto error;
	}

	/* Allocate socket object from URI */
	tmp_sock = lttcomm_alloc_sock_from_uri(uri);
	if (tmp_sock == NULL) {
		goto error_free;
	}

	/*
	 * Create socket object which basically sets the ops according to the
	 * socket protocol.
	 */
	lttcomm_copy_sock(&rsock->sock, tmp_sock);
	/* Temporary socket pointer not needed anymore. */
	lttcomm_destroy_sock(tmp_sock);
	ret = lttcomm_create_sock(&rsock->sock);
	if (ret < 0) {
		goto error_free;
	}

	rsock->major = major;
	rsock->minor = minor;

	return rsock;

error_free:
	free(rsock);
error:
	return NULL;
}

/*
 * Set socket receiving timeout.
 */
LTTNG_HIDDEN
int lttcomm_setsockopt_rcv_timeout(int sock, unsigned int msec)
{
	int ret;
	struct timeval tv;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec % 1000) * 1000;

	ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		PERROR("setsockopt SO_RCVTIMEO");
	}

	return ret;
}

/*
 * Set socket sending timeout.
 */
LTTNG_HIDDEN
int lttcomm_setsockopt_snd_timeout(int sock, unsigned int msec)
{
	int ret;
	struct timeval tv;

	tv.tv_sec = msec / 1000;
	tv.tv_usec = (msec % 1000) * 1000;

	ret = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		PERROR("setsockopt SO_SNDTIMEO");
	}

	return ret;
}

LTTNG_HIDDEN
void lttcomm_init(void)
{
	const char *env;

	env = getenv(NETWORK_TIMEOUT_ENV);
	if (env) {
		long timeout;

		errno = 0;
		timeout = strtol(env, NULL, 0);
		if (errno != 0 || timeout < -1L) {
			PERROR("Network timeout");
		} else {
			if (timeout > 0) {
				network_timeout = timeout;
			}
		}
	}
}

LTTNG_HIDDEN
unsigned long lttcomm_get_network_timeout(void)
{
	return network_timeout;
}
