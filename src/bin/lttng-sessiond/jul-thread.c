/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/uri.h>
#include <common/utils.h>

#include "fd-limit.h"
#include "jul-thread.h"
#include "lttng-sessiond.h"

/*
 * Note that there is not port here. It's set after this URI is parsed so we
 * can let the user define a custom one. However, localhost is ALWAYS the
 * default listening address.
 */
static const char *default_reg_uri = "tcp://localhost";

/*
 * Create and init socket from uri.
 */
static struct lttcomm_sock *init_tcp_socket(void)
{
	int ret;
	struct lttng_uri *uri = NULL;
	struct lttcomm_sock *sock = NULL;

	/*
	 * This should never fail since the URI is hardcoded and the port is set
	 * before this thread is launched.
	 */
	ret = uri_parse(default_reg_uri, &uri);
	assert(ret);
	assert(jul_tcp_port);
	uri->port = jul_tcp_port;

	sock = lttcomm_alloc_sock_from_uri(uri);
	uri_free(uri);
	if (sock == NULL) {
		ERR("[jul-thread] JUL allocating TCP socket");
		goto error;
	}

	ret = lttcomm_create_sock(sock);
	if (ret < 0) {
		goto error;
	}

	ret = sock->ops->bind(sock);
	if (ret < 0) {
		goto error;
	}

	ret = sock->ops->listen(sock, -1);
	if (ret < 0) {
		goto error;
	}

	DBG("[jul-thread] Listening on TCP port %u and socket %d", jul_tcp_port,
			sock->fd);

	return sock;

error:
	if (sock) {
		lttcomm_destroy_sock(sock);
	}
	return NULL;
}

/*
 * Close and destroy the given TCP socket.
 */
static void destroy_tcp_socket(struct lttcomm_sock *sock)
{
	assert(sock);

	DBG3("[jul-thread] Destroy TCP socket on port %u", jul_tcp_port);

	/* This will return gracefully if fd is invalid. */
	sock->ops->close(sock);
	lttcomm_destroy_sock(sock);
}

/*
 * This thread manage application notify communication.
 */
void *jul_thread_manage_registration(void *data)
{
	int i, ret, pollfd;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct lttcomm_sock *reg_sock;

	DBG("[jul-thread] Manage JUL application registration.");

	rcu_register_thread();
	rcu_thread_online();

	/* Create pollset with size 2, quit pipe and socket. */
	ret = sessiond_set_thread_pollset(&events, 2);
	if (ret < 0) {
		goto error_poll_create;
	}

	reg_sock = init_tcp_socket();
	if (!reg_sock) {
		goto error_tcp_socket;
	}

	/* Add create valid TCP socket to poll set. */
	ret = lttng_poll_add(&events, reg_sock->fd,
			LPOLLIN | LPOLLERR | LPOLLHUP | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	while (1) {
		DBG3("[jul-thread] Manage JUL polling on %d fds",
				LTTNG_POLL_GETNB(&events));

		/* Inifinite blocking call, waiting for transmission */
restart:
		ret = lttng_poll_wait(&events, -1);
		if (ret < 0) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				goto restart;
			}
			goto error;
		}
		nb_fd = ret;

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Thread quit pipe has been closed. Killing thread. */
			ret = sessiond_check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				goto exit;
			}

			/*
			 * Check first if this is a POLLERR since POLLIN is also included
			 * in an error value thus checking first.
			 */
			if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				/* Removing from the poll set */
				ret = lttng_poll_del(&events, pollfd);
				if (ret < 0) {
					goto error;
				}

				/* FIXME: Nullify the JUL socket for the associated ust app. */
			} else if (revents & (LPOLLIN | LPOLLPRI)) {
				/*
				 * FIXME: Handle JUL registration which must link an UST-app
				 * and this JUL socket.
				 */
			} else {
				ERR("Unknown poll events %u for sock %d", revents, pollfd);
				continue;
			}
		}
	}

exit:
error:
	destroy_tcp_socket(reg_sock);
error_tcp_socket:
	lttng_poll_clean(&events);
error_poll_create:
	DBG("[jul-thread] is cleaning up and stopping.");

	rcu_thread_offline();
	rcu_unregister_thread();
	return NULL;
}
