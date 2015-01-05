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
#include "session.h"
#include "utils.h"

/*
 * Note that there is not port here. It's set after this URI is parsed so we
 * can let the user define a custom one. However, localhost is ALWAYS the
 * default listening address.
 */
static const char *default_reg_uri =
	"tcp://" DEFAULT_NETWORK_VIEWER_BIND_ADDRESS;

/*
 * Update JUL application using the given socket. This is done just after
 * registration was successful.
 *
 * This is a quite heavy call in terms of locking since the session list lock
 * AND session lock are acquired.
 */
static void update_jul_app(int sock)
{
	struct ltt_session *session, *stmp;
	struct ltt_session_list *list;

	list = session_get_list();
	assert(list);

	session_lock_list();
	cds_list_for_each_entry_safe(session, stmp, &list->head, list) {
		session_lock(session);
		if (session->ust_session) {
			jul_update(&session->ust_session->domain_jul, sock);
		}
		session_unlock(session);
	}
	session_unlock_list();
}

/*
 * Destroy a JUL application by socket.
 */
static void destroy_jul_app(int sock)
{
	struct jul_app *app;

	assert(sock >= 0);

	/*
	 * Not finding an application is a very important error that should NEVER
	 * happen. The hash table deletion is ONLY done through this call even on
	 * thread cleanup.
	 */
	rcu_read_lock();
	app = jul_find_app_by_sock(sock);
	assert(app);
	rcu_read_unlock();

	/* RCU read side lock is taken in this function call. */
	jul_delete_app(app);

	/* The application is freed in a RCU call but the socket is closed here. */
	jul_destroy_app(app);
}

/*
 * Cleanup remaining JUL apps in the hash table. This should only be called in
 * the exit path of the thread.
 */
static void clean_jul_apps_ht(void)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	DBG3("[jul-thread] Cleaning JUL apps ht");

	rcu_read_lock();
	cds_lfht_for_each_entry(jul_apps_ht_by_sock->ht, &iter.iter, node, node) {
		struct jul_app *app;

		app = caa_container_of(node, struct jul_app, node);
		destroy_jul_app(app->sock->fd);
	}
	rcu_read_unlock();
}

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
		WARN("An other session daemon is using this JUL port. JUL support "
				"will be deactivated not interfering with the tracing.");
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
 * Handle a new JUL registration using the reg socket. After that, a new JUL
 * application is added to the global hash table and attach to an UST app
 * object. If r_app is not NULL, the created app is set to the pointer.
 *
 * Return the new FD created upon accept() on success or else a negative errno
 * value.
 */
static int handle_registration(struct lttcomm_sock *reg_sock,
		struct jul_app **r_app)
{
	int ret;
	pid_t pid;
	ssize_t size;
	struct jul_app *app;
	struct jul_register_msg msg;
	struct lttcomm_sock *new_sock;

	assert(reg_sock);

	new_sock = reg_sock->ops->accept(reg_sock);
	if (!new_sock) {
		ret = -ENOTCONN;
		goto error;
	}

	size = new_sock->ops->recvmsg(new_sock, &msg, sizeof(msg), 0);
	if (size < sizeof(msg)) {
		ret = -EINVAL;
		goto error_socket;
	}
	pid = be32toh(msg.pid);

	DBG2("[jul-thread] New registration for pid %d on socket %d", pid,
			new_sock->fd);

	app = jul_create_app(pid, new_sock);
	if (!app) {
		ret = -ENOMEM;
		goto error_socket;
	}

	/*
	 * Add before assigning the socket value to the UST app so it can be found
	 * concurrently.
	 */
	jul_add_app(app);

	/*
	 * We don't need to attach the JUL app to the app. If we ever do
	 * so, we should consider both registration order of JUL before
	 * app and app before JUL.
	 */

	if (r_app) {
		*r_app = app;
	}

	return new_sock->fd;

error_socket:
	new_sock->ops->close(new_sock);
	lttcomm_destroy_sock(new_sock);
error:
	return ret;
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

	/* JUL initialization call MUST be called before starting the thread. */
	assert(jul_apps_ht_by_sock);

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
		DBG3("[jul-thread] Manage JUL polling");

		/* Inifinite blocking call, waiting for transmission */
restart:
		ret = lttng_poll_wait(&events, -1);
		DBG3("[jul-thread] Manage agent return from poll on %d fds",
				LTTNG_POLL_GETNB(&events));
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
		DBG3("[jul-thread] %d fd ready", nb_fd);

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

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

				destroy_jul_app(pollfd);
			} else if (revents & (LPOLLIN)) {
				int new_fd;
				struct jul_app *app = NULL;

				/* Pollin event of JUL app socket should NEVER happen. */
				assert(pollfd == reg_sock->fd);

				new_fd = handle_registration(reg_sock, &app);
				if (new_fd < 0) {
					WARN("[jul-thread] JUL registration failed. Ignoring.");
					/* Somehow the communication failed. Just continue. */
					continue;
				}
				/* Should not have a NULL app on success. */
				assert(app);

				/* Only add poll error event to only detect shutdown. */
				ret = lttng_poll_add(&events, new_fd,
						LPOLLERR | LPOLLHUP | LPOLLRDHUP);
				if (ret < 0) {
					destroy_jul_app(new_fd);
					continue;
				}

				/* Update newly registered app. */
				update_jul_app(new_fd);

				/* On failure, the poll will detect it and clean it up. */
				(void) jul_send_registration_done(app);
			} else {
				ERR("Unknown poll events %u for sock %d", revents, pollfd);
				continue;
			}
		}
	}

exit:
	/* Whatever happens, try to delete it and exit. */
	(void) lttng_poll_del(&events, reg_sock->fd);
error:
	destroy_tcp_socket(reg_sock);
error_tcp_socket:
	lttng_poll_clean(&events);
error_poll_create:
	DBG("[jul-thread] is cleaning up and stopping.");

	if (jul_apps_ht_by_sock) {
		clean_jul_apps_ht();
		lttng_ht_destroy(jul_apps_ht_by_sock);
	}

	rcu_thread_offline();
	rcu_unregister_thread();
	return NULL;
}
