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

#define _LGPL_SOURCE
#include <assert.h>

#include <common/common.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/uri.h>
#include <common/utils.h>

#include <common/compat/endian.h>

#include "fd-limit.h"
#include "agent-thread.h"
#include "agent.h"
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
 * Update agent application using the given socket. This is done just after
 * registration was successful.
 *
 * This is a quite heavy call in terms of locking since the session list lock
 * AND session lock are acquired.
 */
static void update_agent_app(struct agent_app *app)
{
	struct ltt_session *session, *stmp;
	struct ltt_session_list *list;

	list = session_get_list();
	assert(list);

	session_lock_list();
	cds_list_for_each_entry_safe(session, stmp, &list->head, list) {
		session_lock(session);
		if (session->ust_session) {
			struct agent *agt;

			rcu_read_lock();
			agt = trace_ust_find_agent(session->ust_session, app->domain);
			if (agt) {
				agent_update(agt, app->sock->fd);
			}
			rcu_read_unlock();
		}
		session_unlock(session);
	}
	session_unlock_list();
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
	assert(config.agent_tcp_port);
	uri->port = config.agent_tcp_port;

	sock = lttcomm_alloc_sock_from_uri(uri);
	uri_free(uri);
	if (sock == NULL) {
		ERR("[agent-thread] agent allocating TCP socket");
		goto error;
	}

	ret = lttcomm_create_sock(sock);
	if (ret < 0) {
		goto error;
	}

	ret = sock->ops->bind(sock);
	if (ret < 0) {
		WARN("Another session daemon is using this agent port. Agent support "
				"will be deactivated to prevent interfering with the tracing.");
		goto error;
	}

	ret = sock->ops->listen(sock, -1);
	if (ret < 0) {
		goto error;
	}

	DBG("[agent-thread] Listening on TCP port %u and socket %d",
			config.agent_tcp_port, sock->fd);

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

	DBG3("[agent-thread] Destroy TCP socket on port %u", config.agent_tcp_port);

	/* This will return gracefully if fd is invalid. */
	sock->ops->close(sock);
	lttcomm_destroy_sock(sock);
}

/*
 * Handle a new agent registration using the reg socket. After that, a new
 * agent application is added to the global hash table and attach to an UST app
 * object. If r_app is not NULL, the created app is set to the pointer.
 *
 * Return the new FD created upon accept() on success or else a negative errno
 * value.
 */
static int handle_registration(struct lttcomm_sock *reg_sock,
		struct agent_app **r_app)
{
	int ret;
	pid_t pid;
	uint32_t major_version, minor_version;
	ssize_t size;
	enum lttng_domain_type domain;
	struct agent_app *app;
	struct agent_register_msg msg;
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
	domain = be32toh(msg.domain);
	pid = be32toh(msg.pid);
	major_version = be32toh(msg.major_version);
	minor_version = be32toh(msg.minor_version);

	/* Test communication protocol version of the registring agent. */
	if (major_version != AGENT_MAJOR_VERSION) {
		ret = -EINVAL;
		goto error_socket;
	}
	if (minor_version != AGENT_MINOR_VERSION) {
		ret = -EINVAL;
		goto error_socket;
	}

	DBG2("[agent-thread] New registration for pid %d domain %d on socket %d",
			pid, domain, new_sock->fd);

	app = agent_create_app(pid, domain, new_sock);
	if (!app) {
		ret = -ENOMEM;
		goto error_socket;
	}

	/*
	 * Add before assigning the socket value to the UST app so it can be found
	 * concurrently.
	 */
	agent_add_app(app);

	/*
	 * We don't need to attach the agent app to the app. If we ever do so, we
	 * should consider both registration order of agent before app and app
	 * before agent.
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
void *agent_thread_manage_registration(void *data)
{
	int i, ret, pollfd;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct lttcomm_sock *reg_sock;

	DBG("[agent-thread] Manage agent application registration.");

	rcu_register_thread();
	rcu_thread_online();

	/* Agent initialization call MUST be called before starting the thread. */
	assert(agent_apps_ht_by_sock);

	/* Create pollset with size 2, quit pipe and socket. */
	ret = sessiond_set_thread_pollset(&events, 2);
	if (ret < 0) {
		goto error_poll_create;
	}

	reg_sock = init_tcp_socket();
	if (!reg_sock) {
		goto error_tcp_socket;
	}

	/* Add TCP socket to poll set. */
	ret = lttng_poll_add(&events, reg_sock->fd,
			LPOLLIN | LPOLLERR | LPOLLHUP | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	while (1) {
		DBG3("[agent-thread] Manage agent polling");

		/* Inifinite blocking call, waiting for transmission */
restart:
		ret = lttng_poll_wait(&events, -1);
		DBG3("[agent-thread] Manage agent return from poll on %d fds",
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
		DBG3("[agent-thread] %d fd ready", nb_fd);

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

			if (revents & LPOLLIN) {
				int new_fd;
				struct agent_app *app = NULL;

				assert(pollfd == reg_sock->fd);
				new_fd = handle_registration(reg_sock, &app);
				if (new_fd < 0) {
					continue;
				}
				/* Should not have a NULL app on success. */
				assert(app);

				/*
				 * Since this is a command socket (write then read),
				 * only add poll error event to only detect shutdown.
				 */
				ret = lttng_poll_add(&events, new_fd,
						LPOLLERR | LPOLLHUP | LPOLLRDHUP);
				if (ret < 0) {
					agent_destroy_app_by_sock(new_fd);
					continue;
				}

				/* Update newly registered app. */
				update_agent_app(app);

				/* On failure, the poll will detect it and clean it up. */
				ret = agent_send_registration_done(app);
				if (ret < 0) {
					/* Removing from the poll set */
					ret = lttng_poll_del(&events, new_fd);
					if (ret < 0) {
						goto error;
					}
					agent_destroy_app_by_sock(new_fd);
					continue;
				}
			} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				/* Removing from the poll set */
				ret = lttng_poll_del(&events, pollfd);
				if (ret < 0) {
					goto error;
				}
				agent_destroy_app_by_sock(pollfd);
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto error;
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
	DBG("[agent-thread] is cleaning up and stopping.");

	rcu_thread_offline();
	rcu_unregister_thread();
	return NULL;
}
