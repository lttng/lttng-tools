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
#include "thread.h"

struct thread_notifiers {
	struct lttng_pipe *quit_pipe;
	sem_t ready;
};

static int agent_tracing_enabled = -1;

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
		if (!session_get(session)) {
			continue;
		}

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
		session_put(session);
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
	unsigned int port;
	bool bind_succeeded = false;

	/*
	 * This should never fail since the URI is hardcoded and the port is set
	 * before this thread is launched.
	 */
	ret = uri_parse(default_reg_uri, &uri);
	assert(ret);
	assert(config.agent_tcp_port.begin > 0);
	uri->port = config.agent_tcp_port.begin;

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

	for (port = config.agent_tcp_port.begin;
			port <= config.agent_tcp_port.end; port++) {
		ret = lttcomm_sock_set_port(sock, (uint16_t) port);
		if (ret) {
			ERR("[agent-thread] Failed to set port %u on socket",
					port);
			goto error;
		}
		DBG3("[agent-thread] Trying to bind on port %u", port);
		ret = sock->ops->bind(sock);
		if (!ret) {
			bind_succeeded = true;
			break;
		}

		if (errno == EADDRINUSE) {
			DBG("Failed to bind to port %u since it is already in use",
					port);
		} else {
			PERROR("Failed to bind to port %u", port);
			goto error;
		}
	}

	if (!bind_succeeded) {
		if (config.agent_tcp_port.begin == config.agent_tcp_port.end) {
			WARN("Another process is already using the agent port %i. "
					"Agent support will be deactivated.",
					config.agent_tcp_port.begin);
			goto error;
		} else {
			WARN("All ports in the range [%i, %i] are already in use. "
					"Agent support will be deactivated.",
					config.agent_tcp_port.begin,
					config.agent_tcp_port.end);
			goto error;
		}
	}

	ret = sock->ops->listen(sock, -1);
	if (ret < 0) {
		goto error;
	}

	DBG("[agent-thread] Listening on TCP port %u and socket %d",
			port, sock->fd);

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
	int ret;
	uint16_t port;

	assert(sock);

	ret = lttcomm_sock_get_port(sock, &port);
	if (ret) {
		ERR("[agent-thread] Failed to get port of agent TCP socket");
		port = 0;
	}

	DBG3("[agent-thread] Destroy TCP socket on port %" PRIu16,
			port);

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

bool agent_tracing_is_enabled(void)
{
	int enabled;

	enabled = uatomic_read(&agent_tracing_enabled);
	assert(enabled != -1);
	return enabled == 1;
}

/*
 * Write agent TCP port using the rundir.
 */
static int write_agent_port(uint16_t port)
{
	return utils_create_pid_file((pid_t) port,
			config.agent_port_file_path.value);
}

static
void mark_thread_as_ready(struct thread_notifiers *notifiers)
{
	DBG("Marking agent management thread as ready");
	sem_post(&notifiers->ready);
}

static
void wait_until_thread_is_ready(struct thread_notifiers *notifiers)
{
	DBG("Waiting for agent management thread to be ready");
	sem_wait(&notifiers->ready);
	DBG("Agent management thread is ready");
}

/*
 * This thread manage application notify communication.
 */
static void *thread_agent_management(void *data)
{
	int i, ret, pollfd;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct lttcomm_sock *reg_sock;
	struct thread_notifiers *notifiers = data;
	const int quit_pipe_read_fd = lttng_pipe_get_readfd(
			notifiers->quit_pipe);

	DBG("[agent-thread] Manage agent application registration.");

	rcu_register_thread();
	rcu_thread_online();

	/* Agent initialization call MUST be called before starting the thread. */
	assert(agent_apps_ht_by_sock);

	/* Create pollset with size 2, quit pipe and registration socket. */
	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error_poll_create;
	}

	ret = lttng_poll_add(&events, quit_pipe_read_fd,
			LPOLLIN | LPOLLERR);
	if (ret < 0) {
		goto error_tcp_socket;
	}

	reg_sock = init_tcp_socket();
	if (reg_sock) {
		uint16_t port;

		assert(lttcomm_sock_get_port(reg_sock, &port) == 0);

		ret = write_agent_port(port);
		if (ret) {
			ERR("[agent-thread] Failed to create agent port file: agent tracing will be unavailable");
			/* Don't prevent the launch of the sessiond on error. */
			mark_thread_as_ready(notifiers);
			goto error;
		}
	} else {
		/* Don't prevent the launch of the sessiond on error. */
		mark_thread_as_ready(notifiers);
		goto error_tcp_socket;
	}

	/*
	 * Signal that the agent thread is ready. The command thread
	 * may start to query whether or not agent tracing is enabled.
	 */
	uatomic_set(&agent_tracing_enabled, 1);
	mark_thread_as_ready(notifiers);

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

			/* Thread quit pipe has been closed. Killing thread. */
			if (pollfd == quit_pipe_read_fd) {
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
	uatomic_set(&agent_tracing_enabled, 0);
	DBG("[agent-thread] Cleaning up and stopping.");
	rcu_thread_offline();
	rcu_unregister_thread();
	return NULL;
}

static bool shutdown_agent_management_thread(void *data)
{
	struct thread_notifiers *notifiers = data;
	const int write_fd = lttng_pipe_get_writefd(notifiers->quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

static void cleanup_agent_management_thread(void *data)
{
	struct thread_notifiers *notifiers = data;

	lttng_pipe_destroy(notifiers->quit_pipe);
	sem_destroy(&notifiers->ready);
	free(notifiers);
}

bool launch_agent_management_thread(void)
{
	struct thread_notifiers *notifiers;
	struct lttng_thread *thread;

	notifiers = zmalloc(sizeof(*notifiers));
	if (!notifiers) {
		goto error_alloc;
	}

	sem_init(&notifiers->ready, 0, 0);
	notifiers->quit_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!notifiers->quit_pipe) {
		goto error;
	}
	thread = lttng_thread_create("Agent management",
			thread_agent_management,
			shutdown_agent_management_thread,
			cleanup_agent_management_thread,
			notifiers);
	if (!thread) {
		goto error;
	}
	wait_until_thread_is_ready(notifiers);
	lttng_thread_put(thread);
	return true;
error:
	cleanup_agent_management_thread(notifiers);
error_alloc:
	return false;
}
