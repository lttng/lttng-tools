/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "agent-thread.hpp"
#include "agent.hpp"
#include "fd-limit.hpp"
#include "lttng-sessiond.hpp"
#include "session.hpp"
#include "thread.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/compat/endian.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/urcu.hpp>
#include <common/uri.hpp>
#include <common/utils.hpp>

#include <fcntl.h>

namespace {
struct thread_notifiers {
	struct lttng_pipe *quit_pipe;
	sem_t ready;
};

struct agent_app_id {
	pid_t pid;
	enum lttng_domain_type domain;
};

struct agent_protocol_version {
	unsigned int major, minor;
};

int agent_tracing_enabled = -1;

/*
 * Note that there is not port here. It's set after this URI is parsed so we
 * can let the user define a custom one. However, localhost is ALWAYS the
 * default listening address.
 */
const char *default_reg_uri = "tcp://" DEFAULT_NETWORK_VIEWER_BIND_ADDRESS;
} /* namespace */

/*
 * Update agent application using the given socket. This is done just after
 * registration was successful.
 *
 * This will acquire the various sessions' lock; none must be held by the
 * caller.
 * The caller must hold the session list lock.
 */
static void update_agent_app(const struct agent_app *app)
{
	struct ltt_session *session, *stmp;
	struct ltt_session_list *list;
	struct agent *trigger_agent;
	struct lttng_ht_iter iter;

	list = session_get_list();
	LTTNG_ASSERT(list);

	cds_list_for_each_entry_safe (session, stmp, &list->head, list) {
		if (!session_get(session)) {
			continue;
		}

		session_lock(session);
		if (session->ust_session) {
			const struct agent *agt;

			lttng::urcu::read_lock_guard read_lock;
			agt = trace_ust_find_agent(session->ust_session, app->domain);
			if (agt) {
				agent_update(agt, app);
			}
		}
		session_unlock(session);
		session_put(session);
	}

	{
		/*
		 * We are protected against the addition of new events by the session
		 * list lock being held.
		 */
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			the_trigger_agents_ht_by_domain->ht, &iter.iter, trigger_agent, node.node) {
			agent_update(trigger_agent, app);
		}
	}
}

/*
 * Create and init socket from uri.
 */
static struct lttcomm_sock *init_tcp_socket()
{
	int ret;
	struct lttng_uri *uri = nullptr;
	struct lttcomm_sock *sock = nullptr;
	unsigned int port;
	bool bind_succeeded = false;

	/*
	 * This should never fail since the URI is hardcoded and the port is set
	 * before this thread is launched.
	 */
	ret = uri_parse(default_reg_uri, &uri);
	LTTNG_ASSERT(ret);
	LTTNG_ASSERT(the_config.agent_tcp_port.begin > 0);
	uri->port = the_config.agent_tcp_port.begin;

	sock = lttcomm_alloc_sock_from_uri(uri);
	uri_free(uri);
	if (sock == nullptr) {
		ERR("agent allocating TCP socket");
		goto error;
	}

	ret = lttcomm_create_sock(sock);
	if (ret < 0) {
		goto error;
	}

	for (port = the_config.agent_tcp_port.begin; port <= the_config.agent_tcp_port.end;
	     port++) {
		ret = lttcomm_sock_set_port(sock, (uint16_t) port);
		if (ret) {
			ERR("Failed to set port %u on socket", port);
			goto error;
		}
		DBG3("Trying to bind on port %u", port);
		ret = sock->ops->bind(sock);
		if (!ret) {
			bind_succeeded = true;
			break;
		}

		if (errno == EADDRINUSE) {
			DBG("Failed to bind to port %u since it is already in use", port);
		} else {
			PERROR("Failed to bind to port %u", port);
			goto error;
		}
	}

	if (!bind_succeeded) {
		if (the_config.agent_tcp_port.begin == the_config.agent_tcp_port.end) {
			WARN("Another process is already using the agent port %i. "
			     "Agent support will be deactivated.",
			     the_config.agent_tcp_port.begin);
			goto error;
		} else {
			WARN("All ports in the range [%i, %i] are already in use. "
			     "Agent support will be deactivated.",
			     the_config.agent_tcp_port.begin,
			     the_config.agent_tcp_port.end);
			goto error;
		}
	}

	ret = sock->ops->listen(sock, -1);
	if (ret < 0) {
		goto error;
	}

	DBG("Listening on TCP port %u and socket %d", port, sock->fd);

	return sock;

error:
	if (sock) {
		lttcomm_destroy_sock(sock);
	}
	return nullptr;
}

/*
 * Close and destroy the given TCP socket.
 */
static void destroy_tcp_socket(struct lttcomm_sock *sock)
{
	int ret;
	uint16_t port;

	LTTNG_ASSERT(sock);

	ret = lttcomm_sock_get_port(sock, &port);
	if (ret) {
		ERR("Failed to get port of agent TCP socket");
		port = 0;
	}

	DBG3("Destroy TCP socket on port %" PRIu16, port);

	/* This will return gracefully if fd is invalid. */
	sock->ops->close(sock);
	lttcomm_destroy_sock(sock);
}

static const char *domain_type_str(enum lttng_domain_type domain_type)
{
	switch (domain_type) {
	case LTTNG_DOMAIN_NONE:
		return "none";
	case LTTNG_DOMAIN_KERNEL:
		return "kernel";
	case LTTNG_DOMAIN_UST:
		return "ust";
	case LTTNG_DOMAIN_JUL:
		return "jul";
	case LTTNG_DOMAIN_LOG4J:
		return "log4j";
	case LTTNG_DOMAIN_PYTHON:
		return "python";
	default:
		return "unknown";
	}
}

static bool is_agent_protocol_version_supported(const struct agent_protocol_version *version)
{
	const bool is_supported = version->major == AGENT_MAJOR_VERSION &&
		version->minor == AGENT_MINOR_VERSION;

	if (!is_supported) {
		WARN("Refusing agent connection: unsupported protocol version %ui.%ui, expected %i.%i",
		     version->major,
		     version->minor,
		     AGENT_MAJOR_VERSION,
		     AGENT_MINOR_VERSION);
	}

	return is_supported;
}

/*
 * Handle a new agent connection on the registration socket.
 *
 * Returns 0 on success, or else a negative errno value.
 * On success, the resulting socket is returned through `agent_app_socket`
 * and the application's reported id is updated through `agent_app_id`.
 */
static int accept_agent_connection(struct lttcomm_sock *reg_sock,
				   struct agent_app_id *agent_app_id,
				   struct lttcomm_sock **agent_app_socket)
{
	int ret;
	struct agent_protocol_version agent_version;
	ssize_t size;
	struct agent_register_msg msg;
	struct lttcomm_sock *new_sock;

	LTTNG_ASSERT(reg_sock);

	new_sock = reg_sock->ops->accept(reg_sock);
	if (!new_sock) {
		ret = -ENOTCONN;
		goto end;
	}

	size = new_sock->ops->recvmsg(new_sock, &msg, sizeof(msg), 0);
	if (size < sizeof(msg)) {
		if (size < 0) {
			PERROR("Failed to register new agent application");
		} else if (size != 0) {
			ERR("Failed to register new agent application: invalid registration message length: expected length = %zu, message length = %zd",
			    sizeof(msg),
			    size);
		} else {
			DBG("Failed to register new agent application: connection closed");
		}
		ret = -EINVAL;
		goto error_close_socket;
	}

	agent_version = (struct agent_protocol_version){
		be32toh(msg.major_version),
		be32toh(msg.minor_version),
	};

	/* Test communication protocol version of the registering agent. */
	if (!is_agent_protocol_version_supported(&agent_version)) {
		ret = -EINVAL;
		goto error_close_socket;
	}

	*agent_app_id = (struct agent_app_id){
		.pid = (pid_t) be32toh(msg.pid),
		.domain = (lttng_domain_type) be32toh(msg.domain),
	};

	DBG2("New registration for agent application: pid = %ld, domain = %s, socket fd = %d",
	     (long) agent_app_id->pid,
	     domain_type_str(agent_app_id->domain),
	     new_sock->fd);

	*agent_app_socket = new_sock;
	new_sock = nullptr;
	ret = 0;
	goto end;

error_close_socket:
	new_sock->ops->close(new_sock);
	lttcomm_destroy_sock(new_sock);
end:
	return ret;
}

bool agent_tracing_is_enabled()
{
	int enabled;

	enabled = uatomic_read(&agent_tracing_enabled);
	LTTNG_ASSERT(enabled != -1);
	return enabled == 1;
}

/*
 * Write agent TCP port using the rundir.
 */
static int write_agent_port(uint16_t port)
{
	return utils_create_pid_file((pid_t) port, the_config.agent_port_file_path.value);
}

static void mark_thread_as_ready(struct thread_notifiers *notifiers)
{
	DBG("Marking agent management thread as ready");
	sem_post(&notifiers->ready);
}

static void wait_until_thread_is_ready(struct thread_notifiers *notifiers)
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
	int i, ret;
	uint32_t nb_fd;
	struct lttng_poll_event events;
	struct lttcomm_sock *reg_sock;
	struct thread_notifiers *notifiers = (thread_notifiers *) data;
	const auto thread_quit_pipe_fd = lttng_pipe_get_readfd(notifiers->quit_pipe);

	DBG("Manage agent application registration.");

	rcu_register_thread();
	rcu_thread_online();

	/* Agent initialization call MUST be called before starting the thread. */
	LTTNG_ASSERT(the_agent_apps_ht_by_sock);

	/* Create pollset with size 2, quit pipe and registration socket. */
	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error_poll_create;
	}

	ret = lttng_poll_add(&events, thread_quit_pipe_fd, LPOLLIN);
	if (ret < 0) {
		goto error_tcp_socket;
	}

	reg_sock = init_tcp_socket();
	if (reg_sock) {
		uint16_t port;

		ret = lttcomm_sock_get_port(reg_sock, &port);
		LTTNG_ASSERT(ret == 0);

		ret = write_agent_port(port);
		if (ret) {
			ERR("Failed to create agent port file: agent tracing will be unavailable");
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

	/* Add TCP socket to the poll set. */
	ret = lttng_poll_add(&events, reg_sock->fd, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	while (true) {
		DBG3("Manage agent polling");

		/* Inifinite blocking call, waiting for transmission */
	restart:
		ret = lttng_poll_wait(&events, -1);
		DBG3("Manage agent return from poll on %d fds", LTTNG_POLL_GETNB(&events));
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
		DBG3("%d fd ready", nb_fd);

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			const auto revents = LTTNG_POLL_GETEV(&events, i);
			const auto pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Activity on thread quit pipe, exiting. */
			if (pollfd == thread_quit_pipe_fd) {
				DBG("Activity on thread quit pipe");
				goto exit;
			}

			/* Activity on the registration socket. */
			if (revents & LPOLLIN) {
				struct agent_app_id new_app_id;
				struct agent_app *new_app = nullptr;
				struct lttcomm_sock *new_app_socket;
				int new_app_socket_fd;

				LTTNG_ASSERT(pollfd == reg_sock->fd);

				ret = accept_agent_connection(
					reg_sock, &new_app_id, &new_app_socket);
				if (ret < 0) {
					/* Errors are already logged. */
					continue;
				}

				/*
				 * new_app_socket's ownership has been
				 * transferred to the new agent app.
				 */
				new_app = agent_create_app(
					new_app_id.pid, new_app_id.domain, new_app_socket);
				if (!new_app) {
					new_app_socket->ops->close(new_app_socket);
					continue;
				}
				new_app_socket_fd = new_app_socket->fd;
				new_app_socket = nullptr;

				/*
				 * Since this is a command socket (write then
				 * read), only add poll error event to only
				 * detect shutdown.
				 */
				ret = lttng_poll_add(&events, new_app_socket_fd, LPOLLRDHUP);
				if (ret < 0) {
					agent_destroy_app(new_app);
					continue;
				}

				/*
				 * Prevent sessions from being modified while
				 * the agent application's configuration is
				 * updated.
				 */
				session_lock_list();

				/*
				 * Update the newly registered applications's
				 * configuration.
				 */
				update_agent_app(new_app);

				ret = agent_send_registration_done(new_app);
				if (ret < 0) {
					agent_destroy_app(new_app);
					/* Removing from the poll set. */
					ret = lttng_poll_del(&events, new_app_socket_fd);
					if (ret < 0) {
						session_unlock_list();
						goto error;
					}
					continue;
				}

				/* Publish the new agent app. */
				agent_add_app(new_app);

				session_unlock_list();
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
	DBG("Cleaning up and stopping.");
	rcu_thread_offline();
	rcu_unregister_thread();
	return nullptr;
}

static bool shutdown_agent_management_thread(void *data)
{
	struct thread_notifiers *notifiers = (thread_notifiers *) data;
	const int write_fd = lttng_pipe_get_writefd(notifiers->quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

static void cleanup_agent_management_thread(void *data)
{
	struct thread_notifiers *notifiers = (thread_notifiers *) data;

	lttng_pipe_destroy(notifiers->quit_pipe);
	sem_destroy(&notifiers->ready);
	free(notifiers);
}

bool launch_agent_management_thread()
{
	struct thread_notifiers *notifiers;
	struct lttng_thread *thread;

	notifiers = zmalloc<thread_notifiers>();
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
