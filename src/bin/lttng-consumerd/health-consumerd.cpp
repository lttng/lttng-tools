/*
 * SPDX-FileCopyrightText: 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "health-consumerd.hpp"
#include "lttng-consumerd.hpp"

#include <common/common.hpp>
#include <common/compat/poll.hpp>
#include <common/consumer/consumer-timer.hpp>
#include <common/consumer/consumer.hpp>
#include <common/defaults.hpp>
#include <common/exception.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/utils.hpp>

#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ulimit.h>
#include <unistd.h>
#include <urcu/compiler.h>
#include <urcu/list.h>

int health_quit_pipe[2] = { -1, -1 };

namespace {
/* Global health check unix path */
char health_unix_sock_path[PATH_MAX];

/*
 * Send data on a unix socket using the liblttsessiondcomm API.
 *
 * Return lttcomm error code.
 */
int send_unix_sock(int sock, void *buf, size_t len)
{
	/* Check valid length */
	if (len == 0) {
		return -1;
	}

	return lttcomm_send_unix_sock(sock, buf, len);
}

void setup_health_path()
{
	if (strlen(health_unix_sock_path) != 0) {
		return;
	}

	const char *consumer_health_socket_fmt_string;
	const auto consumer_type = lttng_consumer_get_type();
	switch (consumer_type) {
	case LTTNG_CONSUMER_KERNEL:
	{
		consumer_health_socket_fmt_string = DEFAULT_KCONSUMER_HEALTH_UNIX_SOCK;
		break;
	}
	case LTTNG_CONSUMER64_UST:
	{
		consumer_health_socket_fmt_string = DEFAULT_USTCONSUMER64_HEALTH_UNIX_SOCK;
		break;
	}
	case LTTNG_CONSUMER32_UST:
	{
		consumer_health_socket_fmt_string = DEFAULT_USTCONSUMER32_HEALTH_UNIX_SOCK;
		break;
	}
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			"Invalid consumer type encountered while setting up consumerd health socket path");
	}

	const auto rundir_path =
		lttng::make_unique_wrapper<char, lttng::memory::free>(utils_get_rundir(0));
	if (!rundir_path) {
		LTTNG_THROW_ALLOCATION_FAILURE_ERROR(
			"Failed to determine RUNDIR for health socket creation");
	}

	DIAGNOSTIC_PUSH
	DIAGNOSTIC_IGNORE_FORMAT_NONLITERAL
	const auto fmt_ret = snprintf(health_unix_sock_path,
				      sizeof(health_unix_sock_path),
				      consumer_health_socket_fmt_string,
				      rundir_path.get());
	DIAGNOSTIC_POP
	if (fmt_ret < 0) {
		LTTNG_THROW_POSIX(fmt::format("Failed to format {} health socket path",
					      consumer_type),
				  errno);
	}
}
} /* namespace */

/*
 * Thread managing health check socket.
 */
void *thread_manage_health_consumerd(void *data __attribute__((unused)))
{
	int sock = -1, new_sock = -1, ret, i, err = -1;
	uint32_t nb_fd;
	struct lttng_poll_event events;
	struct health_comm_msg msg;
	struct health_comm_reply reply;
	int is_root;

	DBG("[thread] Manage health check started");

	try {
		setup_health_path();
	} catch (const lttng::runtime_error& ex) {
		ERR("Failed to setup health path: %s", ex.what());
		err = -1;
		goto error;
	}

	rcu_register_thread();

	/* We might hit an error path before this is created. */
	lttng_poll_init(&events);

	/* Create unix socket */
	sock = lttcomm_create_unix_sock(health_unix_sock_path);
	if (sock < 0) {
		ERR("Unable to create health check Unix socket");
		err = -1;
		goto error;
	}

	is_root = !getuid();
	if (is_root) {
		/* lttng health client socket path permissions */
		gid_t gid;

		ret = utils_get_group_id(tracing_group_name, true, &gid);
		if (ret) {
			/* Default to root group. */
			gid = 0;
		}

		ret = chown(health_unix_sock_path, 0, gid);
		if (ret < 0) {
			ERR("Unable to set group on %s", health_unix_sock_path);
			PERROR("chown");
			err = -1;
			goto error;
		}

		ret = chmod(health_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (ret < 0) {
			ERR("Unable to set permissions on %s", health_unix_sock_path);
			PERROR("chmod");
			err = -1;
			goto error;
		}
	}

	/*
	 * Set the CLOEXEC flag. Return code is useless because either way, the
	 * show must go on.
	 */
	(void) utils_set_fd_cloexec(sock);

	ret = lttcomm_listen_unix_sock(sock);
	if (ret < 0) {
		goto error;
	}

	/* Size is set to 2 for the quit pipe and registration socket. */
	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		ERR("Poll set creation failed");
		goto error;
	}

	ret = lttng_poll_add(&events, health_quit_pipe[0], LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, sock, LPOLLIN | LPOLLPRI);
	if (ret < 0) {
		goto error;
	}

	/* Perform prior memory accesses before decrementing ready */
	cmm_smp_mb__before_uatomic_dec();
	uatomic_dec(&lttng_consumer_ready);

	while (true) {
		DBG("Health check ready");

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
			const auto revents = LTTNG_POLL_GETEV(&events, i);
			const auto pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Activity on health quit pipe, exiting. */
			if (pollfd == health_quit_pipe[0]) {
				DBG("Activity on health quit pipe");
				err = 0;
				goto exit;
			}

			/* Event on the registration socket */
			if (pollfd == sock) {
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP) &&
				    !(revents & LPOLLIN)) {
					ERR("Health socket poll error");
					goto error;
				}
			}
		}

		new_sock = lttcomm_accept_unix_sock(sock);
		if (new_sock < 0) {
			goto error;
		}

		/*
		 * Set the CLOEXEC flag. Return code is useless because either way, the
		 * show must go on.
		 */
		(void) utils_set_fd_cloexec(new_sock);

		DBG("Receiving data from client for health...");
		ret = lttcomm_recv_unix_sock(new_sock, (void *) &msg, sizeof(msg));
		if (ret <= 0) {
			DBG("Nothing recv() from client... continuing");
			ret = close(new_sock);
			if (ret) {
				PERROR("close");
			}
			new_sock = -1;
			continue;
		}

		rcu_thread_online();

		LTTNG_ASSERT(msg.cmd == HEALTH_CMD_CHECK);

		memset(&reply, 0, sizeof(reply));
		for (i = 0; i < NR_HEALTH_CONSUMERD_TYPES; i++) {
			/*
			 * health_check_state return 0 if thread is in
			 * error.
			 */
			if (!health_check_state(health_consumerd, i)) {
				reply.ret_code |= 1ULL << i;
			}
		}

		DBG("Health check return value %" PRIx64, reply.ret_code);

		ret = send_unix_sock(new_sock, (void *) &reply, sizeof(reply));
		if (ret < 0) {
			ERR("Failed to send health data back to client");
		}

		/* End of transmission */
		ret = close(new_sock);
		if (ret) {
			PERROR("close");
		}
		new_sock = -1;
	}

exit:
error:
	if (err) {
		ERR("Health error occurred in %s", __func__);
	}
	DBG("Health check thread dying");
	unlink(health_unix_sock_path);
	if (sock >= 0) {
		ret = close(sock);
		if (ret) {
			PERROR("close");
		}
	}

	lttng_poll_clean(&events);

	rcu_unregister_thread();
	return nullptr;
}
