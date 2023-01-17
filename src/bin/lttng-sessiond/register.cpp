/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "fd-limit.hpp"
#include "health-sessiond.hpp"
#include "lttng-sessiond.hpp"
#include "register.hpp"
#include "testpoint.hpp"
#include "thread.hpp"
#include "utils.hpp"

#include <common/futex.hpp>
#include <common/macros.hpp>
#include <common/shm.hpp>
#include <common/utils.hpp>

#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <urcu.h>

namespace {
struct thread_state {
	struct lttng_pipe *quit_pipe;
	struct ust_cmd_queue *ust_cmd_queue;
	sem_t ready;
	bool running;
	int application_socket;
};
} /* namespace */

/*
 * Creates the application socket.
 */
static int create_application_socket()
{
	int ret = 0;
	int apps_sock;

	/* Create the application unix socket */
	apps_sock = lttcomm_create_unix_sock(the_config.apps_unix_sock_path.value);
	if (apps_sock < 0) {
		ERR("Create unix sock failed: %s", the_config.apps_unix_sock_path.value);
		ret = -1;
		goto end;
	}

	/* Set the cloexec flag */
	ret = utils_set_fd_cloexec(apps_sock);
	if (ret < 0) {
		ERR("Unable to set CLOEXEC flag to the app Unix socket (fd: %d). "
		    "Continuing but note that the consumer daemon will have a "
		    "reference to this socket on exec()",
		    apps_sock);
	}

	/* File permission MUST be 666 */
	ret = chmod(the_config.apps_unix_sock_path.value,
		    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (ret < 0) {
		PERROR("Set file permissions failed on %s", the_config.apps_unix_sock_path.value);
		goto error_close_socket;
	}

	DBG3("Session daemon application socket created (fd = %d) ", apps_sock);
	ret = apps_sock;
end:
	return ret;
error_close_socket:
	if (close(apps_sock)) {
		PERROR("Failed to close application socket in error path");
	}
	apps_sock = -1;
	ret = -1;
	goto end;
}

/*
 * Notify UST applications using the shm mmap futex.
 */
static int notify_ust_apps(int active, bool is_root)
{
	char *wait_shm_mmap;

	DBG("Notifying applications of session daemon state: %d", active);

	/* See shm.c for this call implying mmap, shm and futex calls */
	wait_shm_mmap = shm_ust_get_mmap(the_config.wait_shm_path.value, is_root);
	if (wait_shm_mmap == nullptr) {
		goto error;
	}

	/* Wake waiting process */
	futex_wait_update((int32_t *) wait_shm_mmap, active);

	/* Apps notified successfully */
	return 0;

error:
	return -1;
}

static void cleanup_application_registration_thread(void *data)
{
	struct thread_state *thread_state = (struct thread_state *) data;

	if (!data) {
		return;
	}

	lttng_pipe_destroy(thread_state->quit_pipe);
	free(thread_state);
}

static void set_thread_status(struct thread_state *thread_state, bool running)
{
	DBG("Marking application registration thread's state as %s", running ? "running" : "error");
	thread_state->running = running;
	sem_post(&thread_state->ready);
}

static bool wait_thread_status(struct thread_state *thread_state)
{
	DBG("Waiting for application registration thread to be ready");
	sem_wait(&thread_state->ready);
	if (thread_state->running) {
		DBG("Application registration thread is ready");
	} else {
		ERR("Initialization of application registration thread failed");
	}

	return thread_state->running;
}

static void thread_init_cleanup(void *data)
{
	struct thread_state *thread_state = (struct thread_state *) data;

	set_thread_status(thread_state, false);
}

/*
 * This thread manage application registration.
 */
static void *thread_application_registration(void *data)
{
	int sock = -1, i, ret, err = -1;
	uint32_t nb_fd;
	struct lttng_poll_event events;
	/*
	 * Gets allocated in this thread, enqueued to a global queue, dequeued
	 * and freed in the manage apps thread.
	 */
	struct ust_command *ust_cmd = nullptr;
	const bool is_root = (getuid() == 0);
	struct thread_state *thread_state = (struct thread_state *) data;
	const int application_socket = thread_state->application_socket;
	const auto thread_quit_pipe_fd = lttng_pipe_get_readfd(thread_state->quit_pipe);

	DBG("[thread] Manage application registration started");

	pthread_cleanup_push(thread_init_cleanup, thread_state);
	health_register(the_health_sessiond, HEALTH_SESSIOND_TYPE_APP_REG);

	ret = lttcomm_listen_unix_sock(application_socket);
	if (ret < 0) {
		goto error_listen;
	}

	/*
	 * Pass 2 as size here for the thread quit pipe and apps_sock. Nothing
	 * more will be added to this poll set.
	 */
	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error_create_poll;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, application_socket, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error_poll_add;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, thread_quit_pipe_fd, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error_poll_add;
	}

	set_thread_status(thread_state, true);
	pthread_cleanup_pop(0);

	if (testpoint(sessiond_thread_registration_apps)) {
		goto error_poll_add;
	}

	while (true) {
		DBG("Accepting application registration");

		/* Inifinite blocking call, waiting for transmission */
	restart:
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		health_poll_exit();
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
			health_code_update();

			/* Fetch once the poll data */
			const auto revents = LTTNG_POLL_GETEV(&events, i);
			const auto pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Activity on thread quit pipe, closing. */
			if (pollfd == thread_quit_pipe_fd) {
				err = 0;
				goto exit;
			}

			/* Event on the registration socket. */
			if (revents & LPOLLIN) {
				sock = lttcomm_accept_unix_sock(application_socket);
				if (sock < 0) {
					goto error;
				}

				/*
				 * Set socket timeout for both receiving and ending.
				 * app_socket_timeout is in seconds, whereas
				 * lttcomm_setsockopt_rcv_timeout and
				 * lttcomm_setsockopt_snd_timeout expect msec as
				 * parameter.
				 */
				if (the_config.app_socket_timeout >= 0) {
					(void) lttcomm_setsockopt_rcv_timeout(
						sock, the_config.app_socket_timeout * 1000);
					(void) lttcomm_setsockopt_snd_timeout(
						sock, the_config.app_socket_timeout * 1000);
				}

				/*
				 * Set the CLOEXEC flag. Return code is useless because
				 * either way, the show must go on.
				 */
				(void) utils_set_fd_cloexec(sock);

				/* Create UST registration command for enqueuing */
				ust_cmd = zmalloc<ust_command>();
				if (ust_cmd == nullptr) {
					PERROR("ust command zmalloc");
					ret = close(sock);
					if (ret) {
						PERROR("close");
					}
					sock = -1;
					goto error;
				}

				/*
				 * Using message-based transmissions to ensure we don't
				 * have to deal with partially received messages.
				 */
				ret = lttng_fd_get(LTTNG_FD_APPS, 1);
				if (ret < 0) {
					ERR("Exhausted file descriptors allowed for applications.");
					free(ust_cmd);
					ret = close(sock);
					if (ret) {
						PERROR("close");
					}
					sock = -1;
					continue;
				}

				health_code_update();
				ret = ust_app_recv_registration(sock, &ust_cmd->reg_msg);
				if (ret < 0) {
					free(ust_cmd);
					/* Close socket of the application. */
					ret = close(sock);
					if (ret) {
						PERROR("close");
					}
					lttng_fd_put(LTTNG_FD_APPS, 1);
					sock = -1;
					continue;
				}
				health_code_update();

				ust_cmd->sock = sock;
				sock = -1;

				DBG("UST registration received with pid:%d ppid:%d uid:%d"
				    " gid:%d sock:%d name:%s (version %d.%d)",
				    ust_cmd->reg_msg.pid,
				    ust_cmd->reg_msg.ppid,
				    ust_cmd->reg_msg.uid,
				    ust_cmd->reg_msg.gid,
				    ust_cmd->sock,
				    ust_cmd->reg_msg.name,
				    ust_cmd->reg_msg.major,
				    ust_cmd->reg_msg.minor);

				/*
				 * Lock free enqueue the registration request. The red pill
				 * has been taken! This apps will be part of the *system*.
				 */
				cds_wfcq_head_ptr_t head;
				head.h = &thread_state->ust_cmd_queue->head;
				cds_wfcq_enqueue(
					head, &thread_state->ust_cmd_queue->tail, &ust_cmd->node);

				/*
				 * Wake the registration queue futex. Implicit memory
				 * barrier with the exchange in cds_wfcq_enqueue.
				 */
				futex_nto1_wake(&thread_state->ust_cmd_queue->futex);
			} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("Register apps socket poll error");
				goto error;
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto error;
			}
		}
	}

exit:
error:
	/* Notify that the registration thread is gone */
	notify_ust_apps(0, is_root);

	ret = close(application_socket);
	if (ret) {
		PERROR("Failed to close application registration socket");
	}
	if (sock >= 0) {
		ret = close(sock);
		if (ret) {
			PERROR("Failed to close application socket");
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
	}
	unlink(the_config.apps_unix_sock_path.value);

error_poll_add:
	lttng_poll_clean(&events);
error_listen:
error_create_poll:
	DBG("UST Registration thread cleanup complete");
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(the_health_sessiond);
	return nullptr;
}

static bool shutdown_application_registration_thread(void *data)
{
	struct thread_state *thread_state = (struct thread_state *) data;
	const int write_fd = lttng_pipe_get_writefd(thread_state->quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

struct lttng_thread *launch_application_registration_thread(struct ust_cmd_queue *cmd_queue)
{
	int ret;
	struct lttng_pipe *quit_pipe;
	struct thread_state *thread_state = nullptr;
	struct lttng_thread *thread = nullptr;
	const bool is_root = (getuid() == 0);
	int application_socket = -1;

	thread_state = zmalloc<struct thread_state>();
	if (!thread_state) {
		goto error_alloc;
	}
	quit_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!quit_pipe) {
		goto error;
	}
	thread_state->quit_pipe = quit_pipe;
	thread_state->ust_cmd_queue = cmd_queue;
	application_socket = create_application_socket();
	if (application_socket < 0) {
		goto error;
	}
	thread_state->application_socket = application_socket;
	sem_init(&thread_state->ready, 0, 0);

	thread = lttng_thread_create("UST application registration",
				     thread_application_registration,
				     shutdown_application_registration_thread,
				     cleanup_application_registration_thread,
				     thread_state);
	if (!thread) {
		goto error;
	}
	/*
	 * The application registration thread now owns the application socket
	 * and the global thread state. The thread state is used to wait for
	 * the thread's status, but its ownership now belongs to the thread.
	 */
	application_socket = -1;
	if (!wait_thread_status(thread_state)) {
		thread_state = nullptr;
		goto error;
	}

	/* Notify all applications to register. */
	ret = notify_ust_apps(1, is_root);
	if (ret < 0) {
		ERR("Failed to notify applications or create the wait shared memory.\n"
		    "Execution continues but there might be problems for already\n"
		    "running applications that wishes to register.");
	}

	return thread;
error:
	lttng_thread_put(thread);
	cleanup_application_registration_thread(thread_state);
	if (application_socket >= 0) {
		if (close(application_socket)) {
			PERROR("Failed to close application registration socket");
		}
	}
error_alloc:
	return nullptr;
}
