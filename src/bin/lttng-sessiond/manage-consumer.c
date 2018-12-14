/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <signal.h>

#include <common/pipe.h>
#include <common/utils.h>

#include "manage-consumer.h"
#include "testpoint.h"
#include "health-sessiond.h"
#include "utils.h"
#include "thread.h"
#include "ust-consumer.h"

struct thread_notifiers {
	struct lttng_pipe *quit_pipe;
	struct consumer_data *consumer_data;
        sem_t ready;
	int initialization_result;
};

static void mark_thread_as_ready(struct thread_notifiers *notifiers)
{
	DBG("Marking consumer management thread as ready");
	notifiers->initialization_result = 0;
	sem_post(&notifiers->ready);
}

static void mark_thread_intialization_as_failed(
		struct thread_notifiers *notifiers)
{
        ERR("Consumer management thread entering error state");
	notifiers->initialization_result = -1;
	sem_post(&notifiers->ready);
}

static void wait_until_thread_is_ready(struct thread_notifiers *notifiers)
{
	DBG("Waiting for consumer management thread to be ready");
	sem_wait(&notifiers->ready);
	DBG("Consumer management thread is ready");
}

/*
 * This thread manage the consumer error sent back to the session daemon.
 */
void *thread_consumer_management(void *data)
{
	int sock = -1, i, ret, pollfd, err = -1, should_quit = 0;
	uint32_t revents, nb_fd;
	enum lttcomm_return_code code;
	struct lttng_poll_event events;
	struct thread_notifiers *notifiers = data;
	struct consumer_data *consumer_data = notifiers->consumer_data;
	const int quit_pipe_read_fd = lttng_pipe_get_readfd(notifiers->quit_pipe);
	struct consumer_socket *cmd_socket_wrapper = NULL;

	DBG("[thread] Manage consumer started");

	rcu_register_thread();
	rcu_thread_online();

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_CONSUMER);

	health_code_update();

	/*
	 * Pass 3 as size here for the thread quit pipe, consumerd_err_sock and the
	 * metadata_sock. Nothing more will be added to this poll set.
	 */
	ret = lttng_poll_create(&events, 3, LTTNG_CLOEXEC);
	if (ret < 0) {
		mark_thread_intialization_as_failed(notifiers);
		goto error_poll;
	}

	ret = lttng_poll_add(&events, quit_pipe_read_fd, LPOLLIN | LPOLLERR);
	if (ret < 0) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	/*
	 * The error socket here is already in a listening state which was done
	 * just before spawning this thread to avoid a race between the consumer
	 * daemon exec trying to connect and the listen() call.
	 */
	ret = lttng_poll_add(&events, consumer_data->err_sock, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	health_code_update();

	/* Infinite blocking call, waiting for transmission */
	health_poll_entry();

	if (testpoint(sessiond_thread_manage_consumer)) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	ret = lttng_poll_wait(&events, -1);
	health_poll_exit();
	if (ret < 0) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	nb_fd = ret;

	for (i = 0; i < nb_fd; i++) {
		/* Fetch once the poll data */
		revents = LTTNG_POLL_GETEV(&events, i);
		pollfd = LTTNG_POLL_GETFD(&events, i);

		health_code_update();

		/* Thread quit pipe has been closed. Killing thread. */
		if (pollfd == quit_pipe_read_fd) {
			err = 0;
			mark_thread_intialization_as_failed(notifiers);
			goto exit;
		} else if (pollfd == consumer_data->err_sock) {
			/* Event on the registration socket */
			if (revents & LPOLLIN) {
				continue;
			} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("consumer err socket poll error");
				mark_thread_intialization_as_failed(notifiers);
				goto error;
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				mark_thread_intialization_as_failed(notifiers);
				goto error;
			}
		}
	}

	sock = lttcomm_accept_unix_sock(consumer_data->err_sock);
	if (sock < 0) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	/*
	 * Set the CLOEXEC flag. Return code is useless because either way, the
	 * show must go on.
	 */
	(void) utils_set_fd_cloexec(sock);

	health_code_update();

	DBG2("Receiving code from consumer err_sock");

	/* Getting status code from kconsumerd */
	ret = lttcomm_recv_unix_sock(sock, &code,
			sizeof(enum lttcomm_return_code));
	if (ret <= 0) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	health_code_update();
	if (code != LTTCOMM_CONSUMERD_COMMAND_SOCK_READY) {
		ERR("consumer error when waiting for SOCK_READY : %s",
				lttcomm_get_readable_code(-code));
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	/* Connect both command and metadata sockets. */
	consumer_data->cmd_sock =
			lttcomm_connect_unix_sock(
				consumer_data->cmd_unix_sock_path);
	consumer_data->metadata_fd =
			lttcomm_connect_unix_sock(
				consumer_data->cmd_unix_sock_path);
	if (consumer_data->cmd_sock < 0 || consumer_data->metadata_fd < 0) {
		PERROR("consumer connect cmd socket");
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	consumer_data->metadata_sock.fd_ptr = &consumer_data->metadata_fd;

	/* Create metadata socket lock. */
	consumer_data->metadata_sock.lock = zmalloc(sizeof(pthread_mutex_t));
	if (consumer_data->metadata_sock.lock == NULL) {
		PERROR("zmalloc pthread mutex");
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}
	pthread_mutex_init(consumer_data->metadata_sock.lock, NULL);

	DBG("Consumer command socket ready (fd: %d)", consumer_data->cmd_sock);
	DBG("Consumer metadata socket ready (fd: %d)",
			consumer_data->metadata_fd);

	/*
	 * Remove the consumerd error sock since we've established a connection.
	 */
	ret = lttng_poll_del(&events, consumer_data->err_sock);
	if (ret < 0) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	/* Add new accepted error socket. */
	ret = lttng_poll_add(&events, sock, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	/* Add metadata socket that is successfully connected. */
	ret = lttng_poll_add(&events, consumer_data->metadata_fd,
			LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	health_code_update();

	/*
	 * Transfer the write-end of the channel monitoring pipe to the consumer
	 * by issuing a SET_CHANNEL_MONITOR_PIPE command.
	 */
	cmd_socket_wrapper = consumer_allocate_socket(&consumer_data->cmd_sock);
	if (!cmd_socket_wrapper) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}
	cmd_socket_wrapper->lock = &consumer_data->lock;

	pthread_mutex_lock(cmd_socket_wrapper->lock);
	ret = consumer_init(cmd_socket_wrapper, sessiond_uuid);
	if (ret) {
		ERR("Failed to send sessiond uuid to consumer daemon");
		mark_thread_intialization_as_failed(notifiers);
		pthread_mutex_unlock(cmd_socket_wrapper->lock);
		goto error;
	}
	pthread_mutex_unlock(cmd_socket_wrapper->lock);

	ret = consumer_send_channel_monitor_pipe(cmd_socket_wrapper,
			consumer_data->channel_monitor_pipe);
	if (ret) {
		mark_thread_intialization_as_failed(notifiers);
		goto error;
	}

	/* Discard the socket wrapper as it is no longer needed. */
	consumer_destroy_socket(cmd_socket_wrapper);
	cmd_socket_wrapper = NULL;

	/* The thread is completely initialized, signal that it is ready. */
	mark_thread_as_ready(notifiers);

	/* Infinite blocking call, waiting for transmission */
	while (1) {
		health_code_update();

		/* Exit the thread because the thread quit pipe has been triggered. */
		if (should_quit) {
			/* Not a health error. */
			err = 0;
			goto exit;
		}

		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		health_poll_exit();
		if (ret < 0) {
			goto error;
		}

		nb_fd = ret;

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			/*
			 * Thread quit pipe has been triggered, flag that we should stop
			 * but continue the current loop to handle potential data from
			 * consumer.
			 */
			if (pollfd == quit_pipe_read_fd) {
				should_quit = 1;
			} else if (pollfd == sock) {
				/* Event on the consumerd socket */
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)
						&& !(revents & LPOLLIN)) {
					ERR("consumer err socket second poll error");
					goto error;
				}
				health_code_update();
				/* Wait for any kconsumerd error */
				ret = lttcomm_recv_unix_sock(sock, &code,
						sizeof(enum lttcomm_return_code));
				if (ret <= 0) {
					ERR("consumer closed the command socket");
					goto error;
				}

				ERR("consumer return code : %s",
						lttcomm_get_readable_code(-code));

				goto exit;
			} else if (pollfd == consumer_data->metadata_fd) {
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)
						&& !(revents & LPOLLIN)) {
					ERR("consumer err metadata socket second poll error");
					goto error;
				}
				/* UST metadata requests */
				ret = ust_consumer_metadata_request(
						&consumer_data->metadata_sock);
				if (ret < 0) {
					ERR("Handling metadata request");
					goto error;
				}
			}
			/* No need for an else branch all FDs are tested prior. */
		}
		health_code_update();
	}

exit:
error:
	/*
	 * We lock here because we are about to close the sockets and some other
	 * thread might be using them so get exclusive access which will abort all
	 * other consumer command by other threads.
	 */
	pthread_mutex_lock(&consumer_data->lock);

	/* Immediately set the consumerd state to stopped */
	if (consumer_data->type == LTTNG_CONSUMER_KERNEL) {
		uatomic_set(&kernel_consumerd_state, CONSUMER_ERROR);
	} else if (consumer_data->type == LTTNG_CONSUMER64_UST ||
			consumer_data->type == LTTNG_CONSUMER32_UST) {
		uatomic_set(&ust_consumerd_state, CONSUMER_ERROR);
	} else {
		/* Code flow error... */
		assert(0);
	}

	if (consumer_data->err_sock >= 0) {
		ret = close(consumer_data->err_sock);
		if (ret) {
			PERROR("close");
		}
		consumer_data->err_sock = -1;
	}
	if (consumer_data->cmd_sock >= 0) {
		ret = close(consumer_data->cmd_sock);
		if (ret) {
			PERROR("close");
		}
		consumer_data->cmd_sock = -1;
	}
	if (consumer_data->metadata_sock.fd_ptr &&
	    *consumer_data->metadata_sock.fd_ptr >= 0) {
		ret = close(*consumer_data->metadata_sock.fd_ptr);
		if (ret) {
			PERROR("close");
		}
	}
	if (sock >= 0) {
		ret = close(sock);
		if (ret) {
			PERROR("close");
		}
	}

	unlink(consumer_data->err_unix_sock_path);
	unlink(consumer_data->cmd_unix_sock_path);
	pthread_mutex_unlock(&consumer_data->lock);

	/* Cleanup metadata socket mutex. */
	if (consumer_data->metadata_sock.lock) {
		pthread_mutex_destroy(consumer_data->metadata_sock.lock);
		free(consumer_data->metadata_sock.lock);
	}
	lttng_poll_clean(&events);

	if (cmd_socket_wrapper) {
		consumer_destroy_socket(cmd_socket_wrapper);
	}
error_poll:
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_sessiond);
	DBG("consumer thread cleanup completed");

	rcu_thread_offline();
	rcu_unregister_thread();

	return NULL;
}

static bool shutdown_consumer_management_thread(void *data)
{
	struct thread_notifiers *notifiers = data;
	const int write_fd = lttng_pipe_get_writefd(notifiers->quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

static void cleanup_consumer_management_thread(void *data)
{
	struct thread_notifiers *notifiers = data;

	lttng_pipe_destroy(notifiers->quit_pipe);
	free(notifiers);
}

bool launch_consumer_management_thread(struct consumer_data *consumer_data)
{
	struct lttng_pipe *quit_pipe;
	struct thread_notifiers *notifiers = NULL;
	struct lttng_thread *thread;

	notifiers = zmalloc(sizeof(*notifiers));
	if (!notifiers) {
		goto error_alloc;
	}

	quit_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!quit_pipe) {
		goto error;
	}
	notifiers->quit_pipe = quit_pipe;
	notifiers->consumer_data = consumer_data;
	sem_init(&notifiers->ready, 0, 0);

	thread = lttng_thread_create("Consumer management",
			thread_consumer_management,
			shutdown_consumer_management_thread,
			cleanup_consumer_management_thread,
			notifiers);
	if (!thread) {
		goto error;
	}
	wait_until_thread_is_ready(notifiers);
	lttng_thread_put(thread);
	if (notifiers->initialization_result) {
		return false;
	}
	return true;
error:
	cleanup_consumer_management_thread(notifiers);
error_alloc:
	return false;
}
