/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "health-sessiond.hpp"
#include "manage-consumer.hpp"
#include "testpoint.hpp"
#include "thread.hpp"
#include "ust-consumer.hpp"
#include "utils.hpp"

#include <common/pipe.hpp>
#include <common/scope-exit.hpp>
#include <common/utils.hpp>

#include <fcntl.h>
#include <signal.h>

#define MAX_ERROR_MSG_PAYLOAD_SIZE 65535

namespace {
enum consumerd_error_msg_handling_status {
	CONSUMERD_ERROR_MSG_HANDLING_STATUS_OK,
	CONSUMERD_ERROR_MSG_HANDLING_STATUS_FATAL_ERROR,
};

struct thread_notifiers {
	struct lttng_pipe *quit_pipe;
	struct consumer_data *consumer_data;
	sem_t ready;
	int initialization_result;
};

void mark_thread_as_ready(struct thread_notifiers *notifiers)
{
	DBG("Marking consumer management thread as ready");
	notifiers->initialization_result = 0;
	sem_post(&notifiers->ready);
}

void mark_thread_initialization_as_failed(struct thread_notifiers *notifiers)
{
	ERR("Consumer management thread entering error state");
	notifiers->initialization_result = -1;
	sem_post(&notifiers->ready);
}

void wait_until_thread_is_ready(struct thread_notifiers *notifiers)
{
	DBG("Waiting for consumer management thread to be ready");
	sem_wait(&notifiers->ready);
	DBG("Consumer management thread is ready");
}

int receive_consumer_error_msg(int sock, lttng_payload *msg_payload)
{
	int ret;
	uint64_t msg_specific_payload_size;

	DBG("Beginning reception of consumer error message");

	ret = lttng_dynamic_buffer_set_size(&msg_payload->buffer,
					    sizeof(struct lttcomm_consumer_error_msg_header));
	if (ret) {
		PERROR("Failed to allocate a payload buffer for lttcomm_consumer_error_msg_header");
		return -1;
	}

	ret = lttcomm_recv_unix_sock(sock, msg_payload->buffer.data, msg_payload->buffer.size);
	if (ret <= 0) {
		ERR("Communication error encountered while receiving error message from the consumer daemon");
		return -1;
	}

	const lttcomm_consumer_error_msg_header *header =
		reinterpret_cast<decltype(header)>(msg_payload->buffer.data);

	if (header->size > MAX_ERROR_MSG_PAYLOAD_SIZE) {
		ERR_FMT("Error message payload received from the consumer daemon exceeds the maximum size: payload_size={}",
			header->size);
		return -1;
	}

	msg_specific_payload_size = header->size;
	ret = lttng_dynamic_buffer_set_size(&msg_payload->buffer,
					    msg_payload->buffer.size + msg_specific_payload_size);
	if (ret) {
		PERROR_FMT(
			"Failed to allocate a payload buffer for message-specific payload: message_type={}, payload_size={}",
			static_cast<int>(header->msg_type),
			msg_specific_payload_size);
		return ret;
	}

	DBG_FMT("Receiving error message type specific payload of consumer error message: msg_specific_payload_size={}",
		msg_specific_payload_size);
	ret = lttcomm_recv_unix_sock(sock,
				     msg_payload->buffer.data +
					     sizeof(struct lttcomm_consumer_error_msg_header),
				     msg_specific_payload_size);
	if (ret <= 0) {
		ERR("Communication error encountered while receiving error message from the consumer daemon");
		return -1;
	}

	DBG_FMT("Completed reception of consumer daemon error message: size={}",
		msg_payload->buffer.size);

	return 0;
}

consumerd_error_msg_handling_status
handle_consumerd_error_msg_error_code(const lttng_payload_view *error_code_msg_payload_view)
{
	lttcomm_return_code code;
	const lttcomm_consumer_error_msg_error_code *payload;

	if (error_code_msg_payload_view->buffer.size < sizeof(*payload)) {
		ERR_FMT("Consumer error message payload too short to contain "
			"an error code message: size={}, expected_size={}",
			error_code_msg_payload_view->buffer.size,
			sizeof(*payload));
		return CONSUMERD_ERROR_MSG_HANDLING_STATUS_FATAL_ERROR;
	}

	payload = reinterpret_cast<decltype(payload)>(error_code_msg_payload_view->buffer.data);
	code = static_cast<enum lttcomm_return_code>(payload->error_code);

	if (code == LTTCOMM_CONSUMERD_COMMAND_SOCK_READY) {
		DBG("Consumer daemon reported its command socket is ready");
		return CONSUMERD_ERROR_MSG_HANDLING_STATUS_OK;
	} else {
		ERR_FMT("Consumer reported an error: error_code={}",
			lttcomm_get_readable_code(code));
		return CONSUMERD_ERROR_MSG_HANDLING_STATUS_FATAL_ERROR;
	}
}

/*
 * Receive a vector of owner that are free to reclaim.
 */
consumerd_error_msg_handling_status handle_consumerd_error_msg_owner_reclaim_notification(
	const lttng_payload_view *error_code_msg_payload_view)
{
	const lttcomm_consumer_error_msg_owner_reclaim_notification *payload;

	if (error_code_msg_payload_view->buffer.size < sizeof(*payload)) {
		ERR_FMT("Consumer owner reclaim notification message payload too short "
			"expected_minimum_size={}, actual_size={}",
			sizeof(*payload),
			error_code_msg_payload_view->buffer.size);
		return CONSUMERD_ERROR_MSG_HANDLING_STATUS_FATAL_ERROR;
	}

	payload = reinterpret_cast<decltype(payload)>(error_code_msg_payload_view->buffer.data);

	if (error_code_msg_payload_view->buffer.size <
	    (sizeof(*payload) + sizeof(uint32_t) * payload->length)) {
		ERR_FMT("Consumer owner reclaim notification message payload too short "
			"expected_minimum_size={}, actual_size={}",
			sizeof(*payload) + sizeof(uint32_t) * payload->length,
			error_code_msg_payload_view->buffer.size);
		return CONSUMERD_ERROR_MSG_HANDLING_STATUS_FATAL_ERROR;
	}

	std::vector<uint32_t> owners;

	try {
		owners.reserve(payload->length);
	} catch (const std::bad_alloc&) {
		ERR("Failed to allocate memory for owner reclaim notification");
		return CONSUMERD_ERROR_MSG_HANDLING_STATUS_FATAL_ERROR;
	}

	for (size_t i = 0; i < payload->length; ++i) {
		owners.push_back(payload->owners[i]);
	}

	ust_app_notify_reclaimed_owner_ids(owners);

	return CONSUMERD_ERROR_MSG_HANDLING_STATUS_OK;
}

consumerd_error_msg_handling_status
dispatch_consumer_error_msg(struct lttng_payload_view *msg_payload_view)
{
	const lttcomm_consumer_error_msg_header *header =
		reinterpret_cast<decltype(header)>(msg_payload_view->buffer.data);

	LTTNG_ASSERT(msg_payload_view->buffer.size > sizeof(*header));

	const auto msg_type = static_cast<enum lttng_consumer_error_msg_type>(header->msg_type);
	const auto msg_specific_payload_view =
		lttng_payload_view_from_view(msg_payload_view, sizeof(*header), -1);

	switch (msg_type) {
	case LTTNG_CONSUMER_ERROR_MSG_TYPE_ERROR_CODE:
		return handle_consumerd_error_msg_error_code(&msg_specific_payload_view);
	case LTTNG_CONSUMER_ERROR_MSG_TYPE_OWNER_RECLAIM_NOTIFICATION:
		return handle_consumerd_error_msg_owner_reclaim_notification(
			&msg_specific_payload_view);
	default:
		ERR_FMT("Unknown consumer daemon error message type: "
			"msg_type={}",
			static_cast<std::uint8_t>(msg_type));
		return CONSUMERD_ERROR_MSG_HANDLING_STATUS_FATAL_ERROR;
	}
}

consumerd_error_msg_handling_status handle_consumerd_error_socket_in(int consumerd_error_sock)
{
	lttng_payload error_msg_payload;

	lttng_payload_init(&error_msg_payload);
	const auto reset_payload = lttng::make_scope_exit(
		[&error_msg_payload]() noexcept { lttng_payload_reset(&error_msg_payload); });

	const auto receive_ret =
		receive_consumer_error_msg(consumerd_error_sock, &error_msg_payload);
	if (receive_ret) {
		ERR("Failed to receive consumer daemon error message");
		return CONSUMERD_ERROR_MSG_HANDLING_STATUS_FATAL_ERROR;
	} else {
		auto view = lttng_payload_view_from_payload(&error_msg_payload, 0, -1);

		return dispatch_consumer_error_msg(&view);
	}
}

bool receive_consumerd_status(int sock, lttcomm_return_code *code)
{
	LTTNG_ASSERT(code);

	lttcomm_consumer_error_msg_header header;
	auto recv_ret = lttcomm_recv_unix_sock(sock, &header, sizeof(header));

	if (recv_ret != sizeof(header)) {
		ERR("Failed to get status from consumerd");
		return false;
	}

	if (header.msg_type != LTTNG_CONSUMER_ERROR_MSG_TYPE_ERROR_CODE) {
		ERR_FMT("Failed to get status from consumerd: expected_msg_type=`{}`, received_msg_type=`{}`",
			static_cast<std::uint8_t>(LTTNG_CONSUMER_ERROR_MSG_TYPE_ERROR_CODE),
			header.msg_type);
		return false;
	}

	uint8_t raw_code;
	if (header.size != sizeof(raw_code)) {
		ERR("Bad payload size for consumerd error message type "
		    "LTTNG_CONSUMER_ERROR_MSG_TYPE_ERROR_CODE");
		return false;
	}

	recv_ret = lttcomm_recv_unix_sock(sock, &raw_code, sizeof(raw_code));
	if (recv_ret != sizeof(raw_code)) {
		ERR_FMT("Expecting {} bytes in payload but got {}", sizeof(raw_code), recv_ret);
		return false;
	}

	*code = static_cast<enum lttcomm_return_code>(raw_code);

	return true;
}

/*
 * This thread manage the consumer error sent back to the session daemon.
 */
void *thread_consumer_management(void *data)
{
	int sock = -1, i, ret, err = -1, should_quit = 0;
	uint32_t nb_fd;
	enum lttcomm_return_code code;
	struct lttng_poll_event events;
	struct thread_notifiers *notifiers = (thread_notifiers *) data;
	struct consumer_data *consumer_data = notifiers->consumer_data;
	const auto thread_quit_pipe_fd = lttng_pipe_get_readfd(notifiers->quit_pipe);
	struct consumer_socket *cmd_socket_wrapper = nullptr;

	DBG("[thread] Manage consumer started");

	rcu_register_thread();
	rcu_thread_online();

	health_register(the_health_sessiond, HEALTH_SESSIOND_TYPE_CONSUMER);

	health_code_update();

	/*
	 * Pass 3 as size here for the thread quit pipe, consumerd_err_sock and the
	 * metadata_sock. Nothing more will be added to this poll set.
	 */
	ret = lttng_poll_create(&events, 3, LTTNG_CLOEXEC);
	if (ret < 0) {
		mark_thread_initialization_as_failed(notifiers);
		goto error_poll;
	}

	ret = lttng_poll_add(&events, thread_quit_pipe_fd, LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	/*
	 * The error socket here is already in a listening state which was done
	 * just before spawning this thread to avoid a race between the consumer
	 * daemon exec trying to connect and the listen() call.
	 */
	ret = lttng_poll_add(&events, consumer_data->err_sock, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Infinite blocking call, waiting for transmission */
	health_poll_entry();

	if (testpoint(sessiond_thread_manage_consumer)) {
		goto error;
	}

	ret = lttng_poll_wait(&events, -1);
	health_poll_exit();
	if (ret < 0) {
		goto error;
	}

	nb_fd = ret;

	for (i = 0; i < nb_fd; i++) {
		/* Fetch once the poll data */
		const auto revents = LTTNG_POLL_GETEV(&events, i);
		const auto pollfd = LTTNG_POLL_GETFD(&events, i);

		health_code_update();

		/* Activity on thread quit pipe, exiting. */
		if (pollfd == thread_quit_pipe_fd) {
			DBG("Activity on thread quit pipe");
			err = 0;
			goto error;
		} else if (pollfd == consumer_data->err_sock) {
			/* Event on the registration socket */
			if (revents & LPOLLIN) {
				continue;
			} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("consumer err socket poll error");
				goto error;
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto error;
			}
		}
	}

	sock = lttcomm_accept_unix_sock(consumer_data->err_sock);
	if (sock < 0) {
		goto error;
	}

	/*
	 * Set the CLOEXEC flag. Return code is useless because either way, the
	 * show must go on.
	 */
	(void) utils_set_fd_cloexec(sock);

	health_code_update();

	DBG2("Receiving code from consumer err_sock");

	/* Getting status code from consumerd */
	if (!receive_consumerd_status(sock, &code)) {
		goto error;
	}

	health_code_update();
	if (code != LTTCOMM_CONSUMERD_COMMAND_SOCK_READY) {
		ERR("consumer error when waiting for SOCK_READY : %s",
		    lttcomm_get_readable_code((lttcomm_return_code) -code));
		goto error;
	}

	/* Connect both command and metadata sockets. */
	consumer_data->cmd_sock = lttcomm_connect_unix_sock(consumer_data->cmd_unix_sock_path);
	consumer_data->metadata_fd = lttcomm_connect_unix_sock(consumer_data->cmd_unix_sock_path);
	if (consumer_data->cmd_sock < 0 || consumer_data->metadata_fd < 0) {
		PERROR("consumer connect cmd socket");
		goto error;
	}

	consumer_data->metadata_sock.fd_ptr = &consumer_data->metadata_fd;

	/* Create metadata socket lock. */
	consumer_data->metadata_sock.lock = zmalloc<pthread_mutex_t>();
	if (consumer_data->metadata_sock.lock == nullptr) {
		PERROR("zmalloc pthread mutex");
		goto error;
	}
	pthread_mutex_init(consumer_data->metadata_sock.lock, nullptr);

	DBG("Consumer command socket ready (fd: %d)", consumer_data->cmd_sock);
	DBG("Consumer metadata socket ready (fd: %d)", consumer_data->metadata_fd);

	/*
	 * Remove the consumerd error sock since we've established a connection.
	 */
	ret = lttng_poll_del(&events, consumer_data->err_sock);
	if (ret < 0) {
		goto error;
	}

	/* Add new accepted error socket. */
	ret = lttng_poll_add(&events, sock, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	/* Add metadata socket that is successfully connected. */
	ret = lttng_poll_add(&events, consumer_data->metadata_fd, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

	/*
	 * Transfer the write-end of the channel monitoring pipe to the consumer
	 * by issuing a SET_CHANNEL_MONITOR_PIPE command.
	 */
	cmd_socket_wrapper = consumer_allocate_socket(&consumer_data->cmd_sock);
	if (!cmd_socket_wrapper) {
		goto error;
	}
	cmd_socket_wrapper->lock = &consumer_data->lock;

	pthread_mutex_lock(cmd_socket_wrapper->lock);
	ret = consumer_init(cmd_socket_wrapper, the_sessiond_uuid);
	if (ret) {
		ERR("Failed to send sessiond uuid to consumer daemon");
		pthread_mutex_unlock(cmd_socket_wrapper->lock);
		goto error;
	}
	pthread_mutex_unlock(cmd_socket_wrapper->lock);

	ret = consumer_send_channel_monitor_pipe(cmd_socket_wrapper,
						 consumer_data->channel_monitor_pipe);
	if (ret) {
		goto error;
	}

	/* Discard the socket wrapper as it is no longer needed. */
	consumer_destroy_socket(cmd_socket_wrapper);
	cmd_socket_wrapper = nullptr;

	/* The thread is completely initialized, signal that it is ready. */
	mark_thread_as_ready(notifiers);

	/* Infinite blocking call, waiting for transmission */
	while (true) {
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
			const auto revents = LTTNG_POLL_GETEV(&events, i);
			const auto pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			/*
			 * Thread quit pipe has been triggered, flag that we should stop
			 * but continue the current loop to handle potential data from
			 * consumer.
			 */
			if (pollfd == thread_quit_pipe_fd) {
				should_quit = 1;
			} else if (pollfd == sock) {
				/* Event on the consumerd socket */
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP) &&
				    !(revents & LPOLLIN)) {
					ERR("consumer err socket second poll error");
					goto error;
				}

				const auto handling_status = handle_consumerd_error_socket_in(sock);
				if (handling_status != CONSUMERD_ERROR_MSG_HANDLING_STATUS_OK) {
					goto exit;
				}
			} else if (pollfd == consumer_data->metadata_fd) {
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP) &&
				    !(revents & LPOLLIN)) {
					ERR("consumer err metadata socket second poll error");
					goto error;
				}
				/* UST metadata requests */
				ret = ust_consumer_metadata_request(&consumer_data->metadata_sock);
				if (ret < 0) {
					ERR("Handling metadata request");
					goto error;
				}
			}
			/* No need for an else branch all FDs are tested prior. */
		}
		health_code_update();
	}

error:
	mark_thread_initialization_as_failed(notifiers);
exit:
	/*
	 * We lock here because we are about to close the sockets and some other
	 * thread might be using them so get exclusive access which will abort all
	 * other consumer command by other threads.
	 */
	pthread_mutex_lock(&consumer_data->lock);

	/* Immediately set the consumerd state to stopped */
	if (consumer_data->type == LTTNG_CONSUMER_KERNEL) {
		uatomic_set(&the_kernel_consumerd_state, CONSUMER_ERROR);
	} else if (consumer_data->type == LTTNG_CONSUMER64_UST ||
		   consumer_data->type == LTTNG_CONSUMER32_UST) {
		uatomic_set(&the_ust_consumerd_state, CONSUMER_ERROR);
	} else {
		/* Code flow error... */
		abort();
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
	if (consumer_data->metadata_sock.fd_ptr && *consumer_data->metadata_sock.fd_ptr >= 0) {
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
	health_unregister(the_health_sessiond);
	DBG("consumer thread cleanup completed");

	rcu_thread_offline();
	rcu_unregister_thread();

	return nullptr;
}

bool shutdown_consumer_management_thread(void *data)
{
	struct thread_notifiers *notifiers = (thread_notifiers *) data;
	const int write_fd = lttng_pipe_get_writefd(notifiers->quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

void cleanup_consumer_management_thread(void *data)
{
	struct thread_notifiers *notifiers = (thread_notifiers *) data;

	lttng_pipe_destroy(notifiers->quit_pipe);
	free(notifiers);
}
} /* namespace */

bool launch_consumer_management_thread(struct consumer_data *consumer_data)
{
	struct lttng_pipe *quit_pipe;
	struct thread_notifiers *notifiers = nullptr;
	struct lttng_thread *thread;

	notifiers = zmalloc<thread_notifiers>();
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
	return notifiers->initialization_result == 0;
error:
	cleanup_consumer_management_thread(notifiers);
error_alloc:
	return false;
}
