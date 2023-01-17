/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/unix.hpp>
#include <common/utils.hpp>

#include <lttng/constant.h>

#include <algorithm>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <tap/tap.h>
#include <unistd.h>

#define HIGH_FD_COUNT		LTTCOMM_MAX_SEND_FDS
#define MESSAGE_COUNT		4
#define LARGE_PAYLOAD_SIZE	(4 * 1024)
#define LARGE_PAYLOAD_RECV_SIZE 100

static const int TEST_COUNT = 37;

/* For error.h */
int lttng_opt_quiet;
int lttng_opt_verbose;
int lttng_opt_mi;

/*
 * Validate that a large number of file descriptors can be received in one shot.
 */
static void test_high_fd_count(unsigned int fd_count)
{
	int sockets[2] = { -1, -1 };
	int ret;
	unsigned int i;
	const unsigned int payload_content = 42;
	struct lttng_payload sent_payload;
	struct lttng_payload received_payload;

	diag("Send and receive high FD count atomically (%u FDs)", fd_count);
	lttng_payload_init(&sent_payload);
	lttng_payload_init(&received_payload);

	ret = lttcomm_create_anon_unix_socketpair(sockets);
	ok(ret == 0, "Created anonymous unix socket pair");
	if (ret < 0) {
		PERROR("Failed to create an anonymous pair of unix sockets");
		goto error;
	}

	/* Add dummy content to payload. */
	ret = lttng_dynamic_buffer_append(
		&sent_payload.buffer, &payload_content, sizeof(payload_content));
	if (ret) {
		PERROR("Failed to initialize test payload");
		goto error;
	}

	for (i = 0; i < fd_count; i++) {
		struct fd_handle *handle;
		int fd = fcntl(STDOUT_FILENO, F_DUPFD, 0);

		if (fd < 0) {
			PERROR("Failed to create fd while creating test payload");
			goto error;
		}

		handle = fd_handle_create(fd);
		if (!handle) {
			if (close(fd)) {
				PERROR("Failed to close fd while preparing test payload");
				goto error;
			}
		}

		ret = lttng_payload_push_fd_handle(&sent_payload, handle);
		fd_handle_put(handle);
		if (ret) {
			PERROR("Failed to add fd handle to test payload");
			goto error;
		}
	}

	/* Send payload. */
	{
		ssize_t sock_ret;
		struct lttng_payload_view pv =
			lttng_payload_view_from_payload(&sent_payload, 0, -1);

		/* Not expected to block considering the size of the payload. */
		sock_ret = lttcomm_send_unix_sock(sockets[0], pv.buffer.data, pv.buffer.size);
		ok(sock_ret == pv.buffer.size, "Sent complete test payload");
		if (sock_ret != pv.buffer.size) {
			ERR("Failed to send test payload bytes: ret = %zd, expected = %zu",
			    sock_ret,
			    pv.buffer.size);
			goto error;
		}

		sock_ret = lttcomm_send_payload_view_fds_unix_sock(sockets[0], &pv);
		ok(sock_ret == 1, "Sent test payload file descriptors");
		if (sock_ret != 1) {
			if (sock_ret < 0) {
				PERROR("Failed to send test payload file descriptors: ret = %zd, expected = %d",
				       sock_ret,
				       1);
			} else {
				diag("Failed to send test payload file descriptors: ret = %zd, expected = %d",
				     sock_ret,
				     1);
			}

			goto error;
		}
	}

	/* Receive payload */
	{
		ssize_t sock_ret;

		ret = lttng_dynamic_buffer_set_size(&received_payload.buffer,
						    sent_payload.buffer.size);
		if (ret) {
			PERROR("Failed to pre-allocate reception buffer");
			goto error;
		}

		sock_ret = lttcomm_recv_unix_sock(
			sockets[1], received_payload.buffer.data, received_payload.buffer.size);
		ok(sock_ret == received_payload.buffer.size, "Received payload bytes");
		if (sock_ret != received_payload.buffer.size) {
			ERR("Failed to receive payload bytes: ret = %zd, expected = %zu",
			    sock_ret,
			    received_payload.buffer.size);
			goto error;
		}

		sock_ret =
			lttcomm_recv_payload_fds_unix_sock(sockets[1], fd_count, &received_payload);
		ok(sock_ret == (int) (sizeof(int) * fd_count),
		   "FD reception return value is number of fd * sizeof(int)");
		if (sock_ret != (int) (sizeof(int) * fd_count)) {
			ERR("Failed to receive test payload file descriptors: ret = %zd, expected = %d",
			    sock_ret,
			    (int) (fd_count * sizeof(int)));
			goto error;
		}

		{
			const struct lttng_payload_view pv =
				lttng_payload_view_from_payload(&received_payload, 0, -1);
			const int fd_handle_count = lttng_payload_view_get_fd_handle_count(&pv);

			ok(fd_handle_count == fd_count,
			   "Received all test payload file descriptors in one invocation");
		}
	}

error:
	for (i = 0; i < 2; i++) {
		if (sockets[i] < 0) {
			continue;
		}

		if (close(sockets[i])) {
			PERROR("Failed to close unix socket");
		}
	}

	lttng_payload_reset(&sent_payload);
	lttng_payload_reset(&received_payload);
}

/*
 * Validate that if the sender sent multiple messages, each containing 1 fd,
 * the receiver can receive one message at a time (the binary payload and its
 * fd) and is not forced to receive all file descriptors at once.
 */
static void test_one_fd_per_message(unsigned int message_count)
{
	const unsigned int payload_content = 42;
	int sockets[2] = { -1, -1 };
	int ret;
	unsigned int i;
	struct lttng_payload sent_payload;
	struct lttng_payload received_payload;

	diag("Send and receive small messages with one FD each (%u messages)", message_count);
	lttng_payload_init(&sent_payload);
	lttng_payload_init(&received_payload);

	ret = lttcomm_create_anon_unix_socketpair(sockets);
	ok(ret == 0, "Created anonymous unix socket pair");
	if (ret < 0) {
		PERROR("Failed to create an anonymous pair of unix sockets");
		goto error;
	}

	/* Send messages with one fd each. */
	for (i = 0; i < message_count; i++) {
		struct fd_handle *handle;
		int fd;

		/* Add dummy content to payload. */
		ret = lttng_dynamic_buffer_append(
			&sent_payload.buffer, &payload_content, sizeof(payload_content));
		if (ret) {
			PERROR("Failed to initialize test payload");
			goto error;
		}

		fd = fcntl(STDOUT_FILENO, F_DUPFD, 0);
		if (fd < 0) {
			PERROR("Failed to create fd while creating test payload");
			goto error;
		}

		handle = fd_handle_create(fd);
		if (!handle) {
			if (close(fd)) {
				PERROR("Failed to close fd while preparing test payload");
				goto error;
			}
		}

		ret = lttng_payload_push_fd_handle(&sent_payload, handle);
		fd_handle_put(handle);
		if (ret) {
			PERROR("Failed to add fd handle to test payload");
			goto error;
		}

		/* Send payload. */
		{
			ssize_t sock_ret;
			struct lttng_payload_view pv =
				lttng_payload_view_from_payload(&sent_payload, 0, -1);

			/* Not expected to block considering the size of the
			 * payload. */
			sock_ret =
				lttcomm_send_unix_sock(sockets[0], pv.buffer.data, pv.buffer.size);
			ok(sock_ret == pv.buffer.size, "Sent binary payload for message %u", i);
			if (sock_ret != pv.buffer.size) {
				ERR("Failed to send test payload bytes: ret = %zd, expected = %zu",
				    sock_ret,
				    pv.buffer.size);
				goto error;
			}

			sock_ret = lttcomm_send_payload_view_fds_unix_sock(sockets[0], &pv);
			ok(sock_ret == 1, "Sent file descriptors payload for message %u", i);
			if (sock_ret != 1) {
				if (sock_ret < 0) {
					PERROR("Failed to send test payload file descriptors: ret = %zd, expected = %d",
					       sock_ret,
					       1);
				} else {
					diag("Failed to send test payload file descriptors: ret = %zd, expected = %d",
					     sock_ret,
					     1);
				}

				goto error;
			}
		}

		lttng_payload_clear(&sent_payload);
	}

	/* Receive messages one at a time. */
	for (i = 0; i < message_count; i++) {
		ssize_t sock_ret;

		ret = lttng_dynamic_buffer_set_size(&received_payload.buffer,
						    sizeof(payload_content));
		if (ret) {
			PERROR("Failed to pre-allocate reception buffer");
			goto error;
		}

		sock_ret = lttcomm_recv_unix_sock(
			sockets[1], received_payload.buffer.data, received_payload.buffer.size);
		ok(sock_ret == received_payload.buffer.size,
		   "Received payload bytes for message %u",
		   i);
		if (sock_ret != received_payload.buffer.size) {
			ERR("Failed to receive payload bytes: ret = %zd, expected = %zu",
			    sock_ret,
			    received_payload.buffer.size);
			goto error;
		}

		sock_ret = lttcomm_recv_payload_fds_unix_sock(sockets[1], 1, &received_payload);
		ok(sock_ret == (int) sizeof(int), "Received fd for message %u", i);
		if (sock_ret != (int) sizeof(int)) {
			ERR("Failed to receive test payload file descriptors: ret = %zd, expected = %u",
			    sock_ret,
			    (int) sizeof(int));
			goto error;
		}

		{
			const struct lttng_payload_view pv =
				lttng_payload_view_from_payload(&received_payload, 0, -1);
			const int fd_handle_count = lttng_payload_view_get_fd_handle_count(&pv);

			ok(fd_handle_count == 1, "Payload contains 1 fd for message %u", i);
		}

		lttng_payload_clear(&received_payload);
	}

error:
	for (i = 0; i < 2; i++) {
		if (sockets[i] < 0) {
			continue;
		}

		if (close(sockets[i])) {
			PERROR("Failed to close unix socket");
		}
	}

	lttng_payload_reset(&sent_payload);
	lttng_payload_reset(&received_payload);
}

/*
 * Validate that a large message can be received in multiple chunks.
 */
static void test_receive_in_chunks(unsigned int payload_size, unsigned int max_recv_size)
{
	int sockets[2] = { -1, -1 };
	int ret;
	unsigned int i;
	struct lttng_payload sent_payload;
	struct lttng_payload received_payload;
	struct fd_handle *handle;
	int fd;
	ssize_t sock_ret, received = 0;

	diag("Receive a message in multiple chunks");
	lttng_payload_init(&sent_payload);
	lttng_payload_init(&received_payload);

	ret = lttcomm_create_anon_unix_socketpair(sockets);
	ok(ret == 0, "Created anonymous unix socket pair");
	if (ret < 0) {
		PERROR("Failed to create an anonymous pair of unix sockets");
		goto error;
	}

	/* Add dummy content to payload. */
	ret = lttng_dynamic_buffer_set_size(&sent_payload.buffer, payload_size);
	if (ret) {
		PERROR("Failed to initialize test payload");
		goto error;
	}

	fd = fcntl(STDOUT_FILENO, F_DUPFD, 0);
	if (fd < 0) {
		PERROR("Failed to create fd while creating test payload");
		goto error;
	}

	handle = fd_handle_create(fd);
	if (!handle) {
		if (close(fd)) {
			PERROR("Failed to close fd while preparing test payload");
			goto error;
		}
	}

	ret = lttng_payload_push_fd_handle(&sent_payload, handle);
	fd_handle_put(handle);
	if (ret) {
		PERROR("Failed to add fd handle to test payload");
		goto error;
	}

	/* Send payload. */
	{
		struct lttng_payload_view pv =
			lttng_payload_view_from_payload(&sent_payload, 0, -1);

		/* Not expected to block considering the size of the payload. */
		sock_ret = lttcomm_send_unix_sock(sockets[0], pv.buffer.data, pv.buffer.size);
		ok(sock_ret == pv.buffer.size, "Sent complete test payload");
		if (sock_ret != pv.buffer.size) {
			ERR("Failed to send test payload bytes: ret = %zd, expected = %zu",
			    sock_ret,
			    pv.buffer.size);
			goto error;
		}

		sock_ret = lttcomm_send_payload_view_fds_unix_sock(sockets[0], &pv);
		ok(sock_ret == 1, "Sent test payload file descriptors");
		if (sock_ret != 1) {
			if (sock_ret < 0) {
				PERROR("Failed to send test payload file descriptors: ret = %zd, expected = %d",
				       sock_ret,
				       1);
			} else {
				diag("Failed to send test payload file descriptors: ret = %zd, expected = %d",
				     sock_ret,
				     1);
			}

			goto error;
		}
	}

	/* Receive payload */
	ret = lttng_dynamic_buffer_set_size(&received_payload.buffer, sent_payload.buffer.size);
	if (ret) {
		PERROR("Failed to pre-allocate reception buffer");
		goto error;
	}

	do {
		const ssize_t to_receive_this_pass =
			std::min<ssize_t>(max_recv_size, sent_payload.buffer.size - received);

		sock_ret = lttcomm_recv_unix_sock(
			sockets[1], received_payload.buffer.data + received, to_receive_this_pass);
		if (sock_ret != to_receive_this_pass) {
			ERR("Failed to receive payload bytes: ret = %zd, expected = %zu",
			    sock_ret,
			    to_receive_this_pass);
			break;
		}

		received += sock_ret;
	} while (received < sent_payload.buffer.size);

	ok(received == sent_payload.buffer.size,
	   "Received complete payload in chunks of %u bytes",
	   max_recv_size);
	if (received != sent_payload.buffer.size) {
		goto error;
	}

	sock_ret = lttcomm_recv_payload_fds_unix_sock(sockets[1], 1, &received_payload);
	ok(sock_ret == (int) sizeof(int),
	   "Received file descriptor after receiving payload in chunks");
	if (sock_ret != (int) sizeof(int)) {
		ERR("Failed to receive test payload file descriptors: ret = %zd, expected = %d",
		    sock_ret,
		    (int) sizeof(int));
		goto error;
	}

	{
		const struct lttng_payload_view pv =
			lttng_payload_view_from_payload(&received_payload, 0, -1);
		const int fd_handle_count = lttng_payload_view_get_fd_handle_count(&pv);

		ok(fd_handle_count == 1, "Payload contains 1 fd after receiving payload in chunks");
	}

error:
	for (i = 0; i < 2; i++) {
		if (sockets[i] < 0) {
			continue;
		}

		if (close(sockets[i])) {
			PERROR("Failed to close unix socket");
		}
	}

	lttng_payload_reset(&sent_payload);
	lttng_payload_reset(&received_payload);
}

static void test_creds_passing()
{
	pid_t fork_ret = -1;
	int ret, parent_socket = -1, child_connection_socket = -1;
	ssize_t sock_ret;
	char socket_dir_path[] = "/tmp/test.unix.socket.creds.passing.XXXXXX";
	char socket_path[PATH_MAX] = {};
	struct expected_creds {
		uid_t euid;
		gid_t egid;
		pid_t pid;
	} expected_creds;

	diag("Receive peer's effective uid, effective gid, and pid from a unix socket");

	if (!mkdtemp(socket_dir_path)) {
		PERROR("Failed to generate temporary socket location");
		goto error;
	}

	strncat(socket_path, socket_dir_path, sizeof(socket_path) - strlen(socket_path) - 1);
	strncat(socket_path, "/test_unix_socket", sizeof(socket_path) - strlen(socket_path) - 1);

	parent_socket = lttcomm_create_unix_sock(socket_path);
	ok(parent_socket >= 0, "Created unix socket at path `%s`", socket_path);
	if (parent_socket < 0) {
		PERROR("Failed to create unix socket at path `%s`", socket_path);
		goto error;
	}

	ret = lttcomm_listen_unix_sock(parent_socket);
	if (ret < 0) {
		PERROR("Failed to mark parent socket as a passive socket");
		goto error;
	}

	ret = lttcomm_setsockopt_creds_unix_sock(parent_socket);
	if (ret) {
		PERROR("Failed to set SO_PASSCRED on parent socket");
		goto error;
	}

	fork_ret = fork();
	if (fork_ret < 0) {
		PERROR("Failed to fork");
		goto error;
	}

	if (fork_ret == 0) {
		/* Child. */
		int child_socket;

		expected_creds = (struct expected_creds){
			.euid = geteuid(),
			.egid = getegid(),
			.pid = getpid(),
		};

		child_socket = lttcomm_connect_unix_sock(socket_path);
		if (child_socket < 0) {
			PERROR("Failed to connect to parent socket");
			goto error;
		}

		ret = lttcomm_setsockopt_creds_unix_sock(child_socket);
		if (ret) {
			PERROR("Failed to set SO_PASSCRED on child socket");
		}

		sock_ret = lttcomm_send_creds_unix_sock(
			child_socket, &expected_creds, sizeof(expected_creds));
		if (sock_ret < 0) {
			PERROR("Failed to send expected credentials");
		}

		ret = close(child_socket);
		if (ret) {
			PERROR("Failed to close child socket");
		}
	} else {
		/* Parent. */
		int child_status;
		pid_t wait_pid_ret;
		lttng_sock_cred received_creds = {};

		child_connection_socket = lttcomm_accept_unix_sock(parent_socket);
		if (child_connection_socket < 0) {
			PERROR();
			goto error;
		}

		ret = lttcomm_setsockopt_creds_unix_sock(child_connection_socket);
		if (ret) {
			PERROR("Failed to set SO_PASSCRED on child connection socket");
			goto error;
		}

		sock_ret = lttcomm_recv_creds_unix_sock(child_connection_socket,
							&expected_creds,
							sizeof(expected_creds),
							&received_creds);
		if (sock_ret < 0) {
			PERROR("Failed to receive credentials");
			goto error;
		}

		wait_pid_ret = waitpid(fork_ret, &child_status, 0);
		if (wait_pid_ret == -1) {
			PERROR("Failed to wait for termination of child process");
			goto error;
		}
		if (!WIFEXITED(child_status) || WEXITSTATUS(child_status)) {
			diag("Child process reported an error, test failed");
			goto error;
		}

		ok(expected_creds.euid == received_creds.uid,
		   "Received the expected effective uid (%d == %d)",
		   expected_creds.euid,
		   received_creds.uid);
		ok(expected_creds.egid == received_creds.gid,
		   "Received the expected effective gid (%d == %d)",
		   expected_creds.egid,
		   received_creds.gid);
		ok(expected_creds.pid == received_creds.pid,
		   "Received the expected pid (%d == %d)",
		   expected_creds.pid,
		   received_creds.pid);
	}

error:
	if (parent_socket >= 0) {
		ret = close(parent_socket);
		if (ret) {
			PERROR("Failed to close parent socket");
		}
	}

	if (fork_ret == 0) {
		/* Prevent libtap from printing a result for the child. */
		fclose(stdout);
		fclose(stderr);

		/* Child exits at the end of this test. */
		exit(0);
	} else if (parent_socket >= 0) {
		if (child_connection_socket >= 0) {
			ret = close(child_connection_socket);
			if (ret) {
				PERROR("Failed to close child connection socket");
			}
		}

		ret = unlink(socket_path);
		if (ret) {
			PERROR("Failed to unlink socket at path `%s`", socket_path);
		}

		ret = rmdir(socket_dir_path);
		if (ret) {
			PERROR("Failed to remove test directory at `%s`", socket_dir_path);
		}
	}
}

int main()
{
	plan_tests(TEST_COUNT);

	test_high_fd_count(HIGH_FD_COUNT);
	test_one_fd_per_message(MESSAGE_COUNT);
	test_receive_in_chunks(LARGE_PAYLOAD_SIZE, LARGE_PAYLOAD_RECV_SIZE);
	test_creds_passing();

	return exit_status();
}
