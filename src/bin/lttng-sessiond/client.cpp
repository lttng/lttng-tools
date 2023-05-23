/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "agent-thread.hpp"
#include "clear.hpp"
#include "client.hpp"
#include "cmd.hpp"
#include "common/buffer-view.hpp"
#include "common/compat/socket.hpp"
#include "common/dynamic-array.hpp"
#include "common/dynamic-buffer.hpp"
#include "common/fd-handle.hpp"
#include "common/payload-view.hpp"
#include "common/payload.hpp"
#include "common/sessiond-comm/sessiond-comm.hpp"
#include "health-sessiond.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "lttng/lttng-error.h"
#include "lttng/tracker.h"
#include "manage-consumer.hpp"
#include "save.hpp"
#include "testpoint.hpp"
#include "utils.hpp"

#include <common/compat/getenv.hpp>
#include <common/exception.hpp>
#include <common/tracker.hpp>
#include <common/unix.hpp>
#include <common/utils.hpp>

#include <lttng/error-query-internal.hpp>
#include <lttng/event-internal.hpp>
#include <lttng/session-descriptor-internal.hpp>
#include <lttng/session-internal.hpp>
#include <lttng/userspace-probe-internal.hpp>

#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
bool is_root;

struct thread_state {
	sem_t ready;
	bool running;
	int client_sock;
} thread_state;
} /* namespace */

static void set_thread_status(bool running)
{
	DBG("Marking client thread's state as %s", running ? "running" : "error");
	thread_state.running = running;
	sem_post(&thread_state.ready);
}

static bool wait_thread_status()
{
	DBG("Waiting for client thread to be ready");
	sem_wait(&thread_state.ready);
	if (thread_state.running) {
		DBG("Client thread is ready");
	} else {
		ERR("Initialization of client thread failed");
	}

	return thread_state.running;
}

/*
 * Setup the outgoing data buffer for the response (llm) by allocating the
 * right amount of memory and copying the original information from the lsm
 * structure.
 *
 * Return 0 on success, negative value on error.
 */
static int setup_lttng_msg(struct command_ctx *cmd_ctx,
			   const void *payload_buf,
			   size_t payload_len,
			   const void *cmd_header_buf,
			   size_t cmd_header_len)
{
	int ret = 0;
	const size_t header_len = sizeof(struct lttcomm_lttng_msg);
	const size_t total_msg_size = header_len + cmd_header_len + payload_len;
	lttcomm_lttng_msg llm{};

	llm.cmd_type = cmd_ctx->lsm.cmd_type;
	llm.pid = (uint32_t) cmd_ctx->lsm.domain.attr.pid;
	llm.cmd_header_size = (uint32_t) cmd_header_len;
	llm.data_size = (uint32_t) payload_len;

	ret = lttng_dynamic_buffer_set_size(&cmd_ctx->reply_payload.buffer, 0);
	if (ret) {
		goto end;
	}

	lttng_dynamic_pointer_array_clear(&cmd_ctx->reply_payload._fd_handles);

	cmd_ctx->lttng_msg_size = total_msg_size;

	/* Append reply header. */
	ret = lttng_dynamic_buffer_append(&cmd_ctx->reply_payload.buffer, &llm, sizeof(llm));
	if (ret) {
		goto end;
	}

	/* Append command header. */
	if (cmd_header_len) {
		ret = lttng_dynamic_buffer_append(
			&cmd_ctx->reply_payload.buffer, cmd_header_buf, cmd_header_len);
		if (ret) {
			goto end;
		}
	}

	/* Append payload. */
	if (payload_len) {
		ret = lttng_dynamic_buffer_append(
			&cmd_ctx->reply_payload.buffer, payload_buf, payload_len);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

static int setup_empty_lttng_msg(struct command_ctx *cmd_ctx)
{
	int ret;
	const struct lttcomm_lttng_msg llm = {};

	ret = lttng_dynamic_buffer_set_size(&cmd_ctx->reply_payload.buffer, 0);
	if (ret) {
		goto end;
	}

	/* Append place-holder reply header. */
	ret = lttng_dynamic_buffer_append(&cmd_ctx->reply_payload.buffer, &llm, sizeof(llm));
	if (ret) {
		goto end;
	}

	cmd_ctx->lttng_msg_size = sizeof(llm);
end:
	return ret;
}

static void update_lttng_msg(struct command_ctx *cmd_ctx, size_t cmd_header_len, size_t payload_len)
{
	const size_t header_len = sizeof(struct lttcomm_lttng_msg);
	const size_t total_msg_size = header_len + cmd_header_len + payload_len;
	struct lttcomm_lttng_msg *p_llm;
	lttcomm_lttng_msg llm{};

	llm.cmd_type = cmd_ctx->lsm.cmd_type;
	llm.pid = (uint32_t) cmd_ctx->lsm.domain.attr.pid;
	llm.cmd_header_size = (uint32_t) cmd_header_len;
	llm.data_size = (uint32_t) payload_len;

	LTTNG_ASSERT(cmd_ctx->reply_payload.buffer.size >= sizeof(llm));

	p_llm = (typeof(p_llm)) cmd_ctx->reply_payload.buffer.data;

	/* Update existing header. */
	memcpy(p_llm, &llm, sizeof(llm));

	cmd_ctx->lttng_msg_size = total_msg_size;
}

/*
 * Start the thread_manage_consumer. This must be done after a lttng-consumerd
 * exec or it will fail.
 */
static int spawn_consumer_thread(struct consumer_data *consumer_data)
{
	return launch_consumer_management_thread(consumer_data) ? 0 : -1;
}

/*
 * Fork and exec a consumer daemon (consumerd).
 *
 * Return pid if successful else -1.
 */
static pid_t spawn_consumerd(struct consumer_data *consumer_data)
{
	int ret;
	pid_t pid;
	const char *consumer_to_use;
	const char *verbosity;
	struct stat st;

	DBG("Spawning consumerd");

	pid = fork();
	if (pid == 0) {
		/*
		 * Exec consumerd.
		 */
		if (the_config.verbose_consumer) {
			verbosity = "--verbose";
		} else if (lttng_opt_quiet) {
			verbosity = "--quiet";
		} else {
			verbosity = "";
		}

		switch (consumer_data->type) {
		case LTTNG_CONSUMER_KERNEL:
			/*
			 * Find out which consumerd to execute. We will first try the
			 * 64-bit path, then the sessiond's installation directory, and
			 * fallback on the 32-bit one,
			 */
			DBG3("Looking for a kernel consumer at these locations:");
			DBG3("	1) %s", the_config.consumerd64_bin_path.value ?: "NULL");
			DBG3("	2) %s/%s", INSTALL_BIN_PATH, DEFAULT_CONSUMERD_FILE);
			DBG3("	3) %s", the_config.consumerd32_bin_path.value ?: "NULL");
			if (stat(the_config.consumerd64_bin_path.value, &st) == 0) {
				DBG3("Found location #1");
				consumer_to_use = the_config.consumerd64_bin_path.value;
			} else if (stat(INSTALL_BIN_PATH "/" DEFAULT_CONSUMERD_FILE, &st) == 0) {
				DBG3("Found location #2");
				consumer_to_use = INSTALL_BIN_PATH "/" DEFAULT_CONSUMERD_FILE;
			} else if (the_config.consumerd32_bin_path.value &&
				   stat(the_config.consumerd32_bin_path.value, &st) == 0) {
				DBG3("Found location #3");
				consumer_to_use = the_config.consumerd32_bin_path.value;
			} else {
				DBG("Could not find any valid consumerd executable");
				ret = -EINVAL;
				goto error;
			}
			DBG("Using kernel consumer at: %s", consumer_to_use);
			(void) execl(consumer_to_use,
				     "lttng-consumerd",
				     verbosity,
				     "-k",
				     "--consumerd-cmd-sock",
				     consumer_data->cmd_unix_sock_path,
				     "--consumerd-err-sock",
				     consumer_data->err_unix_sock_path,
				     "--group",
				     the_config.tracing_group_name.value,
				     NULL);
			break;
		case LTTNG_CONSUMER64_UST:
		{
			if (the_config.consumerd64_lib_dir.value) {
				const char *tmp;
				size_t tmplen;
				char *tmpnew;

				tmp = lttng_secure_getenv("LD_LIBRARY_PATH");
				if (!tmp) {
					tmp = "";
				}
				tmplen = strlen(the_config.consumerd64_lib_dir.value) + 1 /* : */ +
					strlen(tmp);
				tmpnew = zmalloc<char>(tmplen + 1 /* \0 */);
				if (!tmpnew) {
					ret = -ENOMEM;
					goto error;
				}
				strcat(tmpnew, the_config.consumerd64_lib_dir.value);
				if (tmp[0] != '\0') {
					strcat(tmpnew, ":");
					strcat(tmpnew, tmp);
				}
				ret = setenv("LD_LIBRARY_PATH", tmpnew, 1);
				free(tmpnew);
				if (ret) {
					ret = -errno;
					goto error;
				}
			}
			DBG("Using 64-bit UST consumer at: %s",
			    the_config.consumerd64_bin_path.value);
			(void) execl(the_config.consumerd64_bin_path.value,
				     "lttng-consumerd",
				     verbosity,
				     "-u",
				     "--consumerd-cmd-sock",
				     consumer_data->cmd_unix_sock_path,
				     "--consumerd-err-sock",
				     consumer_data->err_unix_sock_path,
				     "--group",
				     the_config.tracing_group_name.value,
				     NULL);
			break;
		}
		case LTTNG_CONSUMER32_UST:
		{
			if (the_config.consumerd32_lib_dir.value) {
				const char *tmp;
				size_t tmplen;
				char *tmpnew;

				tmp = lttng_secure_getenv("LD_LIBRARY_PATH");
				if (!tmp) {
					tmp = "";
				}
				tmplen = strlen(the_config.consumerd32_lib_dir.value) + 1 /* : */ +
					strlen(tmp);
				tmpnew = zmalloc<char>(tmplen + 1 /* \0 */);
				if (!tmpnew) {
					ret = -ENOMEM;
					goto error;
				}
				strcat(tmpnew, the_config.consumerd32_lib_dir.value);
				if (tmp[0] != '\0') {
					strcat(tmpnew, ":");
					strcat(tmpnew, tmp);
				}
				ret = setenv("LD_LIBRARY_PATH", tmpnew, 1);
				free(tmpnew);
				if (ret) {
					ret = -errno;
					goto error;
				}
			}
			DBG("Using 32-bit UST consumer at: %s",
			    the_config.consumerd32_bin_path.value);
			(void) execl(the_config.consumerd32_bin_path.value,
				     "lttng-consumerd",
				     verbosity,
				     "-u",
				     "--consumerd-cmd-sock",
				     consumer_data->cmd_unix_sock_path,
				     "--consumerd-err-sock",
				     consumer_data->err_unix_sock_path,
				     "--group",
				     the_config.tracing_group_name.value,
				     NULL);
			break;
		}
		default:
			ERR("unknown consumer type");
			errno = 0;
		}
		if (errno != 0) {
			PERROR("Consumer execl()");
		}
		/* Reaching this point, we got a failure on our execl(). */
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		ret = pid;
	} else {
		PERROR("start consumer fork");
		ret = -errno;
	}
error:
	return ret;
}

/*
 * Spawn the consumerd daemon and session daemon thread.
 */
static int start_consumerd(struct consumer_data *consumer_data)
{
	int ret;

	/*
	 * Set the listen() state on the socket since there is a possible race
	 * between the exec() of the consumer daemon and this call if place in the
	 * consumer thread. See bug #366 for more details.
	 */
	ret = lttcomm_listen_unix_sock(consumer_data->err_sock);
	if (ret < 0) {
		goto error;
	}

	pthread_mutex_lock(&consumer_data->pid_mutex);
	if (consumer_data->pid != 0) {
		pthread_mutex_unlock(&consumer_data->pid_mutex);
		goto end;
	}

	ret = spawn_consumerd(consumer_data);
	if (ret < 0) {
		ERR("Spawning consumerd failed");
		pthread_mutex_unlock(&consumer_data->pid_mutex);
		goto error;
	}

	/* Setting up the consumer_data pid */
	consumer_data->pid = ret;
	DBG2("Consumer pid %d", consumer_data->pid);
	pthread_mutex_unlock(&consumer_data->pid_mutex);

	DBG2("Spawning consumer control thread");
	ret = spawn_consumer_thread(consumer_data);
	if (ret < 0) {
		ERR("Fatal error spawning consumer control thread");
		goto error;
	}

end:
	return 0;

error:
	/* Cleanup already created sockets on error. */
	if (consumer_data->err_sock >= 0) {
		int err;

		err = close(consumer_data->err_sock);
		if (err < 0) {
			PERROR("close consumer data error socket");
		}
	}
	return ret;
}

/*
 * Copy consumer output from the tracing session to the domain session. The
 * function also applies the right modification on a per domain basis for the
 * trace files destination directory.
 */
static int copy_session_consumer(int domain, struct ltt_session *session)
{
	int ret;
	const char *dir_name;
	struct consumer_output *consumer;

	LTTNG_ASSERT(session);
	LTTNG_ASSERT(session->consumer);

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		DBG3("Copying tracing session consumer output in kernel session");
		/*
		 * XXX: We should audit the session creation and what this function
		 * does "extra" in order to avoid a destroy since this function is used
		 * in the domain session creation (kernel and ust) only. Same for UST
		 * domain.
		 */
		if (session->kernel_session->consumer) {
			consumer_output_put(session->kernel_session->consumer);
		}
		session->kernel_session->consumer = consumer_copy_output(session->consumer);
		/* Ease our life a bit for the next part */
		consumer = session->kernel_session->consumer;
		dir_name = DEFAULT_KERNEL_TRACE_DIR;
		break;
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_UST:
		DBG3("Copying tracing session consumer output in UST session");
		if (session->ust_session->consumer) {
			consumer_output_put(session->ust_session->consumer);
		}
		session->ust_session->consumer = consumer_copy_output(session->consumer);
		/* Ease our life a bit for the next part */
		consumer = session->ust_session->consumer;
		dir_name = DEFAULT_UST_TRACE_DIR;
		break;
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

	/* Append correct directory to subdir */
	ret = lttng_strncpy(consumer->domain_subdir, dir_name, sizeof(consumer->domain_subdir));
	if (ret) {
		ret = LTTNG_ERR_UNK;
		goto error;
	}
	DBG3("Copy session consumer subdir %s", consumer->domain_subdir);
	ret = LTTNG_OK;

error:
	return ret;
}

/*
 * Create an UST session and add it to the session ust list.
 */
static int create_ust_session(struct ltt_session *session, const struct lttng_domain *domain)
{
	int ret;
	struct ltt_ust_session *lus = nullptr;

	LTTNG_ASSERT(session);
	LTTNG_ASSERT(domain);
	LTTNG_ASSERT(session->consumer);

	switch (domain->type) {
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_UST:
		break;
	default:
		ERR("Unknown UST domain on create session %d", domain->type);
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

	DBG("Creating UST session");

	lus = trace_ust_create_session(session->id);
	if (lus == nullptr) {
		ret = LTTNG_ERR_UST_SESS_FAIL;
		goto error;
	}

	lus->uid = session->uid;
	lus->gid = session->gid;
	lus->output_traces = session->output_traces;
	lus->snapshot_mode = session->snapshot_mode;
	lus->live_timer_interval = session->live_timer;
	session->ust_session = lus;
	if (session->shm_path[0]) {
		strncpy(lus->root_shm_path, session->shm_path, sizeof(lus->root_shm_path));
		lus->root_shm_path[sizeof(lus->root_shm_path) - 1] = '\0';
		strncpy(lus->shm_path, session->shm_path, sizeof(lus->shm_path));
		lus->shm_path[sizeof(lus->shm_path) - 1] = '\0';
		strncat(lus->shm_path, "/ust", sizeof(lus->shm_path) - strlen(lus->shm_path) - 1);
	}
	/* Copy session output to the newly created UST session */
	ret = copy_session_consumer(domain->type, session);
	if (ret != LTTNG_OK) {
		goto error;
	}

	return LTTNG_OK;

error:
	free(lus);
	session->ust_session = nullptr;
	return ret;
}

/*
 * Create a kernel tracer session then create the default channel.
 */
static int create_kernel_session(struct ltt_session *session)
{
	int ret;

	DBG("Creating kernel session");

	ret = kernel_create_session(session);
	if (ret < 0) {
		ret = LTTNG_ERR_KERN_SESS_FAIL;
		goto error_create;
	}

	/* Code flow safety */
	LTTNG_ASSERT(session->kernel_session);

	/* Copy session output to the newly created Kernel session */
	ret = copy_session_consumer(LTTNG_DOMAIN_KERNEL, session);
	if (ret != LTTNG_OK) {
		goto error;
	}

	session->kernel_session->uid = session->uid;
	session->kernel_session->gid = session->gid;
	session->kernel_session->output_traces = session->output_traces;
	session->kernel_session->snapshot_mode = session->snapshot_mode;
	session->kernel_session->is_live_session = session->live_timer != 0;

	return LTTNG_OK;

error:
	trace_kernel_destroy_session(session->kernel_session);
	session->kernel_session = nullptr;
error_create:
	return ret;
}

/*
 * Count number of session permitted by uid/gid.
 */
static unsigned int lttng_sessions_count(uid_t uid, gid_t gid __attribute__((unused)))
{
	unsigned int i = 0;
	struct ltt_session *session;
	const struct ltt_session_list *session_list = session_get_list();

	DBG("Counting number of available session for UID %d", uid);
	cds_list_for_each_entry (session, &session_list->head, list) {
		if (!session_get(session)) {
			continue;
		}
		session_lock(session);
		/* Only count the sessions the user can control. */
		if (session_access_ok(session, uid) && !session->destroyed) {
			i++;
		}
		session_unlock(session);
		session_put(session);
	}
	return i;
}

static enum lttng_error_code receive_lttng_trigger(struct command_ctx *cmd_ctx,
						   int sock,
						   int *sock_error,
						   struct lttng_trigger **_trigger)
{
	int ret;
	size_t trigger_len;
	ssize_t sock_recv_len;
	enum lttng_error_code ret_code;
	struct lttng_payload trigger_payload;
	struct lttng_trigger *trigger = nullptr;

	lttng_payload_init(&trigger_payload);
	trigger_len = (size_t) cmd_ctx->lsm.u.trigger.length;
	ret = lttng_dynamic_buffer_set_size(&trigger_payload.buffer, trigger_len);
	if (ret) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	sock_recv_len = lttcomm_recv_unix_sock(sock, trigger_payload.buffer.data, trigger_len);
	if (sock_recv_len < 0 || sock_recv_len != trigger_len) {
		ERR("Failed to receive trigger in command payload");
		*sock_error = 1;
		ret_code = LTTNG_ERR_INVALID_PROTOCOL;
		goto end;
	}

	/* Receive fds, if any. */
	if (cmd_ctx->lsm.fd_count > 0) {
		sock_recv_len = lttcomm_recv_payload_fds_unix_sock(
			sock, cmd_ctx->lsm.fd_count, &trigger_payload);
		if (sock_recv_len > 0 && sock_recv_len != cmd_ctx->lsm.fd_count * sizeof(int)) {
			ERR("Failed to receive all file descriptors for trigger in command payload: expected fd count = %u, ret = %d",
			    cmd_ctx->lsm.fd_count,
			    (int) ret);
			ret_code = LTTNG_ERR_INVALID_PROTOCOL;
			*sock_error = 1;
			goto end;
		} else if (sock_recv_len <= 0) {
			ERR("Failed to receive file descriptors for trigger in command payload: expected fd count = %u, ret = %d",
			    cmd_ctx->lsm.fd_count,
			    (int) ret);
			ret_code = LTTNG_ERR_FATAL;
			*sock_error = 1;
			goto end;
		}
	}

	/* Deserialize trigger. */
	{
		struct lttng_payload_view view =
			lttng_payload_view_from_payload(&trigger_payload, 0, -1);

		if (lttng_trigger_create_from_payload(&view, &trigger) != trigger_len) {
			ERR("Invalid trigger received as part of command payload");
			ret_code = LTTNG_ERR_INVALID_TRIGGER;
			lttng_trigger_put(trigger);
			goto end;
		}
	}

	*_trigger = trigger;
	ret_code = LTTNG_OK;

end:
	lttng_payload_reset(&trigger_payload);
	return ret_code;
}

static enum lttng_error_code receive_lttng_error_query(struct command_ctx *cmd_ctx,
						       int sock,
						       int *sock_error,
						       struct lttng_error_query **_query)
{
	int ret;
	size_t query_len;
	ssize_t sock_recv_len;
	enum lttng_error_code ret_code;
	struct lttng_payload query_payload;
	struct lttng_error_query *query = nullptr;

	lttng_payload_init(&query_payload);
	query_len = (size_t) cmd_ctx->lsm.u.error_query.length;
	ret = lttng_dynamic_buffer_set_size(&query_payload.buffer, query_len);
	if (ret) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	sock_recv_len = lttcomm_recv_unix_sock(sock, query_payload.buffer.data, query_len);
	if (sock_recv_len < 0 || sock_recv_len != query_len) {
		ERR("Failed to receive error query in command payload");
		*sock_error = 1;
		ret_code = LTTNG_ERR_INVALID_PROTOCOL;
		goto end;
	}

	/* Receive fds, if any. */
	if (cmd_ctx->lsm.fd_count > 0) {
		sock_recv_len = lttcomm_recv_payload_fds_unix_sock(
			sock, cmd_ctx->lsm.fd_count, &query_payload);
		if (sock_recv_len > 0 && sock_recv_len != cmd_ctx->lsm.fd_count * sizeof(int)) {
			ERR("Failed to receive all file descriptors for error query in command payload: expected fd count = %u, ret = %d",
			    cmd_ctx->lsm.fd_count,
			    (int) ret);
			ret_code = LTTNG_ERR_INVALID_PROTOCOL;
			*sock_error = 1;
			goto end;
		} else if (sock_recv_len <= 0) {
			ERR("Failed to receive file descriptors for error query in command payload: expected fd count = %u, ret = %d",
			    cmd_ctx->lsm.fd_count,
			    (int) ret);
			ret_code = LTTNG_ERR_FATAL;
			*sock_error = 1;
			goto end;
		}
	}

	/* Deserialize error query. */
	{
		struct lttng_payload_view view =
			lttng_payload_view_from_payload(&query_payload, 0, -1);

		if (lttng_error_query_create_from_payload(&view, &query) != query_len) {
			ERR("Invalid error query received as part of command payload");
			ret_code = LTTNG_ERR_INVALID_PROTOCOL;
			goto end;
		}
	}

	*_query = query;
	ret_code = LTTNG_OK;

end:
	lttng_payload_reset(&query_payload);
	return ret_code;
}

static enum lttng_error_code receive_lttng_event(struct command_ctx *cmd_ctx,
						 int sock,
						 int *sock_error,
						 struct lttng_event **out_event,
						 char **out_filter_expression,
						 struct lttng_bytecode **out_bytecode,
						 struct lttng_event_exclusion **out_exclusion)
{
	int ret;
	size_t event_len;
	ssize_t sock_recv_len;
	enum lttng_error_code ret_code;
	struct lttng_payload event_payload;
	struct lttng_event *local_event = nullptr;
	char *local_filter_expression = nullptr;
	struct lttng_bytecode *local_bytecode = nullptr;
	struct lttng_event_exclusion *local_exclusion = nullptr;

	lttng_payload_init(&event_payload);
	if (cmd_ctx->lsm.cmd_type == LTTCOMM_SESSIOND_COMMAND_ENABLE_EVENT) {
		event_len = (size_t) cmd_ctx->lsm.u.enable.length;
	} else if (cmd_ctx->lsm.cmd_type == LTTCOMM_SESSIOND_COMMAND_DISABLE_EVENT) {
		event_len = (size_t) cmd_ctx->lsm.u.disable.length;
	} else {
		abort();
	}

	ret = lttng_dynamic_buffer_set_size(&event_payload.buffer, event_len);
	if (ret) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	sock_recv_len = lttcomm_recv_unix_sock(sock, event_payload.buffer.data, event_len);
	if (sock_recv_len < 0 || sock_recv_len != event_len) {
		ERR("Failed to receive event in command payload");
		*sock_error = 1;
		ret_code = LTTNG_ERR_INVALID_PROTOCOL;
		goto end;
	}

	/* Receive fds, if any. */
	if (cmd_ctx->lsm.fd_count > 0) {
		sock_recv_len = lttcomm_recv_payload_fds_unix_sock(
			sock, cmd_ctx->lsm.fd_count, &event_payload);
		if (sock_recv_len > 0 && sock_recv_len != cmd_ctx->lsm.fd_count * sizeof(int)) {
			ERR("Failed to receive all file descriptors for event in command payload: expected fd count = %u, ret = %d",
			    cmd_ctx->lsm.fd_count,
			    (int) ret);
			ret_code = LTTNG_ERR_INVALID_PROTOCOL;
			*sock_error = 1;
			goto end;
		} else if (sock_recv_len <= 0) {
			ERR("Failed to receive file descriptors for event in command payload: expected fd count = %u, ret = %d",
			    cmd_ctx->lsm.fd_count,
			    (int) ret);
			ret_code = LTTNG_ERR_FATAL;
			*sock_error = 1;
			goto end;
		}
	}

	/* Deserialize event. */
	{
		ssize_t len;
		struct lttng_payload_view event_view =
			lttng_payload_view_from_payload(&event_payload, 0, -1);

		len = lttng_event_create_from_payload(&event_view,
						      &local_event,
						      &local_exclusion,
						      &local_filter_expression,
						      &local_bytecode);

		if (len < 0) {
			ERR("Failed to create an event from the received buffer");
			ret_code = LTTNG_ERR_INVALID_PROTOCOL;
			goto end;
		}

		if (len != event_len) {
			ERR("Userspace probe location from the received buffer is not the advertised length: header length = %zu" PRIu32
			    ", payload length = %zd",
			    event_len,
			    len);
			ret_code = LTTNG_ERR_INVALID_PROTOCOL;
			goto end;
		}
	}

	*out_event = local_event;
	*out_exclusion = local_exclusion;
	*out_filter_expression = local_filter_expression;
	*out_bytecode = local_bytecode;
	local_event = nullptr;
	local_exclusion = nullptr;
	local_filter_expression = nullptr;
	local_bytecode = nullptr;

	ret_code = LTTNG_OK;

end:
	lttng_payload_reset(&event_payload);
	lttng_event_destroy(local_event);
	free(local_filter_expression);
	free(local_bytecode);
	free(local_exclusion);
	return ret_code;
}

static enum lttng_error_code
receive_lttng_event_context(const struct command_ctx *cmd_ctx,
			    int sock,
			    int *sock_error,
			    struct lttng_event_context **out_event_context)
{
	int ret;
	const size_t event_context_len = (size_t) cmd_ctx->lsm.u.context.length;
	ssize_t sock_recv_len;
	enum lttng_error_code ret_code;
	struct lttng_payload event_context_payload;
	struct lttng_event_context *context = nullptr;

	lttng_payload_init(&event_context_payload);

	ret = lttng_dynamic_buffer_set_size(&event_context_payload.buffer, event_context_len);
	if (ret) {
		ret_code = LTTNG_ERR_NOMEM;
		goto end;
	}

	sock_recv_len =
		lttcomm_recv_unix_sock(sock, event_context_payload.buffer.data, event_context_len);
	if (sock_recv_len < 0 || sock_recv_len != event_context_len) {
		ERR("Failed to receive event context in command payload");
		*sock_error = 1;
		ret_code = LTTNG_ERR_INVALID_PROTOCOL;
		goto end;
	}

	/* Deserialize event. */
	{
		ssize_t len;
		struct lttng_payload_view event_context_view =
			lttng_payload_view_from_payload(&event_context_payload, 0, -1);

		len = lttng_event_context_create_from_payload(&event_context_view, &context);

		if (len < 0) {
			ERR("Failed to create a event context from the received buffer");
			ret_code = LTTNG_ERR_INVALID_PROTOCOL;
			goto end;
		}

		if (len != event_context_len) {
			ERR("Event context from the received buffer is not the advertised length: expected length = %zu, payload length = %zd",
			    event_context_len,
			    len);
			ret_code = LTTNG_ERR_INVALID_PROTOCOL;
			goto end;
		}
	}

	*out_event_context = context;
	context = nullptr;
	ret_code = LTTNG_OK;

end:
	lttng_event_context_destroy(context);
	lttng_payload_reset(&event_context_payload);
	return ret_code;
}

/*
 * Version of setup_lttng_msg() without command header.
 */
static int
setup_lttng_msg_no_cmd_header(struct command_ctx *cmd_ctx, void *payload_buf, size_t payload_len)
{
	return setup_lttng_msg(cmd_ctx, payload_buf, payload_len, nullptr, 0);
}

/*
 * Check if the current kernel tracer supports the session rotation feature.
 * Return 1 if it does, 0 otherwise.
 */
static int check_rotate_compatible()
{
	int ret = 1;

	if (the_kernel_tracer_version.major != 2 || the_kernel_tracer_version.minor < 11) {
		DBG("Kernel tracer version is not compatible with the rotation feature");
		ret = 0;
	}

	return ret;
}

/*
 * Send data on a unix socket using the liblttsessiondcomm API.
 *
 * Return lttcomm error code.
 */
static int send_unix_sock(int sock, struct lttng_payload_view *view)
{
	int ret;
	const int fd_count = lttng_payload_view_get_fd_handle_count(view);

	/* Check valid length */
	if (view->buffer.size == 0) {
		ret = -1;
		goto end;
	}

	ret = lttcomm_send_unix_sock(sock, view->buffer.data, view->buffer.size);
	if (ret < 0) {
		goto end;
	}

	if (fd_count > 0) {
		ret = lttcomm_send_payload_view_fds_unix_sock(sock, view);
		if (ret < 0) {
			goto end;
		}
	}

end:
	return ret;
}

/*
 * Process the command requested by the lttng client within the command
 * context structure. This function make sure that the return structure (llm)
 * is set and ready for transmission before returning.
 *
 * Return any error encountered or 0 for success.
 *
 * "sock" is only used for special-case var. len data.
 * A command may assume the ownership of the socket, in which case its value
 * should be set to -1.
 */
static int process_client_msg(struct command_ctx *cmd_ctx, int *sock, int *sock_error)
{
	int ret = LTTNG_OK;
	bool need_tracing_session = true;
	bool need_domain;
	bool need_consumerd;

	if (!lttcomm_sessiond_command_is_valid((lttcomm_sessiond_command) cmd_ctx->lsm.cmd_type)) {
		ERR("Unknown client command received: command id = %" PRIu32,
		    cmd_ctx->lsm.cmd_type);
		ret = LTTNG_ERR_UND;
		goto error;
	}

	DBG("Processing client command '%s\' (%d)",
	    lttcomm_sessiond_command_str((lttcomm_sessiond_command) cmd_ctx->lsm.cmd_type),
	    cmd_ctx->lsm.cmd_type);

	*sock_error = 0;

	switch (cmd_ctx->lsm.cmd_type) {
	case LTTCOMM_SESSIOND_COMMAND_CREATE_SESSION_EXT:
	case LTTCOMM_SESSIOND_COMMAND_DESTROY_SESSION:
	case LTTCOMM_SESSIOND_COMMAND_LIST_SESSIONS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_DOMAINS:
	case LTTCOMM_SESSIOND_COMMAND_START_TRACE:
	case LTTCOMM_SESSIOND_COMMAND_STOP_TRACE:
	case LTTCOMM_SESSIOND_COMMAND_DATA_PENDING:
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_ADD_OUTPUT:
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_DEL_OUTPUT:
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_LIST_OUTPUT:
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_RECORD:
	case LTTCOMM_SESSIOND_COMMAND_SAVE_SESSION:
	case LTTCOMM_SESSIOND_COMMAND_SET_SESSION_SHM_PATH:
	case LTTCOMM_SESSIOND_COMMAND_REGENERATE_METADATA:
	case LTTCOMM_SESSIOND_COMMAND_REGENERATE_STATEDUMP:
	case LTTCOMM_SESSIOND_COMMAND_ROTATE_SESSION:
	case LTTCOMM_SESSIOND_COMMAND_ROTATION_GET_INFO:
	case LTTCOMM_SESSIOND_COMMAND_ROTATION_SET_SCHEDULE:
	case LTTCOMM_SESSIOND_COMMAND_SESSION_LIST_ROTATION_SCHEDULES:
	case LTTCOMM_SESSIOND_COMMAND_CLEAR_SESSION:
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRIGGERS:
	case LTTCOMM_SESSIOND_COMMAND_EXECUTE_ERROR_QUERY:
		need_domain = false;
		break;
	default:
		need_domain = true;
	}

	/* Needs a functioning consumerd? */
	switch (cmd_ctx->lsm.cmd_type) {
	case LTTCOMM_SESSIOND_COMMAND_REGISTER_TRIGGER:
	case LTTCOMM_SESSIOND_COMMAND_UNREGISTER_TRIGGER:
	case LTTCOMM_SESSIOND_COMMAND_EXECUTE_ERROR_QUERY:
		need_consumerd = false;
		break;
	default:
		need_consumerd = true;
		break;
	}

	if (the_config.no_kernel && need_domain &&
	    cmd_ctx->lsm.domain.type == LTTNG_DOMAIN_KERNEL) {
		if (!is_root) {
			ret = LTTNG_ERR_NEED_ROOT_SESSIOND;
		} else {
			ret = LTTNG_ERR_KERN_NA;
		}
		goto error;
	}

	/* Deny register consumer if we already have a spawned consumer. */
	if (cmd_ctx->lsm.cmd_type == LTTCOMM_SESSIOND_COMMAND_REGISTER_CONSUMER) {
		pthread_mutex_lock(&the_kconsumer_data.pid_mutex);
		if (the_kconsumer_data.pid > 0) {
			ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
			pthread_mutex_unlock(&the_kconsumer_data.pid_mutex);
			goto error;
		}
		pthread_mutex_unlock(&the_kconsumer_data.pid_mutex);
	}

	/*
	 * Check for command that don't needs to allocate a returned payload. We do
	 * this here so we don't have to make the call for no payload at each
	 * command.
	 */
	switch (cmd_ctx->lsm.cmd_type) {
	case LTTCOMM_SESSIOND_COMMAND_LIST_SESSIONS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINTS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINT_FIELDS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_DOMAINS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_CHANNELS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_EVENTS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_SYSCALLS:
	case LTTCOMM_SESSIOND_COMMAND_SESSION_LIST_ROTATION_SCHEDULES:
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_POLICY:
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_INCLUSION_SET:
	case LTTCOMM_SESSIOND_COMMAND_DATA_PENDING:
	case LTTCOMM_SESSIOND_COMMAND_ROTATE_SESSION:
	case LTTCOMM_SESSIOND_COMMAND_ROTATION_GET_INFO:
	case LTTCOMM_SESSIOND_COMMAND_REGISTER_TRIGGER:
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRIGGERS:
	case LTTCOMM_SESSIOND_COMMAND_EXECUTE_ERROR_QUERY:
		break;
	default:
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, nullptr, 0);
		if (ret < 0) {
			/* This label does not try to unlock the session */
			goto init_setup_error;
		}
	}

	/* Commands that DO NOT need a session. */
	switch (cmd_ctx->lsm.cmd_type) {
	case LTTCOMM_SESSIOND_COMMAND_CREATE_SESSION_EXT:
	case LTTCOMM_SESSIOND_COMMAND_LIST_SESSIONS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINTS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_SYSCALLS:
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINT_FIELDS:
	case LTTCOMM_SESSIOND_COMMAND_SAVE_SESSION:
	case LTTCOMM_SESSIOND_COMMAND_REGISTER_TRIGGER:
	case LTTCOMM_SESSIOND_COMMAND_UNREGISTER_TRIGGER:
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRIGGERS:
	case LTTCOMM_SESSIOND_COMMAND_EXECUTE_ERROR_QUERY:
		need_tracing_session = false;
		break;
	default:
		DBG("Getting session %s by name", cmd_ctx->lsm.session.name);
		/*
		 * We keep the session list lock across _all_ commands
		 * for now, because the per-session lock does not
		 * handle teardown properly.
		 */
		session_lock_list();
		cmd_ctx->session = session_find_by_name(cmd_ctx->lsm.session.name);
		if (cmd_ctx->session == nullptr) {
			ret = LTTNG_ERR_SESS_NOT_FOUND;
			goto error;
		} else {
			/* Acquire lock for the session */
			session_lock(cmd_ctx->session);
		}
		break;
	}

	/*
	 * Commands that need a valid session but should NOT create one if none
	 * exists. Instead of creating one and destroying it when the command is
	 * handled, process that right before so we save some round trip in useless
	 * code path.
	 */
	switch (cmd_ctx->lsm.cmd_type) {
	case LTTCOMM_SESSIOND_COMMAND_DISABLE_CHANNEL:
	case LTTCOMM_SESSIOND_COMMAND_DISABLE_EVENT:
		switch (cmd_ctx->lsm.domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			if (!cmd_ctx->session->kernel_session) {
				ret = LTTNG_ERR_NO_CHANNEL;
				goto error;
			}
			break;
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
		case LTTNG_DOMAIN_UST:
			if (!cmd_ctx->session->ust_session) {
				ret = LTTNG_ERR_NO_CHANNEL;
				goto error;
			}
			break;
		default:
			ret = LTTNG_ERR_UNKNOWN_DOMAIN;
			goto error;
		}
	default:
		break;
	}

	if (!need_domain) {
		goto skip_domain;
	}

	/*
	 * Check domain type for specific "pre-action".
	 */
	switch (cmd_ctx->lsm.domain.type) {
	case LTTNG_DOMAIN_KERNEL:
		if (!is_root) {
			ret = LTTNG_ERR_NEED_ROOT_SESSIOND;
			goto error;
		}

		/* Kernel tracer check */
		if (!kernel_tracer_is_initialized()) {
			/* Basically, load kernel tracer modules */
			ret = init_kernel_tracer();
			if (ret != 0) {
				goto error;
			}
		}

		/* Consumer is in an ERROR state. Report back to client */
		if (need_consumerd && uatomic_read(&the_kernel_consumerd_state) == CONSUMER_ERROR) {
			ret = LTTNG_ERR_NO_KERNCONSUMERD;
			goto error;
		}

		/* Need a session for kernel command */
		if (need_tracing_session) {
			if (cmd_ctx->session->kernel_session == nullptr) {
				ret = create_kernel_session(cmd_ctx->session);
				if (ret != LTTNG_OK) {
					ret = LTTNG_ERR_KERN_SESS_FAIL;
					goto error;
				}
			}

			/* Start the kernel consumer daemon */
			pthread_mutex_lock(&the_kconsumer_data.pid_mutex);
			if (the_kconsumer_data.pid == 0 &&
			    cmd_ctx->lsm.cmd_type != LTTCOMM_SESSIOND_COMMAND_REGISTER_CONSUMER) {
				pthread_mutex_unlock(&the_kconsumer_data.pid_mutex);
				ret = start_consumerd(&the_kconsumer_data);
				if (ret < 0) {
					ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
					goto error;
				}
				uatomic_set(&the_kernel_consumerd_state, CONSUMER_STARTED);
			} else {
				pthread_mutex_unlock(&the_kconsumer_data.pid_mutex);
			}

			/*
			 * The consumer was just spawned so we need to add the socket to
			 * the consumer output of the session if exist.
			 */
			ret = consumer_create_socket(&the_kconsumer_data,
						     cmd_ctx->session->kernel_session->consumer);
			if (ret < 0) {
				goto error;
			}
		}

		break;
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
		if (!agent_tracing_is_enabled()) {
			ret = LTTNG_ERR_AGENT_TRACING_DISABLED;
			goto error;
		}
		/* Fallthrough */
	case LTTNG_DOMAIN_UST:
	{
		if (!ust_app_supported()) {
			ret = LTTNG_ERR_NO_UST;
			goto error;
		}

		/* Consumer is in an ERROR state. Report back to client */
		if (need_consumerd && uatomic_read(&the_ust_consumerd_state) == CONSUMER_ERROR) {
			ret = LTTNG_ERR_NO_USTCONSUMERD;
			goto error;
		}

		if (need_tracing_session) {
			/* Create UST session if none exist. */
			if (cmd_ctx->session->ust_session == nullptr) {
				lttng_domain domain = cmd_ctx->lsm.domain;
				ret = create_ust_session(cmd_ctx->session, &domain);
				if (ret != LTTNG_OK) {
					goto error;
				}
			}

			/* Start the UST consumer daemons */
			/* 64-bit */
			pthread_mutex_lock(&the_ustconsumer64_data.pid_mutex);
			if (the_config.consumerd64_bin_path.value &&
			    the_ustconsumer64_data.pid == 0 &&
			    cmd_ctx->lsm.cmd_type != LTTCOMM_SESSIOND_COMMAND_REGISTER_CONSUMER) {
				pthread_mutex_unlock(&the_ustconsumer64_data.pid_mutex);
				ret = start_consumerd(&the_ustconsumer64_data);
				if (ret < 0) {
					ret = LTTNG_ERR_UST_CONSUMER64_FAIL;
					uatomic_set(&the_ust_consumerd64_fd, -EINVAL);
					goto error;
				}

				uatomic_set(&the_ust_consumerd64_fd,
					    the_ustconsumer64_data.cmd_sock);
				uatomic_set(&the_ust_consumerd_state, CONSUMER_STARTED);
			} else {
				pthread_mutex_unlock(&the_ustconsumer64_data.pid_mutex);
			}

			/*
			 * Setup socket for consumer 64 bit. No need for atomic access
			 * since it was set above and can ONLY be set in this thread.
			 */
			ret = consumer_create_socket(&the_ustconsumer64_data,
						     cmd_ctx->session->ust_session->consumer);
			if (ret < 0) {
				goto error;
			}

			/* 32-bit */
			pthread_mutex_lock(&the_ustconsumer32_data.pid_mutex);
			if (the_config.consumerd32_bin_path.value &&
			    the_ustconsumer32_data.pid == 0 &&
			    cmd_ctx->lsm.cmd_type != LTTCOMM_SESSIOND_COMMAND_REGISTER_CONSUMER) {
				pthread_mutex_unlock(&the_ustconsumer32_data.pid_mutex);
				ret = start_consumerd(&the_ustconsumer32_data);
				if (ret < 0) {
					ret = LTTNG_ERR_UST_CONSUMER32_FAIL;
					uatomic_set(&the_ust_consumerd32_fd, -EINVAL);
					goto error;
				}

				uatomic_set(&the_ust_consumerd32_fd,
					    the_ustconsumer32_data.cmd_sock);
				uatomic_set(&the_ust_consumerd_state, CONSUMER_STARTED);
			} else {
				pthread_mutex_unlock(&the_ustconsumer32_data.pid_mutex);
			}

			/*
			 * Setup socket for consumer 32 bit. No need for atomic access
			 * since it was set above and can ONLY be set in this thread.
			 */
			ret = consumer_create_socket(&the_ustconsumer32_data,
						     cmd_ctx->session->ust_session->consumer);
			if (ret < 0) {
				goto error;
			}
		}
		break;
	}
	default:
		break;
	}
skip_domain:

	/* Validate consumer daemon state when start/stop trace command */
	if (cmd_ctx->lsm.cmd_type == LTTCOMM_SESSIOND_COMMAND_START_TRACE ||
	    cmd_ctx->lsm.cmd_type == LTTCOMM_SESSIOND_COMMAND_STOP_TRACE) {
		switch (cmd_ctx->lsm.domain.type) {
		case LTTNG_DOMAIN_NONE:
			break;
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
		case LTTNG_DOMAIN_UST:
			if (uatomic_read(&the_ust_consumerd_state) != CONSUMER_STARTED) {
				ret = LTTNG_ERR_NO_USTCONSUMERD;
				goto error;
			}
			break;
		case LTTNG_DOMAIN_KERNEL:
			if (uatomic_read(&the_kernel_consumerd_state) != CONSUMER_STARTED) {
				ret = LTTNG_ERR_NO_KERNCONSUMERD;
				goto error;
			}
			break;
		default:
			ret = LTTNG_ERR_UNKNOWN_DOMAIN;
			goto error;
		}
	}

	/*
	 * Check that the UID matches that of the tracing session.
	 * The root user can interact with all sessions.
	 */
	if (need_tracing_session) {
		if (!session_access_ok(cmd_ctx->session,
				       LTTNG_SOCK_GET_UID_CRED(&cmd_ctx->creds)) ||
		    cmd_ctx->session->destroyed) {
			ret = LTTNG_ERR_EPERM;
			goto error;
		}
	}

	/*
	 * Send relayd information to consumer as soon as we have a domain and a
	 * session defined.
	 */
	if (cmd_ctx->session && need_domain) {
		/*
		 * Setup relayd if not done yet. If the relayd information was already
		 * sent to the consumer, this call will gracefully return.
		 */
		ret = cmd_setup_relayd(cmd_ctx->session);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	/* Process by command type */
	switch (cmd_ctx->lsm.cmd_type) {
	case LTTCOMM_SESSIOND_COMMAND_ADD_CONTEXT:
	{
		struct lttng_event_context *event_context = nullptr;
		const enum lttng_error_code ret_code =
			receive_lttng_event_context(cmd_ctx, *sock, sock_error, &event_context);

		if (ret_code != LTTNG_OK) {
			ret = (int) ret_code;
			goto error;
		}

		ret = cmd_add_context(cmd_ctx, event_context, the_kernel_poll_pipe[1]);
		lttng_event_context_destroy(event_context);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_DISABLE_CHANNEL:
	{
		ret = cmd_disable_channel(cmd_ctx->session,
					  cmd_ctx->lsm.domain.type,
					  cmd_ctx->lsm.u.disable.channel_name);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_ENABLE_CHANNEL:
	{
		ret = cmd_enable_channel(cmd_ctx, *sock, the_kernel_poll_pipe[1]);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_ADD_INCLUDE_VALUE:
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_REMOVE_INCLUDE_VALUE:
	{
		struct lttng_dynamic_buffer payload;
		struct lttng_buffer_view payload_view;
		const bool add_value = cmd_ctx->lsm.cmd_type ==
			LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_ADD_INCLUDE_VALUE;
		const size_t name_len =
			cmd_ctx->lsm.u.process_attr_tracker_add_remove_include_value.name_len;
		const enum lttng_domain_type domain_type =
			(enum lttng_domain_type) cmd_ctx->lsm.domain.type;
		const enum lttng_process_attr process_attr =
			(enum lttng_process_attr) cmd_ctx->lsm.u
				.process_attr_tracker_add_remove_include_value.process_attr;
		const enum lttng_process_attr_value_type value_type =
			(enum lttng_process_attr_value_type) cmd_ctx->lsm.u
				.process_attr_tracker_add_remove_include_value.value_type;
		struct process_attr_value *value;
		enum lttng_error_code ret_code;
		long login_name_max;

		login_name_max = sysconf(_SC_LOGIN_NAME_MAX);
		if (login_name_max < 0) {
			PERROR("Failed to get _SC_LOGIN_NAME_MAX system configuration");
			ret = LTTNG_ERR_INVALID;
			goto error;
		}

		/* Receive remaining variable length payload if applicable. */
		if (name_len > login_name_max) {
			/*
			 * POSIX mandates user and group names that are at least
			 * 8 characters long. Note that although shadow-utils
			 * (useradd, groupaadd, etc.) use 32 chars as their
			 * limit (from bits/utmp.h, UT_NAMESIZE),
			 * LOGIN_NAME_MAX is defined to 256.
			 */
			ERR("Rejecting process attribute tracker value %s as the provided exceeds the maximal allowed length: argument length = %zu, maximal length = %ld",
			    add_value ? "addition" : "removal",
			    name_len,
			    login_name_max);
			ret = LTTNG_ERR_INVALID;
			goto error;
		}

		lttng_dynamic_buffer_init(&payload);
		if (name_len != 0) {
			/*
			 * Receive variable payload for user/group name
			 * arguments.
			 */
			ret = lttng_dynamic_buffer_set_size(&payload, name_len);
			if (ret) {
				ERR("Failed to allocate buffer to receive payload of %s process attribute tracker value argument",
				    add_value ? "add" : "remove");
				ret = LTTNG_ERR_NOMEM;
				goto error_add_remove_tracker_value;
			}

			ret = lttcomm_recv_unix_sock(*sock, payload.data, name_len);
			if (ret <= 0) {
				ERR("Failed to receive payload of %s process attribute tracker value argument",
				    add_value ? "add" : "remove");
				*sock_error = 1;
				ret = LTTNG_ERR_INVALID_PROTOCOL;
				goto error_add_remove_tracker_value;
			}
		}

		payload_view = lttng_buffer_view_from_dynamic_buffer(&payload, 0, name_len);
		if (name_len > 0 && !lttng_buffer_view_is_valid(&payload_view)) {
			ret = LTTNG_ERR_INVALID_PROTOCOL;
			goto error_add_remove_tracker_value;
		}

		/*
		 * Validate the value type and domains are legal for the process
		 * attribute tracker that is specified and convert the value to
		 * add/remove to the internal sessiond representation.
		 */
		ret_code = process_attr_value_from_comm(
			domain_type,
			process_attr,
			value_type,
			&cmd_ctx->lsm.u.process_attr_tracker_add_remove_include_value.integral_value,
			&payload_view,
			&value);
		if (ret_code != LTTNG_OK) {
			ret = ret_code;
			goto error_add_remove_tracker_value;
		}

		if (add_value) {
			ret = cmd_process_attr_tracker_inclusion_set_add_value(
				cmd_ctx->session, domain_type, process_attr, value);
		} else {
			ret = cmd_process_attr_tracker_inclusion_set_remove_value(
				cmd_ctx->session, domain_type, process_attr, value);
		}
		process_attr_value_destroy(value);
	error_add_remove_tracker_value:
		lttng_dynamic_buffer_reset(&payload);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_POLICY:
	{
		enum lttng_tracking_policy tracking_policy;
		const enum lttng_domain_type domain_type =
			(enum lttng_domain_type) cmd_ctx->lsm.domain.type;
		const enum lttng_process_attr process_attr =
			(enum lttng_process_attr) cmd_ctx->lsm.u
				.process_attr_tracker_get_tracking_policy.process_attr;

		ret = cmd_process_attr_tracker_get_tracking_policy(
			cmd_ctx->session, domain_type, process_attr, &tracking_policy);
		if (ret != LTTNG_OK) {
			goto error;
		}

		uint32_t tracking_policy_u32 = tracking_policy;
		ret = setup_lttng_msg_no_cmd_header(
			cmd_ctx, &tracking_policy_u32, sizeof(uint32_t));
		if (ret < 0) {
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}
		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_SET_POLICY:
	{
		const enum lttng_tracking_policy tracking_policy =
			(enum lttng_tracking_policy) cmd_ctx->lsm.u
				.process_attr_tracker_set_tracking_policy.tracking_policy;
		const enum lttng_domain_type domain_type =
			(enum lttng_domain_type) cmd_ctx->lsm.domain.type;
		const enum lttng_process_attr process_attr =
			(enum lttng_process_attr) cmd_ctx->lsm.u
				.process_attr_tracker_set_tracking_policy.process_attr;

		ret = cmd_process_attr_tracker_set_tracking_policy(
			cmd_ctx->session, domain_type, process_attr, tracking_policy);
		if (ret != LTTNG_OK) {
			goto error;
		}
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_PROCESS_ATTR_TRACKER_GET_INCLUSION_SET:
	{
		struct lttng_process_attr_values *values;
		struct lttng_dynamic_buffer reply;
		const enum lttng_domain_type domain_type =
			(enum lttng_domain_type) cmd_ctx->lsm.domain.type;
		const enum lttng_process_attr process_attr =
			(enum lttng_process_attr)
				cmd_ctx->lsm.u.process_attr_tracker_get_inclusion_set.process_attr;

		ret = cmd_process_attr_tracker_get_inclusion_set(
			cmd_ctx->session, domain_type, process_attr, &values);
		if (ret != LTTNG_OK) {
			goto error;
		}

		lttng_dynamic_buffer_init(&reply);
		ret = lttng_process_attr_values_serialize(values, &reply);
		if (ret < 0) {
			goto error_tracker_get_inclusion_set;
		}

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, reply.data, reply.size);
		if (ret < 0) {
			ret = LTTNG_ERR_NOMEM;
			goto error_tracker_get_inclusion_set;
		}
		ret = LTTNG_OK;

	error_tracker_get_inclusion_set:
		lttng_process_attr_values_destroy(values);
		lttng_dynamic_buffer_reset(&reply);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_ENABLE_EVENT:
	case LTTCOMM_SESSIOND_COMMAND_DISABLE_EVENT:
	{
		struct lttng_event *event;
		char *filter_expression;
		struct lttng_event_exclusion *exclusions;
		struct lttng_bytecode *bytecode;
		const enum lttng_error_code ret_code = receive_lttng_event(cmd_ctx,
									   *sock,
									   sock_error,
									   &event,
									   &filter_expression,
									   &bytecode,
									   &exclusions);

		if (ret_code != LTTNG_OK) {
			ret = (int) ret_code;
			goto error;
		}

		/*
		 * Ownership of filter_expression, exclusions, and bytecode is
		 * always transferred.
		 */
		ret = cmd_ctx->lsm.cmd_type == LTTCOMM_SESSIOND_COMMAND_ENABLE_EVENT ?
			cmd_enable_event(cmd_ctx,
					 event,
					 filter_expression,
					 exclusions,
					 bytecode,
					 the_kernel_poll_pipe[1]) :
			cmd_disable_event(cmd_ctx, event, filter_expression, bytecode, exclusions);
		lttng_event_destroy(event);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINTS:
	{
		enum lttng_error_code ret_code;
		size_t original_payload_size;
		size_t payload_size;
		const size_t command_header_size = sizeof(struct lttcomm_list_command_header);

		ret = setup_empty_lttng_msg(cmd_ctx);
		if (ret) {
			ret = LTTNG_ERR_NOMEM;
			goto setup_error;
		}

		original_payload_size = cmd_ctx->reply_payload.buffer.size;

		session_lock_list();
		ret_code = cmd_list_tracepoints(cmd_ctx->lsm.domain.type, &cmd_ctx->reply_payload);
		session_unlock_list();
		if (ret_code != LTTNG_OK) {
			ret = (int) ret_code;
			goto error;
		}

		payload_size = cmd_ctx->reply_payload.buffer.size - command_header_size -
			original_payload_size;
		update_lttng_msg(cmd_ctx, command_header_size, payload_size);

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRACEPOINT_FIELDS:
	{
		enum lttng_error_code ret_code;
		size_t original_payload_size;
		size_t payload_size;
		const size_t command_header_size = sizeof(struct lttcomm_list_command_header);

		ret = setup_empty_lttng_msg(cmd_ctx);
		if (ret) {
			ret = LTTNG_ERR_NOMEM;
			goto setup_error;
		}

		original_payload_size = cmd_ctx->reply_payload.buffer.size;

		session_lock_list();
		ret_code = cmd_list_tracepoint_fields(cmd_ctx->lsm.domain.type,
						      &cmd_ctx->reply_payload);
		session_unlock_list();
		if (ret_code != LTTNG_OK) {
			ret = (int) ret_code;
			goto error;
		}

		payload_size = cmd_ctx->reply_payload.buffer.size - command_header_size -
			original_payload_size;
		update_lttng_msg(cmd_ctx, command_header_size, payload_size);

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_LIST_SYSCALLS:
	{
		enum lttng_error_code ret_code;
		size_t original_payload_size;
		size_t payload_size;
		const size_t command_header_size = sizeof(struct lttcomm_list_command_header);

		ret = setup_empty_lttng_msg(cmd_ctx);
		if (ret) {
			ret = LTTNG_ERR_NOMEM;
			goto setup_error;
		}

		original_payload_size = cmd_ctx->reply_payload.buffer.size;

		ret_code = cmd_list_syscalls(&cmd_ctx->reply_payload);
		if (ret_code != LTTNG_OK) {
			ret = (int) ret_code;
			goto error;
		}

		payload_size = cmd_ctx->reply_payload.buffer.size - command_header_size -
			original_payload_size;
		update_lttng_msg(cmd_ctx, command_header_size, payload_size);

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_SET_CONSUMER_URI:
	{
		size_t nb_uri, len;
		struct lttng_uri *uris;

		nb_uri = cmd_ctx->lsm.u.uri.size;
		len = nb_uri * sizeof(struct lttng_uri);

		if (nb_uri == 0) {
			ret = LTTNG_ERR_INVALID;
			goto error;
		}

		uris = calloc<lttng_uri>(nb_uri);
		if (uris == nullptr) {
			ret = LTTNG_ERR_FATAL;
			goto error;
		}

		/* Receive variable len data */
		DBG("Receiving %zu URI(s) from client ...", nb_uri);
		ret = lttcomm_recv_unix_sock(*sock, uris, len);
		if (ret <= 0) {
			DBG("No URIs received from client... continuing");
			*sock_error = 1;
			ret = LTTNG_ERR_SESSION_FAIL;
			free(uris);
			goto error;
		}

		ret = cmd_set_consumer_uri(cmd_ctx->session, nb_uri, uris);
		free(uris);
		if (ret != LTTNG_OK) {
			goto error;
		}

		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_START_TRACE:
	{
		/*
		 * On the first start, if we have a kernel session and we have
		 * enabled time or size-based rotations, we have to make sure
		 * the kernel tracer supports it.
		 */
		if (!cmd_ctx->session->has_been_started && cmd_ctx->session->kernel_session &&
		    (cmd_ctx->session->rotate_timer_period || cmd_ctx->session->rotate_size) &&
		    !check_rotate_compatible()) {
			DBG("Kernel tracer version is not compatible with the rotation feature");
			ret = LTTNG_ERR_ROTATION_WRONG_VERSION;
			goto error;
		}
		ret = cmd_start_trace(cmd_ctx->session);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_STOP_TRACE:
	{
		ret = cmd_stop_trace(cmd_ctx->session);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_DESTROY_SESSION:
	{
		ret = cmd_destroy_session(cmd_ctx->session, sock);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_LIST_DOMAINS:
	{
		ssize_t nb_dom;
		struct lttng_domain *domains = nullptr;

		nb_dom = cmd_list_domains(cmd_ctx->session, &domains);
		if (nb_dom < 0) {
			/* Return value is a negative lttng_error_code. */
			ret = -nb_dom;
			goto error;
		}

		ret = setup_lttng_msg_no_cmd_header(
			cmd_ctx, domains, nb_dom * sizeof(struct lttng_domain));
		free(domains);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_LIST_CHANNELS:
	{
		enum lttng_error_code ret_code;
		size_t original_payload_size;
		size_t payload_size;
		const size_t command_header_size = sizeof(struct lttcomm_list_command_header);

		ret = setup_empty_lttng_msg(cmd_ctx);
		if (ret) {
			ret = LTTNG_ERR_NOMEM;
			goto setup_error;
		}

		original_payload_size = cmd_ctx->reply_payload.buffer.size;

		ret_code = cmd_list_channels(
			cmd_ctx->lsm.domain.type, cmd_ctx->session, &cmd_ctx->reply_payload);
		if (ret_code != LTTNG_OK) {
			ret = (int) ret_code;
			goto error;
		}

		payload_size = cmd_ctx->reply_payload.buffer.size - command_header_size -
			original_payload_size;
		update_lttng_msg(cmd_ctx, command_header_size, payload_size);

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_LIST_EVENTS:
	{
		enum lttng_error_code ret_code;
		size_t original_payload_size;
		size_t payload_size;
		const size_t command_header_size = sizeof(struct lttcomm_list_command_header);

		ret = setup_empty_lttng_msg(cmd_ctx);
		if (ret) {
			ret = LTTNG_ERR_NOMEM;
			goto setup_error;
		}

		original_payload_size = cmd_ctx->reply_payload.buffer.size;

		ret_code = cmd_list_events(cmd_ctx->lsm.domain.type,
					   cmd_ctx->session,
					   cmd_ctx->lsm.u.list.channel_name,
					   &cmd_ctx->reply_payload);
		if (ret_code != LTTNG_OK) {
			ret = (int) ret_code;
			goto error;
		}

		payload_size = cmd_ctx->reply_payload.buffer.size - command_header_size -
			original_payload_size;
		update_lttng_msg(cmd_ctx, command_header_size, payload_size);

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_LIST_SESSIONS:
	{
		unsigned int nr_sessions;
		lttng_session *sessions_payload = nullptr;
		size_t payload_len = 0;

		session_lock_list();
		nr_sessions = lttng_sessions_count(LTTNG_SOCK_GET_UID_CRED(&cmd_ctx->creds),
						   LTTNG_SOCK_GET_GID_CRED(&cmd_ctx->creds));

		if (nr_sessions > 0) {
			payload_len = (sizeof(struct lttng_session) * nr_sessions) +
				(sizeof(struct lttng_session_extended) * nr_sessions);
			sessions_payload = zmalloc<lttng_session>(payload_len);
			if (!sessions_payload) {
				session_unlock_list();
				ret = -ENOMEM;
				goto setup_error;
			}

			cmd_list_lttng_sessions(sessions_payload,
						nr_sessions,
						LTTNG_SOCK_GET_UID_CRED(&cmd_ctx->creds),
						LTTNG_SOCK_GET_GID_CRED(&cmd_ctx->creds));
		}

		session_unlock_list();

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, sessions_payload, payload_len);
		free(sessions_payload);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_REGISTER_CONSUMER:
	{
		struct consumer_data *cdata;

		switch (cmd_ctx->lsm.domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			cdata = &the_kconsumer_data;
			break;
		default:
			ret = LTTNG_ERR_UND;
			goto error;
		}

		ret = cmd_register_consumer(
			cmd_ctx->session, cmd_ctx->lsm.domain.type, cmd_ctx->lsm.u.reg.path, cdata);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_DATA_PENDING:
	{
		int pending_ret;
		uint8_t pending_ret_byte;

		pending_ret = cmd_data_pending(cmd_ctx->session);

		/*
		 * FIXME
		 *
		 * This function may returns 0 or 1 to indicate whether or not
		 * there is data pending. In case of error, it should return an
		 * LTTNG_ERR code. However, some code paths may still return
		 * a nondescript error code, which we handle by returning an
		 * "unknown" error.
		 */
		if (pending_ret == 0 || pending_ret == 1) {
			/*
			 * ret will be set to LTTNG_OK at the end of
			 * this function.
			 */
		} else if (pending_ret < 0) {
			ret = LTTNG_ERR_UNK;
			goto setup_error;
		} else {
			ret = pending_ret;
			goto setup_error;
		}

		pending_ret_byte = (uint8_t) pending_ret;

		/* 1 byte to return whether or not data is pending */
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, &pending_ret_byte, 1);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_ADD_OUTPUT:
	{
		uint32_t snapshot_id;
		struct lttcomm_lttng_output_id reply;
		lttng_snapshot_output output = cmd_ctx->lsm.u.snapshot_output.output;

		ret = cmd_snapshot_add_output(cmd_ctx->session, &output, &snapshot_id);
		if (ret != LTTNG_OK) {
			goto error;
		}
		reply.id = snapshot_id;

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, &reply, sizeof(reply));
		if (ret < 0) {
			goto setup_error;
		}

		/* Copy output list into message payload */
		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_DEL_OUTPUT:
	{
		lttng_snapshot_output output = cmd_ctx->lsm.u.snapshot_output.output;
		ret = cmd_snapshot_del_output(cmd_ctx->session, &output);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_LIST_OUTPUT:
	{
		ssize_t nb_output;
		struct lttng_snapshot_output *outputs = nullptr;

		nb_output = cmd_snapshot_list_outputs(cmd_ctx->session, &outputs);
		if (nb_output < 0) {
			ret = -nb_output;
			goto error;
		}

		LTTNG_ASSERT((nb_output > 0 && outputs) || nb_output == 0);
		ret = setup_lttng_msg_no_cmd_header(
			cmd_ctx, outputs, nb_output * sizeof(struct lttng_snapshot_output));
		free(outputs);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_SNAPSHOT_RECORD:
	{
		lttng_snapshot_output output = cmd_ctx->lsm.u.snapshot_record.output;
		ret = cmd_snapshot_record(cmd_ctx->session, &output, 0); // RFC: set to zero since
									 // it's ignored by
									 // cmd_snapshot_record
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_CREATE_SESSION_EXT:
	{
		struct lttng_dynamic_buffer payload;
		struct lttng_session_descriptor *return_descriptor = nullptr;

		lttng_dynamic_buffer_init(&payload);
		ret = cmd_create_session(cmd_ctx, *sock, &return_descriptor);
		if (ret != LTTNG_OK) {
			goto error;
		}

		ret = lttng_session_descriptor_serialize(return_descriptor, &payload);
		if (ret) {
			ERR("Failed to serialize session descriptor in reply to \"create session\" command");
			lttng_session_descriptor_destroy(return_descriptor);
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, payload.data, payload.size);
		if (ret) {
			lttng_session_descriptor_destroy(return_descriptor);
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}
		lttng_dynamic_buffer_reset(&payload);
		lttng_session_descriptor_destroy(return_descriptor);
		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_SAVE_SESSION:
	{
		ret = cmd_save_sessions(&cmd_ctx->lsm.u.save_session.attr, &cmd_ctx->creds);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_SET_SESSION_SHM_PATH:
	{
		ret = cmd_set_session_shm_path(cmd_ctx->session,
					       cmd_ctx->lsm.u.set_shm_path.shm_path);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_REGENERATE_METADATA:
	{
		ret = cmd_regenerate_metadata(cmd_ctx->session);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_REGENERATE_STATEDUMP:
	{
		ret = cmd_regenerate_statedump(cmd_ctx->session);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_REGISTER_TRIGGER:
	{
		struct lttng_trigger *payload_trigger;
		struct lttng_trigger *return_trigger;
		size_t original_reply_payload_size;
		size_t reply_payload_size;
		const struct lttng_credentials cmd_creds = {
			.uid = LTTNG_OPTIONAL_INIT_VALUE(cmd_ctx->creds.uid),
			.gid = LTTNG_OPTIONAL_INIT_VALUE(cmd_ctx->creds.gid),
		};

		ret = setup_empty_lttng_msg(cmd_ctx);
		if (ret) {
			ret = LTTNG_ERR_NOMEM;
			goto setup_error;
		}

		ret = receive_lttng_trigger(cmd_ctx, *sock, sock_error, &payload_trigger);
		if (ret != LTTNG_OK) {
			goto error;
		}

		original_reply_payload_size = cmd_ctx->reply_payload.buffer.size;

		ret = cmd_register_trigger(&cmd_creds,
					   payload_trigger,
					   cmd_ctx->lsm.u.trigger.is_trigger_anonymous,
					   the_notification_thread_handle,
					   &return_trigger);
		if (ret != LTTNG_OK) {
			lttng_trigger_put(payload_trigger);
			goto error;
		}

		ret = lttng_trigger_serialize(return_trigger, &cmd_ctx->reply_payload);
		lttng_trigger_put(payload_trigger);
		lttng_trigger_put(return_trigger);
		if (ret) {
			ERR("Failed to serialize trigger in reply to \"register trigger\" command");
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}

		reply_payload_size =
			cmd_ctx->reply_payload.buffer.size - original_reply_payload_size;

		update_lttng_msg(cmd_ctx, 0, reply_payload_size);

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_UNREGISTER_TRIGGER:
	{
		struct lttng_trigger *payload_trigger;
		const struct lttng_credentials cmd_creds = {
			.uid = LTTNG_OPTIONAL_INIT_VALUE(cmd_ctx->creds.uid),
			.gid = LTTNG_OPTIONAL_INIT_VALUE(cmd_ctx->creds.gid),
		};

		ret = receive_lttng_trigger(cmd_ctx, *sock, sock_error, &payload_trigger);
		if (ret != LTTNG_OK) {
			goto error;
		}

		ret = cmd_unregister_trigger(
			&cmd_creds, payload_trigger, the_notification_thread_handle);
		lttng_trigger_put(payload_trigger);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_ROTATE_SESSION:
	{
		struct lttng_rotate_session_return rotate_return;

		DBG("Client rotate session \"%s\"", cmd_ctx->session->name);

		memset(&rotate_return, 0, sizeof(rotate_return));
		if (cmd_ctx->session->kernel_session && !check_rotate_compatible()) {
			DBG("Kernel tracer version is not compatible with the rotation feature");
			ret = LTTNG_ERR_ROTATION_WRONG_VERSION;
			goto error;
		}

		ret = cmd_rotate_session(cmd_ctx->session,
					 &rotate_return,
					 false,
					 LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED);
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, &rotate_return, sizeof(rotate_return));
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_ROTATION_GET_INFO:
	{
		struct lttng_rotation_get_info_return get_info_return;

		memset(&get_info_return, 0, sizeof(get_info_return));
		ret = cmd_rotate_get_info(cmd_ctx->session,
					  &get_info_return,
					  cmd_ctx->lsm.u.get_rotation_info.rotation_id);
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = setup_lttng_msg_no_cmd_header(
			cmd_ctx, &get_info_return, sizeof(get_info_return));
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_ROTATION_SET_SCHEDULE:
	{
		bool set_schedule;
		enum lttng_rotation_schedule_type schedule_type;
		uint64_t value;

		if (cmd_ctx->session->kernel_session && !check_rotate_compatible()) {
			DBG("Kernel tracer version does not support session rotations");
			ret = LTTNG_ERR_ROTATION_WRONG_VERSION;
			goto error;
		}

		set_schedule = cmd_ctx->lsm.u.rotation_set_schedule.set == 1;
		schedule_type = (enum lttng_rotation_schedule_type)
					cmd_ctx->lsm.u.rotation_set_schedule.type;
		value = cmd_ctx->lsm.u.rotation_set_schedule.value;

		ret = cmd_rotation_set_schedule(
			cmd_ctx->session, set_schedule, schedule_type, value);
		if (ret != LTTNG_OK) {
			goto error;
		}

		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_SESSION_LIST_ROTATION_SCHEDULES:
	{
		lttng_session_list_schedules_return schedules;

		schedules.periodic.set = !!cmd_ctx->session->rotate_timer_period;
		schedules.periodic.value = cmd_ctx->session->rotate_timer_period;
		schedules.size.set = !!cmd_ctx->session->rotate_size;
		schedules.size.value = cmd_ctx->session->rotate_size;

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, &schedules, sizeof(schedules));
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_CLEAR_SESSION:
	{
		ret = cmd_clear_session(cmd_ctx->session, sock);
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_LIST_TRIGGERS:
	{
		struct lttng_triggers *return_triggers = nullptr;
		size_t original_payload_size;
		size_t payload_size;

		ret = setup_empty_lttng_msg(cmd_ctx);
		if (ret) {
			ret = LTTNG_ERR_NOMEM;
			goto setup_error;
		}

		original_payload_size = cmd_ctx->reply_payload.buffer.size;

		ret = cmd_list_triggers(cmd_ctx, the_notification_thread_handle, &return_triggers);
		if (ret != LTTNG_OK) {
			goto error;
		}

		LTTNG_ASSERT(return_triggers);
		ret = lttng_triggers_serialize(return_triggers, &cmd_ctx->reply_payload);
		lttng_triggers_destroy(return_triggers);
		if (ret) {
			ERR("Failed to serialize triggers in reply to `list triggers` command");
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}

		payload_size = cmd_ctx->reply_payload.buffer.size - original_payload_size;

		update_lttng_msg(cmd_ctx, 0, payload_size);

		ret = LTTNG_OK;
		break;
	}
	case LTTCOMM_SESSIOND_COMMAND_EXECUTE_ERROR_QUERY:
	{
		struct lttng_error_query *query;
		const struct lttng_credentials cmd_creds = {
			.uid = LTTNG_OPTIONAL_INIT_VALUE(cmd_ctx->creds.uid),
			.gid = LTTNG_OPTIONAL_INIT_VALUE(cmd_ctx->creds.gid),
		};
		struct lttng_error_query_results *results = nullptr;
		size_t original_payload_size;
		size_t payload_size;

		ret = setup_empty_lttng_msg(cmd_ctx);
		if (ret) {
			ret = LTTNG_ERR_NOMEM;
			goto setup_error;
		}

		original_payload_size = cmd_ctx->reply_payload.buffer.size;

		ret = receive_lttng_error_query(cmd_ctx, *sock, sock_error, &query);
		if (ret != LTTNG_OK) {
			goto error;
		}

		ret = cmd_execute_error_query(
			&cmd_creds, query, &results, the_notification_thread_handle);
		lttng_error_query_destroy(query);
		if (ret != LTTNG_OK) {
			goto error;
		}

		LTTNG_ASSERT(results);
		ret = lttng_error_query_results_serialize(results, &cmd_ctx->reply_payload);
		lttng_error_query_results_destroy(results);
		if (ret) {
			ERR("Failed to serialize error query result set in reply to `execute error query` command");
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}

		payload_size = cmd_ctx->reply_payload.buffer.size - original_payload_size;

		update_lttng_msg(cmd_ctx, 0, payload_size);

		ret = LTTNG_OK;

		break;
	}
	default:
		ret = LTTNG_ERR_UND;
		break;
	}

error:
	if (cmd_ctx->reply_payload.buffer.size == 0) {
		DBG("Missing llm header, creating one.");
		if (setup_lttng_msg_no_cmd_header(cmd_ctx, nullptr, 0) < 0) {
			goto setup_error;
		}
	}
	/* Set return code */
	((struct lttcomm_lttng_msg *) (cmd_ctx->reply_payload.buffer.data))->ret_code = ret;
setup_error:
	if (cmd_ctx->session) {
		session_unlock(cmd_ctx->session);
		session_put(cmd_ctx->session);
		cmd_ctx->session = nullptr;
	}
	if (need_tracing_session) {
		session_unlock_list();
	}
init_setup_error:
	LTTNG_ASSERT(!rcu_read_ongoing());
	return ret;
}

static int create_client_sock()
{
	int ret, client_sock;

	/* Create client tool unix socket */
	client_sock = lttcomm_create_unix_sock(the_config.client_unix_sock_path.value);
	if (client_sock < 0) {
		ERR("Create unix sock failed: %s", the_config.client_unix_sock_path.value);
		ret = -1;
		goto end;
	}

	/* Set the cloexec flag */
	ret = utils_set_fd_cloexec(client_sock);
	if (ret < 0) {
		ERR("Unable to set CLOEXEC flag to the client Unix socket (fd: %d). "
		    "Continuing but note that the consumer daemon will have a "
		    "reference to this socket on exec()",
		    client_sock);
	}

	/* File permission MUST be 660 */
	ret = chmod(the_config.client_unix_sock_path.value, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", the_config.client_unix_sock_path.value);
		PERROR("chmod");
		(void) lttcomm_close_unix_sock(client_sock);
		ret = -1;
		goto end;
	}
	DBG("Created client socket (fd = %i)", client_sock);
	ret = client_sock;
end:
	return ret;
}

static void cleanup_client_thread(void *data)
{
	struct lttng_pipe *quit_pipe = (lttng_pipe *) data;

	lttng_pipe_destroy(quit_pipe);
}

static void thread_init_cleanup(void *data __attribute__((unused)))
{
	set_thread_status(false);
}

/*
 * This thread manage all clients request using the unix client socket for
 * communication.
 */
static void *thread_manage_clients(void *data)
{
	int sock = -1, ret, i, err = -1;
	int sock_error;
	uint32_t nb_fd;
	struct lttng_poll_event events;
	const int client_sock = thread_state.client_sock;
	struct lttng_pipe *quit_pipe = (lttng_pipe *) data;
	const int thread_quit_pipe_fd = lttng_pipe_get_readfd(quit_pipe);
	struct command_ctx cmd_ctx = {};

	DBG("[thread] Manage client started");

	lttng_payload_init(&cmd_ctx.reply_payload);

	is_root = (getuid() == 0);

	pthread_cleanup_push(thread_init_cleanup, nullptr);

	rcu_register_thread();

	health_register(the_health_sessiond, HEALTH_SESSIOND_TYPE_CMD);

	health_code_update();

	ret = lttcomm_listen_unix_sock(client_sock);
	if (ret < 0) {
		goto error_listen;
	}

	/*
	 * Pass 2 as size here for the thread quit pipe and client_sock. Nothing
	 * more will be added to this poll set.
	 */
	ret = lttng_poll_create(&events, 2, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error_create_poll;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, client_sock, LPOLLIN | LPOLLPRI);
	if (ret < 0) {
		goto error;
	}

	/* Add thread quit pipe */
	ret = lttng_poll_add(&events, thread_quit_pipe_fd, LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	/* Set state as running. */
	set_thread_status(true);
	pthread_cleanup_pop(0);

	/* This testpoint is after we signal readiness to the parent. */
	if (testpoint(sessiond_thread_manage_clients)) {
		goto error;
	}

	if (testpoint(sessiond_thread_manage_clients_before_loop)) {
		goto error;
	}

	health_code_update();

	while (true) {
		const struct cmd_completion_handler *cmd_completion_handler;

		cmd_ctx.creds.uid = UINT32_MAX;
		cmd_ctx.creds.gid = UINT32_MAX;
		cmd_ctx.creds.pid = 0;
		cmd_ctx.session = nullptr;
		lttng_payload_clear(&cmd_ctx.reply_payload);
		cmd_ctx.lttng_msg_size = 0;

		DBG("Accepting client command ...");

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
			/* Fetch once the poll data. */
			const auto revents = LTTNG_POLL_GETEV(&events, i);
			const auto pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			/* Activity on thread quit pipe, exiting. */
			if (pollfd == thread_quit_pipe_fd) {
				DBG("Activity on thread quit pipe");
				err = 0;
				goto exit;
			}

			/* Event on the registration socket */
			if (revents & LPOLLIN) {
				continue;
			} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("Client socket poll error");
				goto error;
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto error;
			}
		}

		DBG("Wait for client response");

		health_code_update();

		sock = lttcomm_accept_unix_sock(client_sock);
		if (sock < 0) {
			goto error;
		}

		/*
		 * Set the CLOEXEC flag. Return code is useless because either way, the
		 * show must go on.
		 */
		(void) utils_set_fd_cloexec(sock);

		/* Set socket option for credentials retrieval */
		ret = lttcomm_setsockopt_creds_unix_sock(sock);
		if (ret < 0) {
			goto error;
		}

		health_code_update();

		/*
		 * Data is received from the lttng client. The struct
		 * lttcomm_session_msg (lsm) contains the command and data request of
		 * the client.
		 */
		DBG("Receiving data from client ...");
		ret = lttcomm_recv_creds_unix_sock(
			sock, &cmd_ctx.lsm, sizeof(struct lttcomm_session_msg), &cmd_ctx.creds);
		if (ret != sizeof(struct lttcomm_session_msg)) {
			DBG("Incomplete recv() from client... continuing");
			ret = close(sock);
			if (ret) {
				PERROR("close");
			}
			sock = -1;
			continue;
		}

		health_code_update();

		// TODO: Validate cmd_ctx including sanity check for
		// security purpose.

		rcu_thread_online();
		/*
		 * This function dispatch the work to the kernel or userspace tracer
		 * libs and fill the lttcomm_lttng_msg data structure of all the needed
		 * informations for the client. The command context struct contains
		 * everything this function may needs.
		 */
		try {
			ret = process_client_msg(&cmd_ctx, &sock, &sock_error);
			rcu_thread_offline();
			if (ret < 0) {
				if (sock >= 0) {
					ret = close(sock);
					if (ret) {
						PERROR("close");
					}
				}
				sock = -1;
				/*
				 * TODO: Inform client somehow of the fatal error. At
				 * this point, ret < 0 means that a zmalloc failed
				 * (ENOMEM). Error detected but still accept
				 * command, unless a socket error has been
				 * detected.
				 */
				continue;
			}
		} catch (const std::bad_alloc& ex) {
			WARN_FMT("Failed to allocate memory while handling client request: {}",
				 ex.what());
			ret = LTTNG_ERR_NOMEM;
		} catch (const lttng::ctl::error& ex) {
			WARN_FMT("Client request failed: {}", ex.what());
			ret = ex.code();
		} catch (const std::exception& ex) {
			WARN_FMT("Client request failed: {}", ex.what());
			ret = LTTNG_ERR_UNK;
		}

		if (ret < LTTNG_OK || ret >= LTTNG_ERR_NR) {
			WARN("Command returned an invalid status code, returning unknown error: "
			     "command type = %s (%d), ret = %d",
			     lttcomm_sessiond_command_str(
				     (lttcomm_sessiond_command) cmd_ctx.lsm.cmd_type),
			     cmd_ctx.lsm.cmd_type,
			     ret);
			ret = LTTNG_ERR_UNK;
		}

		cmd_completion_handler = cmd_pop_completion_handler();
		if (cmd_completion_handler) {
			enum lttng_error_code completion_code;

			completion_code = cmd_completion_handler->run(cmd_completion_handler->data);
			if (completion_code != LTTNG_OK) {
				continue;
			}
		}

		health_code_update();

		if (sock >= 0) {
			struct lttng_payload_view view =
				lttng_payload_view_from_payload(&cmd_ctx.reply_payload, 0, -1);
			struct lttcomm_lttng_msg *llm =
				(typeof(llm)) cmd_ctx.reply_payload.buffer.data;

			LTTNG_ASSERT(cmd_ctx.reply_payload.buffer.size >= sizeof(*llm));
			LTTNG_ASSERT(cmd_ctx.lttng_msg_size == cmd_ctx.reply_payload.buffer.size);

			llm->fd_count = lttng_payload_view_get_fd_handle_count(&view);

			DBG("Sending response (size: %d, retcode: %s (%d))",
			    cmd_ctx.lttng_msg_size,
			    lttng_strerror(-llm->ret_code),
			    llm->ret_code);
			ret = send_unix_sock(sock, &view);
			if (ret < 0) {
				ERR("Failed to send data back to client");
			}

			/* End of transmission */
			ret = close(sock);
			if (ret) {
				PERROR("close");
			}
		}
		sock = -1;

		health_code_update();
	}

exit:
error:
	if (sock >= 0) {
		ret = close(sock);
		if (ret) {
			PERROR("close");
		}
	}

	lttng_poll_clean(&events);

error_listen:
error_create_poll:
	unlink(the_config.client_unix_sock_path.value);
	ret = close(client_sock);
	if (ret) {
		PERROR("close");
	}

	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}

	health_unregister(the_health_sessiond);

	DBG("Client thread dying");
	lttng_payload_reset(&cmd_ctx.reply_payload);
	rcu_unregister_thread();
	return nullptr;
}

static bool shutdown_client_thread(void *thread_data)
{
	struct lttng_pipe *client_quit_pipe = (lttng_pipe *) thread_data;
	const int write_fd = lttng_pipe_get_writefd(client_quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

struct lttng_thread *launch_client_thread()
{
	bool thread_running;
	struct lttng_pipe *client_quit_pipe;
	struct lttng_thread *thread = nullptr;
	int client_sock_fd = -1;

	sem_init(&thread_state.ready, 0, 0);
	client_quit_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!client_quit_pipe) {
		goto error;
	}

	client_sock_fd = create_client_sock();
	if (client_sock_fd < 0) {
		goto error;
	}

	thread_state.client_sock = client_sock_fd;
	thread = lttng_thread_create("Client management",
				     thread_manage_clients,
				     shutdown_client_thread,
				     cleanup_client_thread,
				     client_quit_pipe);
	if (!thread) {
		goto error;
	}
	/* The client thread now owns the client sock fd and the quit pipe. */
	client_sock_fd = -1;
	client_quit_pipe = nullptr;

	/*
	 * This thread is part of the threads that need to be fully
	 * initialized before the session daemon is marked as "ready".
	 */
	thread_running = wait_thread_status();
	if (!thread_running) {
		goto error;
	}
	return thread;
error:
	if (client_sock_fd >= 0) {
		if (close(client_sock_fd)) {
			PERROR("Failed to close client socket");
		}
	}
	lttng_thread_put(thread);
	cleanup_client_thread(client_quit_pipe);
	return nullptr;
}
