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

#include <stddef.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <common/compat/getenv.h>
#include <common/unix.h>
#include <common/utils.h>
#include <lttng/userspace-probe-internal.h>
#include <lttng/event-internal.h>
#include <lttng/session-internal.h>
#include <lttng/session-descriptor-internal.h>

#include "client.h"
#include "lttng-sessiond.h"
#include "cmd.h"
#include "kernel.h"
#include "save.h"
#include "health-sessiond.h"
#include "testpoint.h"
#include "utils.h"
#include "manage-consumer.h"

static bool is_root;

static struct thread_state {
	sem_t ready;
	bool running;
} thread_state;

static void set_thread_status(bool running)
{
	DBG("Marking client thread's state as %s", running ? "running" : "error");
	thread_state.running = running;
	sem_post(&thread_state.ready);
}

static bool wait_thread_status(void)
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
	const void *payload_buf, size_t payload_len,
	const void *cmd_header_buf, size_t cmd_header_len)
{
	int ret = 0;
	const size_t header_len = sizeof(struct lttcomm_lttng_msg);
	const size_t cmd_header_offset = header_len;
	const size_t payload_offset = cmd_header_offset + cmd_header_len;
	const size_t total_msg_size = header_len + cmd_header_len + payload_len;

	free(cmd_ctx->llm);
	cmd_ctx->llm = zmalloc(total_msg_size);

	if (cmd_ctx->llm == NULL) {
		PERROR("zmalloc");
		ret = -ENOMEM;
		goto end;
	}

	/* Copy common data */
	cmd_ctx->llm->cmd_type = cmd_ctx->lsm->cmd_type;
	cmd_ctx->llm->pid = cmd_ctx->lsm->domain.attr.pid;
	cmd_ctx->llm->cmd_header_size = cmd_header_len;
	cmd_ctx->llm->data_size = payload_len;
	cmd_ctx->lttng_msg_size = total_msg_size;

	/* Copy command header */
	if (cmd_header_len) {
		memcpy(((uint8_t *) cmd_ctx->llm) + cmd_header_offset, cmd_header_buf,
			cmd_header_len);
	}

	/* Copy payload */
	if (payload_len) {
		memcpy(((uint8_t *) cmd_ctx->llm) + payload_offset, payload_buf,
			payload_len);
	}

end:
	return ret;
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
		if (config.verbose_consumer) {
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
			DBG3("	1) %s", config.consumerd64_bin_path.value ? : "NULL");
			DBG3("	2) %s/%s", INSTALL_BIN_PATH, DEFAULT_CONSUMERD_FILE);
			DBG3("	3) %s", config.consumerd32_bin_path.value ? : "NULL");
			if (stat(config.consumerd64_bin_path.value, &st) == 0) {
				DBG3("Found location #1");
				consumer_to_use = config.consumerd64_bin_path.value;
			} else if (stat(INSTALL_BIN_PATH "/" DEFAULT_CONSUMERD_FILE, &st) == 0) {
				DBG3("Found location #2");
				consumer_to_use = INSTALL_BIN_PATH "/" DEFAULT_CONSUMERD_FILE;
			} else if (config.consumerd32_bin_path.value &&
					stat(config.consumerd32_bin_path.value, &st) == 0) {
				DBG3("Found location #3");
				consumer_to_use = config.consumerd32_bin_path.value;
			} else {
				DBG("Could not find any valid consumerd executable");
				ret = -EINVAL;
				goto error;
			}
			DBG("Using kernel consumer at: %s",  consumer_to_use);
			(void) execl(consumer_to_use,
				"lttng-consumerd", verbosity, "-k",
				"--consumerd-cmd-sock", consumer_data->cmd_unix_sock_path,
				"--consumerd-err-sock", consumer_data->err_unix_sock_path,
				"--group", config.tracing_group_name.value,
				NULL);
			break;
		case LTTNG_CONSUMER64_UST:
		{
			if (config.consumerd64_lib_dir.value) {
				char *tmp;
				size_t tmplen;
				char *tmpnew;

				tmp = lttng_secure_getenv("LD_LIBRARY_PATH");
				if (!tmp) {
					tmp = "";
				}
				tmplen = strlen(config.consumerd64_lib_dir.value) + 1 /* : */ + strlen(tmp);
				tmpnew = zmalloc(tmplen + 1 /* \0 */);
				if (!tmpnew) {
					ret = -ENOMEM;
					goto error;
				}
				strcat(tmpnew, config.consumerd64_lib_dir.value);
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
			DBG("Using 64-bit UST consumer at: %s",  config.consumerd64_bin_path.value);
			(void) execl(config.consumerd64_bin_path.value, "lttng-consumerd", verbosity, "-u",
					"--consumerd-cmd-sock", consumer_data->cmd_unix_sock_path,
					"--consumerd-err-sock", consumer_data->err_unix_sock_path,
					"--group", config.tracing_group_name.value,
					NULL);
			break;
		}
		case LTTNG_CONSUMER32_UST:
		{
			if (config.consumerd32_lib_dir.value) {
				char *tmp;
				size_t tmplen;
				char *tmpnew;

				tmp = lttng_secure_getenv("LD_LIBRARY_PATH");
				if (!tmp) {
					tmp = "";
				}
				tmplen = strlen(config.consumerd32_lib_dir.value) + 1 /* : */ + strlen(tmp);
				tmpnew = zmalloc(tmplen + 1 /* \0 */);
				if (!tmpnew) {
					ret = -ENOMEM;
					goto error;
				}
				strcat(tmpnew, config.consumerd32_lib_dir.value);
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
			DBG("Using 32-bit UST consumer at: %s",  config.consumerd32_bin_path.value);
			(void) execl(config.consumerd32_bin_path.value, "lttng-consumerd", verbosity, "-u",
					"--consumerd-cmd-sock", consumer_data->cmd_unix_sock_path,
					"--consumerd-err-sock", consumer_data->err_unix_sock_path,
					"--group", config.tracing_group_name.value,
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
 *
 * Should *NOT* be called with RCU read-side lock held.
 */
static int copy_session_consumer(int domain, struct ltt_session *session)
{
	int ret;
	const char *dir_name;
	struct consumer_output *consumer;

	assert(session);
	assert(session->consumer);

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
		session->kernel_session->consumer =
			consumer_copy_output(session->consumer);
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
		session->ust_session->consumer =
			consumer_copy_output(session->consumer);
		/* Ease our life a bit for the next part */
		consumer = session->ust_session->consumer;
		dir_name = DEFAULT_UST_TRACE_DIR;
		break;
	default:
		ret = LTTNG_ERR_UNKNOWN_DOMAIN;
		goto error;
	}

	/* Append correct directory to subdir */
	ret = lttng_strncpy(consumer->domain_subdir, dir_name,
			sizeof(consumer->domain_subdir));
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
 *
 * Should *NOT* be called with RCU read-side lock held.
 */
static int create_ust_session(struct ltt_session *session,
		struct lttng_domain *domain)
{
	int ret;
	struct ltt_ust_session *lus = NULL;

	assert(session);
	assert(domain);
	assert(session->consumer);

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
	if (lus == NULL) {
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
		strncpy(lus->root_shm_path, session->shm_path,
			sizeof(lus->root_shm_path));
		lus->root_shm_path[sizeof(lus->root_shm_path) - 1] = '\0';
		strncpy(lus->shm_path, session->shm_path,
			sizeof(lus->shm_path));
		lus->shm_path[sizeof(lus->shm_path) - 1] = '\0';
		strncat(lus->shm_path, "/ust",
			sizeof(lus->shm_path) - strlen(lus->shm_path) - 1);
	}
	/* Copy session output to the newly created UST session */
	ret = copy_session_consumer(domain->type, session);
	if (ret != LTTNG_OK) {
		goto error;
	}

	return LTTNG_OK;

error:
	free(lus);
	session->ust_session = NULL;
	return ret;
}

/*
 * Create a kernel tracer session then create the default channel.
 */
static int create_kernel_session(struct ltt_session *session)
{
	int ret;

	DBG("Creating kernel session");

	ret = kernel_create_session(session, kernel_tracer_fd);
	if (ret < 0) {
		ret = LTTNG_ERR_KERN_SESS_FAIL;
		goto error_create;
	}

	/* Code flow safety */
	assert(session->kernel_session);

	/* Copy session output to the newly created Kernel session */
	ret = copy_session_consumer(LTTNG_DOMAIN_KERNEL, session);
	if (ret != LTTNG_OK) {
		goto error;
	}

	session->kernel_session->uid = session->uid;
	session->kernel_session->gid = session->gid;
	session->kernel_session->output_traces = session->output_traces;
	session->kernel_session->snapshot_mode = session->snapshot_mode;

	return LTTNG_OK;

error:
	trace_kernel_destroy_session(session->kernel_session);
	session->kernel_session = NULL;
error_create:
	return ret;
}

/*
 * Count number of session permitted by uid/gid.
 */
static unsigned int lttng_sessions_count(uid_t uid, gid_t gid)
{
	unsigned int i = 0;
	struct ltt_session *session;
	const struct ltt_session_list *session_list = session_get_list();

	DBG("Counting number of available session for UID %d GID %d",
			uid, gid);
	cds_list_for_each_entry(session, &session_list->head, list) {
		if (!session_get(session)) {
			continue;
		}
		session_lock(session);
		/* Only count the sessions the user can control. */
		if (session_access_ok(session, uid, gid) &&
				!session->destroyed) {
			i++;
		}
		session_unlock(session);
		session_put(session);
	}
	return i;
}

static int receive_userspace_probe(struct command_ctx *cmd_ctx, int sock,
		int *sock_error, struct lttng_event *event)
{
	int fd, ret;
	struct lttng_userspace_probe_location *probe_location;
	const struct lttng_userspace_probe_location_lookup_method *lookup = NULL;
	struct lttng_dynamic_buffer probe_location_buffer;
	struct lttng_buffer_view buffer_view;

	/*
	 * Create a buffer to store the serialized version of the probe
	 * location.
	 */
	lttng_dynamic_buffer_init(&probe_location_buffer);
	ret = lttng_dynamic_buffer_set_size(&probe_location_buffer,
			cmd_ctx->lsm->u.enable.userspace_probe_location_len);
	if (ret) {
		ret = LTTNG_ERR_NOMEM;
		goto error;
	}

	/*
	 * Receive the probe location.
	 */
	ret = lttcomm_recv_unix_sock(sock, probe_location_buffer.data,
			probe_location_buffer.size);
	if (ret <= 0) {
		DBG("Nothing recv() from client var len data... continuing");
		*sock_error = 1;
		lttng_dynamic_buffer_reset(&probe_location_buffer);
		ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
		goto error;
	}

	buffer_view = lttng_buffer_view_from_dynamic_buffer(
			&probe_location_buffer, 0, probe_location_buffer.size);

	/*
	 * Extract the probe location from the serialized version.
	 */
	ret = lttng_userspace_probe_location_create_from_buffer(
				&buffer_view, &probe_location);
	if (ret < 0) {
		WARN("Failed to create a userspace probe location from the received buffer");
		lttng_dynamic_buffer_reset( &probe_location_buffer);
		ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
		goto error;
	}

	/*
	 * Receive the file descriptor to the target binary from the client.
	 */
	DBG("Receiving userspace probe target FD from client ...");
	ret = lttcomm_recv_fds_unix_sock(sock, &fd, 1);
	if (ret <= 0) {
		DBG("Nothing recv() from client userspace probe fd... continuing");
		*sock_error = 1;
		ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
		goto error;
	}

	/*
	 * Set the file descriptor received from the client through the unix
	 * socket in the probe location.
	 */
	lookup = lttng_userspace_probe_location_get_lookup_method(probe_location);
	if (!lookup) {
		ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
		goto error;
	}

	/*
	 * From the kernel tracer's perspective, all userspace probe event types
	 * are all the same: a file and an offset.
	 */
	switch (lttng_userspace_probe_location_lookup_method_get_type(lookup)) {
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_FUNCTION_ELF:
		ret = lttng_userspace_probe_location_function_set_binary_fd(
				probe_location, fd);
		break;
	case LTTNG_USERSPACE_PROBE_LOCATION_LOOKUP_METHOD_TYPE_TRACEPOINT_SDT:
		ret = lttng_userspace_probe_location_tracepoint_set_binary_fd(
				probe_location, fd);
		break;
	default:
		ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
		goto error;
	}

	if (ret) {
		ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
		goto error;
	}

	/* Attach the probe location to the event. */
	ret = lttng_event_set_userspace_probe_location(event, probe_location);
	if (ret) {
		ret = LTTNG_ERR_PROBE_LOCATION_INVAL;
		goto error;
	}

	lttng_dynamic_buffer_reset(&probe_location_buffer);
error:
	return ret;
}

/*
 * Version of setup_lttng_msg() without command header.
 */
static int setup_lttng_msg_no_cmd_header(struct command_ctx *cmd_ctx,
	void *payload_buf, size_t payload_len)
{
	return setup_lttng_msg(cmd_ctx, payload_buf, payload_len, NULL, 0);
}

/*
 * Free memory of a command context structure.
 */
static void clean_command_ctx(struct command_ctx **cmd_ctx)
{
	DBG("Clean command context structure");
	if (*cmd_ctx) {
		if ((*cmd_ctx)->llm) {
			free((*cmd_ctx)->llm);
		}
		if ((*cmd_ctx)->lsm) {
			free((*cmd_ctx)->lsm);
		}
		free(*cmd_ctx);
		*cmd_ctx = NULL;
	}
}

/*
 * Check if the current kernel tracer supports the session rotation feature.
 * Return 1 if it does, 0 otherwise.
 */
static int check_rotate_compatible(void)
{
	int ret = 1;

	if (kernel_tracer_version.major != 2 || kernel_tracer_version.minor < 11) {
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
static int send_unix_sock(int sock, void *buf, size_t len)
{
	/* Check valid length */
	if (len == 0) {
		return -1;
	}

	return lttcomm_send_unix_sock(sock, buf, len);
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
 *
 * Should *NOT* be called with RCU read-side lock held.
 */
static int process_client_msg(struct command_ctx *cmd_ctx, int *sock,
		int *sock_error)
{
	int ret = LTTNG_OK;
	int need_tracing_session = 1;
	int need_domain;

	DBG("Processing client command %d", cmd_ctx->lsm->cmd_type);

	assert(!rcu_read_ongoing());

	*sock_error = 0;

	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_CREATE_SESSION_EXT:
	case LTTNG_DESTROY_SESSION:
	case LTTNG_LIST_SESSIONS:
	case LTTNG_LIST_DOMAINS:
	case LTTNG_START_TRACE:
	case LTTNG_STOP_TRACE:
	case LTTNG_DATA_PENDING:
	case LTTNG_SNAPSHOT_ADD_OUTPUT:
	case LTTNG_SNAPSHOT_DEL_OUTPUT:
	case LTTNG_SNAPSHOT_LIST_OUTPUT:
	case LTTNG_SNAPSHOT_RECORD:
	case LTTNG_SAVE_SESSION:
	case LTTNG_SET_SESSION_SHM_PATH:
	case LTTNG_REGENERATE_METADATA:
	case LTTNG_REGENERATE_STATEDUMP:
	case LTTNG_REGISTER_TRIGGER:
	case LTTNG_UNREGISTER_TRIGGER:
	case LTTNG_ROTATE_SESSION:
	case LTTNG_ROTATION_GET_INFO:
	case LTTNG_ROTATION_SET_SCHEDULE:
	case LTTNG_SESSION_LIST_ROTATION_SCHEDULES:
		need_domain = 0;
		break;
	default:
		need_domain = 1;
	}

	if (config.no_kernel && need_domain
			&& cmd_ctx->lsm->domain.type == LTTNG_DOMAIN_KERNEL) {
		if (!is_root) {
			ret = LTTNG_ERR_NEED_ROOT_SESSIOND;
		} else {
			ret = LTTNG_ERR_KERN_NA;
		}
		goto error;
	}

	/* Deny register consumer if we already have a spawned consumer. */
	if (cmd_ctx->lsm->cmd_type == LTTNG_REGISTER_CONSUMER) {
		pthread_mutex_lock(&kconsumer_data.pid_mutex);
		if (kconsumer_data.pid > 0) {
			ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
			pthread_mutex_unlock(&kconsumer_data.pid_mutex);
			goto error;
		}
		pthread_mutex_unlock(&kconsumer_data.pid_mutex);
	}

	/*
	 * Check for command that don't needs to allocate a returned payload. We do
	 * this here so we don't have to make the call for no payload at each
	 * command.
	 */
	switch(cmd_ctx->lsm->cmd_type) {
	case LTTNG_LIST_SESSIONS:
	case LTTNG_LIST_TRACEPOINTS:
	case LTTNG_LIST_TRACEPOINT_FIELDS:
	case LTTNG_LIST_DOMAINS:
	case LTTNG_LIST_CHANNELS:
	case LTTNG_LIST_EVENTS:
	case LTTNG_LIST_SYSCALLS:
	case LTTNG_LIST_TRACKER_PIDS:
	case LTTNG_DATA_PENDING:
	case LTTNG_ROTATE_SESSION:
	case LTTNG_ROTATION_GET_INFO:
	case LTTNG_SESSION_LIST_ROTATION_SCHEDULES:
		break;
	default:
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, NULL, 0);
		if (ret < 0) {
			/* This label does not try to unlock the session */
			goto init_setup_error;
		}
	}

	/* Commands that DO NOT need a session. */
	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_CREATE_SESSION_EXT:
	case LTTNG_LIST_SESSIONS:
	case LTTNG_LIST_TRACEPOINTS:
	case LTTNG_LIST_SYSCALLS:
	case LTTNG_LIST_TRACEPOINT_FIELDS:
	case LTTNG_SAVE_SESSION:
	case LTTNG_REGISTER_TRIGGER:
	case LTTNG_UNREGISTER_TRIGGER:
		need_tracing_session = 0;
		break;
	default:
		DBG("Getting session %s by name", cmd_ctx->lsm->session.name);
		/*
		 * We keep the session list lock across _all_ commands
		 * for now, because the per-session lock does not
		 * handle teardown properly.
		 */
		session_lock_list();
		cmd_ctx->session = session_find_by_name(cmd_ctx->lsm->session.name);
		if (cmd_ctx->session == NULL) {
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
	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_DISABLE_CHANNEL:
	case LTTNG_DISABLE_EVENT:
		switch (cmd_ctx->lsm->domain.type) {
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
	switch (cmd_ctx->lsm->domain.type) {
	case LTTNG_DOMAIN_KERNEL:
		if (!is_root) {
			ret = LTTNG_ERR_NEED_ROOT_SESSIOND;
			goto error;
		}

		/* Consumer is in an ERROR state. Report back to client */
		if (uatomic_read(&kernel_consumerd_state) == CONSUMER_ERROR) {
			ret = LTTNG_ERR_NO_KERNCONSUMERD;
			goto error;
		}

		/* Need a session for kernel command */
		if (need_tracing_session) {
			if (cmd_ctx->session->kernel_session == NULL) {
				ret = create_kernel_session(cmd_ctx->session);
				if (ret != LTTNG_OK) {
					ret = LTTNG_ERR_KERN_SESS_FAIL;
					goto error;
				}
			}

			/* Start the kernel consumer daemon */
			pthread_mutex_lock(&kconsumer_data.pid_mutex);
			if (kconsumer_data.pid == 0 &&
					cmd_ctx->lsm->cmd_type != LTTNG_REGISTER_CONSUMER) {
				pthread_mutex_unlock(&kconsumer_data.pid_mutex);
				ret = start_consumerd(&kconsumer_data);
				if (ret < 0) {
					ret = LTTNG_ERR_KERN_CONSUMER_FAIL;
					goto error;
				}
				uatomic_set(&kernel_consumerd_state, CONSUMER_STARTED);
			} else {
				pthread_mutex_unlock(&kconsumer_data.pid_mutex);
			}

			/*
			 * The consumer was just spawned so we need to add the socket to
			 * the consumer output of the session if exist.
			 */
			ret = consumer_create_socket(&kconsumer_data,
					cmd_ctx->session->kernel_session->consumer);
			if (ret < 0) {
				goto error;
			}
		}

		break;
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_UST:
	{
		if (!ust_app_supported()) {
			ret = LTTNG_ERR_NO_UST;
			goto error;
		}
		/* Consumer is in an ERROR state. Report back to client */
		if (uatomic_read(&ust_consumerd_state) == CONSUMER_ERROR) {
			ret = LTTNG_ERR_NO_USTCONSUMERD;
			goto error;
		}

		if (need_tracing_session) {
			/* Create UST session if none exist. */
			if (cmd_ctx->session->ust_session == NULL) {
				ret = create_ust_session(cmd_ctx->session,
						&cmd_ctx->lsm->domain);
				if (ret != LTTNG_OK) {
					goto error;
				}
			}

			/* Start the UST consumer daemons */
			/* 64-bit */
			pthread_mutex_lock(&ustconsumer64_data.pid_mutex);
			if (config.consumerd64_bin_path.value &&
					ustconsumer64_data.pid == 0 &&
					cmd_ctx->lsm->cmd_type != LTTNG_REGISTER_CONSUMER) {
				pthread_mutex_unlock(&ustconsumer64_data.pid_mutex);
				ret = start_consumerd(&ustconsumer64_data);
				if (ret < 0) {
					ret = LTTNG_ERR_UST_CONSUMER64_FAIL;
					uatomic_set(&ust_consumerd64_fd, -EINVAL);
					goto error;
				}

				uatomic_set(&ust_consumerd64_fd, ustconsumer64_data.cmd_sock);
				uatomic_set(&ust_consumerd_state, CONSUMER_STARTED);
			} else {
				pthread_mutex_unlock(&ustconsumer64_data.pid_mutex);
			}

			/*
			 * Setup socket for consumer 64 bit. No need for atomic access
			 * since it was set above and can ONLY be set in this thread.
			 */
			ret = consumer_create_socket(&ustconsumer64_data,
					cmd_ctx->session->ust_session->consumer);
			if (ret < 0) {
				goto error;
			}

			/* 32-bit */
			pthread_mutex_lock(&ustconsumer32_data.pid_mutex);
			if (config.consumerd32_bin_path.value &&
					ustconsumer32_data.pid == 0 &&
					cmd_ctx->lsm->cmd_type != LTTNG_REGISTER_CONSUMER) {
				pthread_mutex_unlock(&ustconsumer32_data.pid_mutex);
				ret = start_consumerd(&ustconsumer32_data);
				if (ret < 0) {
					ret = LTTNG_ERR_UST_CONSUMER32_FAIL;
					uatomic_set(&ust_consumerd32_fd, -EINVAL);
					goto error;
				}

				uatomic_set(&ust_consumerd32_fd, ustconsumer32_data.cmd_sock);
				uatomic_set(&ust_consumerd_state, CONSUMER_STARTED);
			} else {
				pthread_mutex_unlock(&ustconsumer32_data.pid_mutex);
			}

			/*
			 * Setup socket for consumer 32 bit. No need for atomic access
			 * since it was set above and can ONLY be set in this thread.
			 */
			ret = consumer_create_socket(&ustconsumer32_data,
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
	if (cmd_ctx->lsm->cmd_type == LTTNG_START_TRACE ||
			cmd_ctx->lsm->cmd_type == LTTNG_STOP_TRACE) {
		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_NONE:
			break;
		case LTTNG_DOMAIN_JUL:
		case LTTNG_DOMAIN_LOG4J:
		case LTTNG_DOMAIN_PYTHON:
		case LTTNG_DOMAIN_UST:
			if (uatomic_read(&ust_consumerd_state) != CONSUMER_STARTED) {
				ret = LTTNG_ERR_NO_USTCONSUMERD;
				goto error;
			}
			break;
		case LTTNG_DOMAIN_KERNEL:
			if (uatomic_read(&kernel_consumerd_state) != CONSUMER_STARTED) {
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
	 * Check that the UID or GID match that of the tracing session.
	 * The root user can interact with all sessions.
	 */
	if (need_tracing_session) {
		if (!session_access_ok(cmd_ctx->session,
				LTTNG_SOCK_GET_UID_CRED(&cmd_ctx->creds),
				LTTNG_SOCK_GET_GID_CRED(&cmd_ctx->creds)) ||
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
	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_ADD_CONTEXT:
	{
		/*
		 * An LTTNG_ADD_CONTEXT command might have a supplementary
		 * payload if the context being added is an application context.
		 */
		if (cmd_ctx->lsm->u.context.ctx.ctx ==
				LTTNG_EVENT_CONTEXT_APP_CONTEXT) {
			char *provider_name = NULL, *context_name = NULL;
			size_t provider_name_len =
					cmd_ctx->lsm->u.context.provider_name_len;
			size_t context_name_len =
					cmd_ctx->lsm->u.context.context_name_len;

			if (provider_name_len == 0 || context_name_len == 0) {
				/*
				 * Application provider and context names MUST
				 * be provided.
				 */
				ret = -LTTNG_ERR_INVALID;
				goto error;
			}

			provider_name = zmalloc(provider_name_len + 1);
			if (!provider_name) {
				ret = -LTTNG_ERR_NOMEM;
				goto error;
			}
			cmd_ctx->lsm->u.context.ctx.u.app_ctx.provider_name =
					provider_name;

			context_name = zmalloc(context_name_len + 1);
			if (!context_name) {
				ret = -LTTNG_ERR_NOMEM;
				goto error_add_context;
			}
			cmd_ctx->lsm->u.context.ctx.u.app_ctx.ctx_name =
					context_name;

			ret = lttcomm_recv_unix_sock(*sock, provider_name,
					provider_name_len);
			if (ret < 0) {
				goto error_add_context;
			}

			ret = lttcomm_recv_unix_sock(*sock, context_name,
					context_name_len);
			if (ret < 0) {
				goto error_add_context;
			}
		}

		/*
		 * cmd_add_context assumes ownership of the provider and context
		 * names.
		 */
		ret = cmd_add_context(cmd_ctx->session,
				cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.context.channel_name,
				&cmd_ctx->lsm->u.context.ctx,
				kernel_poll_pipe[1]);

		cmd_ctx->lsm->u.context.ctx.u.app_ctx.provider_name = NULL;
		cmd_ctx->lsm->u.context.ctx.u.app_ctx.ctx_name = NULL;
error_add_context:
		free(cmd_ctx->lsm->u.context.ctx.u.app_ctx.provider_name);
		free(cmd_ctx->lsm->u.context.ctx.u.app_ctx.ctx_name);
		if (ret < 0) {
			goto error;
		}
		break;
	}
	case LTTNG_DISABLE_CHANNEL:
	{
		ret = cmd_disable_channel(cmd_ctx->session, cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.disable.channel_name);
		break;
	}
	case LTTNG_DISABLE_EVENT:
	{

		/*
		 * FIXME: handle filter; for now we just receive the filter's
		 * bytecode along with the filter expression which are sent by
		 * liblttng-ctl and discard them.
		 *
		 * This fixes an issue where the client may block while sending
		 * the filter payload and encounter an error because the session
		 * daemon closes the socket without ever handling this data.
		 */
		size_t count = cmd_ctx->lsm->u.disable.expression_len +
			cmd_ctx->lsm->u.disable.bytecode_len;

		if (count) {
			char data[LTTNG_FILTER_MAX_LEN];

			DBG("Discarding disable event command payload of size %zu", count);
			while (count) {
				ret = lttcomm_recv_unix_sock(*sock, data,
				        count > sizeof(data) ? sizeof(data) : count);
				if (ret < 0) {
					goto error;
				}

				count -= (size_t) ret;
			}
		}
		/* FIXME: passing packed structure to non-packed pointer */
		ret = cmd_disable_event(cmd_ctx->session, cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.disable.channel_name,
				&cmd_ctx->lsm->u.disable.event);
		break;
	}
	case LTTNG_ENABLE_CHANNEL:
	{
		cmd_ctx->lsm->u.channel.chan.attr.extended.ptr =
				(struct lttng_channel_extended *) &cmd_ctx->lsm->u.channel.extended;
		ret = cmd_enable_channel(cmd_ctx->session, &cmd_ctx->lsm->domain,
				&cmd_ctx->lsm->u.channel.chan,
				kernel_poll_pipe[1]);
		break;
	}
	case LTTNG_TRACK_PID:
	{
		ret = cmd_track_pid(cmd_ctx->session,
				cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.pid_tracker.pid);
		break;
	}
	case LTTNG_UNTRACK_PID:
	{
		ret = cmd_untrack_pid(cmd_ctx->session,
				cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.pid_tracker.pid);
		break;
	}
	case LTTNG_ENABLE_EVENT:
	{
		struct lttng_event *ev = NULL;
		struct lttng_event_exclusion *exclusion = NULL;
		struct lttng_filter_bytecode *bytecode = NULL;
		char *filter_expression = NULL;

		/* Handle exclusion events and receive it from the client. */
		if (cmd_ctx->lsm->u.enable.exclusion_count > 0) {
			size_t count = cmd_ctx->lsm->u.enable.exclusion_count;

			exclusion = zmalloc(sizeof(struct lttng_event_exclusion) +
					(count * LTTNG_SYMBOL_NAME_LEN));
			if (!exclusion) {
				ret = LTTNG_ERR_EXCLUSION_NOMEM;
				goto error;
			}

			DBG("Receiving var len exclusion event list from client ...");
			exclusion->count = count;
			ret = lttcomm_recv_unix_sock(*sock, exclusion->names,
					count * LTTNG_SYMBOL_NAME_LEN);
			if (ret <= 0) {
				DBG("Nothing recv() from client var len data... continuing");
				*sock_error = 1;
				free(exclusion);
				ret = LTTNG_ERR_EXCLUSION_INVAL;
				goto error;
			}
		}

		/* Get filter expression from client. */
		if (cmd_ctx->lsm->u.enable.expression_len > 0) {
			size_t expression_len =
				cmd_ctx->lsm->u.enable.expression_len;

			if (expression_len > LTTNG_FILTER_MAX_LEN) {
				ret = LTTNG_ERR_FILTER_INVAL;
				free(exclusion);
				goto error;
			}

			filter_expression = zmalloc(expression_len);
			if (!filter_expression) {
				free(exclusion);
				ret = LTTNG_ERR_FILTER_NOMEM;
				goto error;
			}

			/* Receive var. len. data */
			DBG("Receiving var len filter's expression from client ...");
			ret = lttcomm_recv_unix_sock(*sock, filter_expression,
				expression_len);
			if (ret <= 0) {
				DBG("Nothing recv() from client var len data... continuing");
				*sock_error = 1;
				free(filter_expression);
				free(exclusion);
				ret = LTTNG_ERR_FILTER_INVAL;
				goto error;
			}
		}

		/* Handle filter and get bytecode from client. */
		if (cmd_ctx->lsm->u.enable.bytecode_len > 0) {
			size_t bytecode_len = cmd_ctx->lsm->u.enable.bytecode_len;

			if (bytecode_len > LTTNG_FILTER_MAX_LEN) {
				ret = LTTNG_ERR_FILTER_INVAL;
				free(filter_expression);
				free(exclusion);
				goto error;
			}

			bytecode = zmalloc(bytecode_len);
			if (!bytecode) {
				free(filter_expression);
				free(exclusion);
				ret = LTTNG_ERR_FILTER_NOMEM;
				goto error;
			}

			/* Receive var. len. data */
			DBG("Receiving var len filter's bytecode from client ...");
			ret = lttcomm_recv_unix_sock(*sock, bytecode, bytecode_len);
			if (ret <= 0) {
				DBG("Nothing recv() from client var len data... continuing");
				*sock_error = 1;
				free(filter_expression);
				free(bytecode);
				free(exclusion);
				ret = LTTNG_ERR_FILTER_INVAL;
				goto error;
			}

			if ((bytecode->len + sizeof(*bytecode)) != bytecode_len) {
				free(filter_expression);
				free(bytecode);
				free(exclusion);
				ret = LTTNG_ERR_FILTER_INVAL;
				goto error;
			}
		}

		ev = lttng_event_copy(&cmd_ctx->lsm->u.enable.event);
		if (!ev) {
			DBG("Failed to copy event: %s",
					cmd_ctx->lsm->u.enable.event.name);
			free(filter_expression);
			free(bytecode);
			free(exclusion);
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}


		if (cmd_ctx->lsm->u.enable.userspace_probe_location_len > 0) {
			/* Expect a userspace probe description. */
			ret = receive_userspace_probe(cmd_ctx, *sock, sock_error, ev);
			if (ret) {
				free(filter_expression);
				free(bytecode);
				free(exclusion);
				lttng_event_destroy(ev);
				goto error;
			}
		}

		ret = cmd_enable_event(cmd_ctx->session, &cmd_ctx->lsm->domain,
				cmd_ctx->lsm->u.enable.channel_name,
				ev,
				filter_expression, bytecode, exclusion,
				kernel_poll_pipe[1]);
		lttng_event_destroy(ev);
		break;
	}
	case LTTNG_LIST_TRACEPOINTS:
	{
		struct lttng_event *events;
		ssize_t nb_events;

		session_lock_list();
		nb_events = cmd_list_tracepoints(cmd_ctx->lsm->domain.type, &events);
		session_unlock_list();
		if (nb_events < 0) {
			/* Return value is a negative lttng_error_code. */
			ret = -nb_events;
			goto error;
		}

		/*
		 * Setup lttng message with payload size set to the event list size in
		 * bytes and then copy list into the llm payload.
		 */
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, events,
			sizeof(struct lttng_event) * nb_events);
		free(events);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_LIST_TRACEPOINT_FIELDS:
	{
		struct lttng_event_field *fields;
		ssize_t nb_fields;

		session_lock_list();
		nb_fields = cmd_list_tracepoint_fields(cmd_ctx->lsm->domain.type,
				&fields);
		session_unlock_list();
		if (nb_fields < 0) {
			/* Return value is a negative lttng_error_code. */
			ret = -nb_fields;
			goto error;
		}

		/*
		 * Setup lttng message with payload size set to the event list size in
		 * bytes and then copy list into the llm payload.
		 */
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, fields,
				sizeof(struct lttng_event_field) * nb_fields);
		free(fields);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_LIST_SYSCALLS:
	{
		struct lttng_event *events;
		ssize_t nb_events;

		nb_events = cmd_list_syscalls(&events);
		if (nb_events < 0) {
			/* Return value is a negative lttng_error_code. */
			ret = -nb_events;
			goto error;
		}

		/*
		 * Setup lttng message with payload size set to the event list size in
		 * bytes and then copy list into the llm payload.
		 */
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, events,
			sizeof(struct lttng_event) * nb_events);
		free(events);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_LIST_TRACKER_PIDS:
	{
		int32_t *pids = NULL;
		ssize_t nr_pids;

		nr_pids = cmd_list_tracker_pids(cmd_ctx->session,
				cmd_ctx->lsm->domain.type, &pids);
		if (nr_pids < 0) {
			/* Return value is a negative lttng_error_code. */
			ret = -nr_pids;
			goto error;
		}

		/*
		 * Setup lttng message with payload size set to the event list size in
		 * bytes and then copy list into the llm payload.
		 */
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, pids,
			sizeof(int32_t) * nr_pids);
		free(pids);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_SET_CONSUMER_URI:
	{
		size_t nb_uri, len;
		struct lttng_uri *uris;

		nb_uri = cmd_ctx->lsm->u.uri.size;
		len = nb_uri * sizeof(struct lttng_uri);

		if (nb_uri == 0) {
			ret = LTTNG_ERR_INVALID;
			goto error;
		}

		uris = zmalloc(len);
		if (uris == NULL) {
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
	case LTTNG_START_TRACE:
	{
		/*
		 * On the first start, if we have a kernel session and we have
		 * enabled time or size-based rotations, we have to make sure
		 * the kernel tracer supports it.
		 */
		if (!cmd_ctx->session->has_been_started && \
				cmd_ctx->session->kernel_session && \
				(cmd_ctx->session->rotate_timer_period || \
					cmd_ctx->session->rotate_size) && \
				!check_rotate_compatible()) {
			DBG("Kernel tracer version is not compatible with the rotation feature");
			ret = LTTNG_ERR_ROTATION_WRONG_VERSION;
			goto error;
		}
		ret = cmd_start_trace(cmd_ctx->session);
		break;
	}
	case LTTNG_STOP_TRACE:
	{
		ret = cmd_stop_trace(cmd_ctx->session);
		break;
	}
	case LTTNG_DESTROY_SESSION:
	{
		ret = cmd_destroy_session(cmd_ctx->session,
				notification_thread_handle,
				sock);
		break;
	}
	case LTTNG_LIST_DOMAINS:
	{
		ssize_t nb_dom;
		struct lttng_domain *domains = NULL;

		nb_dom = cmd_list_domains(cmd_ctx->session, &domains);
		if (nb_dom < 0) {
			/* Return value is a negative lttng_error_code. */
			ret = -nb_dom;
			goto error;
		}

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, domains,
			nb_dom * sizeof(struct lttng_domain));
		free(domains);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_LIST_CHANNELS:
	{
		ssize_t payload_size;
		struct lttng_channel *channels = NULL;

		payload_size = cmd_list_channels(cmd_ctx->lsm->domain.type,
				cmd_ctx->session, &channels);
		if (payload_size < 0) {
			/* Return value is a negative lttng_error_code. */
			ret = -payload_size;
			goto error;
		}

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, channels,
			payload_size);
		free(channels);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_LIST_EVENTS:
	{
		ssize_t nb_event;
		struct lttng_event *events = NULL;
		struct lttcomm_event_command_header cmd_header;
		size_t total_size;

		memset(&cmd_header, 0, sizeof(cmd_header));
		/* Extended infos are included at the end of events */
		nb_event = cmd_list_events(cmd_ctx->lsm->domain.type,
			cmd_ctx->session, cmd_ctx->lsm->u.list.channel_name,
			&events, &total_size);

		if (nb_event < 0) {
			/* Return value is a negative lttng_error_code. */
			ret = -nb_event;
			goto error;
		}

		cmd_header.nb_events = nb_event;
		ret = setup_lttng_msg(cmd_ctx, events, total_size,
			&cmd_header, sizeof(cmd_header));
		free(events);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_LIST_SESSIONS:
	{
		unsigned int nr_sessions;
		void *sessions_payload;
		size_t payload_len;

		session_lock_list();
		nr_sessions = lttng_sessions_count(
				LTTNG_SOCK_GET_UID_CRED(&cmd_ctx->creds),
				LTTNG_SOCK_GET_GID_CRED(&cmd_ctx->creds));

		payload_len = (sizeof(struct lttng_session) * nr_sessions) +
				(sizeof(struct lttng_session_extended) * nr_sessions);
		sessions_payload = zmalloc(payload_len);

		if (!sessions_payload) {
			session_unlock_list();
			ret = -ENOMEM;
			goto setup_error;
		}

		cmd_list_lttng_sessions(sessions_payload, nr_sessions,
			LTTNG_SOCK_GET_UID_CRED(&cmd_ctx->creds),
			LTTNG_SOCK_GET_GID_CRED(&cmd_ctx->creds));
		session_unlock_list();

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, sessions_payload,
			payload_len);
		free(sessions_payload);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_REGISTER_CONSUMER:
	{
		struct consumer_data *cdata;

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			cdata = &kconsumer_data;
			break;
		default:
			ret = LTTNG_ERR_UND;
			goto error;
		}

		ret = cmd_register_consumer(cmd_ctx->session, cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.reg.path, cdata);
		break;
	}
	case LTTNG_DATA_PENDING:
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
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx,
			&pending_ret_byte, 1);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_SNAPSHOT_ADD_OUTPUT:
	{
		struct lttcomm_lttng_output_id reply;

		ret = cmd_snapshot_add_output(cmd_ctx->session,
				&cmd_ctx->lsm->u.snapshot_output.output, &reply.id);
		if (ret != LTTNG_OK) {
			goto error;
		}

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, &reply,
			sizeof(reply));
		if (ret < 0) {
			goto setup_error;
		}

		/* Copy output list into message payload */
		ret = LTTNG_OK;
		break;
	}
	case LTTNG_SNAPSHOT_DEL_OUTPUT:
	{
		ret = cmd_snapshot_del_output(cmd_ctx->session,
				&cmd_ctx->lsm->u.snapshot_output.output);
		break;
	}
	case LTTNG_SNAPSHOT_LIST_OUTPUT:
	{
		ssize_t nb_output;
		struct lttng_snapshot_output *outputs = NULL;

		nb_output = cmd_snapshot_list_outputs(cmd_ctx->session, &outputs);
		if (nb_output < 0) {
			ret = -nb_output;
			goto error;
		}

		assert((nb_output > 0 && outputs) || nb_output == 0);
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, outputs,
				nb_output * sizeof(struct lttng_snapshot_output));
		free(outputs);

		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_SNAPSHOT_RECORD:
	{
		ret = cmd_snapshot_record(cmd_ctx->session,
				&cmd_ctx->lsm->u.snapshot_record.output,
				cmd_ctx->lsm->u.snapshot_record.wait);
		break;
	}
	case LTTNG_CREATE_SESSION_EXT:
	{
		struct lttng_dynamic_buffer payload;
		struct lttng_session_descriptor *return_descriptor = NULL;

		lttng_dynamic_buffer_init(&payload);
		ret = cmd_create_session(cmd_ctx, *sock, &return_descriptor);
		if (ret != LTTNG_OK) {
			goto error;
		}

		ret = lttng_session_descriptor_serialize(return_descriptor,
				&payload);
		if (ret) {
			ERR("Failed to serialize session descriptor in reply to \"create session\" command");
			lttng_session_descriptor_destroy(return_descriptor);
			ret = LTTNG_ERR_NOMEM;
			goto error;
		}
		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, payload.data,
				payload.size);
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
	case LTTNG_SAVE_SESSION:
	{
		ret = cmd_save_sessions(&cmd_ctx->lsm->u.save_session.attr,
			&cmd_ctx->creds);
		break;
	}
	case LTTNG_SET_SESSION_SHM_PATH:
	{
		ret = cmd_set_session_shm_path(cmd_ctx->session,
				cmd_ctx->lsm->u.set_shm_path.shm_path);
		break;
	}
	case LTTNG_REGENERATE_METADATA:
	{
		ret = cmd_regenerate_metadata(cmd_ctx->session);
		break;
	}
	case LTTNG_REGENERATE_STATEDUMP:
	{
		ret = cmd_regenerate_statedump(cmd_ctx->session);
		break;
	}
	case LTTNG_REGISTER_TRIGGER:
	{
		ret = cmd_register_trigger(cmd_ctx, *sock,
				notification_thread_handle);
		break;
	}
	case LTTNG_UNREGISTER_TRIGGER:
	{
		ret = cmd_unregister_trigger(cmd_ctx, *sock,
				notification_thread_handle);
		break;
	}
	case LTTNG_ROTATE_SESSION:
	{
		struct lttng_rotate_session_return rotate_return;

		DBG("Client rotate session \"%s\"", cmd_ctx->session->name);

		memset(&rotate_return, 0, sizeof(rotate_return));
		if (cmd_ctx->session->kernel_session && !check_rotate_compatible()) {
			DBG("Kernel tracer version is not compatible with the rotation feature");
			ret = LTTNG_ERR_ROTATION_WRONG_VERSION;
			goto error;
		}

		ret = cmd_rotate_session(cmd_ctx->session, &rotate_return);
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, &rotate_return,
				sizeof(rotate_return));
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_ROTATION_GET_INFO:
	{
		struct lttng_rotation_get_info_return get_info_return;

		memset(&get_info_return, 0, sizeof(get_info_return));
		ret = cmd_rotate_get_info(cmd_ctx->session, &get_info_return,
				cmd_ctx->lsm->u.get_rotation_info.rotation_id);
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, &get_info_return,
				sizeof(get_info_return));
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = LTTNG_OK;
		break;
	}
	case LTTNG_ROTATION_SET_SCHEDULE:
	{
		bool set_schedule;
		enum lttng_rotation_schedule_type schedule_type;
		uint64_t value;

		if (cmd_ctx->session->kernel_session && !check_rotate_compatible()) {
			DBG("Kernel tracer version does not support session rotations");
			ret = LTTNG_ERR_ROTATION_WRONG_VERSION;
			goto error;
		}

		set_schedule = cmd_ctx->lsm->u.rotation_set_schedule.set == 1;
		schedule_type = (enum lttng_rotation_schedule_type) cmd_ctx->lsm->u.rotation_set_schedule.type;
		value = cmd_ctx->lsm->u.rotation_set_schedule.value;

		ret = cmd_rotation_set_schedule(cmd_ctx->session,
				set_schedule,
				schedule_type,
				value,
				notification_thread_handle);
		if (ret != LTTNG_OK) {
			goto error;
		}

		break;
	}
	case LTTNG_SESSION_LIST_ROTATION_SCHEDULES:
	{
		struct lttng_session_list_schedules_return schedules = {
			.periodic.set = !!cmd_ctx->session->rotate_timer_period,
			.periodic.value = cmd_ctx->session->rotate_timer_period,
			.size.set = !!cmd_ctx->session->rotate_size,
			.size.value = cmd_ctx->session->rotate_size,
		};

		ret = setup_lttng_msg_no_cmd_header(cmd_ctx, &schedules,
				sizeof(schedules));
		if (ret < 0) {
			ret = -ret;
			goto error;
		}

		ret = LTTNG_OK;
		break;
	}
	default:
		ret = LTTNG_ERR_UND;
		break;
	}

error:
	if (cmd_ctx->llm == NULL) {
		DBG("Missing llm structure. Allocating one.");
		if (setup_lttng_msg_no_cmd_header(cmd_ctx, NULL, 0) < 0) {
			goto setup_error;
		}
	}
	/* Set return code */
	cmd_ctx->llm->ret_code = ret;
setup_error:
	if (cmd_ctx->session) {
		session_unlock(cmd_ctx->session);
		session_put(cmd_ctx->session);
		cmd_ctx->session = NULL;
	}
	if (need_tracing_session) {
		session_unlock_list();
	}
init_setup_error:
	assert(!rcu_read_ongoing());
	return ret;
}

static int create_client_sock(void)
{
	int ret, client_sock;
	const mode_t old_umask = umask(0);

	/* Create client tool unix socket */
	client_sock = lttcomm_create_unix_sock(config.client_unix_sock_path.value);
	if (client_sock < 0) {
		ERR("Create unix sock failed: %s", config.client_unix_sock_path.value);
		ret = -1;
		goto end;
	}

	/* Set the cloexec flag */
	ret = utils_set_fd_cloexec(client_sock);
	if (ret < 0) {
		ERR("Unable to set CLOEXEC flag to the client Unix socket (fd: %d). "
				"Continuing but note that the consumer daemon will have a "
				"reference to this socket on exec()", client_sock);
	}

	/* File permission MUST be 660 */
	ret = chmod(config.client_unix_sock_path.value, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", config.client_unix_sock_path.value);
		PERROR("chmod");
		goto end;
	}
	DBG("Created client socket (fd = %i)", client_sock);
	ret = client_sock;
end:
	umask(old_umask);
	return ret;
}

static void cleanup_client_thread(void *data)
{
	struct lttng_pipe *quit_pipe = data;

	lttng_pipe_destroy(quit_pipe);
}

static void thread_init_cleanup(void *data)
{
	set_thread_status(false);
}

/*
 * This thread manage all clients request using the unix client socket for
 * communication.
 */
static void *thread_manage_clients(void *data)
{
	int sock = -1, ret, i, pollfd, err = -1;
	int sock_error;
	uint32_t revents, nb_fd;
	struct command_ctx *cmd_ctx = NULL;
	struct lttng_poll_event events;
	int client_sock = -1;
	struct lttng_pipe *quit_pipe = data;
	const int thread_quit_pipe_fd = lttng_pipe_get_readfd(quit_pipe);

	DBG("[thread] Manage client started");

	is_root = (getuid() == 0);

	pthread_cleanup_push(thread_init_cleanup, NULL);
	client_sock = create_client_sock();
	if (client_sock < 0) {
		goto error_listen;
	}

	rcu_register_thread();

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_CMD);

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
	ret = lttng_poll_add(&events, thread_quit_pipe_fd, LPOLLIN | LPOLLERR);
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

	while (1) {
		const struct cmd_completion_handler *cmd_completion_handler;

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
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			if (pollfd == thread_quit_pipe_fd) {
				err = 0;
				goto exit;
			} else {
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

		/* Allocate context command to process the client request */
		cmd_ctx = zmalloc(sizeof(struct command_ctx));
		if (cmd_ctx == NULL) {
			PERROR("zmalloc cmd_ctx");
			goto error;
		}

		/* Allocate data buffer for reception */
		cmd_ctx->lsm = zmalloc(sizeof(struct lttcomm_session_msg));
		if (cmd_ctx->lsm == NULL) {
			PERROR("zmalloc cmd_ctx->lsm");
			goto error;
		}

		cmd_ctx->llm = NULL;
		cmd_ctx->session = NULL;

		health_code_update();

		/*
		 * Data is received from the lttng client. The struct
		 * lttcomm_session_msg (lsm) contains the command and data request of
		 * the client.
		 */
		DBG("Receiving data from client ...");
		ret = lttcomm_recv_creds_unix_sock(sock, cmd_ctx->lsm,
				sizeof(struct lttcomm_session_msg), &cmd_ctx->creds);
		if (ret <= 0) {
			DBG("Nothing recv() from client... continuing");
			ret = close(sock);
			if (ret) {
				PERROR("close");
			}
			sock = -1;
			clean_command_ctx(&cmd_ctx);
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
		ret = process_client_msg(cmd_ctx, &sock, &sock_error);
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
			clean_command_ctx(&cmd_ctx);
			continue;
		}

		cmd_completion_handler = cmd_pop_completion_handler();
		if (cmd_completion_handler) {
			enum lttng_error_code completion_code;

			completion_code = cmd_completion_handler->run(
					cmd_completion_handler->data);
			if (completion_code != LTTNG_OK) {
				clean_command_ctx(&cmd_ctx);
				continue;
			}
		}

		health_code_update();

		if (sock >= 0) {
			DBG("Sending response (size: %d, retcode: %s (%d))",
					cmd_ctx->lttng_msg_size,
					lttng_strerror(-cmd_ctx->llm->ret_code),
					cmd_ctx->llm->ret_code);
			ret = send_unix_sock(sock, cmd_ctx->llm,
					cmd_ctx->lttng_msg_size);
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

		clean_command_ctx(&cmd_ctx);

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
	clean_command_ctx(&cmd_ctx);

error_listen:
error_create_poll:
	unlink(config.client_unix_sock_path.value);
	if (client_sock >= 0) {
		ret = close(client_sock);
		if (ret) {
			PERROR("close");
		}
	}

	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}

	health_unregister(health_sessiond);

	DBG("Client thread dying");

	rcu_unregister_thread();
	return NULL;
}

static
bool shutdown_client_thread(void *thread_data)
{
	struct lttng_pipe *client_quit_pipe = thread_data;
	const int write_fd = lttng_pipe_get_writefd(client_quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

struct lttng_thread *launch_client_thread(void)
{
	bool thread_running;
	struct lttng_pipe *client_quit_pipe;
	struct lttng_thread *thread;

	sem_init(&thread_state.ready, 0, 0);
	client_quit_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!client_quit_pipe) {
		goto error;
	}

	thread = lttng_thread_create("Client management",
			thread_manage_clients,
			shutdown_client_thread,
			cleanup_client_thread,
			client_quit_pipe);
	if (!thread) {
		goto error;
	}

	/*
	 * This thread is part of the threads that need to be fully
	 * initialized before the session daemon is marked as "ready".
	 */
	thread_running = wait_thread_status();
	if (!thread_running) {
		lttng_thread_put(thread);
		thread = NULL;
	}
	return thread;
error:
	cleanup_client_thread(client_quit_pipe);
	return NULL;
}
