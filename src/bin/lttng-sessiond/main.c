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

#define _LGPL_SOURCE
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <paths.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <urcu/uatomic.h>
#include <unistd.h>
#include <ctype.h>

#include <common/common.h>
#include <common/compat/socket.h>
#include <common/compat/getenv.h>
#include <common/defaults.h>
#include <common/kernel-consumer/kernel-consumer.h>
#include <common/futex.h>
#include <common/relayd/relayd.h>
#include <common/utils.h>
#include <common/daemonize.h>
#include <common/config/session-config.h>

#include "lttng-sessiond.h"
#include "buffer-registry.h"
#include "channel.h"
#include "cmd.h"
#include "consumer.h"
#include "context.h"
#include "event.h"
#include "kernel.h"
#include "kernel-consumer.h"
#include "modprobe.h"
#include "shm.h"
#include "ust-ctl.h"
#include "ust-consumer.h"
#include "utils.h"
#include "fd-limit.h"
#include "health-sessiond.h"
#include "testpoint.h"
#include "ust-thread.h"
#include "agent-thread.h"
#include "save.h"
#include "load-session-thread.h"
#include "notification-thread.h"
#include "notification-thread-commands.h"
#include "syscall.h"
#include "agent.h"
#include "ht-cleanup.h"
#include "sessiond-config.h"

static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-sessiond.8.h>
#else
NULL
#endif
;

const char *progname;
static pid_t ppid;          /* Parent PID for --sig-parent option */
static pid_t child_ppid;    /* Internal parent PID use with daemonize. */
static int lockfile_fd = -1;

/* Set to 1 when a SIGUSR1 signal is received. */
static int recv_child_signal;

/*
 * Consumer daemon specific control data. Every value not initialized here is
 * set to 0 by the static definition.
 */
static struct consumer_data kconsumer_data = {
	.type = LTTNG_CONSUMER_KERNEL,
	.err_sock = -1,
	.cmd_sock = -1,
	.channel_monitor_pipe = -1,
	.pid_mutex = PTHREAD_MUTEX_INITIALIZER,
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.cond = PTHREAD_COND_INITIALIZER,
	.cond_mutex = PTHREAD_MUTEX_INITIALIZER,
};
static struct consumer_data ustconsumer64_data = {
	.type = LTTNG_CONSUMER64_UST,
	.err_sock = -1,
	.cmd_sock = -1,
	.channel_monitor_pipe = -1,
	.pid_mutex = PTHREAD_MUTEX_INITIALIZER,
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.cond = PTHREAD_COND_INITIALIZER,
	.cond_mutex = PTHREAD_MUTEX_INITIALIZER,
};
static struct consumer_data ustconsumer32_data = {
	.type = LTTNG_CONSUMER32_UST,
	.err_sock = -1,
	.cmd_sock = -1,
	.channel_monitor_pipe = -1,
	.pid_mutex = PTHREAD_MUTEX_INITIALIZER,
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.cond = PTHREAD_COND_INITIALIZER,
	.cond_mutex = PTHREAD_MUTEX_INITIALIZER,
};

/* Command line options */
static const struct option long_options[] = {
	{ "client-sock", required_argument, 0, 'c' },
	{ "apps-sock", required_argument, 0, 'a' },
	{ "kconsumerd-cmd-sock", required_argument, 0, '\0' },
	{ "kconsumerd-err-sock", required_argument, 0, '\0' },
	{ "ustconsumerd32-cmd-sock", required_argument, 0, '\0' },
	{ "ustconsumerd32-err-sock", required_argument, 0, '\0' },
	{ "ustconsumerd64-cmd-sock", required_argument, 0, '\0' },
	{ "ustconsumerd64-err-sock", required_argument, 0, '\0' },
	{ "consumerd32-path", required_argument, 0, '\0' },
	{ "consumerd32-libdir", required_argument, 0, '\0' },
	{ "consumerd64-path", required_argument, 0, '\0' },
	{ "consumerd64-libdir", required_argument, 0, '\0' },
	{ "daemonize", no_argument, 0, 'd' },
	{ "background", no_argument, 0, 'b' },
	{ "sig-parent", no_argument, 0, 'S' },
	{ "help", no_argument, 0, 'h' },
	{ "group", required_argument, 0, 'g' },
	{ "version", no_argument, 0, 'V' },
	{ "quiet", no_argument, 0, 'q' },
	{ "verbose", no_argument, 0, 'v' },
	{ "verbose-consumer", no_argument, 0, '\0' },
	{ "no-kernel", no_argument, 0, '\0' },
	{ "pidfile", required_argument, 0, 'p' },
	{ "agent-tcp-port", required_argument, 0, '\0' },
	{ "config", required_argument, 0, 'f' },
	{ "load", required_argument, 0, 'l' },
	{ "kmod-probes", required_argument, 0, '\0' },
	{ "extra-kmod-probes", required_argument, 0, '\0' },
	{ NULL, 0, 0, 0 }
};

struct sessiond_config config;

/* Command line options to ignore from configuration file */
static const char *config_ignore_options[] = { "help", "version", "config" };

/* Shared between threads */
static int dispatch_thread_exit;

/* Sockets and FDs */
static int client_sock = -1;
static int apps_sock = -1;
int kernel_tracer_fd = -1;
static int kernel_poll_pipe[2] = { -1, -1 };

/*
 * Quit pipe for all threads. This permits a single cancellation point
 * for all threads when receiving an event on the pipe.
 */
static int thread_quit_pipe[2] = { -1, -1 };

/*
 * This pipe is used to inform the thread managing application communication
 * that a command is queued and ready to be processed.
 */
static int apps_cmd_pipe[2] = { -1, -1 };

int apps_cmd_notify_pipe[2] = { -1, -1 };

/* Pthread, Mutexes and Semaphores */
static pthread_t apps_thread;
static pthread_t apps_notify_thread;
static pthread_t reg_apps_thread;
static pthread_t client_thread;
static pthread_t kernel_thread;
static pthread_t dispatch_thread;
static pthread_t health_thread;
static pthread_t ht_cleanup_thread;
static pthread_t agent_reg_thread;
static pthread_t load_session_thread;
static pthread_t notification_thread;

/*
 * UST registration command queue. This queue is tied with a futex and uses a N
 * wakers / 1 waiter implemented and detailed in futex.c/.h
 *
 * The thread_registration_apps and thread_dispatch_ust_registration uses this
 * queue along with the wait/wake scheme. The thread_manage_apps receives down
 * the line new application socket and monitors it for any I/O error or clean
 * close that triggers an unregistration of the application.
 */
static struct ust_cmd_queue ust_cmd_queue;

/*
 * Pointer initialized before thread creation.
 *
 * This points to the tracing session list containing the session count and a
 * mutex lock. The lock MUST be taken if you iterate over the list. The lock
 * MUST NOT be taken if you call a public function in session.c.
 *
 * The lock is nested inside the structure: session_list_ptr->lock. Please use
 * session_lock_list and session_unlock_list for lock acquisition.
 */
static struct ltt_session_list *session_list_ptr;

int ust_consumerd64_fd = -1;
int ust_consumerd32_fd = -1;

static const char *module_proc_lttng = "/proc/lttng";

/*
 * Consumer daemon state which is changed when spawning it, killing it or in
 * case of a fatal error.
 */
enum consumerd_state {
	CONSUMER_STARTED = 1,
	CONSUMER_STOPPED = 2,
	CONSUMER_ERROR   = 3,
};

/*
 * This consumer daemon state is used to validate if a client command will be
 * able to reach the consumer. If not, the client is informed. For instance,
 * doing a "lttng start" when the consumer state is set to ERROR will return an
 * error to the client.
 *
 * The following example shows a possible race condition of this scheme:
 *
 * consumer thread error happens
 *                                    client cmd arrives
 *                                    client cmd checks state -> still OK
 * consumer thread exit, sets error
 *                                    client cmd try to talk to consumer
 *                                    ...
 *
 * However, since the consumer is a different daemon, we have no way of making
 * sure the command will reach it safely even with this state flag. This is why
 * we consider that up to the state validation during command processing, the
 * command is safe. After that, we can not guarantee the correctness of the
 * client request vis-a-vis the consumer.
 */
static enum consumerd_state ust_consumerd_state;
static enum consumerd_state kernel_consumerd_state;

/* Set in main() with the current page size. */
long page_size;

/* Application health monitoring */
struct health_app *health_sessiond;

/* Am I root or not. */
int is_root;			/* Set to 1 if the daemon is running as root */

const char * const config_section_name = "sessiond";

/* Load session thread information to operate. */
struct load_session_thread_data *load_info;

/* Notification thread handle. */
struct notification_thread_handle *notification_thread_handle;

/* Global hash tables */
struct lttng_ht *agent_apps_ht_by_sock = NULL;

/*
 * Whether sessiond is ready for commands/notification channel/health check
 * requests.
 * NR_LTTNG_SESSIOND_READY must match the number of calls to
 * sessiond_notify_ready().
 */
#define NR_LTTNG_SESSIOND_READY		4
int lttng_sessiond_ready = NR_LTTNG_SESSIOND_READY;

int sessiond_check_thread_quit_pipe(int fd, uint32_t events)
{
	return (fd == thread_quit_pipe[0] && (events & LPOLLIN)) ? 1 : 0;
}

/* Notify parents that we are ready for cmd and health check */
LTTNG_HIDDEN
void sessiond_notify_ready(void)
{
	if (uatomic_sub_return(&lttng_sessiond_ready, 1) == 0) {
		/*
		 * Notify parent pid that we are ready to accept command
		 * for client side.  This ppid is the one from the
		 * external process that spawned us.
		 */
		if (config.sig_parent) {
			kill(ppid, SIGUSR1);
		}

		/*
		 * Notify the parent of the fork() process that we are
		 * ready.
		 */
		if (config.daemonize || config.background) {
			kill(child_ppid, SIGUSR1);
		}
	}
}

static
int __sessiond_set_thread_pollset(struct lttng_poll_event *events, size_t size,
		int *a_pipe)
{
	int ret;

	assert(events);

	ret = lttng_poll_create(events, size, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error;
	}

	/* Add quit pipe */
	ret = lttng_poll_add(events, a_pipe[0], LPOLLIN | LPOLLERR);
	if (ret < 0) {
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 * Create a poll set with O_CLOEXEC and add the thread quit pipe to the set.
 */
int sessiond_set_thread_pollset(struct lttng_poll_event *events, size_t size)
{
	return __sessiond_set_thread_pollset(events, size, thread_quit_pipe);
}

/*
 * Init thread quit pipe.
 *
 * Return -1 on error or 0 if all pipes are created.
 */
static int __init_thread_quit_pipe(int *a_pipe)
{
	int ret, i;

	ret = pipe(a_pipe);
	if (ret < 0) {
		PERROR("thread quit pipe");
		goto error;
	}

	for (i = 0; i < 2; i++) {
		ret = fcntl(a_pipe[i], F_SETFD, FD_CLOEXEC);
		if (ret < 0) {
			PERROR("fcntl");
			goto error;
		}
	}

error:
	return ret;
}

static int init_thread_quit_pipe(void)
{
	return __init_thread_quit_pipe(thread_quit_pipe);
}

/*
 * Stop all threads by closing the thread quit pipe.
 */
static void stop_threads(void)
{
	int ret;

	/* Stopping all threads */
	DBG("Terminating all threads");
	ret = notify_thread_pipe(thread_quit_pipe[1]);
	if (ret < 0) {
		ERR("write error on thread quit pipe");
	}

	/* Dispatch thread */
	CMM_STORE_SHARED(dispatch_thread_exit, 1);
	futex_nto1_wake(&ust_cmd_queue.futex);
}

/*
 * Close every consumer sockets.
 */
static void close_consumer_sockets(void)
{
	int ret;

	if (kconsumer_data.err_sock >= 0) {
		ret = close(kconsumer_data.err_sock);
		if (ret < 0) {
			PERROR("kernel consumer err_sock close");
		}
	}
	if (ustconsumer32_data.err_sock >= 0) {
		ret = close(ustconsumer32_data.err_sock);
		if (ret < 0) {
			PERROR("UST consumerd32 err_sock close");
		}
	}
	if (ustconsumer64_data.err_sock >= 0) {
		ret = close(ustconsumer64_data.err_sock);
		if (ret < 0) {
			PERROR("UST consumerd64 err_sock close");
		}
	}
	if (kconsumer_data.cmd_sock >= 0) {
		ret = close(kconsumer_data.cmd_sock);
		if (ret < 0) {
			PERROR("kernel consumer cmd_sock close");
		}
	}
	if (ustconsumer32_data.cmd_sock >= 0) {
		ret = close(ustconsumer32_data.cmd_sock);
		if (ret < 0) {
			PERROR("UST consumerd32 cmd_sock close");
		}
	}
	if (ustconsumer64_data.cmd_sock >= 0) {
		ret = close(ustconsumer64_data.cmd_sock);
		if (ret < 0) {
			PERROR("UST consumerd64 cmd_sock close");
		}
	}
	if (kconsumer_data.channel_monitor_pipe >= 0) {
		ret = close(kconsumer_data.channel_monitor_pipe);
		if (ret < 0) {
			PERROR("kernel consumer channel monitor pipe close");
		}
	}
	if (ustconsumer32_data.channel_monitor_pipe >= 0) {
		ret = close(ustconsumer32_data.channel_monitor_pipe);
		if (ret < 0) {
			PERROR("UST consumerd32 channel monitor pipe close");
		}
	}
	if (ustconsumer64_data.channel_monitor_pipe >= 0) {
		ret = close(ustconsumer64_data.channel_monitor_pipe);
		if (ret < 0) {
			PERROR("UST consumerd64 channel monitor pipe close");
		}
	}
}

/*
 * Wait on consumer process termination.
 *
 * Need to be called with the consumer data lock held or from a context
 * ensuring no concurrent access to data (e.g: cleanup).
 */
static void wait_consumer(struct consumer_data *consumer_data)
{
	pid_t ret;
	int status;

	if (consumer_data->pid <= 0) {
		return;
	}

	DBG("Waiting for complete teardown of consumerd (PID: %d)",
			consumer_data->pid);
	ret = waitpid(consumer_data->pid, &status, 0);
	if (ret == -1) {
		PERROR("consumerd waitpid pid: %d", consumer_data->pid)
	} else	if (!WIFEXITED(status)) {
		ERR("consumerd termination with error: %d",
				WEXITSTATUS(ret));
	}
	consumer_data->pid = 0;
}

/*
 * Cleanup the session daemon's data structures.
 */
static void sessiond_cleanup(void)
{
	int ret;
	struct ltt_session *sess, *stmp;

	DBG("Cleanup sessiond");

	/*
	 * Close the thread quit pipe. It has already done its job,
	 * since we are now called.
	 */
	utils_close_pipe(thread_quit_pipe);

	/*
	 * If config.pid_file_path.value is undefined, the default file will be
	 * wiped when removing the rundir.
	 */
	if (config.pid_file_path.value) {
		ret = remove(config.pid_file_path.value);
		if (ret < 0) {
			PERROR("remove pidfile %s", config.pid_file_path.value);
		}
	}

	DBG("Removing sessiond and consumerd content of directory %s",
		config.rundir.value);

	/* sessiond */
	DBG("Removing %s", config.pid_file_path.value);
	(void) unlink(config.pid_file_path.value);

	DBG("Removing %s", config.agent_port_file_path.value);
	(void) unlink(config.agent_port_file_path.value);

	/* kconsumerd */
	DBG("Removing %s", kconsumer_data.err_unix_sock_path);
	(void) unlink(kconsumer_data.err_unix_sock_path);

	DBG("Removing directory %s", config.kconsumerd_path.value);
	(void) rmdir(config.kconsumerd_path.value);

	/* ust consumerd 32 */
	DBG("Removing %s", config.consumerd32_err_unix_sock_path.value);
	(void) unlink(config.consumerd32_err_unix_sock_path.value);

	DBG("Removing directory %s", config.consumerd32_path.value);
	(void) rmdir(config.consumerd32_path.value);

	/* ust consumerd 64 */
	DBG("Removing %s", config.consumerd64_err_unix_sock_path.value);
	(void) unlink(config.consumerd64_err_unix_sock_path.value);

	DBG("Removing directory %s", config.consumerd64_path.value);
	(void) rmdir(config.consumerd64_path.value);

	DBG("Cleaning up all sessions");

	/* Destroy session list mutex */
	if (session_list_ptr != NULL) {
		pthread_mutex_destroy(&session_list_ptr->lock);

		/* Cleanup ALL session */
		cds_list_for_each_entry_safe(sess, stmp,
				&session_list_ptr->head, list) {
			cmd_destroy_session(sess, kernel_poll_pipe[1]);
		}
	}

	wait_consumer(&kconsumer_data);
	wait_consumer(&ustconsumer64_data);
	wait_consumer(&ustconsumer32_data);

	DBG("Cleaning up all agent apps");
	agent_app_ht_clean();

	DBG("Closing all UST sockets");
	ust_app_clean_list();
	buffer_reg_destroy_registries();

	if (is_root && !config.no_kernel) {
		DBG2("Closing kernel fd");
		if (kernel_tracer_fd >= 0) {
			ret = close(kernel_tracer_fd);
			if (ret) {
				PERROR("close");
			}
		}
		DBG("Unloading kernel modules");
		modprobe_remove_lttng_all();
		free(syscall_table);
	}

	close_consumer_sockets();

	if (load_info) {
		load_session_destroy_data(load_info);
		free(load_info);
	}

	/*
	 * Cleanup lock file by deleting it and finaly closing it which will
	 * release the file system lock.
	 */
	if (lockfile_fd >= 0) {
		ret = remove(config.lock_file_path.value);
		if (ret < 0) {
			PERROR("remove lock file");
		}
		ret = close(lockfile_fd);
		if (ret < 0) {
			PERROR("close lock file");
		}
	}

	/*
	 * We do NOT rmdir rundir because there are other processes
	 * using it, for instance lttng-relayd, which can start in
	 * parallel with this teardown.
	 */
}

/*
 * Cleanup the daemon's option data structures.
 */
static void sessiond_cleanup_options(void)
{
	DBG("Cleaning up options");

	sessiond_config_fini(&config);

	run_as_destroy_worker();
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
 * Notify UST applications using the shm mmap futex.
 */
static int notify_ust_apps(int active)
{
	char *wait_shm_mmap;

	DBG("Notifying applications of session daemon state: %d", active);

	/* See shm.c for this call implying mmap, shm and futex calls */
	wait_shm_mmap = shm_ust_get_mmap(config.wait_shm_path.value, is_root);
	if (wait_shm_mmap == NULL) {
		goto error;
	}

	/* Wake waiting process */
	futex_wait_update((int32_t *) wait_shm_mmap, active);

	/* Apps notified successfully */
	return 0;

error:
	return -1;
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
 * Version of setup_lttng_msg() without command header.
 */
static int setup_lttng_msg_no_cmd_header(struct command_ctx *cmd_ctx,
	void *payload_buf, size_t payload_len)
{
	return setup_lttng_msg(cmd_ctx, payload_buf, payload_len, NULL, 0);
}
/*
 * Update the kernel poll set of all channel fd available over all tracing
 * session. Add the wakeup pipe at the end of the set.
 */
static int update_kernel_poll(struct lttng_poll_event *events)
{
	int ret;
	struct ltt_session *session;
	struct ltt_kernel_channel *channel;

	DBG("Updating kernel poll set");

	session_lock_list();
	cds_list_for_each_entry(session, &session_list_ptr->head, list) {
		session_lock(session);
		if (session->kernel_session == NULL) {
			session_unlock(session);
			continue;
		}

		cds_list_for_each_entry(channel,
				&session->kernel_session->channel_list.head, list) {
			/* Add channel fd to the kernel poll set */
			ret = lttng_poll_add(events, channel->fd, LPOLLIN | LPOLLRDNORM);
			if (ret < 0) {
				session_unlock(session);
				goto error;
			}
			DBG("Channel fd %d added to kernel set", channel->fd);
		}
		session_unlock(session);
	}
	session_unlock_list();

	return 0;

error:
	session_unlock_list();
	return -1;
}

/*
 * Find the channel fd from 'fd' over all tracing session. When found, check
 * for new channel stream and send those stream fds to the kernel consumer.
 *
 * Useful for CPU hotplug feature.
 */
static int update_kernel_stream(struct consumer_data *consumer_data, int fd)
{
	int ret = 0;
	struct ltt_session *session;
	struct ltt_kernel_session *ksess;
	struct ltt_kernel_channel *channel;

	DBG("Updating kernel streams for channel fd %d", fd);

	session_lock_list();
	cds_list_for_each_entry(session, &session_list_ptr->head, list) {
		session_lock(session);
		if (session->kernel_session == NULL) {
			session_unlock(session);
			continue;
		}
		ksess = session->kernel_session;

		cds_list_for_each_entry(channel,
				&ksess->channel_list.head, list) {
			struct lttng_ht_iter iter;
			struct consumer_socket *socket;

			if (channel->fd != fd) {
				continue;
			}
			DBG("Channel found, updating kernel streams");
			ret = kernel_open_channel_stream(channel);
			if (ret < 0) {
				goto error;
			}
			/* Update the stream global counter */
			ksess->stream_count_global += ret;

			/*
			 * Have we already sent fds to the consumer? If yes, it
			 * means that tracing is started so it is safe to send
			 * our updated stream fds.
			 */
			if (ksess->consumer_fds_sent != 1
					|| ksess->consumer == NULL) {
				ret = -1;
				goto error;
			}

			rcu_read_lock();
			cds_lfht_for_each_entry(ksess->consumer->socks->ht,
					&iter.iter, socket, node.node) {
				pthread_mutex_lock(socket->lock);
				ret = kernel_consumer_send_channel_stream(socket,
						channel, ksess,
						session->output_traces ? 1 : 0);
				pthread_mutex_unlock(socket->lock);
				if (ret < 0) {
					rcu_read_unlock();
					goto error;
				}
			}
			rcu_read_unlock();
		}
		session_unlock(session);
	}
	session_unlock_list();
	return ret;

error:
	session_unlock(session);
	session_unlock_list();
	return ret;
}

/*
 * For each tracing session, update newly registered apps. The session list
 * lock MUST be acquired before calling this.
 */
static void update_ust_app(int app_sock)
{
	struct ltt_session *sess, *stmp;

	/* Consumer is in an ERROR state. Stop any application update. */
	if (uatomic_read(&ust_consumerd_state) == CONSUMER_ERROR) {
		/* Stop the update process since the consumer is dead. */
		return;
	}

	/* For all tracing session(s) */
	cds_list_for_each_entry_safe(sess, stmp, &session_list_ptr->head, list) {
		struct ust_app *app;

		session_lock(sess);
		if (!sess->ust_session) {
			goto unlock_session;
		}

		rcu_read_lock();
		assert(app_sock >= 0);
		app = ust_app_find_by_sock(app_sock);
		if (app == NULL) {
			/*
			 * Application can be unregistered before so
			 * this is possible hence simply stopping the
			 * update.
			 */
			DBG3("UST app update failed to find app sock %d",
				app_sock);
			goto unlock_rcu;
		}
		ust_app_global_update(sess->ust_session, app);
	unlock_rcu:
		rcu_read_unlock();
	unlock_session:
		session_unlock(sess);
	}
}

/*
 * This thread manage event coming from the kernel.
 *
 * Features supported in this thread:
 *    -) CPU Hotplug
 */
static void *thread_manage_kernel(void *data)
{
	int ret, i, pollfd, update_poll_flag = 1, err = -1;
	uint32_t revents, nb_fd;
	char tmp;
	struct lttng_poll_event events;

	DBG("[thread] Thread manage kernel started");

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_KERNEL);

	/*
	 * This first step of the while is to clean this structure which could free
	 * non NULL pointers so initialize it before the loop.
	 */
	lttng_poll_init(&events);

	if (testpoint(sessiond_thread_manage_kernel)) {
		goto error_testpoint;
	}

	health_code_update();

	if (testpoint(sessiond_thread_manage_kernel_before_loop)) {
		goto error_testpoint;
	}

	while (1) {
		health_code_update();

		if (update_poll_flag == 1) {
			/* Clean events object. We are about to populate it again. */
			lttng_poll_clean(&events);

			ret = sessiond_set_thread_pollset(&events, 2);
			if (ret < 0) {
				goto error_poll_create;
			}

			ret = lttng_poll_add(&events, kernel_poll_pipe[0], LPOLLIN);
			if (ret < 0) {
				goto error;
			}

			/* This will add the available kernel channel if any. */
			ret = update_kernel_poll(&events);
			if (ret < 0) {
				goto error;
			}
			update_poll_flag = 0;
		}

		DBG("Thread kernel polling");

		/* Poll infinite value of time */
	restart:
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		DBG("Thread kernel return from poll on %d fds",
				LTTNG_POLL_GETNB(&events));
		health_poll_exit();
		if (ret < 0) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				goto restart;
			}
			goto error;
		} else if (ret == 0) {
			/* Should not happen since timeout is infinite */
			ERR("Return value of poll is 0 with an infinite timeout.\n"
				"This should not have happened! Continuing...");
			continue;
		}

		nb_fd = ret;

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			/* Thread quit pipe has been closed. Killing thread. */
			ret = sessiond_check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Check for data on kernel pipe */
			if (revents & LPOLLIN) {
				if (pollfd == kernel_poll_pipe[0]) {
					(void) lttng_read(kernel_poll_pipe[0],
						&tmp, 1);
					/*
					 * Ret value is useless here, if this pipe gets any actions an
					 * update is required anyway.
					 */
					update_poll_flag = 1;
					continue;
				} else {
					/*
					 * New CPU detected by the kernel. Adding kernel stream to
					 * kernel session and updating the kernel consumer
					 */
					ret = update_kernel_stream(&kconsumer_data, pollfd);
					if (ret < 0) {
						continue;
					}
					break;
				}
			} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				update_poll_flag = 1;
				continue;
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto error;
			}
		}
	}

exit:
error:
	lttng_poll_clean(&events);
error_poll_create:
error_testpoint:
	utils_close_pipe(kernel_poll_pipe);
	kernel_poll_pipe[0] = kernel_poll_pipe[1] = -1;
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
		WARN("Kernel thread died unexpectedly. "
				"Kernel tracing can continue but CPU hotplug is disabled.");
	}
	health_unregister(health_sessiond);
	DBG("Kernel thread dying");
	return NULL;
}

/*
 * Signal pthread condition of the consumer data that the thread.
 */
static void signal_consumer_condition(struct consumer_data *data, int state)
{
	pthread_mutex_lock(&data->cond_mutex);

	/*
	 * The state is set before signaling. It can be any value, it's the waiter
	 * job to correctly interpret this condition variable associated to the
	 * consumer pthread_cond.
	 *
	 * A value of 0 means that the corresponding thread of the consumer data
	 * was not started. 1 indicates that the thread has started and is ready
	 * for action. A negative value means that there was an error during the
	 * thread bootstrap.
	 */
	data->consumer_thread_is_ready = state;
	(void) pthread_cond_signal(&data->cond);

	pthread_mutex_unlock(&data->cond_mutex);
}

/*
 * This thread manage the consumer error sent back to the session daemon.
 */
static void *thread_manage_consumer(void *data)
{
	int sock = -1, i, ret, pollfd, err = -1, should_quit = 0;
	uint32_t revents, nb_fd;
	enum lttcomm_return_code code;
	struct lttng_poll_event events;
	struct consumer_data *consumer_data = data;
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
	ret = sessiond_set_thread_pollset(&events, 3);
	if (ret < 0) {
		goto error_poll;
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
restart:
	health_poll_entry();

	if (testpoint(sessiond_thread_manage_consumer)) {
		goto error;
	}

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
		/* Fetch once the poll data */
		revents = LTTNG_POLL_GETEV(&events, i);
		pollfd = LTTNG_POLL_GETFD(&events, i);

		health_code_update();

		if (!revents) {
			/* No activity for this FD (poll implementation). */
			continue;
		}

		/* Thread quit pipe has been closed. Killing thread. */
		ret = sessiond_check_thread_quit_pipe(pollfd, revents);
		if (ret) {
			err = 0;
			goto exit;
		}

		/* Event on the registration socket */
		if (pollfd == consumer_data->err_sock) {
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

	/* Getting status code from kconsumerd */
	ret = lttcomm_recv_unix_sock(sock, &code,
			sizeof(enum lttcomm_return_code));
	if (ret <= 0) {
		goto error;
	}

	health_code_update();
	if (code != LTTCOMM_CONSUMERD_COMMAND_SOCK_READY) {
		ERR("consumer error when waiting for SOCK_READY : %s",
				lttcomm_get_readable_code(-code));
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
		/* On error, signal condition and quit. */
		signal_consumer_condition(consumer_data, -1);
		goto error;
	}

	consumer_data->metadata_sock.fd_ptr = &consumer_data->metadata_fd;

	/* Create metadata socket lock. */
	consumer_data->metadata_sock.lock = zmalloc(sizeof(pthread_mutex_t));
	if (consumer_data->metadata_sock.lock == NULL) {
		PERROR("zmalloc pthread mutex");
		goto error;
	}
	pthread_mutex_init(consumer_data->metadata_sock.lock, NULL);

	DBG("Consumer command socket ready (fd: %d", consumer_data->cmd_sock);
	DBG("Consumer metadata socket ready (fd: %d)",
			consumer_data->metadata_fd);

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
	ret = lttng_poll_add(&events, consumer_data->metadata_fd,
			LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	health_code_update();

	/*
	 * Transfer the write-end of the channel monitoring pipe to the
	 * by issuing a SET_CHANNEL_MONITOR_PIPE command.
	 */
	cmd_socket_wrapper = consumer_allocate_socket(&consumer_data->cmd_sock);
	if (!cmd_socket_wrapper) {
		goto error;
	}

	ret = consumer_send_channel_monitor_pipe(cmd_socket_wrapper,
			consumer_data->channel_monitor_pipe);
	if (ret) {
		goto error;
	}
	/* Discard the socket wrapper as it is no longer needed. */
	consumer_destroy_socket(cmd_socket_wrapper);
	cmd_socket_wrapper = NULL;

	/* The thread is completely initialized, signal that it is ready. */
	signal_consumer_condition(consumer_data, 1);

	/* Infinite blocking call, waiting for transmission */
restart_poll:
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
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				goto restart_poll;
			}
			goto error;
		}

		nb_fd = ret;

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			/*
			 * Thread quit pipe has been triggered, flag that we should stop
			 * but continue the current loop to handle potential data from
			 * consumer.
			 */
			should_quit = sessiond_check_thread_quit_pipe(pollfd, revents);

			if (pollfd == sock) {
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

/*
 * This thread receives application command sockets (FDs) on the
 * apps_cmd_pipe and waits (polls) on them until they are closed
 * or an error occurs.
 *
 * At that point, it flushes the data (tracing and metadata) associated
 * with this application and tears down ust app sessions and other
 * associated data structures through ust_app_unregister().
 *
 * Note that this thread never sends commands to the applications
 * through the command sockets; it merely listens for hang-ups
 * and errors on those sockets and cleans-up as they occur.
 */
static void *thread_manage_apps(void *data)
{
	int i, ret, pollfd, err = -1;
	ssize_t size_ret;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;

	DBG("[thread] Manage application started");

	rcu_register_thread();
	rcu_thread_online();

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_APP_MANAGE);

	if (testpoint(sessiond_thread_manage_apps)) {
		goto error_testpoint;
	}

	health_code_update();

	ret = sessiond_set_thread_pollset(&events, 2);
	if (ret < 0) {
		goto error_poll_create;
	}

	ret = lttng_poll_add(&events, apps_cmd_pipe[0], LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	if (testpoint(sessiond_thread_manage_apps_before_loop)) {
		goto error;
	}

	health_code_update();

	while (1) {
		DBG("Apps thread polling");

		/* Inifinite blocking call, waiting for transmission */
	restart:
		health_poll_entry();
		ret = lttng_poll_wait(&events, -1);
		DBG("Apps thread return from poll on %d fds",
				LTTNG_POLL_GETNB(&events));
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
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			/* Thread quit pipe has been closed. Killing thread. */
			ret = sessiond_check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Inspect the apps cmd pipe */
			if (pollfd == apps_cmd_pipe[0]) {
				if (revents & LPOLLIN) {
					int sock;

					/* Empty pipe */
					size_ret = lttng_read(apps_cmd_pipe[0], &sock, sizeof(sock));
					if (size_ret < sizeof(sock)) {
						PERROR("read apps cmd pipe");
						goto error;
					}

					health_code_update();

					/*
					 * Since this is a command socket (write then read),
					 * we only monitor the error events of the socket.
					 */
					ret = lttng_poll_add(&events, sock,
							LPOLLERR | LPOLLHUP | LPOLLRDHUP);
					if (ret < 0) {
						goto error;
					}

					DBG("Apps with sock %d added to poll set", sock);
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Apps command pipe error");
					goto error;
				} else {
					ERR("Unknown poll events %u for sock %d", revents, pollfd);
					goto error;
				}
			} else {
				/*
				 * At this point, we know that a registered application made
				 * the event at poll_wait.
				 */
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					/* Removing from the poll set */
					ret = lttng_poll_del(&events, pollfd);
					if (ret < 0) {
						goto error;
					}

					/* Socket closed on remote end. */
					ust_app_unregister(pollfd);
				} else {
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
					goto error;
				}
			}

			health_code_update();
		}
	}

exit:
error:
	lttng_poll_clean(&events);
error_poll_create:
error_testpoint:
	utils_close_pipe(apps_cmd_pipe);
	apps_cmd_pipe[0] = apps_cmd_pipe[1] = -1;

	/*
	 * We don't clean the UST app hash table here since already registered
	 * applications can still be controlled so let them be until the session
	 * daemon dies or the applications stop.
	 */

	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_sessiond);
	DBG("Application communication apps thread cleanup complete");
	rcu_thread_offline();
	rcu_unregister_thread();
	return NULL;
}

/*
 * Send a socket to a thread This is called from the dispatch UST registration
 * thread once all sockets are set for the application.
 *
 * The sock value can be invalid, we don't really care, the thread will handle
 * it and make the necessary cleanup if so.
 *
 * On success, return 0 else a negative value being the errno message of the
 * write().
 */
static int send_socket_to_thread(int fd, int sock)
{
	ssize_t ret;

	/*
	 * It's possible that the FD is set as invalid with -1 concurrently just
	 * before calling this function being a shutdown state of the thread.
	 */
	if (fd < 0) {
		ret = -EBADF;
		goto error;
	}

	ret = lttng_write(fd, &sock, sizeof(sock));
	if (ret < sizeof(sock)) {
		PERROR("write apps pipe %d", fd);
		if (ret < 0) {
			ret = -errno;
		}
		goto error;
	}

	/* All good. Don't send back the write positive ret value. */
	ret = 0;
error:
	return (int) ret;
}

/*
 * Sanitize the wait queue of the dispatch registration thread meaning removing
 * invalid nodes from it. This is to avoid memory leaks for the case the UST
 * notify socket is never received.
 */
static void sanitize_wait_queue(struct ust_reg_wait_queue *wait_queue)
{
	int ret, nb_fd = 0, i;
	unsigned int fd_added = 0;
	struct lttng_poll_event events;
	struct ust_reg_wait_node *wait_node = NULL, *tmp_wait_node;

	assert(wait_queue);

	lttng_poll_init(&events);

	/* Just skip everything for an empty queue. */
	if (!wait_queue->count) {
		goto end;
	}

	ret = lttng_poll_create(&events, wait_queue->count, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error_create;
	}

	cds_list_for_each_entry_safe(wait_node, tmp_wait_node,
			&wait_queue->head, head) {
		assert(wait_node->app);
		ret = lttng_poll_add(&events, wait_node->app->sock,
				LPOLLHUP | LPOLLERR);
		if (ret < 0) {
			goto error;
		}

		fd_added = 1;
	}

	if (!fd_added) {
		goto end;
	}

	/*
	 * Poll but don't block so we can quickly identify the faulty events and
	 * clean them afterwards from the wait queue.
	 */
	ret = lttng_poll_wait(&events, 0);
	if (ret < 0) {
		goto error;
	}
	nb_fd = ret;

	for (i = 0; i < nb_fd; i++) {
		/* Get faulty FD. */
		uint32_t revents = LTTNG_POLL_GETEV(&events, i);
		int pollfd = LTTNG_POLL_GETFD(&events, i);

		if (!revents) {
			/* No activity for this FD (poll implementation). */
			continue;
		}

		cds_list_for_each_entry_safe(wait_node, tmp_wait_node,
				&wait_queue->head, head) {
			if (pollfd == wait_node->app->sock &&
					(revents & (LPOLLHUP | LPOLLERR))) {
				cds_list_del(&wait_node->head);
				wait_queue->count--;
				ust_app_destroy(wait_node->app);
				free(wait_node);
				/*
				 * Silence warning of use-after-free in
				 * cds_list_for_each_entry_safe which uses
				 * __typeof__(*wait_node).
				 */
				wait_node = NULL;
				break;
			} else {
				ERR("Unexpected poll events %u for sock %d", revents, pollfd);
				goto error;
			}
		}
	}

	if (nb_fd > 0) {
		DBG("Wait queue sanitized, %d node were cleaned up", nb_fd);
	}

end:
	lttng_poll_clean(&events);
	return;

error:
	lttng_poll_clean(&events);
error_create:
	ERR("Unable to sanitize wait queue");
	return;
}

/*
 * Dispatch request from the registration threads to the application
 * communication thread.
 */
static void *thread_dispatch_ust_registration(void *data)
{
	int ret, err = -1;
	struct cds_wfcq_node *node;
	struct ust_command *ust_cmd = NULL;
	struct ust_reg_wait_node *wait_node = NULL, *tmp_wait_node;
	struct ust_reg_wait_queue wait_queue = {
		.count = 0,
	};

	rcu_register_thread();

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_APP_REG_DISPATCH);

	if (testpoint(sessiond_thread_app_reg_dispatch)) {
		goto error_testpoint;
	}

	health_code_update();

	CDS_INIT_LIST_HEAD(&wait_queue.head);

	DBG("[thread] Dispatch UST command started");

	for (;;) {
		health_code_update();

		/* Atomically prepare the queue futex */
		futex_nto1_prepare(&ust_cmd_queue.futex);

		if (CMM_LOAD_SHARED(dispatch_thread_exit)) {
			break;
		}

		do {
			struct ust_app *app = NULL;
			ust_cmd = NULL;

			/*
			 * Make sure we don't have node(s) that have hung up before receiving
			 * the notify socket. This is to clean the list in order to avoid
			 * memory leaks from notify socket that are never seen.
			 */
			sanitize_wait_queue(&wait_queue);

			health_code_update();
			/* Dequeue command for registration */
			node = cds_wfcq_dequeue_blocking(&ust_cmd_queue.head, &ust_cmd_queue.tail);
			if (node == NULL) {
				DBG("Woken up but nothing in the UST command queue");
				/* Continue thread execution */
				break;
			}

			ust_cmd = caa_container_of(node, struct ust_command, node);

			DBG("Dispatching UST registration pid:%d ppid:%d uid:%d"
					" gid:%d sock:%d name:%s (version %d.%d)",
					ust_cmd->reg_msg.pid, ust_cmd->reg_msg.ppid,
					ust_cmd->reg_msg.uid, ust_cmd->reg_msg.gid,
					ust_cmd->sock, ust_cmd->reg_msg.name,
					ust_cmd->reg_msg.major, ust_cmd->reg_msg.minor);

			if (ust_cmd->reg_msg.type == USTCTL_SOCKET_CMD) {
				wait_node = zmalloc(sizeof(*wait_node));
				if (!wait_node) {
					PERROR("zmalloc wait_node dispatch");
					ret = close(ust_cmd->sock);
					if (ret < 0) {
						PERROR("close ust sock dispatch %d", ust_cmd->sock);
					}
					lttng_fd_put(LTTNG_FD_APPS, 1);
					free(ust_cmd);
					goto error;
				}
				CDS_INIT_LIST_HEAD(&wait_node->head);

				/* Create application object if socket is CMD. */
				wait_node->app = ust_app_create(&ust_cmd->reg_msg,
						ust_cmd->sock);
				if (!wait_node->app) {
					ret = close(ust_cmd->sock);
					if (ret < 0) {
						PERROR("close ust sock dispatch %d", ust_cmd->sock);
					}
					lttng_fd_put(LTTNG_FD_APPS, 1);
					free(wait_node);
					free(ust_cmd);
					continue;
				}
				/*
				 * Add application to the wait queue so we can set the notify
				 * socket before putting this object in the global ht.
				 */
				cds_list_add(&wait_node->head, &wait_queue.head);
				wait_queue.count++;

				free(ust_cmd);
				/*
				 * We have to continue here since we don't have the notify
				 * socket and the application MUST be added to the hash table
				 * only at that moment.
				 */
				continue;
			} else {
				/*
				 * Look for the application in the local wait queue and set the
				 * notify socket if found.
				 */
				cds_list_for_each_entry_safe(wait_node, tmp_wait_node,
						&wait_queue.head, head) {
					health_code_update();
					if (wait_node->app->pid == ust_cmd->reg_msg.pid) {
						wait_node->app->notify_sock = ust_cmd->sock;
						cds_list_del(&wait_node->head);
						wait_queue.count--;
						app = wait_node->app;
						free(wait_node);
						DBG3("UST app notify socket %d is set", ust_cmd->sock);
						break;
					}
				}

				/*
				 * With no application at this stage the received socket is
				 * basically useless so close it before we free the cmd data
				 * structure for good.
				 */
				if (!app) {
					ret = close(ust_cmd->sock);
					if (ret < 0) {
						PERROR("close ust sock dispatch %d", ust_cmd->sock);
					}
					lttng_fd_put(LTTNG_FD_APPS, 1);
				}
				free(ust_cmd);
			}

			if (app) {
				/*
				 * @session_lock_list
				 *
				 * Lock the global session list so from the register up to the
				 * registration done message, no thread can see the application
				 * and change its state.
				 */
				session_lock_list();
				rcu_read_lock();

				/*
				 * Add application to the global hash table. This needs to be
				 * done before the update to the UST registry can locate the
				 * application.
				 */
				ust_app_add(app);

				/* Set app version. This call will print an error if needed. */
				(void) ust_app_version(app);

				/* Send notify socket through the notify pipe. */
				ret = send_socket_to_thread(apps_cmd_notify_pipe[1],
						app->notify_sock);
				if (ret < 0) {
					rcu_read_unlock();
					session_unlock_list();
					/*
					 * No notify thread, stop the UST tracing. However, this is
					 * not an internal error of the this thread thus setting
					 * the health error code to a normal exit.
					 */
					err = 0;
					goto error;
				}

				/*
				 * Update newly registered application with the tracing
				 * registry info already enabled information.
				 */
				update_ust_app(app->sock);

				/*
				 * Don't care about return value. Let the manage apps threads
				 * handle app unregistration upon socket close.
				 */
				(void) ust_app_register_done(app);

				/*
				 * Even if the application socket has been closed, send the app
				 * to the thread and unregistration will take place at that
				 * place.
				 */
				ret = send_socket_to_thread(apps_cmd_pipe[1], app->sock);
				if (ret < 0) {
					rcu_read_unlock();
					session_unlock_list();
					/*
					 * No apps. thread, stop the UST tracing. However, this is
					 * not an internal error of the this thread thus setting
					 * the health error code to a normal exit.
					 */
					err = 0;
					goto error;
				}

				rcu_read_unlock();
				session_unlock_list();
			}
		} while (node != NULL);

		health_poll_entry();
		/* Futex wait on queue. Blocking call on futex() */
		futex_nto1_wait(&ust_cmd_queue.futex);
		health_poll_exit();
	}
	/* Normal exit, no error */
	err = 0;

error:
	/* Clean up wait queue. */
	cds_list_for_each_entry_safe(wait_node, tmp_wait_node,
			&wait_queue.head, head) {
		cds_list_del(&wait_node->head);
		wait_queue.count--;
		free(wait_node);
	}

	/* Empty command queue. */
	for (;;) {
		/* Dequeue command for registration */
		node = cds_wfcq_dequeue_blocking(&ust_cmd_queue.head, &ust_cmd_queue.tail);
		if (node == NULL) {
			break;
		}
		ust_cmd = caa_container_of(node, struct ust_command, node);
		ret = close(ust_cmd->sock);
		if (ret < 0) {
			PERROR("close ust sock exit dispatch %d", ust_cmd->sock);
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
		free(ust_cmd);
	}

error_testpoint:
	DBG("Dispatch thread dying");
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_sessiond);
	rcu_unregister_thread();
	return NULL;
}

/*
 * This thread manage application registration.
 */
static void *thread_registration_apps(void *data)
{
	int sock = -1, i, ret, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	/*
	 * Get allocated in this thread, enqueued to a global queue, dequeued and
	 * freed in the manage apps thread.
	 */
	struct ust_command *ust_cmd = NULL;

	DBG("[thread] Manage application registration started");

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_APP_REG);

	if (testpoint(sessiond_thread_registration_apps)) {
		goto error_testpoint;
	}

	ret = lttcomm_listen_unix_sock(apps_sock);
	if (ret < 0) {
		goto error_listen;
	}

	/*
	 * Pass 2 as size here for the thread quit pipe and apps socket. Nothing
	 * more will be added to this poll set.
	 */
	ret = sessiond_set_thread_pollset(&events, 2);
	if (ret < 0) {
		goto error_create_poll;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, apps_sock, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error_poll_add;
	}

	/* Notify all applications to register */
	ret = notify_ust_apps(1);
	if (ret < 0) {
		ERR("Failed to notify applications or create the wait shared memory.\n"
			"Execution continues but there might be problem for already\n"
			"running applications that wishes to register.");
	}

	while (1) {
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
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			/* Thread quit pipe has been closed. Killing thread. */
			ret = sessiond_check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Event on the registration socket */
			if (pollfd == apps_sock) {
				if (revents & LPOLLIN) {
					sock = lttcomm_accept_unix_sock(apps_sock);
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
					if (config.app_socket_timeout >= 0) {
						(void) lttcomm_setsockopt_rcv_timeout(sock,
								config.app_socket_timeout * 1000);
						(void) lttcomm_setsockopt_snd_timeout(sock,
								config.app_socket_timeout * 1000);
					}

					/*
					 * Set the CLOEXEC flag. Return code is useless because
					 * either way, the show must go on.
					 */
					(void) utils_set_fd_cloexec(sock);

					/* Create UST registration command for enqueuing */
					ust_cmd = zmalloc(sizeof(struct ust_command));
					if (ust_cmd == NULL) {
						PERROR("ust command zmalloc");
						ret = close(sock);
						if (ret) {
							PERROR("close");
						}
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
							ust_cmd->reg_msg.pid, ust_cmd->reg_msg.ppid,
							ust_cmd->reg_msg.uid, ust_cmd->reg_msg.gid,
							ust_cmd->sock, ust_cmd->reg_msg.name,
							ust_cmd->reg_msg.major, ust_cmd->reg_msg.minor);

					/*
					 * Lock free enqueue the registration request. The red pill
					 * has been taken! This apps will be part of the *system*.
					 */
					cds_wfcq_enqueue(&ust_cmd_queue.head, &ust_cmd_queue.tail, &ust_cmd->node);

					/*
					 * Wake the registration queue futex. Implicit memory
					 * barrier with the exchange in cds_wfcq_enqueue.
					 */
					futex_nto1_wake(&ust_cmd_queue.futex);
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Register apps socket poll error");
					goto error;
				} else {
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
					goto error;
				}
			}
		}
	}

exit:
error:
	/* Notify that the registration thread is gone */
	notify_ust_apps(0);

	if (apps_sock >= 0) {
		ret = close(apps_sock);
		if (ret) {
			PERROR("close");
		}
	}
	if (sock >= 0) {
		ret = close(sock);
		if (ret) {
			PERROR("close");
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
	}
	unlink(config.apps_unix_sock_path.value);

error_poll_add:
	lttng_poll_clean(&events);
error_listen:
error_create_poll:
error_testpoint:
	DBG("UST Registration thread cleanup complete");
	if (err) {
		health_error();
		ERR("Health error occurred in %s", __func__);
	}
	health_unregister(health_sessiond);

	return NULL;
}

/*
 * Start the thread_manage_consumer. This must be done after a lttng-consumerd
 * exec or it will fails.
 */
static int spawn_consumer_thread(struct consumer_data *consumer_data)
{
	int ret, clock_ret;
	struct timespec timeout;

	/*
	 * Make sure we set the readiness flag to 0 because we are NOT ready.
	 * This access to consumer_thread_is_ready does not need to be
	 * protected by consumer_data.cond_mutex (yet) since the consumer
	 * management thread has not been started at this point.
	 */
	consumer_data->consumer_thread_is_ready = 0;

	/* Setup pthread condition */
	ret = pthread_condattr_init(&consumer_data->condattr);
	if (ret) {
		errno = ret;
		PERROR("pthread_condattr_init consumer data");
		goto error;
	}

	/*
	 * Set the monotonic clock in order to make sure we DO NOT jump in time
	 * between the clock_gettime() call and the timedwait call. See bug #324
	 * for a more details and how we noticed it.
	 */
	ret = pthread_condattr_setclock(&consumer_data->condattr, CLOCK_MONOTONIC);
	if (ret) {
		errno = ret;
		PERROR("pthread_condattr_setclock consumer data");
		goto error;
	}

	ret = pthread_cond_init(&consumer_data->cond, &consumer_data->condattr);
	if (ret) {
		errno = ret;
		PERROR("pthread_cond_init consumer data");
		goto error;
	}

	ret = pthread_create(&consumer_data->thread, default_pthread_attr(),
			thread_manage_consumer, consumer_data);
	if (ret) {
		errno = ret;
		PERROR("pthread_create consumer");
		ret = -1;
		goto error;
	}

	/* We are about to wait on a pthread condition */
	pthread_mutex_lock(&consumer_data->cond_mutex);

	/* Get time for sem_timedwait absolute timeout */
	clock_ret = lttng_clock_gettime(CLOCK_MONOTONIC, &timeout);
	/*
	 * Set the timeout for the condition timed wait even if the clock gettime
	 * call fails since we might loop on that call and we want to avoid to
	 * increment the timeout too many times.
	 */
	timeout.tv_sec += DEFAULT_SEM_WAIT_TIMEOUT;

	/*
	 * The following loop COULD be skipped in some conditions so this is why we
	 * set ret to 0 in order to make sure at least one round of the loop is
	 * done.
	 */
	ret = 0;

	/*
	 * Loop until the condition is reached or when a timeout is reached. Note
	 * that the pthread_cond_timedwait(P) man page specifies that EINTR can NOT
	 * be returned but the pthread_cond(3), from the glibc-doc, says that it is
	 * possible. This loop does not take any chances and works with both of
	 * them.
	 */
	while (!consumer_data->consumer_thread_is_ready && ret != ETIMEDOUT) {
		if (clock_ret < 0) {
			PERROR("clock_gettime spawn consumer");
			/* Infinite wait for the consumerd thread to be ready */
			ret = pthread_cond_wait(&consumer_data->cond,
					&consumer_data->cond_mutex);
		} else {
			ret = pthread_cond_timedwait(&consumer_data->cond,
					&consumer_data->cond_mutex, &timeout);
		}
	}

	/* Release the pthread condition */
	pthread_mutex_unlock(&consumer_data->cond_mutex);

	if (ret != 0) {
		errno = ret;
		if (ret == ETIMEDOUT) {
			int pth_ret;

			/*
			 * Call has timed out so we kill the kconsumerd_thread and return
			 * an error.
			 */
			ERR("Condition timed out. The consumer thread was never ready."
					" Killing it");
			pth_ret = pthread_cancel(consumer_data->thread);
			if (pth_ret < 0) {
				PERROR("pthread_cancel consumer thread");
			}
		} else {
			PERROR("pthread_cond_wait failed consumer thread");
		}
		/* Caller is expecting a negative value on failure. */
		ret = -1;
		goto error;
	}

	pthread_mutex_lock(&consumer_data->pid_mutex);
	if (consumer_data->pid == 0) {
		ERR("Consumerd did not start");
		pthread_mutex_unlock(&consumer_data->pid_mutex);
		goto error;
	}
	pthread_mutex_unlock(&consumer_data->pid_mutex);

	return 0;

error:
	return ret;
}

/*
 * Join consumer thread
 */
static int join_consumer_thread(struct consumer_data *consumer_data)
{
	void *status;

	/* Consumer pid must be a real one. */
	if (consumer_data->pid > 0) {
		int ret;
		ret = kill(consumer_data->pid, SIGTERM);
		if (ret) {
			PERROR("Error killing consumer daemon");
			return ret;
		}
		return pthread_join(consumer_data->thread, &status);
	} else {
		return 0;
	}
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
			} else if (stat(config.consumerd32_bin_path.value, &st) == 0) {
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
 * Setup necessary data for kernel tracer action.
 */
static int init_kernel_tracer(void)
{
	int ret;

	/* Modprobe lttng kernel modules */
	ret = modprobe_lttng_control();
	if (ret < 0) {
		goto error;
	}

	/* Open debugfs lttng */
	kernel_tracer_fd = open(module_proc_lttng, O_RDWR);
	if (kernel_tracer_fd < 0) {
		DBG("Failed to open %s", module_proc_lttng);
		goto error_open;
	}

	/* Validate kernel version */
	ret = kernel_validate_version(kernel_tracer_fd);
	if (ret < 0) {
		goto error_version;
	}

	ret = modprobe_lttng_data();
	if (ret < 0) {
		goto error_modules;
	}

	ret = kernel_supports_ring_buffer_snapshot_sample_positions(
			kernel_tracer_fd);
	if (ret < 0) {
		goto error_modules;
	}

	if (ret < 1) {
		WARN("Kernel tracer does not support buffer monitoring. "
			"The monitoring timer of channels in the kernel domain "
			"will be set to 0 (disabled).");
	}

	DBG("Kernel tracer fd %d", kernel_tracer_fd);
	return 0;

error_version:
	modprobe_remove_lttng_control();
	ret = close(kernel_tracer_fd);
	if (ret) {
		PERROR("close");
	}
	kernel_tracer_fd = -1;
	return LTTNG_ERR_KERN_VERSION;

error_modules:
	ret = close(kernel_tracer_fd);
	if (ret) {
		PERROR("close");
	}

error_open:
	modprobe_remove_lttng_control();

error:
	WARN("No kernel tracer available");
	kernel_tracer_fd = -1;
	if (!is_root) {
		return LTTNG_ERR_NEED_ROOT_SESSIOND;
	} else {
		return LTTNG_ERR_KERN_NA;
	}
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
	strncat(consumer->subdir, dir_name,
			sizeof(consumer->subdir) - strlen(consumer->subdir) - 1);
	DBG3("Copy session consumer subdir %s", consumer->subdir);

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
		goto error;
	}

	/* Code flow safety */
	assert(session->kernel_session);

	/* Copy session output to the newly created Kernel session */
	ret = copy_session_consumer(LTTNG_DOMAIN_KERNEL, session);
	if (ret != LTTNG_OK) {
		goto error;
	}

	/* Create directory(ies) on local filesystem. */
	if (session->kernel_session->consumer->type == CONSUMER_DST_LOCAL &&
			strlen(session->kernel_session->consumer->dst.trace_path) > 0) {
		ret = run_as_mkdir_recursive(
				session->kernel_session->consumer->dst.trace_path,
				S_IRWXU | S_IRWXG, session->uid, session->gid);
		if (ret < 0) {
			if (errno != EEXIST) {
				ERR("Trace directory creation error");
				goto error;
			}
		}
	}

	session->kernel_session->uid = session->uid;
	session->kernel_session->gid = session->gid;
	session->kernel_session->output_traces = session->output_traces;
	session->kernel_session->snapshot_mode = session->snapshot_mode;

	return LTTNG_OK;

error:
	trace_kernel_destroy_session(session->kernel_session);
	session->kernel_session = NULL;
	return ret;
}

/*
 * Count number of session permitted by uid/gid.
 */
static unsigned int lttng_sessions_count(uid_t uid, gid_t gid)
{
	unsigned int i = 0;
	struct ltt_session *session;

	DBG("Counting number of available session for UID %d GID %d",
			uid, gid);
	cds_list_for_each_entry(session, &session_list_ptr->head, list) {
		/*
		 * Only list the sessions the user can control.
		 */
		if (!session_access_ok(session, uid, gid)) {
			continue;
		}
		i++;
	}
	return i;
}

/*
 * Process the command requested by the lttng client within the command
 * context structure. This function make sure that the return structure (llm)
 * is set and ready for transmission before returning.
 *
 * Return any error encountered or 0 for success.
 *
 * "sock" is only used for special-case var. len data.
 *
 * Should *NOT* be called with RCU read-side lock held.
 */
static int process_client_msg(struct command_ctx *cmd_ctx, int sock,
		int *sock_error)
{
	int ret = LTTNG_OK;
	int need_tracing_session = 1;
	int need_domain;

	DBG("Processing client command %d", cmd_ctx->lsm->cmd_type);

	assert(!rcu_read_ongoing());

	*sock_error = 0;

	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_CREATE_SESSION:
	case LTTNG_CREATE_SESSION_SNAPSHOT:
	case LTTNG_CREATE_SESSION_LIVE:
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
	case LTTNG_CREATE_SESSION:
	case LTTNG_CREATE_SESSION_SNAPSHOT:
	case LTTNG_CREATE_SESSION_LIVE:
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

		/* Kernel tracer check */
		if (kernel_tracer_fd == -1) {
			/* Basically, load kernel tracer modules */
			ret = init_kernel_tracer();
			if (ret != 0) {
				goto error;
			}
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
				if (ret < 0) {
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
			 * Setup socket for consumer 64 bit. No need for atomic access
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
				LTTNG_SOCK_GET_GID_CRED(&cmd_ctx->creds))) {
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

			ret = lttcomm_recv_unix_sock(sock, provider_name,
					provider_name_len);
			if (ret < 0) {
				goto error_add_context;
			}

			ret = lttcomm_recv_unix_sock(sock, context_name,
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
				ret = lttcomm_recv_unix_sock(sock, data,
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
			ret = lttcomm_recv_unix_sock(sock, exclusion->names,
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
			ret = lttcomm_recv_unix_sock(sock, filter_expression,
				expression_len);
			if (ret <= 0) {
				DBG("Nothing recv() from client car len data... continuing");
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
			ret = lttcomm_recv_unix_sock(sock, bytecode, bytecode_len);
			if (ret <= 0) {
				DBG("Nothing recv() from client car len data... continuing");
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

		ret = cmd_enable_event(cmd_ctx->session, &cmd_ctx->lsm->domain,
				cmd_ctx->lsm->u.enable.channel_name,
				&cmd_ctx->lsm->u.enable.event,
				filter_expression, bytecode, exclusion,
				kernel_poll_pipe[1]);
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
		ret = lttcomm_recv_unix_sock(sock, uris, len);
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
		ret = cmd_start_trace(cmd_ctx->session);
		break;
	}
	case LTTNG_STOP_TRACE:
	{
		ret = cmd_stop_trace(cmd_ctx->session);
		break;
	}
	case LTTNG_CREATE_SESSION:
	{
		size_t nb_uri, len;
		struct lttng_uri *uris = NULL;

		nb_uri = cmd_ctx->lsm->u.uri.size;
		len = nb_uri * sizeof(struct lttng_uri);

		if (nb_uri > 0) {
			uris = zmalloc(len);
			if (uris == NULL) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}

			/* Receive variable len data */
			DBG("Waiting for %zu URIs from client ...", nb_uri);
			ret = lttcomm_recv_unix_sock(sock, uris, len);
			if (ret <= 0) {
				DBG("No URIs received from client... continuing");
				*sock_error = 1;
				ret = LTTNG_ERR_SESSION_FAIL;
				free(uris);
				goto error;
			}

			if (nb_uri == 1 && uris[0].dtype != LTTNG_DST_PATH) {
				DBG("Creating session with ONE network URI is a bad call");
				ret = LTTNG_ERR_SESSION_FAIL;
				free(uris);
				goto error;
			}
		}

		ret = cmd_create_session_uri(cmd_ctx->lsm->session.name, uris, nb_uri,
			&cmd_ctx->creds, 0);

		free(uris);

		break;
	}
	case LTTNG_DESTROY_SESSION:
	{
		ret = cmd_destroy_session(cmd_ctx->session, kernel_poll_pipe[1]);

		/* Set session to NULL so we do not unlock it after free. */
		cmd_ctx->session = NULL;
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
		payload_len = sizeof(struct lttng_session) * nr_sessions;
		sessions_payload = zmalloc(payload_len);

		if (!sessions_payload) {
			session_unlock_list();
			ret = -ENOMEM;
			goto setup_error;
		}

		cmd_list_lttng_sessions(sessions_payload,
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
	case LTTNG_CREATE_SESSION_SNAPSHOT:
	{
		size_t nb_uri, len;
		struct lttng_uri *uris = NULL;

		nb_uri = cmd_ctx->lsm->u.uri.size;
		len = nb_uri * sizeof(struct lttng_uri);

		if (nb_uri > 0) {
			uris = zmalloc(len);
			if (uris == NULL) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}

			/* Receive variable len data */
			DBG("Waiting for %zu URIs from client ...", nb_uri);
			ret = lttcomm_recv_unix_sock(sock, uris, len);
			if (ret <= 0) {
				DBG("No URIs received from client... continuing");
				*sock_error = 1;
				ret = LTTNG_ERR_SESSION_FAIL;
				free(uris);
				goto error;
			}

			if (nb_uri == 1 && uris[0].dtype != LTTNG_DST_PATH) {
				DBG("Creating session with ONE network URI is a bad call");
				ret = LTTNG_ERR_SESSION_FAIL;
				free(uris);
				goto error;
			}
		}

		ret = cmd_create_session_snapshot(cmd_ctx->lsm->session.name, uris,
				nb_uri, &cmd_ctx->creds);
		free(uris);
		break;
	}
	case LTTNG_CREATE_SESSION_LIVE:
	{
		size_t nb_uri, len;
		struct lttng_uri *uris = NULL;

		nb_uri = cmd_ctx->lsm->u.uri.size;
		len = nb_uri * sizeof(struct lttng_uri);

		if (nb_uri > 0) {
			uris = zmalloc(len);
			if (uris == NULL) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}

			/* Receive variable len data */
			DBG("Waiting for %zu URIs from client ...", nb_uri);
			ret = lttcomm_recv_unix_sock(sock, uris, len);
			if (ret <= 0) {
				DBG("No URIs received from client... continuing");
				*sock_error = 1;
				ret = LTTNG_ERR_SESSION_FAIL;
				free(uris);
				goto error;
			}

			if (nb_uri == 1 && uris[0].dtype != LTTNG_DST_PATH) {
				DBG("Creating session with ONE network URI is a bad call");
				ret = LTTNG_ERR_SESSION_FAIL;
				free(uris);
				goto error;
			}
		}

		ret = cmd_create_session_uri(cmd_ctx->lsm->session.name, uris,
				nb_uri, &cmd_ctx->creds, cmd_ctx->lsm->u.session_live.timer_interval);
		free(uris);
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
		ret = cmd_register_trigger(cmd_ctx, sock,
				notification_thread_handle);
		break;
	}
	case LTTNG_UNREGISTER_TRIGGER:
	{
		ret = cmd_unregister_trigger(cmd_ctx, sock,
				notification_thread_handle);
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
	}
	if (need_tracing_session) {
		session_unlock_list();
	}
init_setup_error:
	assert(!rcu_read_ongoing());
	return ret;
}

/*
 * Thread managing health check socket.
 */
static void *thread_manage_health(void *data)
{
	int sock = -1, new_sock = -1, ret, i, pollfd, err = -1;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	struct health_comm_msg msg;
	struct health_comm_reply reply;

	DBG("[thread] Manage health check started");

	rcu_register_thread();

	/* We might hit an error path before this is created. */
	lttng_poll_init(&events);

	/* Create unix socket */
	sock = lttcomm_create_unix_sock(config.health_unix_sock_path.value);
	if (sock < 0) {
		ERR("Unable to create health check Unix socket");
		goto error;
	}

	if (is_root) {
		/* lttng health client socket path permissions */
		ret = chown(config.health_unix_sock_path.value, 0,
				utils_get_group_id(config.tracing_group_name.value));
		if (ret < 0) {
			ERR("Unable to set group on %s", config.health_unix_sock_path.value);
			PERROR("chown");
			goto error;
		}

		ret = chmod(config.health_unix_sock_path.value,
				S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
		if (ret < 0) {
			ERR("Unable to set permissions on %s", config.health_unix_sock_path.value);
			PERROR("chmod");
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

	/*
	 * Pass 2 as size here for the thread quit pipe and client_sock. Nothing
	 * more will be added to this poll set.
	 */
	ret = sessiond_set_thread_pollset(&events, 2);
	if (ret < 0) {
		goto error;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, sock, LPOLLIN | LPOLLPRI);
	if (ret < 0) {
		goto error;
	}

	sessiond_notify_ready();

	while (1) {
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
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			/* Thread quit pipe has been closed. Killing thread. */
			ret = sessiond_check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Event on the registration socket */
			if (pollfd == sock) {
				if (revents & LPOLLIN) {
					continue;
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Health socket poll error");
					goto error;
				} else {
					ERR("Unexpected poll events %u for sock %d", revents, pollfd);
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
		ret = lttcomm_recv_unix_sock(new_sock, (void *)&msg, sizeof(msg));
		if (ret <= 0) {
			DBG("Nothing recv() from client... continuing");
			ret = close(new_sock);
			if (ret) {
				PERROR("close");
			}
			continue;
		}

		rcu_thread_online();

		memset(&reply, 0, sizeof(reply));
		for (i = 0; i < NR_HEALTH_SESSIOND_TYPES; i++) {
			/*
			 * health_check_state returns 0 if health is
			 * bad.
			 */
			if (!health_check_state(health_sessiond, i)) {
				reply.ret_code |= 1ULL << i;
			}
		}

		DBG2("Health check return value %" PRIx64, reply.ret_code);

		ret = send_unix_sock(new_sock, (void *) &reply, sizeof(reply));
		if (ret < 0) {
			ERR("Failed to send health data back to client");
		}

		/* End of transmission */
		ret = close(new_sock);
		if (ret) {
			PERROR("close");
		}
	}

exit:
error:
	if (err) {
		ERR("Health error occurred in %s", __func__);
	}
	DBG("Health check thread dying");
	unlink(config.health_unix_sock_path.value);
	if (sock >= 0) {
		ret = close(sock);
		if (ret) {
			PERROR("close");
		}
	}

	lttng_poll_clean(&events);
	stop_threads();
	rcu_unregister_thread();
	return NULL;
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

	DBG("[thread] Manage client started");

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
	ret = sessiond_set_thread_pollset(&events, 2);
	if (ret < 0) {
		goto error_create_poll;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, client_sock, LPOLLIN | LPOLLPRI);
	if (ret < 0) {
		goto error;
	}

	sessiond_notify_ready();
	ret = sem_post(&load_info->message_thread_ready);
	if (ret) {
		PERROR("sem_post message_thread_ready");
		goto error;
	}

	/* This testpoint is after we signal readiness to the parent. */
	if (testpoint(sessiond_thread_manage_clients)) {
		goto error;
	}

	if (testpoint(sessiond_thread_manage_clients_before_loop)) {
		goto error;
	}

	health_code_update();

	while (1) {
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
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			health_code_update();

			if (!revents) {
				/* No activity for this FD (poll implementation). */
				continue;
			}

			/* Thread quit pipe has been closed. Killing thread. */
			ret = sessiond_check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				err = 0;
				goto exit;
			}

			/* Event on the registration socket */
			if (pollfd == client_sock) {
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
		ret = process_client_msg(cmd_ctx, sock, &sock_error);
		rcu_thread_offline();
		if (ret < 0) {
			ret = close(sock);
			if (ret) {
				PERROR("close");
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

		health_code_update();

		DBG("Sending response (size: %d, retcode: %s (%d))",
				cmd_ctx->lttng_msg_size,
				lttng_strerror(-cmd_ctx->llm->ret_code),
				cmd_ctx->llm->ret_code);
		ret = send_unix_sock(sock, cmd_ctx->llm, cmd_ctx->lttng_msg_size);
		if (ret < 0) {
			ERR("Failed to send data back to client");
		}

		/* End of transmission */
		ret = close(sock);
		if (ret) {
			PERROR("close");
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

	/*
	 * Since we are creating the consumer threads, we own them, so we need
	 * to join them before our thread exits.
	 */
	ret = join_consumer_thread(&kconsumer_data);
	if (ret) {
		errno = ret;
		PERROR("join_consumer");
	}

	ret = join_consumer_thread(&ustconsumer32_data);
	if (ret) {
		errno = ret;
		PERROR("join_consumer ust32");
	}

	ret = join_consumer_thread(&ustconsumer64_data);
	if (ret) {
		errno = ret;
		PERROR("join_consumer ust64");
	}
	return NULL;
}

static int string_match(const char *str1, const char *str2)
{
	return (str1 && str2) && !strcmp(str1, str2);
}

/*
 * Take an option from the getopt output and set it in the right variable to be
 * used later.
 *
 * Return 0 on success else a negative value.
 */
static int set_option(int opt, const char *arg, const char *optname)
{
	int ret = 0;

	if (string_match(optname, "client-sock") || opt == 'c') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-c, --client-sock");
		} else {
			config_string_set(&config.client_unix_sock_path,
					strdup(arg));
			if (!config.client_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "apps-sock") || opt == 'a') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-a, --apps-sock");
		} else {
			config_string_set(&config.apps_unix_sock_path,
					strdup(arg));
			if (!config.apps_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "daemonize") || opt == 'd') {
		config.daemonize = true;
	} else if (string_match(optname, "background") || opt == 'b') {
		config.background = true;
	} else if (string_match(optname, "group") || opt == 'g') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-g, --group");
		} else {
			config_string_set(&config.tracing_group_name,
					strdup(arg));
			if (!config.tracing_group_name.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "help") || opt == 'h') {
		ret = utils_show_help(8, "lttng-sessiond", help_msg);
		if (ret) {
			ERR("Cannot show --help for `lttng-sessiond`");
			perror("exec");
		}
		exit(ret ? EXIT_FAILURE : EXIT_SUCCESS);
	} else if (string_match(optname, "version") || opt == 'V') {
		fprintf(stdout, "%s\n", VERSION);
		exit(EXIT_SUCCESS);
	} else if (string_match(optname, "sig-parent") || opt == 'S') {
		config.sig_parent = true;
	} else if (string_match(optname, "kconsumerd-err-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--kconsumerd-err-sock");
		} else {
			config_string_set(&config.kconsumerd_err_unix_sock_path,
					strdup(arg));
			if (!config.kconsumerd_err_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "kconsumerd-cmd-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--kconsumerd-cmd-sock");
		} else {
			config_string_set(&config.kconsumerd_cmd_unix_sock_path,
					strdup(arg));
			if (!config.kconsumerd_cmd_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "ustconsumerd64-err-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--ustconsumerd64-err-sock");
		} else {
			config_string_set(&config.consumerd64_err_unix_sock_path,
					strdup(arg));
			if (!config.consumerd64_err_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "ustconsumerd64-cmd-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--ustconsumerd64-cmd-sock");
		} else {
			config_string_set(&config.consumerd64_cmd_unix_sock_path,
					strdup(arg));
			if (!config.consumerd64_cmd_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "ustconsumerd32-err-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--ustconsumerd32-err-sock");
		} else {
			config_string_set(&config.consumerd32_err_unix_sock_path,
					strdup(arg));
			if (!config.consumerd32_err_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "ustconsumerd32-cmd-sock")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--ustconsumerd32-cmd-sock");
		} else {
			config_string_set(&config.consumerd32_cmd_unix_sock_path,
					strdup(arg));
			if (!config.consumerd32_cmd_unix_sock_path.value) {
				ret = -ENOMEM;
				PERROR("strdup");
			}
		}
	} else if (string_match(optname, "no-kernel")) {
		config.no_kernel = true;
	} else if (string_match(optname, "quiet") || opt == 'q') {
		lttng_opt_quiet = true;
	} else if (string_match(optname, "verbose") || opt == 'v') {
		/* Verbose level can increase using multiple -v */
		if (arg) {
			/* Value obtained from config file */
			config.verbose = config_parse_value(arg);
		} else {
			/* -v used on command line */
			config.verbose++;
		}
		/* Clamp value to [0, 3] */
		config.verbose = config.verbose < 0 ? 0 :
			(config.verbose <= 3 ? config.verbose : 3);
	} else if (string_match(optname, "verbose-consumer")) {
		if (arg) {
			config.verbose_consumer = config_parse_value(arg);
		} else {
			config.verbose_consumer++;
		}
	} else if (string_match(optname, "consumerd32-path")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--consumerd32-path");
		} else {
			config_string_set(&config.consumerd32_bin_path,
					strdup(arg));
			if (!config.consumerd32_bin_path.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "consumerd32-libdir")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--consumerd32-libdir");
		} else {
			config_string_set(&config.consumerd32_lib_dir,
					strdup(arg));
			if (!config.consumerd32_lib_dir.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "consumerd64-path")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--consumerd64-path");
		} else {
			config_string_set(&config.consumerd64_bin_path,
					strdup(arg));
			if (!config.consumerd64_bin_path.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "consumerd64-libdir")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--consumerd64-libdir");
		} else {
			config_string_set(&config.consumerd64_lib_dir,
					strdup(arg));
			if (!config.consumerd64_lib_dir.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "pidfile") || opt == 'p') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-p, --pidfile");
		} else {
			config_string_set(&config.pid_file_path, strdup(arg));
			if (!config.pid_file_path.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "agent-tcp-port")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--agent-tcp-port");
		} else {
			unsigned long v;

			errno = 0;
			v = strtoul(arg, NULL, 0);
			if (errno != 0 || !isdigit(arg[0])) {
				ERR("Wrong value in --agent-tcp-port parameter: %s", arg);
				return -1;
			}
			if (v == 0 || v >= 65535) {
				ERR("Port overflow in --agent-tcp-port parameter: %s", arg);
				return -1;
			}
			config.agent_tcp_port = (uint32_t) v;
			DBG3("Agent TCP port set to non default: %u", config.agent_tcp_port);
		}
	} else if (string_match(optname, "load") || opt == 'l') {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-l, --load");
		} else {
		        config_string_set(&config.load_session_path, strdup(arg));
			if (!config.load_session_path.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "kmod-probes")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--kmod-probes");
		} else {
			config_string_set(&config.kmod_probes_list, strdup(arg));
			if (!config.kmod_probes_list.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "extra-kmod-probes")) {
		if (!arg || *arg == '\0') {
			ret = -EINVAL;
			goto end;
		}
		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"--extra-kmod-probes");
		} else {
			config_string_set(&config.kmod_extra_probes_list,
					strdup(arg));
			if (!config.kmod_extra_probes_list.value) {
				PERROR("strdup");
				ret = -ENOMEM;
			}
		}
	} else if (string_match(optname, "config") || opt == 'f') {
		/* This is handled in set_options() thus silent skip. */
		goto end;
	} else {
		/* Unknown option or other error.
		 * Error is printed by getopt, just return */
		ret = -1;
	}

end:
	if (ret == -EINVAL) {
		const char *opt_name = "unknown";
		int i;

		for (i = 0; i < sizeof(long_options) / sizeof(struct option);
			i++) {
			if (opt == long_options[i].val) {
				opt_name = long_options[i].name;
				break;
			}
		}

		WARN("Invalid argument provided for option \"%s\", using default value.",
			opt_name);
	}

	return ret;
}

/*
 * config_entry_handler_cb used to handle options read from a config file.
 * See config_entry_handler_cb comment in common/config/session-config.h for the
 * return value conventions.
 */
static int config_entry_handler(const struct config_entry *entry, void *unused)
{
	int ret = 0, i;

	if (!entry || !entry->name || !entry->value) {
		ret = -EINVAL;
		goto end;
	}

	/* Check if the option is to be ignored */
	for (i = 0; i < sizeof(config_ignore_options) / sizeof(char *); i++) {
		if (!strcmp(entry->name, config_ignore_options[i])) {
			goto end;
		}
	}

	for (i = 0; i < (sizeof(long_options) / sizeof(struct option)) - 1;
		i++) {

		/* Ignore if not fully matched. */
		if (strcmp(entry->name, long_options[i].name)) {
			continue;
		}

		/*
		 * If the option takes no argument on the command line, we have to
		 * check if the value is "true". We support non-zero numeric values,
		 * true, on and yes.
		 */
		if (!long_options[i].has_arg) {
			ret = config_parse_value(entry->value);
			if (ret <= 0) {
				if (ret) {
					WARN("Invalid configuration value \"%s\" for option %s",
							entry->value, entry->name);
				}
				/* False, skip boolean config option. */
				goto end;
			}
		}

		ret = set_option(long_options[i].val, entry->value, entry->name);
		goto end;
	}

	WARN("Unrecognized option \"%s\" in daemon configuration file.", entry->name);

end:
	return ret;
}

/*
 * daemon configuration loading and argument parsing
 */
static int set_options(int argc, char **argv)
{
	int ret = 0, c = 0, option_index = 0;
	int orig_optopt = optopt, orig_optind = optind;
	char *optstring;
	const char *config_path = NULL;

	optstring = utils_generate_optstring(long_options,
			sizeof(long_options) / sizeof(struct option));
	if (!optstring) {
		ret = -ENOMEM;
		goto end;
	}

	/* Check for the --config option */
	while ((c = getopt_long(argc, argv, optstring, long_options,
					&option_index)) != -1) {
		if (c == '?') {
			ret = -EINVAL;
			goto end;
		} else if (c != 'f') {
			/* if not equal to --config option. */
			continue;
		}

		if (lttng_is_setuid_setgid()) {
			WARN("Getting '%s' argument from setuid/setgid binary refused for security reasons.",
				"-f, --config");
		} else {
			config_path = utils_expand_path(optarg);
			if (!config_path) {
				ERR("Failed to resolve path: %s", optarg);
			}
		}
	}

	ret = config_get_section_entries(config_path, config_section_name,
			config_entry_handler, NULL);
	if (ret) {
		if (ret > 0) {
			ERR("Invalid configuration option at line %i", ret);
			ret = -1;
		}
		goto end;
	}

	/* Reset getopt's global state */
	optopt = orig_optopt;
	optind = orig_optind;
	while (1) {
		option_index = -1;
		/*
		 * getopt_long() will not set option_index if it encounters a
		 * short option.
		 */
		c = getopt_long(argc, argv, optstring, long_options,
				&option_index);
		if (c == -1) {
			break;
		}

		/*
		 * Pass NULL as the long option name if popt left the index
		 * unset.
		 */
		ret = set_option(c, optarg,
				option_index < 0 ? NULL :
				long_options[option_index].name);
		if (ret < 0) {
			break;
		}
	}

end:
	free(optstring);
	return ret;
}

/*
 * Creates the two needed socket by the daemon.
 * 	    apps_sock - The communication socket for all UST apps.
 * 	    client_sock - The communication of the cli tool (lttng).
 */
static int init_daemon_socket(void)
{
	int ret = 0;
	mode_t old_umask;

	old_umask = umask(0);

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

	/* Create the application unix socket */
	apps_sock = lttcomm_create_unix_sock(config.apps_unix_sock_path.value);
	if (apps_sock < 0) {
		ERR("Create unix sock failed: %s", config.apps_unix_sock_path.value);
		ret = -1;
		goto end;
	}

	/* Set the cloexec flag */
	ret = utils_set_fd_cloexec(apps_sock);
	if (ret < 0) {
		ERR("Unable to set CLOEXEC flag to the app Unix socket (fd: %d). "
				"Continuing but note that the consumer daemon will have a "
				"reference to this socket on exec()", apps_sock);
	}

	/* File permission MUST be 666 */
	ret = chmod(config.apps_unix_sock_path.value,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", config.apps_unix_sock_path.value);
		PERROR("chmod");
		goto end;
	}

	DBG3("Session daemon client socket %d and application socket %d created",
			client_sock, apps_sock);

end:
	umask(old_umask);
	return ret;
}

/*
 * Check if the global socket is available, and if a daemon is answering at the
 * other side. If yes, error is returned.
 */
static int check_existing_daemon(void)
{
	/* Is there anybody out there ? */
	if (lttng_session_daemon_alive()) {
		return -EEXIST;
	}

	return 0;
}

/*
 * Set the tracing group gid onto the client socket.
 *
 * Race window between mkdir and chown is OK because we are going from more
 * permissive (root.root) to less permissive (root.tracing).
 */
static int set_permissions(char *rundir)
{
	int ret;
	gid_t gid;

	gid = utils_get_group_id(config.tracing_group_name.value);

	/* Set lttng run dir */
	ret = chown(rundir, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", rundir);
		PERROR("chown");
	}

	/*
	 * Ensure all applications and tracing group can search the run
	 * dir. Allow everyone to read the directory, since it does not
	 * buy us anything to hide its content.
	 */
	ret = chmod(rundir, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	if (ret < 0) {
		ERR("Unable to set permissions on %s", rundir);
		PERROR("chmod");
	}

	/* lttng client socket path */
	ret = chown(config.client_unix_sock_path.value, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", config.client_unix_sock_path.value);
		PERROR("chown");
	}

	/* kconsumer error socket path */
	ret = chown(kconsumer_data.err_unix_sock_path, 0, 0);
	if (ret < 0) {
		ERR("Unable to set group on %s", kconsumer_data.err_unix_sock_path);
		PERROR("chown");
	}

	/* 64-bit ustconsumer error socket path */
	ret = chown(ustconsumer64_data.err_unix_sock_path, 0, 0);
	if (ret < 0) {
		ERR("Unable to set group on %s", ustconsumer64_data.err_unix_sock_path);
		PERROR("chown");
	}

	/* 32-bit ustconsumer compat32 error socket path */
	ret = chown(ustconsumer32_data.err_unix_sock_path, 0, 0);
	if (ret < 0) {
		ERR("Unable to set group on %s", ustconsumer32_data.err_unix_sock_path);
		PERROR("chown");
	}

	DBG("All permissions are set");

	return ret;
}

/*
 * Create the lttng run directory needed for all global sockets and pipe.
 */
static int create_lttng_rundir(void)
{
	int ret;

	DBG3("Creating LTTng run directory: %s", config.rundir.value);

	ret = mkdir(config.rundir.value, S_IRWXU);
	if (ret < 0) {
		if (errno != EEXIST) {
			ERR("Unable to create %s", config.rundir.value);
			goto error;
		} else {
			ret = 0;
		}
	}

error:
	return ret;
}

/*
 * Setup sockets and directory needed by the consumerds' communication with the
 * session daemon.
 */
static int set_consumer_sockets(struct consumer_data *consumer_data)
{
	int ret;
	char *path = NULL;

	switch (consumer_data->type) {
	case LTTNG_CONSUMER_KERNEL:
		path = config.kconsumerd_path.value;
		break;
	case LTTNG_CONSUMER64_UST:
		path = config.consumerd64_path.value;
		break;
	case LTTNG_CONSUMER32_UST:
		path = config.consumerd32_path.value;
		break;
	default:
		ERR("Consumer type unknown");
		ret = -EINVAL;
		goto error;
	}
	assert(path);

	DBG2("Creating consumer directory: %s", path);

	ret = mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP);
	if (ret < 0 && errno != EEXIST) {
		PERROR("mkdir");
		ERR("Failed to create %s", path);
		goto error;
	}
	if (is_root) {
		ret = chown(path, 0, utils_get_group_id(config.tracing_group_name.value));
		if (ret < 0) {
			ERR("Unable to set group on %s", path);
			PERROR("chown");
			goto error;
		}
	}

	/* Create the consumerd error unix socket */
	consumer_data->err_sock =
		lttcomm_create_unix_sock(consumer_data->err_unix_sock_path);
	if (consumer_data->err_sock < 0) {
		ERR("Create unix sock failed: %s", consumer_data->err_unix_sock_path);
		ret = -1;
		goto error;
	}

	/*
	 * Set the CLOEXEC flag. Return code is useless because either way, the
	 * show must go on.
	 */
	ret = utils_set_fd_cloexec(consumer_data->err_sock);
	if (ret < 0) {
		PERROR("utils_set_fd_cloexec");
		/* continue anyway */
	}

	/* File permission MUST be 660 */
	ret = chmod(consumer_data->err_unix_sock_path,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", consumer_data->err_unix_sock_path);
		PERROR("chmod");
		goto error;
	}

error:
	return ret;
}

/*
 * Signal handler for the daemon
 *
 * Simply stop all worker threads, leaving main() return gracefully after
 * joining all threads and calling cleanup().
 */
static void sighandler(int sig)
{
	switch (sig) {
	case SIGINT:
		DBG("SIGINT caught");
		stop_threads();
		break;
	case SIGTERM:
		DBG("SIGTERM caught");
		stop_threads();
		break;
	case SIGUSR1:
		CMM_STORE_SHARED(recv_child_signal, 1);
		break;
	default:
		break;
	}
}

/*
 * Setup signal handler for :
 *		SIGINT, SIGTERM, SIGPIPE
 */
static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		PERROR("sigemptyset");
		return ret;
	}

	sa.sa_mask = sigset;
	sa.sa_flags = 0;

	sa.sa_handler = sighandler;
	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGUSR1, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	sa.sa_handler = SIG_IGN;
	if ((ret = sigaction(SIGPIPE, &sa, NULL)) < 0) {
		PERROR("sigaction");
		return ret;
	}

	DBG("Signal handler set for SIGTERM, SIGUSR1, SIGPIPE and SIGINT");

	return ret;
}

/*
 * Set open files limit to unlimited. This daemon can open a large number of
 * file descriptors in order to consume multiple kernel traces.
 */
static void set_ulimit(void)
{
	int ret;
	struct rlimit lim;

	/* The kernel does not allow an infinite limit for open files */
	lim.rlim_cur = 65535;
	lim.rlim_max = 65535;

	ret = setrlimit(RLIMIT_NOFILE, &lim);
	if (ret < 0) {
		PERROR("failed to set open files limit");
	}
}

static int write_pidfile(void)
{
        return utils_create_pid_file(getpid(), config.pid_file_path.value);
}

/*
 * Create lockfile using the rundir and return its fd.
 */
static int create_lockfile(void)
{
        return utils_create_lock_file(config.lock_file_path.value);
}

/*
 * Write agent TCP port using the rundir.
 */
static int write_agent_port(void)
{
	return utils_create_pid_file(config.agent_tcp_port,
			config.agent_port_file_path.value);
}

static int set_clock_plugin_env(void)
{
	int ret = 0;
	char *env_value = NULL;

	if (!config.lttng_ust_clock_plugin.value) {
		goto end;
	}

        ret = asprintf(&env_value, "LTTNG_UST_CLOCK_PLUGIN=%s",
			config.lttng_ust_clock_plugin.value);
	if (ret < 0) {
		PERROR("asprintf");
		goto end;
	}

	ret = putenv(env_value);
	if (ret) {
		free(env_value);
		PERROR("putenv of LTTNG_UST_CLOCK_PLUGIN");
		goto end;
	}

	DBG("Updated LTTNG_UST_CLOCK_PLUGIN environment variable to \"%s\"",
			config.lttng_ust_clock_plugin.value);
end:
	return ret;
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int ret = 0, retval = 0;
	void *status;
	const char *env_app_timeout;
	struct lttng_pipe *ust32_channel_monitor_pipe = NULL,
			*ust64_channel_monitor_pipe = NULL,
			*kernel_channel_monitor_pipe = NULL;
	bool notification_thread_running = false;

	init_kernel_workarounds();

	rcu_register_thread();

	if (set_signal_handler()) {
		retval = -1;
		goto exit_set_signal_handler;
	}

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		PERROR("sysconf _SC_PAGESIZE");
		page_size = LONG_MAX;
		WARN("Fallback page size to %ld", page_size);
	}

	ret = sessiond_config_init(&config);
	if (ret) {
		retval = -1;
		goto exit_set_signal_handler;
	}

	/*
	 * Parse arguments and load the daemon configuration file.
	 *
	 * We have an exit_options exit path to free memory reserved by
	 * set_options. This is needed because the rest of sessiond_cleanup()
	 * depends on ht_cleanup_thread, which depends on lttng_daemonize, which
	 * depends on set_options.
	 */
	progname = argv[0];
	if (set_options(argc, argv)) {
		retval = -1;
		goto exit_options;
	}

	/* Init config from environment variables. */
	sessiond_config_apply_env_config(&config);

	/*
	 * Resolve all paths received as arguments, configuration option, or
	 * through environment variable as absolute paths. This is necessary
	 * since daemonizing causes the sessiond's current working directory
	 * to '/'.
	 */
	ret = sessiond_config_resolve_paths(&config);
	if (ret) {
		goto exit_options;
	}

	/* Apply config. */
	lttng_opt_verbose = config.verbose;
	lttng_opt_quiet = config.quiet;
	kconsumer_data.err_unix_sock_path =
			config.kconsumerd_err_unix_sock_path.value;
	kconsumer_data.cmd_unix_sock_path =
			config.kconsumerd_cmd_unix_sock_path.value;
	ustconsumer32_data.err_unix_sock_path =
			config.consumerd32_err_unix_sock_path.value;
	ustconsumer32_data.cmd_unix_sock_path =
			config.consumerd32_cmd_unix_sock_path.value;
	ustconsumer64_data.err_unix_sock_path =
			config.consumerd64_err_unix_sock_path.value;
	ustconsumer64_data.cmd_unix_sock_path =
			config.consumerd64_cmd_unix_sock_path.value;
	set_clock_plugin_env();

	sessiond_config_log(&config);

	/* Daemonize */
	if (config.daemonize || config.background) {
		int i;

		ret = lttng_daemonize(&child_ppid, &recv_child_signal,
			!config.background);
		if (ret < 0) {
			retval = -1;
			goto exit_options;
		}

		/*
		 * We are in the child. Make sure all other file descriptors are
		 * closed, in case we are called with more opened file
		 * descriptors than the standard ones.
		 */
		for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
			(void) close(i);
		}
	}

	if (run_as_create_worker(argv[0]) < 0) {
		goto exit_create_run_as_worker_cleanup;
	}

	/*
	 * Starting from here, we can create threads. This needs to be after
	 * lttng_daemonize due to RCU.
	 */

	/*
	 * Initialize the health check subsystem. This call should set the
	 * appropriate time values.
	 */
	health_sessiond = health_app_create(NR_HEALTH_SESSIOND_TYPES);
	if (!health_sessiond) {
		PERROR("health_app_create error");
		retval = -1;
		goto exit_health_sessiond_cleanup;
	}

	/* Create thread to clean up RCU hash tables */
	if (init_ht_cleanup_thread(&ht_cleanup_thread)) {
		retval = -1;
		goto exit_ht_cleanup;
	}

	/* Create thread quit pipe */
	if (init_thread_quit_pipe()) {
		retval = -1;
		goto exit_init_data;
	}

	/* Check if daemon is UID = 0 */
	is_root = !getuid();

	if (create_lttng_rundir()) {
		retval = -1;
		goto exit_init_data;
	}

	if (is_root) {
		/* Create global run dir with root access */

		kernel_channel_monitor_pipe = lttng_pipe_open(0);
		if (!kernel_channel_monitor_pipe) {
			ERR("Failed to create kernel consumer channel monitor pipe");
			retval = -1;
			goto exit_init_data;
		}
		kconsumer_data.channel_monitor_pipe =
				lttng_pipe_release_writefd(
					kernel_channel_monitor_pipe);
		if (kconsumer_data.channel_monitor_pipe < 0) {
			retval = -1;
			goto exit_init_data;
		}
	}

	lockfile_fd = create_lockfile();
	if (lockfile_fd < 0) {
		retval = -1;
		goto exit_init_data;
	}

	/* Set consumer initial state */
	kernel_consumerd_state = CONSUMER_STOPPED;
	ust_consumerd_state = CONSUMER_STOPPED;

	ust32_channel_monitor_pipe = lttng_pipe_open(0);
	if (!ust32_channel_monitor_pipe) {
		ERR("Failed to create 32-bit user space consumer channel monitor pipe");
		retval = -1;
		goto exit_init_data;
	}
	ustconsumer32_data.channel_monitor_pipe = lttng_pipe_release_writefd(
			ust32_channel_monitor_pipe);
	if (ustconsumer32_data.channel_monitor_pipe < 0) {
		retval = -1;
		goto exit_init_data;
	}

	ust64_channel_monitor_pipe = lttng_pipe_open(0);
	if (!ust64_channel_monitor_pipe) {
		ERR("Failed to create 64-bit user space consumer channel monitor pipe");
		retval = -1;
		goto exit_init_data;
	}
	ustconsumer64_data.channel_monitor_pipe = lttng_pipe_release_writefd(
			ust64_channel_monitor_pipe);
	if (ustconsumer64_data.channel_monitor_pipe < 0) {
		retval = -1;
		goto exit_init_data;
	}

	/*
	 * See if daemon already exist.
	 */
	if (check_existing_daemon()) {
		ERR("Already running daemon.\n");
		/*
		 * We do not goto exit because we must not cleanup()
		 * because a daemon is already running.
		 */
		retval = -1;
		goto exit_init_data;
	}

	/*
	 * Init UST app hash table. Alloc hash table before this point since
	 * cleanup() can get called after that point.
	 */
	if (ust_app_ht_alloc()) {
		ERR("Failed to allocate UST app hash table");
		retval = -1;
		goto exit_init_data;
	}

	/*
	 * Initialize agent app hash table. We allocate the hash table here
	 * since cleanup() can get called after this point.
	 */
	if (agent_app_ht_alloc()) {
		ERR("Failed to allocate Agent app hash table");
		retval = -1;
		goto exit_init_data;
	}

	/*
	 * These actions must be executed as root. We do that *after* setting up
	 * the sockets path because we MUST make the check for another daemon using
	 * those paths *before* trying to set the kernel consumer sockets and init
	 * kernel tracer.
	 */
	if (is_root) {
		if (set_consumer_sockets(&kconsumer_data)) {
			retval = -1;
			goto exit_init_data;
		}

		/* Setup kernel tracer */
		if (!config.no_kernel) {
			init_kernel_tracer();
			if (kernel_tracer_fd >= 0) {
				ret = syscall_init_table();
				if (ret < 0) {
					ERR("Unable to populate syscall table. "
						"Syscall tracing won't work "
						"for this session daemon.");
				}
			}
		}

		/* Set ulimit for open files */
		set_ulimit();
	}
	/* init lttng_fd tracking must be done after set_ulimit. */
	lttng_fd_init();

	if (set_consumer_sockets(&ustconsumer64_data)) {
		retval = -1;
		goto exit_init_data;
	}

	if (set_consumer_sockets(&ustconsumer32_data)) {
		retval = -1;
		goto exit_init_data;
	}

	/* Setup the needed unix socket */
	if (init_daemon_socket()) {
		retval = -1;
		goto exit_init_data;
	}

	/* Set credentials to socket */
	if (is_root && set_permissions(config.rundir.value)) {
		retval = -1;
		goto exit_init_data;
	}

	/* Get parent pid if -S, --sig-parent is specified. */
	if (config.sig_parent) {
		ppid = getppid();
	}

	/* Setup the kernel pipe for waking up the kernel thread */
	if (is_root && !config.no_kernel) {
		if (utils_create_pipe_cloexec(kernel_poll_pipe)) {
			retval = -1;
			goto exit_init_data;
		}
	}

	/* Setup the thread apps communication pipe. */
	if (utils_create_pipe_cloexec(apps_cmd_pipe)) {
		retval = -1;
		goto exit_init_data;
	}

	/* Setup the thread apps notify communication pipe. */
	if (utils_create_pipe_cloexec(apps_cmd_notify_pipe)) {
		retval = -1;
		goto exit_init_data;
	}

	/* Initialize global buffer per UID and PID registry. */
	buffer_reg_init_uid_registry();
	buffer_reg_init_pid_registry();

	/* Init UST command queue. */
	cds_wfcq_init(&ust_cmd_queue.head, &ust_cmd_queue.tail);

	/*
	 * Get session list pointer. This pointer MUST NOT be free'd. This list
	 * is statically declared in session.c
	 */
	session_list_ptr = session_get_list();

	cmd_init();

	/* Check for the application socket timeout env variable. */
	env_app_timeout = getenv(DEFAULT_APP_SOCKET_TIMEOUT_ENV);
	if (env_app_timeout) {
		config.app_socket_timeout = atoi(env_app_timeout);
	} else {
		config.app_socket_timeout = DEFAULT_APP_SOCKET_RW_TIMEOUT;
	}

	ret = write_pidfile();
	if (ret) {
		ERR("Error in write_pidfile");
		retval = -1;
		goto exit_init_data;
	}
	ret = write_agent_port();
	if (ret) {
		ERR("Error in write_agent_port");
		retval = -1;
		goto exit_init_data;
	}

	/* Initialize communication library */
	lttcomm_init();
	/* Initialize TCP timeout values */
	lttcomm_inet_init();

	if (load_session_init_data(&load_info) < 0) {
		retval = -1;
		goto exit_init_data;
	}
	load_info->path = config.load_session_path.value;

	/* Create health-check thread. */
	ret = pthread_create(&health_thread, default_pthread_attr(),
			thread_manage_health, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create health");
		retval = -1;
		goto exit_health;
	}

	/* notification_thread_data acquires the pipes' read side. */
	notification_thread_handle = notification_thread_handle_create(
			ust32_channel_monitor_pipe,
			ust64_channel_monitor_pipe,
			kernel_channel_monitor_pipe);
	if (!notification_thread_handle) {
		retval = -1;
		ERR("Failed to create notification thread shared data");
		stop_threads();
		goto exit_notification;
	}

	/* Create notification thread. */
	ret = pthread_create(&notification_thread, default_pthread_attr(),
			thread_notification, notification_thread_handle);
	if (ret) {
		errno = ret;
		PERROR("pthread_create notification");
		retval = -1;
		stop_threads();
		goto exit_notification;
	}
	notification_thread_running = true;

	/* Create thread to manage the client socket */
	ret = pthread_create(&client_thread, default_pthread_attr(),
			thread_manage_clients, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create clients");
		retval = -1;
		stop_threads();
		goto exit_client;
	}

	/* Create thread to dispatch registration */
	ret = pthread_create(&dispatch_thread, default_pthread_attr(),
			thread_dispatch_ust_registration, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create dispatch");
		retval = -1;
		stop_threads();
		goto exit_dispatch;
	}

	/* Create thread to manage application registration. */
	ret = pthread_create(&reg_apps_thread, default_pthread_attr(),
			thread_registration_apps, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create registration");
		retval = -1;
		stop_threads();
		goto exit_reg_apps;
	}

	/* Create thread to manage application socket */
	ret = pthread_create(&apps_thread, default_pthread_attr(),
			thread_manage_apps, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create apps");
		retval = -1;
		stop_threads();
		goto exit_apps;
	}

	/* Create thread to manage application notify socket */
	ret = pthread_create(&apps_notify_thread, default_pthread_attr(),
			ust_thread_manage_notify, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create notify");
		retval = -1;
		stop_threads();
		goto exit_apps_notify;
	}

	/* Create agent registration thread. */
	ret = pthread_create(&agent_reg_thread, default_pthread_attr(),
			agent_thread_manage_registration, (void *) NULL);
	if (ret) {
		errno = ret;
		PERROR("pthread_create agent");
		retval = -1;
		stop_threads();
		goto exit_agent_reg;
	}

	/* Don't start this thread if kernel tracing is not requested nor root */
	if (is_root && !config.no_kernel) {
		/* Create kernel thread to manage kernel event */
		ret = pthread_create(&kernel_thread, default_pthread_attr(),
				thread_manage_kernel, (void *) NULL);
		if (ret) {
			errno = ret;
			PERROR("pthread_create kernel");
			retval = -1;
			stop_threads();
			goto exit_kernel;
		}
	}

	/* Create session loading thread. */
	ret = pthread_create(&load_session_thread, default_pthread_attr(),
			thread_load_session, load_info);
	if (ret) {
		errno = ret;
		PERROR("pthread_create load_session_thread");
		retval = -1;
		stop_threads();
		goto exit_load_session;
	}

	/*
	 * This is where we start awaiting program completion (e.g. through
	 * signal that asks threads to teardown).
	 */

	ret = pthread_join(load_session_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join load_session_thread");
		retval = -1;
	}
exit_load_session:

	if (is_root && !config.no_kernel) {
		ret = pthread_join(kernel_thread, &status);
		if (ret) {
			errno = ret;
			PERROR("pthread_join");
			retval = -1;
		}
	}
exit_kernel:

	ret = pthread_join(agent_reg_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join agent");
		retval = -1;
	}
exit_agent_reg:

	ret = pthread_join(apps_notify_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join apps notify");
		retval = -1;
	}
exit_apps_notify:

	ret = pthread_join(apps_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join apps");
		retval = -1;
	}
exit_apps:

	ret = pthread_join(reg_apps_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join");
		retval = -1;
	}
exit_reg_apps:

	/*
	 * Join dispatch thread after joining reg_apps_thread to ensure
	 * we don't leak applications in the queue.
	 */
	ret = pthread_join(dispatch_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join");
		retval = -1;
	}
exit_dispatch:

	ret = pthread_join(client_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join");
		retval = -1;
	}

exit_client:
exit_notification:
	ret = pthread_join(health_thread, &status);
	if (ret) {
		errno = ret;
		PERROR("pthread_join health thread");
		retval = -1;
	}

exit_health:
exit_init_data:
	/*
	 * Wait for all pending call_rcu work to complete before tearing
	 * down data structures. call_rcu worker may be trying to
	 * perform lookups in those structures.
	 */
	rcu_barrier();
	/*
	 * sessiond_cleanup() is called when no other thread is running, except
	 * the ht_cleanup thread, which is needed to destroy the hash tables.
	 */
	rcu_thread_online();
	sessiond_cleanup();

	/*
	 * Ensure all prior call_rcu are done. call_rcu callbacks may push
	 * hash tables to the ht_cleanup thread. Therefore, we ensure that
	 * the queue is empty before shutting down the clean-up thread.
	 */
	rcu_barrier();

	/*
	 * The teardown of the notification system is performed after the
	 * session daemon's teardown in order to allow it to be notified
	 * of the active session and channels at the moment of the teardown.
	 */
	if (notification_thread_handle) {
		if (notification_thread_running) {
			notification_thread_command_quit(
					notification_thread_handle);
			ret = pthread_join(notification_thread, &status);
			if (ret) {
				errno = ret;
				PERROR("pthread_join notification thread");
				retval = -1;
			}
		}
		notification_thread_handle_destroy(notification_thread_handle);
	}

	rcu_thread_offline();
	rcu_unregister_thread();

	ret = fini_ht_cleanup_thread(&ht_cleanup_thread);
	if (ret) {
		retval = -1;
	}
	lttng_pipe_destroy(ust32_channel_monitor_pipe);
	lttng_pipe_destroy(ust64_channel_monitor_pipe);
	lttng_pipe_destroy(kernel_channel_monitor_pipe);
exit_ht_cleanup:

	health_app_destroy(health_sessiond);
exit_health_sessiond_cleanup:
exit_create_run_as_worker_cleanup:

exit_options:
	sessiond_cleanup_options();

exit_set_signal_handler:
	if (!retval) {
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}
