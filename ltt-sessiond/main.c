/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <urcu/futex.h>
#include <unistd.h>
#include <config.h>

#include <lttng-consumerd.h>
#include <lttng-sessiond-comm.h>
#include <lttng/lttng-consumer.h>
#include <lttngerr.h>

#include "channel.h"
#include "compat/poll.h"
#include "context.h"
#include "event.h"
#include "futex.h"
#include "kernel-ctl.h"
#include "ltt-sessiond.h"
#include "shm.h"
#include "ust-app.h"
#include "ust-ctl.h"
#include "utils.h"
#include "ust-ctl.h"

struct consumer_data {
	enum lttng_consumer_type type;

	pthread_t thread;	/* Worker thread interacting with the consumer */
	sem_t sem;

	/* Mutex to control consumerd pid assignation */
	pthread_mutex_t pid_mutex;
	pid_t pid;

	int err_sock;
	int cmd_sock;

	/* consumer error and command Unix socket path */
	char err_unix_sock_path[PATH_MAX];
	char cmd_unix_sock_path[PATH_MAX];
};

/* Const values */
const char default_home_dir[] = DEFAULT_HOME_DIR;
const char default_tracing_group[] = LTTNG_DEFAULT_TRACING_GROUP;
const char default_ust_sock_dir[] = DEFAULT_UST_SOCK_DIR;
const char default_global_apps_pipe[] = DEFAULT_GLOBAL_APPS_PIPE;

/* Variables */
int opt_verbose;    /* Not static for lttngerr.h */
int opt_verbose_consumer;    /* Not static for lttngerr.h */
int opt_quiet;      /* Not static for lttngerr.h */

const char *progname;
const char *opt_tracing_group;
static int opt_sig_parent;
static int opt_daemon;
static int is_root;			/* Set to 1 if the daemon is running as root */
static pid_t ppid;          /* Parent PID for --sig-parent option */

/* Consumer daemon specific control data */
static struct consumer_data kconsumer_data = {
	.type = LTTNG_CONSUMER_KERNEL,
};
static struct consumer_data ustconsumer_data = {
	.type = LTTNG_CONSUMER_UST,
};

static int dispatch_thread_exit;

/* Global application Unix socket path */
static char apps_unix_sock_path[PATH_MAX];
/* Global client Unix socket path */
static char client_unix_sock_path[PATH_MAX];
/* global wait shm path for UST */
static char wait_shm_path[PATH_MAX];

/* Sockets and FDs */
static int client_sock;
static int apps_sock;
static int kernel_tracer_fd;
static int kernel_poll_pipe[2];

/*
 * Quit pipe for all threads. This permits a single cancellation point
 * for all threads when receiving an event on the pipe.
 */
static int thread_quit_pipe[2];

/*
 * This pipe is used to inform the thread managing application communication
 * that a command is queued and ready to be processed.
 */
static int apps_cmd_pipe[2];

/* Pthread, Mutexes and Semaphores */
static pthread_t apps_thread;
static pthread_t reg_apps_thread;
static pthread_t client_thread;
static pthread_t kernel_thread;
static pthread_t dispatch_thread;


/*
 * UST registration command queue. This queue is tied with a futex and uses a N
 * wakers / 1 waiter implemented and detailed in futex.c/.h
 *
 * The thread_manage_apps and thread_dispatch_ust_registration interact with
 * this queue and the wait/wake scheme.
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

/*
 * Create a poll set with O_CLOEXEC and add the thread quit pipe to the set.
 */
static int create_thread_poll_set(struct lttng_poll_event *events,
		unsigned int size)
{
	int ret;

	if (events == NULL || size == 0) {
		ret = -1;
		goto error;
	}

	ret = lttng_poll_create(events, size, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error;
	}

	/* Add quit pipe */
	ret = lttng_poll_add(events, thread_quit_pipe[0], LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 * Check if the thread quit pipe was triggered.
 *
 * Return 1 if it was triggered else 0;
 */
static int check_thread_quit_pipe(int fd, uint32_t events)
{
	if (fd == thread_quit_pipe[0] && (events & LPOLLIN)) {
		return 1;
	}

	return 0;
}

/*
 * Remove modules in reverse load order.
 */
static int modprobe_remove_kernel_modules(void)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = ARRAY_SIZE(kernel_modules_list) - 1; i >= 0; i--) {
		ret = snprintf(modprobe, sizeof(modprobe),
				"/sbin/modprobe --remove --quiet %s",
				kernel_modules_list[i].name);
		if (ret < 0) {
			perror("snprintf modprobe --remove");
			goto error;
		}
		modprobe[sizeof(modprobe) - 1] = '\0';
		ret = system(modprobe);
		if (ret == -1) {
			ERR("Unable to launch modprobe --remove for module %s",
					kernel_modules_list[i].name);
		} else if (kernel_modules_list[i].required
				&& WEXITSTATUS(ret) != 0) {
			ERR("Unable to remove module %s",
					kernel_modules_list[i].name);
		} else {
			DBG("Modprobe removal successful %s",
					kernel_modules_list[i].name);
		}
	}

error:
	return ret;
}

/*
 * Return group ID of the tracing group or -1 if not found.
 */
static gid_t allowed_group(void)
{
	struct group *grp;

	if (opt_tracing_group) {
		grp = getgrnam(opt_tracing_group);
	} else {
		grp = getgrnam(default_tracing_group);
	}
	if (!grp) {
		return -1;
	} else {
		return grp->gr_gid;
	}
}

/*
 * Init thread quit pipe.
 *
 * Return -1 on error or 0 if all pipes are created.
 */
static int init_thread_quit_pipe(void)
{
	int ret;

	ret = pipe2(thread_quit_pipe, O_CLOEXEC);
	if (ret < 0) {
		perror("thread quit pipe");
		goto error;
	}

error:
	return ret;
}

/*
 * Complete teardown of a kernel session. This free all data structure related
 * to a kernel session and update counter.
 */
static void teardown_kernel_session(struct ltt_session *session)
{
	if (session->kernel_session != NULL) {
		DBG("Tearing down kernel session");

		/*
		 * If a custom kernel consumer was registered, close the socket before
		 * tearing down the complete kernel session structure
		 */
		if (session->kernel_session->consumer_fd != kconsumer_data.cmd_sock) {
			lttcomm_close_unix_sock(session->kernel_session->consumer_fd);
		}

		trace_kernel_destroy_session(session->kernel_session);
		/* Extra precaution */
		session->kernel_session = NULL;
	}
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
	dispatch_thread_exit = 1;
	futex_nto1_wake(&ust_cmd_queue.futex);
}

/*
 * Cleanup the daemon
 */
static void cleanup(void)
{
	int ret;
	char *cmd;
	struct ltt_session *sess, *stmp;

	DBG("Cleaning up");

	/* <fun> */
	MSG("%c[%d;%dm*** assert failed *** ==> %c[%dm%c[%d;%dm"
		"Matthew, BEET driven development works!%c[%dm",
		27, 1, 31, 27, 0, 27, 1, 33, 27, 0);
	/* </fun> */

	if (is_root) {
		DBG("Removing %s directory", LTTNG_RUNDIR);
		ret = asprintf(&cmd, "rm -rf " LTTNG_RUNDIR);
		if (ret < 0) {
			ERR("asprintf failed. Something is really wrong!");
		}

		/* Remove lttng run directory */
		ret = system(cmd);
		if (ret < 0) {
			ERR("Unable to clean " LTTNG_RUNDIR);
		}
	}

	DBG("Cleaning up all session");

	/* Destroy session list mutex */
	if (session_list_ptr != NULL) {
		pthread_mutex_destroy(&session_list_ptr->lock);

		/* Cleanup ALL session */
		cds_list_for_each_entry_safe(sess, stmp,
				&session_list_ptr->head, list) {
			teardown_kernel_session(sess);
			// TODO complete session cleanup (including UST)
		}
	}

	DBG("Closing all UST sockets");
	ust_app_clean_list();

	pthread_mutex_destroy(&kconsumer_data.pid_mutex);

	DBG("Closing kernel fd");
	close(kernel_tracer_fd);

	if (is_root) {
		DBG("Unloading kernel modules");
		modprobe_remove_kernel_modules();
	}

	close(thread_quit_pipe[0]);
	close(thread_quit_pipe[1]);
}

/*
 * Send data on a unix socket using the liblttsessiondcomm API.
 *
 * Return lttcomm error code.
 */
static int send_unix_sock(int sock, void *buf, size_t len)
{
	/* Check valid length */
	if (len <= 0) {
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
 * Send all stream fds of kernel channel to the consumer.
 */
static int send_consumer_channel_streams(struct consumer_data *consumer_data,
		int sock, struct ltt_kernel_channel *channel)
{
	int ret;
	size_t nb_fd;
	struct ltt_kernel_stream *stream;
	struct lttcomm_consumer_msg lkm;

	DBG("Sending streams of channel %s to kernel consumer",
			channel->channel->name);
	nb_fd = channel->stream_count;

	/* Send channel */
	lkm.cmd_type = LTTNG_CONSUMER_ADD_CHANNEL;
	lkm.u.channel.channel_key = channel->fd;
	lkm.u.channel.max_sb_size = channel->channel->attr.subbuf_size;
	lkm.u.channel.mmap_len = 0;	/* for kernel */
	DBG("Sending channel %d to consumer", lkm.u.stream.stream_key);
	ret = lttcomm_send_unix_sock(sock, &lkm, sizeof(lkm));
	if (ret < 0) {
		perror("send consumer channel");
		goto error;
	}

	/* Send streams */
	cds_list_for_each_entry(stream, &channel->stream_list.head, list) {
		if (!stream->fd) {
			continue;
		}
		lkm.cmd_type = LTTNG_CONSUMER_ADD_STREAM;
		lkm.u.stream.channel_key = channel->fd;
		lkm.u.stream.stream_key = stream->fd;
		lkm.u.stream.state = stream->state;
		lkm.u.stream.output = channel->channel->attr.output;
		lkm.u.stream.mmap_len = 0;	/* for kernel */
		strncpy(lkm.u.stream.path_name, stream->pathname, PATH_MAX - 1);
		lkm.u.stream.path_name[PATH_MAX - 1] = '\0';
		DBG("Sending stream %d to consumer", lkm.u.stream.stream_key);
		ret = lttcomm_send_unix_sock(sock, &lkm, sizeof(lkm));
		if (ret < 0) {
			perror("send consumer stream");
			goto error;
		}
		ret = lttcomm_send_fds_unix_sock(sock, &stream->fd, 1);
		if (ret < 0) {
			perror("send consumer stream ancillary data");
			goto error;
		}
	}

	DBG("consumer channel streams sent");

	return 0;

error:
	return ret;
}

/*
 * Send all stream fds of the kernel session to the consumer.
 */
static int send_consumer_session_streams(struct consumer_data *consumer_data,
		struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_channel *chan;
	struct lttcomm_consumer_msg lkm;
	int sock = session->consumer_fd;

	DBG("Sending metadata stream fd");

	/* Extra protection. It's NOT suppose to be set to 0 at this point */
	if (session->consumer_fd == 0) {
		session->consumer_fd = consumer_data->cmd_sock;
	}

	if (session->metadata_stream_fd != 0) {
		/* Send metadata channel fd */
		lkm.cmd_type = LTTNG_CONSUMER_ADD_CHANNEL;
		lkm.u.channel.channel_key = session->metadata->fd;
		lkm.u.channel.max_sb_size = session->metadata->conf->attr.subbuf_size;
		lkm.u.channel.mmap_len = 0;	/* for kernel */
		DBG("Sending metadata channel %d to consumer", lkm.u.stream.stream_key);
		ret = lttcomm_send_unix_sock(sock, &lkm, sizeof(lkm));
		if (ret < 0) {
			perror("send consumer channel");
			goto error;
		}

		/* Send metadata stream fd */
		lkm.cmd_type = LTTNG_CONSUMER_ADD_STREAM;
		lkm.u.stream.channel_key = session->metadata->fd;
		lkm.u.stream.stream_key = session->metadata_stream_fd;
		lkm.u.stream.state = LTTNG_CONSUMER_ACTIVE_STREAM;
		lkm.u.stream.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		lkm.u.stream.mmap_len = 0;	/* for kernel */
		strncpy(lkm.u.stream.path_name, session->metadata->pathname, PATH_MAX - 1);
		lkm.u.stream.path_name[PATH_MAX - 1] = '\0';
		DBG("Sending metadata stream %d to consumer", lkm.u.stream.stream_key);
		ret = lttcomm_send_unix_sock(sock, &lkm, sizeof(lkm));
		if (ret < 0) {
			perror("send consumer stream");
			goto error;
		}
		ret = lttcomm_send_fds_unix_sock(sock, &session->metadata_stream_fd, 1);
		if (ret < 0) {
			perror("send consumer stream");
			goto error;
		}
	}

	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		ret = send_consumer_channel_streams(consumer_data, sock, chan);
		if (ret < 0) {
			goto error;
		}
	}

	DBG("consumer fds (metadata and channel streams) sent");

	return 0;

error:
	return ret;
}

/*
 * Notify UST applications using the shm mmap futex.
 */
static int notify_ust_apps(int active)
{
	char *wait_shm_mmap;

	DBG("Notifying applications of session daemon state: %d", active);

	/* See shm.c for this call implying mmap, shm and futex calls */
	wait_shm_mmap = shm_ust_get_mmap(wait_shm_path, is_root);
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
 * Return total size of the buffer pointed by buf.
 */
static int setup_lttng_msg(struct command_ctx *cmd_ctx, size_t size)
{
	int ret, buf_size;

	buf_size = size;

	cmd_ctx->llm = malloc(sizeof(struct lttcomm_lttng_msg) + buf_size);
	if (cmd_ctx->llm == NULL) {
		perror("malloc");
		ret = -ENOMEM;
		goto error;
	}

	/* Copy common data */
	cmd_ctx->llm->cmd_type = cmd_ctx->lsm->cmd_type;
	cmd_ctx->llm->pid = cmd_ctx->lsm->domain.attr.pid;

	cmd_ctx->llm->data_size = size;
	cmd_ctx->lttng_msg_size = sizeof(struct lttcomm_lttng_msg) + buf_size;

	return buf_size;

error:
	return ret;
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
static int update_stream(struct consumer_data *consumer_data, int fd)
{
	int ret = 0;
	struct ltt_session *session;
	struct ltt_kernel_channel *channel;

	DBG("Updating kernel streams for channel fd %d", fd);

	session_lock_list();
	cds_list_for_each_entry(session, &session_list_ptr->head, list) {
		session_lock(session);
		if (session->kernel_session == NULL) {
			session_unlock(session);
			continue;
		}

		/* This is not suppose to be 0 but this is an extra security check */
		if (session->kernel_session->consumer_fd == 0) {
			session->kernel_session->consumer_fd = consumer_data->cmd_sock;
		}

		cds_list_for_each_entry(channel,
				&session->kernel_session->channel_list.head, list) {
			if (channel->fd == fd) {
				DBG("Channel found, updating kernel streams");
				ret = kernel_open_channel_stream(channel);
				if (ret < 0) {
					goto error;
				}

				/*
				 * Have we already sent fds to the consumer? If yes, it means
				 * that tracing is started so it is safe to send our updated
				 * stream fds.
				 */
				if (session->kernel_session->consumer_fds_sent == 1) {
					ret = send_consumer_channel_streams(consumer_data,
							session->kernel_session->consumer_fd, channel);
					if (ret < 0) {
						goto error;
					}
				}
				goto error;
			}
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
 * This thread manage event coming from the kernel.
 *
 * Features supported in this thread:
 *    -) CPU Hotplug
 */
static void *thread_manage_kernel(void *data)
{
	int ret, i, pollfd, update_poll_flag = 1;
	uint32_t revents, nb_fd;
	char tmp;
	struct lttng_poll_event events;

	DBG("Thread manage kernel started");

	ret = create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(&events, kernel_poll_pipe[0], LPOLLIN);
	if (ret < 0) {
		goto error;
	}

	while (1) {
		if (update_poll_flag == 1) {
			/*
			 * Reset number of fd in the poll set. Always 2 since there is the thread
			 * quit pipe and the kernel pipe.
			 */
			events.nb_fd = 2;

			ret = update_kernel_poll(&events);
			if (ret < 0) {
				goto error;
			}
			update_poll_flag = 0;
		}

		nb_fd = LTTNG_POLL_GETNB(&events);

		DBG("Thread kernel polling on %d fds", nb_fd);

		/* Zeroed the poll events */
		lttng_poll_reset(&events);

		/* Poll infinite value of time */
		ret = lttng_poll_wait(&events, -1);
		if (ret < 0) {
			goto error;
		} else if (ret == 0) {
			/* Should not happen since timeout is infinite */
			ERR("Return value of poll is 0 with an infinite timeout.\n"
				"This should not have happened! Continuing...");
			continue;
		}

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Thread quit pipe has been closed. Killing thread. */
			ret = check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				goto error;
			}

			/* Check for data on kernel pipe */
			if (pollfd == kernel_poll_pipe[0] && (revents & LPOLLIN)) {
				ret = read(kernel_poll_pipe[0], &tmp, 1);
				update_poll_flag = 1;
				continue;
			} else {
				/*
				 * New CPU detected by the kernel. Adding kernel stream to
				 * kernel session and updating the kernel consumer
				 */
				if (revents & LPOLLIN) {
					ret = update_stream(&kconsumer_data, pollfd);
					if (ret < 0) {
						continue;
					}
					break;
					/*
					 * TODO: We might want to handle the LPOLLERR | LPOLLHUP
					 * and unregister kernel stream at this point.
					 */
				}
			}
		}
	}

error:
	DBG("Kernel thread dying");
	close(kernel_poll_pipe[0]);
	close(kernel_poll_pipe[1]);

	lttng_poll_clean(&events);

	return NULL;
}

/*
 * This thread manage the consumer error sent back to the session daemon.
 */
static void *thread_manage_consumer(void *data)
{
	int sock = 0, i, ret, pollfd;
	uint32_t revents, nb_fd;
	enum lttcomm_return_code code;
	struct lttng_poll_event events;
	struct consumer_data *consumer_data = data;

	DBG("[thread] Manage consumer started");

	ret = lttcomm_listen_unix_sock(consumer_data->err_sock);
	if (ret < 0) {
		goto error;
	}

	/*
	 * Pass 2 as size here for the thread quit pipe and kconsumerd_err_sock.
	 * Nothing more will be added to this poll set.
	 */
	ret = create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(&events, consumer_data->err_sock, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	nb_fd = LTTNG_POLL_GETNB(&events);

	/* Inifinite blocking call, waiting for transmission */
	ret = lttng_poll_wait(&events, -1);
	if (ret < 0) {
		goto error;
	}

	for (i = 0; i < nb_fd; i++) {
		/* Fetch once the poll data */
		revents = LTTNG_POLL_GETEV(&events, i);
		pollfd = LTTNG_POLL_GETFD(&events, i);

		/* Thread quit pipe has been closed. Killing thread. */
		ret = check_thread_quit_pipe(pollfd, revents);
		if (ret) {
			goto error;
		}

		/* Event on the registration socket */
		if (pollfd == consumer_data->err_sock) {
			if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("consumer err socket poll error");
				goto error;
			}
		}
	}

	sock = lttcomm_accept_unix_sock(consumer_data->err_sock);
	if (sock < 0) {
		goto error;
	}

	DBG2("Receiving code from consumer err_sock");

	/* Getting status code from kconsumerd */
	ret = lttcomm_recv_unix_sock(sock, &code,
			sizeof(enum lttcomm_return_code));
	if (ret <= 0) {
		goto error;
	}

	if (code == CONSUMERD_COMMAND_SOCK_READY) {
		consumer_data->cmd_sock =
			lttcomm_connect_unix_sock(consumer_data->cmd_unix_sock_path);
		if (consumer_data->cmd_sock < 0) {
			sem_post(&consumer_data->sem);
			perror("consumer connect");
			goto error;
		}
		/* Signal condition to tell that the kconsumerd is ready */
		sem_post(&consumer_data->sem);
		DBG("consumer command socket ready");
	} else {
		ERR("consumer error when waiting for SOCK_READY : %s",
				lttcomm_get_readable_code(-code));
		goto error;
	}

	/* Remove the kconsumerd error sock since we've established a connexion */
	ret = lttng_poll_del(&events, consumer_data->err_sock);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(&events, sock, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	/* Update number of fd */
	nb_fd = LTTNG_POLL_GETNB(&events);

	/* Inifinite blocking call, waiting for transmission */
	ret = lttng_poll_wait(&events, -1);
	if (ret < 0) {
		goto error;
	}

	for (i = 0; i < nb_fd; i++) {
		/* Fetch once the poll data */
		revents = LTTNG_POLL_GETEV(&events, i);
		pollfd = LTTNG_POLL_GETFD(&events, i);

		/* Thread quit pipe has been closed. Killing thread. */
		ret = check_thread_quit_pipe(pollfd, revents);
		if (ret) {
			goto error;
		}

		/* Event on the kconsumerd socket */
		if (pollfd == sock) {
			if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
				ERR("consumer err socket second poll error");
				goto error;
			}
		}
	}

	/* Wait for any kconsumerd error */
	ret = lttcomm_recv_unix_sock(sock, &code,
			sizeof(enum lttcomm_return_code));
	if (ret <= 0) {
		ERR("consumer closed the command socket");
		goto error;
	}

	ERR("consumer return code : %s", lttcomm_get_readable_code(-code));

error:
	DBG("consumer thread dying");
	close(consumer_data->err_sock);
	close(consumer_data->cmd_sock);
	close(sock);

	unlink(consumer_data->err_unix_sock_path);
	unlink(consumer_data->cmd_unix_sock_path);
	consumer_data->pid = 0;

	lttng_poll_clean(&events);

	return NULL;
}

/*
 * This thread manage application communication.
 */
static void *thread_manage_apps(void *data)
{
	int i, ret, pollfd;
	uint32_t revents, nb_fd;
	struct ust_command ust_cmd;
	struct lttng_poll_event events;

	DBG("[thread] Manage application started");

	ret = create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(&events, apps_cmd_pipe[0], LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
	}

	while (1) {
		/* Zeroed the events structure */
		lttng_poll_reset(&events);

		nb_fd = LTTNG_POLL_GETNB(&events);

		DBG("Apps thread polling on %d fds", nb_fd);

		/* Inifinite blocking call, waiting for transmission */
		ret = lttng_poll_wait(&events, -1);
		if (ret < 0) {
			goto error;
		}

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Thread quit pipe has been closed. Killing thread. */
			ret = check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				goto error;
			}

			/* Inspect the apps cmd pipe */
			if (pollfd == apps_cmd_pipe[0]) {
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Apps command pipe error");
					goto error;
				} else if (revents & LPOLLIN) {
					/* Empty pipe */
					ret = read(apps_cmd_pipe[0], &ust_cmd, sizeof(ust_cmd));
					if (ret < 0 || ret < sizeof(ust_cmd)) {
						perror("read apps cmd pipe");
						goto error;
					}

					/* Register applicaton to the session daemon */
					ret = ust_app_register(&ust_cmd.reg_msg,
							ust_cmd.sock);
					if (ret < 0) {
						/* Only critical ENOMEM error can be returned here */
						goto error;
					}

					ret = ustctl_register_done(ust_cmd.sock);
					if (ret < 0) {
						/*
						 * If the registration is not possible, we simply
						 * unregister the apps and continue
						 */
						ust_app_unregister(ust_cmd.sock);
					} else {
						/*
						 * We just need here to monitor the close of the UST
						 * socket and poll set monitor those by default.
						 */
						ret = lttng_poll_add(&events, ust_cmd.sock, 0);
						if (ret < 0) {
							goto error;
						}

						DBG("Apps with sock %d added to poll set",
								ust_cmd.sock);
					}
					break;
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

					/* Socket closed */
					ust_app_unregister(pollfd);
					break;
				}
			}
		}
	}

error:
	DBG("Application communication apps dying");
	close(apps_cmd_pipe[0]);
	close(apps_cmd_pipe[1]);

	lttng_poll_clean(&events);

	return NULL;
}

/*
 * Dispatch request from the registration threads to the application
 * communication thread.
 */
static void *thread_dispatch_ust_registration(void *data)
{
	int ret;
	struct cds_wfq_node *node;
	struct ust_command *ust_cmd = NULL;

	DBG("[thread] Dispatch UST command started");

	while (!dispatch_thread_exit) {
		/* Atomically prepare the queue futex */
		futex_nto1_prepare(&ust_cmd_queue.futex);

		do {
			/* Dequeue command for registration */
			node = cds_wfq_dequeue_blocking(&ust_cmd_queue.queue);
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
			/*
			 * Inform apps thread of the new application registration. This
			 * call is blocking so we can be assured that the data will be read
			 * at some point in time or wait to the end of the world :)
			 */
			ret = write(apps_cmd_pipe[1], ust_cmd,
					sizeof(struct ust_command));
			if (ret < 0) {
				perror("write apps cmd pipe");
				if (errno == EBADF) {
					/*
					 * We can't inform the application thread to process
					 * registration. We will exit or else application
					 * registration will not occur and tracing will never
					 * start.
					 */
					goto error;
				}
			}
			free(ust_cmd);
		} while (node != NULL);

		/* Futex wait on queue. Blocking call on futex() */
		futex_nto1_wait(&ust_cmd_queue.futex);
	}

error:
	DBG("Dispatch thread dying");
	return NULL;
}

/*
 * This thread manage application registration.
 */
static void *thread_registration_apps(void *data)
{
	int sock = 0, i, ret, pollfd;
	uint32_t revents, nb_fd;
	struct lttng_poll_event events;
	/*
	 * Get allocated in this thread, enqueued to a global queue, dequeued and
	 * freed in the manage apps thread.
	 */
	struct ust_command *ust_cmd = NULL;

	DBG("[thread] Manage application registration started");

	ret = lttcomm_listen_unix_sock(apps_sock);
	if (ret < 0) {
		goto error;
	}

	/*
	 * Pass 2 as size here for the thread quit pipe and apps socket. Nothing
	 * more will be added to this poll set.
	 */
	ret = create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, apps_sock, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		goto error;
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

		nb_fd = LTTNG_POLL_GETNB(&events);

		/* Inifinite blocking call, waiting for transmission */
		ret = lttng_poll_wait(&events, -1);
		if (ret < 0) {
			goto error;
		}

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Thread quit pipe has been closed. Killing thread. */
			ret = check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				goto error;
			}

			/* Event on the registration socket */
			if (pollfd == apps_sock) {
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Register apps socket poll error");
					goto error;
				} else if (revents & LPOLLIN) {
					sock = lttcomm_accept_unix_sock(apps_sock);
					if (sock < 0) {
						goto error;
					}

					/* Create UST registration command for enqueuing */
					ust_cmd = malloc(sizeof(struct ust_command));
					if (ust_cmd == NULL) {
						perror("ust command malloc");
						goto error;
					}

					/*
					 * Using message-based transmissions to ensure we don't
					 * have to deal with partially received messages.
					 */
					ret = lttcomm_recv_unix_sock(sock, &ust_cmd->reg_msg,
							sizeof(struct ust_register_msg));
					if (ret < 0 || ret < sizeof(struct ust_register_msg)) {
						if (ret < 0) {
							perror("lttcomm_recv_unix_sock register apps");
						} else {
							ERR("Wrong size received on apps register");
						}
						free(ust_cmd);
						close(sock);
						continue;
					}

					ust_cmd->sock = sock;

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
					cds_wfq_enqueue(&ust_cmd_queue.queue, &ust_cmd->node);

					/*
					 * Wake the registration queue futex. Implicit memory
					 * barrier with the exchange in cds_wfq_enqueue.
					 */
					futex_nto1_wake(&ust_cmd_queue.futex);
				}
			}
		}
	}

error:
	DBG("UST Registration thread dying");

	/* Notify that the registration thread is gone */
	notify_ust_apps(0);

	close(apps_sock);
	close(sock);
	unlink(apps_unix_sock_path);

	lttng_poll_clean(&events);

	return NULL;
}

/*
 * Start the thread_manage_consumer. This must be done after a lttng-consumerd
 * exec or it will fails.
 */
static int spawn_consumer_thread(struct consumer_data *consumer_data)
{
	int ret;
	struct timespec timeout;

	timeout.tv_sec = DEFAULT_SEM_WAIT_TIMEOUT;
	timeout.tv_nsec = 0;

	/* Setup semaphore */
	ret = sem_init(&consumer_data->sem, 0, 0);
	if (ret < 0) {
		PERROR("sem_init consumer semaphore");
		goto error;
	}

	ret = pthread_create(&consumer_data->thread, NULL,
			thread_manage_consumer, consumer_data);
	if (ret != 0) {
		PERROR("pthread_create consumer");
		ret = -1;
		goto error;
	}

	/* Get time for sem_timedwait absolute timeout */
	ret = clock_gettime(CLOCK_REALTIME, &timeout);
	if (ret < 0) {
		PERROR("clock_gettime spawn consumer");
		/* Infinite wait for the kconsumerd thread to be ready */
		ret = sem_wait(&consumer_data->sem);
	} else {
		/* Normal timeout if the gettime was successful */
		timeout.tv_sec += DEFAULT_SEM_WAIT_TIMEOUT;
		ret = sem_timedwait(&consumer_data->sem, &timeout);
	}

	if (ret < 0) {
		if (errno == ETIMEDOUT) {
			/*
			 * Call has timed out so we kill the kconsumerd_thread and return
			 * an error.
			 */
			ERR("The consumer thread was never ready. Killing it");
			ret = pthread_cancel(consumer_data->thread);
			if (ret < 0) {
				PERROR("pthread_cancel consumer thread");
			}
		} else {
			PERROR("semaphore wait failed consumer thread");
		}
		goto error;
	}

	pthread_mutex_lock(&consumer_data->pid_mutex);
	if (consumer_data->pid == 0) {
		ERR("Kconsumerd did not start");
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
	int ret;

	if (consumer_data->pid != 0) {
		ret = kill(consumer_data->pid, SIGTERM);
		if (ret) {
			ERR("Error killing consumer daemon");
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
	const char *verbosity;

	DBG("Spawning consumerd");

	pid = fork();
	if (pid == 0) {
		/*
		 * Exec consumerd.
		 */
		if (opt_verbose > 1 || opt_verbose_consumer) {
			verbosity = "--verbose";
		} else {
			verbosity = "--quiet";
		}
		switch (consumer_data->type) {
		case LTTNG_CONSUMER_KERNEL:
			execl(INSTALL_BIN_PATH "/lttng-consumerd",
					"lttng-consumerd", verbosity, "-k", NULL);
			break;
		case LTTNG_CONSUMER_UST:
			execl(INSTALL_BIN_PATH "/lttng-consumerd",
					"lttng-consumerd", verbosity, "-u", NULL);
			break;
		default:
			perror("unknown consumer type");
			exit(EXIT_FAILURE);
		}
		if (errno != 0) {
			perror("kernel start consumer exec");
		}
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		ret = pid;
	} else {
		perror("start consumer fork");
		ret = -errno;
	}
	return ret;
}

/*
 * Spawn the consumerd daemon and session daemon thread.
 */
static int start_consumerd(struct consumer_data *consumer_data)
{
	int ret;

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
	DBG2("consumer pid %d", consumer_data->pid);
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
	return ret;
}

/*
 * modprobe_kernel_modules
 */
static int modprobe_kernel_modules(void)
{
	int ret = 0, i;
	char modprobe[256];

	for (i = 0; i < ARRAY_SIZE(kernel_modules_list); i++) {
		ret = snprintf(modprobe, sizeof(modprobe),
			"/sbin/modprobe %s%s",
			kernel_modules_list[i].required ? "" : "--quiet ",
			kernel_modules_list[i].name);
		if (ret < 0) {
			perror("snprintf modprobe");
			goto error;
		}
		modprobe[sizeof(modprobe) - 1] = '\0';
		ret = system(modprobe);
		if (ret == -1) {
			ERR("Unable to launch modprobe for module %s",
				kernel_modules_list[i].name);
		} else if (kernel_modules_list[i].required
				&& WEXITSTATUS(ret) != 0) {
			ERR("Unable to load module %s",
				kernel_modules_list[i].name);
		} else {
			DBG("Modprobe successfully %s",
				kernel_modules_list[i].name);
		}
	}

error:
	return ret;
}

/*
 * mount_debugfs
 */
static int mount_debugfs(char *path)
{
	int ret;
	char *type = "debugfs";

	ret = mkdir_recursive(path, S_IRWXU | S_IRWXG, geteuid(), getegid());
	if (ret < 0) {
		PERROR("Cannot create debugfs path");
		goto error;
	}

	ret = mount(type, path, type, 0, NULL);
	if (ret < 0) {
		PERROR("Cannot mount debugfs");
		goto error;
	}

	DBG("Mounted debugfs successfully at %s", path);

error:
	return ret;
}

/*
 * Setup necessary data for kernel tracer action.
 */
static void init_kernel_tracer(void)
{
	int ret;
	char *proc_mounts = "/proc/mounts";
	char line[256];
	char *debugfs_path = NULL, *lttng_path = NULL;
	FILE *fp;

	/* Detect debugfs */
	fp = fopen(proc_mounts, "r");
	if (fp == NULL) {
		ERR("Unable to probe %s", proc_mounts);
		goto error;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strstr(line, "debugfs") != NULL) {
			/* Remove first string */
			strtok(line, " ");
			/* Dup string here so we can reuse line later on */
			debugfs_path = strdup(strtok(NULL, " "));
			DBG("Got debugfs path : %s", debugfs_path);
			break;
		}
	}

	fclose(fp);

	/* Mount debugfs if needded */
	if (debugfs_path == NULL) {
		ret = asprintf(&debugfs_path, "/mnt/debugfs");
		if (ret < 0) {
			perror("asprintf debugfs path");
			goto error;
		}
		ret = mount_debugfs(debugfs_path);
		if (ret < 0) {
			perror("Cannot mount debugfs");
			goto error;
		}
	}

	/* Modprobe lttng kernel modules */
	ret = modprobe_kernel_modules();
	if (ret < 0) {
		goto error;
	}

	/* Setup lttng kernel path */
	ret = asprintf(&lttng_path, "%s/lttng", debugfs_path);
	if (ret < 0) {
		perror("asprintf lttng path");
		goto error;
	}

	/* Open debugfs lttng */
	kernel_tracer_fd = open(lttng_path, O_RDWR);
	if (kernel_tracer_fd < 0) {
		DBG("Failed to open %s", lttng_path);
		goto error;
	}

	free(lttng_path);
	free(debugfs_path);
	DBG("Kernel tracer fd %d", kernel_tracer_fd);
	return;

error:
	if (lttng_path) {
		free(lttng_path);
	}
	if (debugfs_path) {
		free(debugfs_path);
	}
	WARN("No kernel tracer available");
	kernel_tracer_fd = 0;
	return;
}

/*
 * Init tracing by creating trace directory and sending fds kernel consumer.
 */
static int init_kernel_tracing(struct ltt_kernel_session *session)
{
	int ret = 0;

	if (session->consumer_fds_sent == 0) {
		/*
		 * Assign default kernel consumer socket if no consumer assigned to the
		 * kernel session. At this point, it's NOT suppose to be 0 but this is
		 * an extra security check.
		 */
		if (session->consumer_fd == 0) {
			session->consumer_fd = kconsumer_data.cmd_sock;
		}

		ret = send_consumer_session_streams(&kconsumer_data, session);
		if (ret < 0) {
			ret = LTTCOMM_KERN_CONSUMER_FAIL;
			goto error;
		}

		session->consumer_fds_sent = 1;
	}

error:
	return ret;
}

/*
 * Create an UST session and add it to the session ust list.
 */
static int create_ust_session(struct ltt_session *session,
		struct lttng_domain *domain)
{
	int ret;
	struct ltt_ust_session *lus = NULL;
	struct ust_app *app;

	switch (domain->type) {
	case LTTNG_DOMAIN_UST_PID:
		app = ust_app_get_by_pid(domain->attr.pid);
		if (app == NULL) {
			ret = LTTCOMM_APP_NOT_FOUND;
			goto error;
		}
		break;
	default:
		ret = LTTCOMM_UNKNOWN_DOMAIN;
		goto error;
	}

	DBG("Creating UST session");

	lus = trace_ust_create_session(session->path, domain->attr.pid, domain);
	if (lus == NULL) {
		ret = LTTCOMM_UST_SESS_FAIL;
		goto error;
	}

	ret = mkdir_recursive(lus->path, S_IRWXU | S_IRWXG,
			geteuid(), allowed_group());
	if (ret < 0) {
		if (ret != -EEXIST) {
			ERR("Trace directory creation error");
			ret = LTTCOMM_UST_SESS_FAIL;
			goto error;
		}
	}

	/* Create session on the UST tracer */
	ret = ustctl_create_session(app->sock, lus);
	if (ret < 0) {
		ret = LTTCOMM_UST_SESS_FAIL;
		goto error;
	}

	cds_list_add(&lus->list, &session->ust_session_list.head);
	session->ust_session_list.count++;

	return LTTCOMM_OK;

error:
	free(lus);
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
		ret = LTTCOMM_KERN_SESS_FAIL;
		goto error;
	}

	/* Set kernel consumer socket fd */
	if (kconsumer_data.cmd_sock) {
		session->kernel_session->consumer_fd = kconsumer_data.cmd_sock;
	}

	ret = mkdir_recursive(session->kernel_session->trace_path,
			S_IRWXU | S_IRWXG, geteuid(), allowed_group());
	if (ret < 0) {
		if (ret != -EEXIST) {
			ERR("Trace directory creation error");
			goto error;
		}
	}

error:
	return ret;
}

/*
 * Using the session list, filled a lttng_session array to send back to the
 * client for session listing.
 *
 * The session list lock MUST be acquired before calling this function. Use
 * session_lock_list() and session_unlock_list().
 */
static void list_lttng_sessions(struct lttng_session *sessions)
{
	int i = 0;
	struct ltt_session *session;

	DBG("Getting all available session");
	/*
	 * Iterate over session list and append data after the control struct in
	 * the buffer.
	 */
	cds_list_for_each_entry(session, &session_list_ptr->head, list) {
		strncpy(sessions[i].path, session->path, PATH_MAX);
		sessions[i].path[PATH_MAX - 1] = '\0';
		strncpy(sessions[i].name, session->name, NAME_MAX);
		sessions[i].name[NAME_MAX - 1] = '\0';
		i++;
	}
}

/*
 * Fill lttng_channel array of all channels.
 */
static void list_lttng_channels(struct ltt_session *session,
		struct lttng_channel *channels)
{
	int i = 0;
	struct ltt_kernel_channel *kchan;

	DBG("Listing channels for session %s", session->name);

	/* Kernel channels */
	if (session->kernel_session != NULL) {
		cds_list_for_each_entry(kchan,
				&session->kernel_session->channel_list.head, list) {
			/* Copy lttng_channel struct to array */
			memcpy(&channels[i], kchan->channel, sizeof(struct lttng_channel));
			channels[i].enabled = kchan->enabled;
			i++;
		}
	}

	/* TODO: Missing UST listing */
}

/*
 * Fill lttng_event array of all events in the channel.
 */
static void list_lttng_events(struct ltt_kernel_channel *kchan,
		struct lttng_event *events)
{
	/*
	 * TODO: This is ONLY kernel. Need UST support.
	 */
	int i = 0;
	struct ltt_kernel_event *event;

	DBG("Listing events for channel %s", kchan->channel->name);

	/* Kernel channels */
	cds_list_for_each_entry(event, &kchan->events_list.head , list) {
		strncpy(events[i].name, event->event->name, LTTNG_SYMBOL_NAME_LEN);
		events[i].name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		events[i].enabled = event->enabled;
		switch (event->event->instrumentation) {
			case LTTNG_KERNEL_TRACEPOINT:
				events[i].type = LTTNG_EVENT_TRACEPOINT;
				break;
			case LTTNG_KERNEL_KPROBE:
			case LTTNG_KERNEL_KRETPROBE:
				events[i].type = LTTNG_EVENT_PROBE;
				memcpy(&events[i].attr.probe, &event->event->u.kprobe,
						sizeof(struct lttng_kernel_kprobe));
				break;
			case LTTNG_KERNEL_FUNCTION:
				events[i].type = LTTNG_EVENT_FUNCTION;
				memcpy(&events[i].attr.ftrace, &event->event->u.ftrace,
						sizeof(struct lttng_kernel_function));
				break;
			case LTTNG_KERNEL_NOOP:
				events[i].type = LTTNG_EVENT_NOOP;
				break;
			case LTTNG_KERNEL_SYSCALL:
				events[i].type = LTTNG_EVENT_SYSCALL;
				break;
			case LTTNG_KERNEL_ALL:
				assert(0);
				break;
		}
		i++;
	}
}

/*
 * Command LTTNG_DISABLE_CHANNEL processed by the client thread.
 */
static int cmd_disable_channel(struct ltt_session *session,
		int domain, char *channel_name)
{
	int ret;

	switch (domain) {
		case LTTNG_DOMAIN_KERNEL:
			ret = channel_kernel_disable(session->kernel_session,
					channel_name);
			if (ret != LTTCOMM_OK) {
				goto error;
			}

			kernel_wait_quiescent(kernel_tracer_fd);
			break;
		case LTTNG_DOMAIN_UST_PID:
			break;
		default:
			ret = LTTCOMM_UNKNOWN_DOMAIN;
			goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Copy channel from attributes and set it in the application channel list.
 */
static int copy_ust_channel_to_app(struct ltt_ust_session *usess,
		struct lttng_channel *attr, struct ust_app *app)
{
	int ret;
	struct ltt_ust_channel *uchan, *new_chan;

	uchan = trace_ust_get_channel_by_name(attr->name, usess);
	if (uchan == NULL) {
		ret = LTTCOMM_FATAL;
		goto error;
	}

	new_chan = trace_ust_create_channel(attr, usess->path);
	if (new_chan == NULL) {
		PERROR("malloc ltt_ust_channel");
		ret = LTTCOMM_FATAL;
		goto error;
	}

	ret = channel_ust_copy(new_chan, uchan);
	if (ret < 0) {
		ret = LTTCOMM_FATAL;
		goto error;
	}

	/* Add channel to the ust app channel list */
	cds_list_add(&new_chan->list, &app->channels.head);
	app->channels.count++;

error:
	return ret;
}

/*
 * Command LTTNG_ENABLE_CHANNEL processed by the client thread.
 */
static int cmd_enable_channel(struct ltt_session *session,
		struct lttng_domain *domain, struct lttng_channel *attr)
{
	int ret;

	switch (domain->type) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct ltt_kernel_channel *kchan;

		kchan = trace_kernel_get_channel_by_name(attr->name,
				session->kernel_session);
		if (kchan == NULL) {
			ret = channel_kernel_create(session->kernel_session,
					attr, kernel_poll_pipe[1]);
		} else {
			ret = channel_kernel_enable(session->kernel_session, kchan);
		}

		if (ret != LTTCOMM_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	}
	case LTTNG_DOMAIN_UST_PID:
	{
		int sock;
		struct ltt_ust_channel *uchan;
		struct ltt_ust_session *usess;
		struct ust_app *app;

		usess = trace_ust_get_session_by_pid(&session->ust_session_list,
				domain->attr.pid);
		if (usess == NULL) {
			ret = LTTCOMM_UST_CHAN_NOT_FOUND;
			goto error;
		}

		app = ust_app_get_by_pid(domain->attr.pid);
		if (app == NULL) {
			ret = LTTCOMM_APP_NOT_FOUND;
			goto error;
		}
		sock = app->sock;

		uchan = trace_ust_get_channel_by_name(attr->name, usess);
		if (uchan == NULL) {
			ret = channel_ust_create(usess, attr, sock);
		} else {
			ret = channel_ust_enable(usess, uchan, sock);
		}

		if (ret != LTTCOMM_OK) {
			goto error;
		}

		ret = copy_ust_channel_to_app(usess, attr, app);
		if (ret != LTTCOMM_OK) {
			goto error;
		}

		DBG("UST channel %s created for app sock %d with pid %d",
				attr->name, app->sock, domain->attr.pid);
		break;
	}
	default:
		ret = LTTCOMM_UNKNOWN_DOMAIN;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_DISABLE_EVENT processed by the client thread.
 */
static int cmd_disable_event(struct ltt_session *session, int domain,
		char *channel_name, char *event_name)
{
	int ret;
	struct ltt_kernel_channel *kchan;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			ret = LTTCOMM_KERN_CHAN_NOT_FOUND;
			goto error;
		}

		ret = event_kernel_disable_tracepoint(session->kernel_session, kchan, event_name);
		if (ret != LTTCOMM_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	default:
		/* TODO: Userspace tracing */
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_DISABLE_ALL_EVENT processed by the client thread.
 */
static int cmd_disable_event_all(struct ltt_session *session, int domain,
		char *channel_name)
{
	int ret;
	struct ltt_kernel_channel *kchan;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			ret = LTTCOMM_KERN_CHAN_NOT_FOUND;
			goto error;
		}

		ret = event_kernel_disable_all(session->kernel_session, kchan);
		if (ret != LTTCOMM_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	default:
		/* TODO: Userspace tracing */
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_ADD_CONTEXT processed by the client thread.
 */
static int cmd_add_context(struct ltt_session *session, int domain,
		char *channel_name, char *event_name, struct lttng_event_context *ctx)
{
	int ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		/* Add kernel context to kernel tracer */
		ret = context_kernel_add(session->kernel_session, ctx,
				event_name, channel_name);
		if (ret != LTTCOMM_OK) {
			goto error;
		}

		break;
	default:
		/* TODO: Userspace tracing */
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_ENABLE_EVENT processed by the client thread.
 */
static int cmd_enable_event(struct ltt_session *session, int domain,
		char *channel_name, struct lttng_event *event)
{
	int ret;
	struct ltt_kernel_channel *kchan;
	struct lttng_channel *attr;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			attr = channel_new_default_attr(domain);
			if (attr == NULL) {
				ret = LTTCOMM_FATAL;
				goto error;
			}
			snprintf(attr->name, NAME_MAX, "%s", channel_name);

			/* This call will notify the kernel thread */
			ret = channel_kernel_create(session->kernel_session,
					attr, kernel_poll_pipe[1]);
			if (ret != LTTCOMM_OK) {
				goto error;
			}
		}

		/* Get the newly created kernel channel pointer */
		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			/* This sould not happen... */
			ret = LTTCOMM_FATAL;
			goto error;
		}

		ret = event_kernel_enable_tracepoint(session->kernel_session, kchan, event);
		if (ret != LTTCOMM_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	default:
		/* TODO: Userspace tracing */
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_ENABLE_ALL_EVENT processed by the client thread.
 */
static int cmd_enable_event_all(struct ltt_session *session, int domain,
		char *channel_name, int event_type)
{
	int ret;
	struct ltt_kernel_channel *kchan;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			/* This call will notify the kernel thread */
			ret = channel_kernel_create(session->kernel_session, NULL,
					kernel_poll_pipe[1]);
			if (ret != LTTCOMM_OK) {
				goto error;
			}
		}

		/* Get the newly created kernel channel pointer */
		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			/* This sould not happen... */
			ret = LTTCOMM_FATAL;
			goto error;
		}

		switch (event_type) {
		case LTTNG_KERNEL_SYSCALL:
			ret = event_kernel_enable_all_syscalls(session->kernel_session,
					kchan, kernel_tracer_fd);
			break;
		case LTTNG_KERNEL_TRACEPOINT:
			/*
			 * This call enables all LTTNG_KERNEL_TRACEPOINTS and
			 * events already registered to the channel.
			 */
			ret = event_kernel_enable_all_tracepoints(session->kernel_session,
					kchan, kernel_tracer_fd);
			break;
		case LTTNG_KERNEL_ALL:
			/* Enable syscalls and tracepoints */
			ret = event_kernel_enable_all(session->kernel_session,
					kchan, kernel_tracer_fd);
			break;
		default:
			ret = LTTCOMM_KERN_ENABLE_FAIL;
			goto error;
		}
		if (ret != LTTCOMM_OK) {
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
		break;
	default:
		/* TODO: Userspace tracing */
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_LIST_TRACEPOINTS processed by the client thread.
 */
static ssize_t cmd_list_tracepoints(int domain, struct lttng_event **events)
{
	int ret;
	ssize_t nb_events = 0;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		nb_events = kernel_list_events(kernel_tracer_fd, events);
		if (nb_events < 0) {
			ret = LTTCOMM_KERN_LIST_FAIL;
			goto error;
		}
		break;
	default:
		/* TODO: Userspace listing */
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	return nb_events;

error:
	/* Return negative value to differentiate return code */
	return -ret;
}

/*
 * Command LTTNG_START_TRACE processed by the client thread.
 */
static int cmd_start_trace(struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_channel *kchan;
	struct ltt_kernel_session *ksession;

	/* Short cut */
	ksession = session->kernel_session;

	/* Kernel tracing */
	if (ksession != NULL) {
		/* Open kernel metadata */
		if (ksession->metadata == NULL) {
			ret = kernel_open_metadata(ksession, ksession->trace_path);
			if (ret < 0) {
				ret = LTTCOMM_KERN_META_FAIL;
				goto error;
			}
		}

		/* Open kernel metadata stream */
		if (ksession->metadata_stream_fd == 0) {
			ret = kernel_open_metadata_stream(ksession);
			if (ret < 0) {
				ERR("Kernel create metadata stream failed");
				ret = LTTCOMM_KERN_STREAM_FAIL;
				goto error;
			}
		}

		/* For each channel */
		cds_list_for_each_entry(kchan, &ksession->channel_list.head, list) {
			if (kchan->stream_count == 0) {
				ret = kernel_open_channel_stream(kchan);
				if (ret < 0) {
					ret = LTTCOMM_KERN_STREAM_FAIL;
					goto error;
				}
				/* Update the stream global counter */
				ksession->stream_count_global += ret;
			}
		}

		/* Setup kernel consumer socket and send fds to it */
		ret = init_kernel_tracing(ksession);
		if (ret < 0) {
			ret = LTTCOMM_KERN_START_FAIL;
			goto error;
		}

		/* This start the kernel tracing */
		ret = kernel_start_session(ksession);
		if (ret < 0) {
			ret = LTTCOMM_KERN_START_FAIL;
			goto error;
		}

		/* Quiescent wait after starting trace */
		kernel_wait_quiescent(kernel_tracer_fd);
	}

	/* TODO: Start all UST traces */

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_STOP_TRACE processed by the client thread.
 */
static int cmd_stop_trace(struct ltt_session *session)
{
	int ret;
	struct ltt_kernel_channel *kchan;
	struct ltt_kernel_session *ksession;

	/* Short cut */
	ksession = session->kernel_session;

	/* Kernel tracer */
	if (ksession != NULL) {
		DBG("Stop kernel tracing");

		/* Flush all buffers before stopping */
		ret = kernel_metadata_flush_buffer(ksession->metadata_stream_fd);
		if (ret < 0) {
			ERR("Kernel metadata flush failed");
		}

		cds_list_for_each_entry(kchan, &ksession->channel_list.head, list) {
			ret = kernel_flush_buffer(kchan);
			if (ret < 0) {
				ERR("Kernel flush buffer error");
			}
		}

		ret = kernel_stop_session(ksession);
		if (ret < 0) {
			ret = LTTCOMM_KERN_STOP_FAIL;
			goto error;
		}

		kernel_wait_quiescent(kernel_tracer_fd);
	}

	/* TODO : User-space tracer */

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_CREATE_SESSION processed by the client thread.
 */
static int cmd_create_session(char *name, char *path)
{
	int ret;

	ret = session_create(name, path);
	if (ret != LTTCOMM_OK) {
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_DESTROY_SESSION processed by the client thread.
 */
static int cmd_destroy_session(struct ltt_session *session, char *name)
{
	int ret;

	/* Clean kernel session teardown */
	teardown_kernel_session(session);

	/*
	 * Must notify the kernel thread here to update it's poll setin order
	 * to remove the channel(s)' fd just destroyed.
	 */
	ret = notify_thread_pipe(kernel_poll_pipe[1]);
	if (ret < 0) {
		perror("write kernel poll pipe");
	}

	ret = session_destroy(session);

	return ret;
}

/*
 * Command LTTNG_CALIBRATE processed by the client thread.
 */
static int cmd_calibrate(int domain, struct lttng_calibrate *calibrate)
{
	int ret;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
	{
		struct lttng_kernel_calibrate kcalibrate;

		kcalibrate.type = calibrate->type;
		ret = kernel_calibrate(kernel_tracer_fd, &kcalibrate);
		if (ret < 0) {
			ret = LTTCOMM_KERN_ENABLE_FAIL;
			goto error;
		}
		break;
	}
	default:
		/* TODO: Userspace tracing */
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_REGISTER_CONSUMER processed by the client thread.
 */
static int cmd_register_consumer(struct ltt_session *session, int domain,
		char *sock_path)
{
	int ret, sock;

	switch (domain) {
	case LTTNG_DOMAIN_KERNEL:
		/* Can't register a consumer if there is already one */
		if (session->kernel_session->consumer_fd != 0) {
			ret = LTTCOMM_KERN_CONSUMER_FAIL;
			goto error;
		}

		sock = lttcomm_connect_unix_sock(sock_path);
		if (sock < 0) {
			ret = LTTCOMM_CONNECT_FAIL;
			goto error;
		}

		session->kernel_session->consumer_fd = sock;
		break;
	default:
		/* TODO: Userspace tracing */
		ret = LTTCOMM_NOT_IMPLEMENTED;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 * Command LTTNG_LIST_DOMAINS processed by the client thread.
 */
static ssize_t cmd_list_domains(struct ltt_session *session,
		struct lttng_domain **domains)
{
	int ret;
	ssize_t nb_dom = 0;

	if (session->kernel_session != NULL) {
		nb_dom++;
	}

	nb_dom += session->ust_session_list.count;

	*domains = malloc(nb_dom * sizeof(struct lttng_domain));
	if (*domains == NULL) {
		ret = -LTTCOMM_FATAL;
		goto error;
	}

	(*domains)[0].type = LTTNG_DOMAIN_KERNEL;

	/* TODO: User-space tracer domain support */

	return nb_dom;

error:
	return ret;
}

/*
 * Command LTTNG_LIST_CHANNELS processed by the client thread.
 */
static ssize_t cmd_list_channels(struct ltt_session *session,
		struct lttng_channel **channels)
{
	int ret;
	ssize_t nb_chan = 0;

	if (session->kernel_session != NULL) {
		nb_chan += session->kernel_session->channel_count;
	}

	*channels = malloc(nb_chan * sizeof(struct lttng_channel));
	if (*channels == NULL) {
		ret = -LTTCOMM_FATAL;
		goto error;
	}

	list_lttng_channels(session, *channels);

	return nb_chan;

error:
	return ret;
}

/*
 * Command LTTNG_LIST_EVENTS processed by the client thread.
 */
static ssize_t cmd_list_events(struct ltt_session *session,
		char *channel_name, struct lttng_event **events)
{
	int ret;
	ssize_t nb_event = 0;
	struct ltt_kernel_channel *kchan = NULL;

	if (session->kernel_session != NULL) {
		kchan = trace_kernel_get_channel_by_name(channel_name,
				session->kernel_session);
		if (kchan == NULL) {
			ret = -LTTCOMM_KERN_CHAN_NOT_FOUND;
			goto error;
		}
		nb_event += kchan->event_count;
	}

	*events = malloc(nb_event * sizeof(struct lttng_event));
	if (*events == NULL) {
		ret = -LTTCOMM_FATAL;
		goto error;
	}

	list_lttng_events(kchan, *events);

	/* TODO: User-space tracer support */

	return nb_event;

error:
	return ret;
}

/*
 * Process the command requested by the lttng client within the command
 * context structure. This function make sure that the return structure (llm)
 * is set and ready for transmission before returning.
 *
 * Return any error encountered or 0 for success.
 */
static int process_client_msg(struct command_ctx *cmd_ctx)
{
	int ret = LTTCOMM_OK;
	int need_tracing_session = 1;

	DBG("Processing client command %d", cmd_ctx->lsm->cmd_type);

	/*
	 * Check for command that don't needs to allocate a returned payload. We do
	 * this here so we don't have to make the call for no payload at each
	 * command.
	 */
	switch(cmd_ctx->lsm->cmd_type) {
	case LTTNG_LIST_SESSIONS:
	case LTTNG_LIST_TRACEPOINTS:
	case LTTNG_LIST_DOMAINS:
	case LTTNG_LIST_CHANNELS:
	case LTTNG_LIST_EVENTS:
		break;
	default:
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			/* This label does not try to unlock the session */
			goto init_setup_error;
		}
	}

	/* Commands that DO NOT need a session. */
	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_CALIBRATE:
	case LTTNG_CREATE_SESSION:
	case LTTNG_LIST_SESSIONS:
	case LTTNG_LIST_TRACEPOINTS:
		need_tracing_session = 0;
		break;
	default:
		DBG("Getting session %s by name", cmd_ctx->lsm->session.name);
		session_lock_list();
		cmd_ctx->session = session_find_by_name(cmd_ctx->lsm->session.name);
		session_unlock_list();
		if (cmd_ctx->session == NULL) {
			if (cmd_ctx->lsm->session.name != NULL) {
				ret = LTTCOMM_SESS_NOT_FOUND;
			} else {
				/* If no session name specified */
				ret = LTTCOMM_SELECT_SESS;
			}
			goto error;
		} else {
			/* Acquire lock for the session */
			session_lock(cmd_ctx->session);
		}
		break;
	}

	/*
	 * Check domain type for specific "pre-action".
	 */
	switch (cmd_ctx->lsm->domain.type) {
	case LTTNG_DOMAIN_KERNEL:
		/* Kernel tracer check */
		if (kernel_tracer_fd == 0) {
			/* Basically, load kernel tracer modules */
			init_kernel_tracer();
			if (kernel_tracer_fd == 0) {
				ret = LTTCOMM_KERN_NA;
				goto error;
			}
		}

		/* Need a session for kernel command */
		if (need_tracing_session) {
			if (cmd_ctx->session->kernel_session == NULL) {
				ret = create_kernel_session(cmd_ctx->session);
				if (ret < 0) {
					ret = LTTCOMM_KERN_SESS_FAIL;
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
					ret = LTTCOMM_KERN_CONSUMER_FAIL;
					goto error;
				}
			}
			pthread_mutex_unlock(&kconsumer_data.pid_mutex);
		}
		break;
	case LTTNG_DOMAIN_UST_PID:
	{
		struct ltt_ust_session *usess;

		if (need_tracing_session) {
			usess = trace_ust_get_session_by_pid(
					&cmd_ctx->session->ust_session_list,
					cmd_ctx->lsm->domain.attr.pid);
			if (usess == NULL) {
				ret = create_ust_session(cmd_ctx->session,
						&cmd_ctx->lsm->domain);
				if (ret != LTTCOMM_OK) {
					goto error;
				}
			}
		}
		break;
	}
	default:
		/* TODO Userspace tracer */
		break;
	}

	/* Process by command type */
	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_ADD_CONTEXT:
	{
		ret = cmd_add_context(cmd_ctx->session, cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.context.channel_name,
				cmd_ctx->lsm->u.context.event_name,
				&cmd_ctx->lsm->u.context.ctx);
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
		ret = cmd_disable_event(cmd_ctx->session, cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.disable.channel_name,
				cmd_ctx->lsm->u.disable.name);
		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_DISABLE_ALL_EVENT:
	{
		DBG("Disabling all kernel event");

		ret = cmd_disable_event_all(cmd_ctx->session, cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.disable.channel_name);
		break;
	}
	case LTTNG_ENABLE_CHANNEL:
	{
		ret = cmd_enable_channel(cmd_ctx->session, &cmd_ctx->lsm->domain,
				&cmd_ctx->lsm->u.channel.chan);
		break;
	}
	case LTTNG_ENABLE_EVENT:
	{
		ret = cmd_enable_event(cmd_ctx->session, cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.enable.channel_name,
				&cmd_ctx->lsm->u.enable.event);
		break;
	}
	case LTTNG_ENABLE_ALL_EVENT:
	{
		DBG("Enabling all kernel event");

		ret = cmd_enable_event_all(cmd_ctx->session, cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.enable.channel_name,
				cmd_ctx->lsm->u.enable.event.type);
		break;
	}
	case LTTNG_LIST_TRACEPOINTS:
	{
		struct lttng_event *events;
		ssize_t nb_events;

		nb_events = cmd_list_tracepoints(cmd_ctx->lsm->domain.type, &events);
		if (nb_events < 0) {
			ret = -nb_events;
			goto error;
		}

		/*
		 * Setup lttng message with payload size set to the event list size in
		 * bytes and then copy list into the llm payload.
		 */
		ret = setup_lttng_msg(cmd_ctx, sizeof(struct lttng_event) * nb_events);
		if (ret < 0) {
			free(events);
			goto setup_error;
		}

		/* Copy event list into message payload */
		memcpy(cmd_ctx->llm->payload, events,
				sizeof(struct lttng_event) * nb_events);

		free(events);

		ret = LTTCOMM_OK;
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
		ret = cmd_create_session(cmd_ctx->lsm->session.name,
				cmd_ctx->lsm->session.path);
		break;
	}
	case LTTNG_DESTROY_SESSION:
	{
		ret = cmd_destroy_session(cmd_ctx->session,
				cmd_ctx->lsm->session.name);
		break;
	}
	case LTTNG_LIST_DOMAINS:
	{
		ssize_t nb_dom;
		struct lttng_domain *domains;

		nb_dom = cmd_list_domains(cmd_ctx->session, &domains);
		if (nb_dom < 0) {
			ret = -nb_dom;
			goto error;
		}

		ret = setup_lttng_msg(cmd_ctx, nb_dom * sizeof(struct lttng_domain));
		if (ret < 0) {
			goto setup_error;
		}

		/* Copy event list into message payload */
		memcpy(cmd_ctx->llm->payload, domains,
				nb_dom * sizeof(struct lttng_domain));

		free(domains);

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_LIST_CHANNELS:
	{
		size_t nb_chan;
		struct lttng_channel *channels;

		nb_chan = cmd_list_channels(cmd_ctx->session, &channels);
		if (nb_chan < 0) {
			ret = -nb_chan;
			goto error;
		}

		ret = setup_lttng_msg(cmd_ctx, nb_chan * sizeof(struct lttng_channel));
		if (ret < 0) {
			goto setup_error;
		}

		/* Copy event list into message payload */
		memcpy(cmd_ctx->llm->payload, channels,
				nb_chan * sizeof(struct lttng_channel));

		free(channels);

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_LIST_EVENTS:
	{
		size_t nb_event;
		struct lttng_event *events = NULL;

		nb_event = cmd_list_events(cmd_ctx->session,
				cmd_ctx->lsm->u.list.channel_name, &events);
		if (nb_event < 0) {
			ret = -nb_event;
			goto error;
		}

		ret = setup_lttng_msg(cmd_ctx, nb_event * sizeof(struct lttng_event));
		if (ret < 0) {
			goto setup_error;
		}

		/* Copy event list into message payload */
		memcpy(cmd_ctx->llm->payload, events,
				nb_event * sizeof(struct lttng_event));

		free(events);

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_LIST_SESSIONS:
	{
		session_lock_list();

		if (session_list_ptr->count == 0) {
			ret = LTTCOMM_NO_SESSION;
			session_unlock_list();
			goto error;
		}

		ret = setup_lttng_msg(cmd_ctx, sizeof(struct lttng_session) *
				session_list_ptr->count);
		if (ret < 0) {
			session_unlock_list();
			goto setup_error;
		}

		/* Filled the session array */
		list_lttng_sessions((struct lttng_session *)(cmd_ctx->llm->payload));

		session_unlock_list();

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_CALIBRATE:
	{
		ret = cmd_calibrate(cmd_ctx->lsm->domain.type,
				&cmd_ctx->lsm->u.calibrate);
		break;
	}
	case LTTNG_REGISTER_CONSUMER:
	{
		ret = cmd_register_consumer(cmd_ctx->session, cmd_ctx->lsm->domain.type,
				cmd_ctx->lsm->u.reg.path);
		break;
	}
	default:
		ret = LTTCOMM_UND;
		break;
	}

error:
	if (cmd_ctx->llm == NULL) {
		DBG("Missing llm structure. Allocating one.");
		if (setup_lttng_msg(cmd_ctx, 0) < 0) {
			goto setup_error;
		}
	}
	/* Set return code */
	cmd_ctx->llm->ret_code = ret;
setup_error:
	if (cmd_ctx->session) {
		session_unlock(cmd_ctx->session);
	}
init_setup_error:
	return ret;
}

/*
 * This thread manage all clients request using the unix client socket for
 * communication.
 */
static void *thread_manage_clients(void *data)
{
	int sock = 0, ret, i, pollfd;
	uint32_t revents, nb_fd;
	struct command_ctx *cmd_ctx = NULL;
	struct lttng_poll_event events;

	DBG("[thread] Manage client started");

	ret = lttcomm_listen_unix_sock(client_sock);
	if (ret < 0) {
		goto error;
	}

	/*
	 * Pass 2 as size here for the thread quit pipe and client_sock. Nothing
	 * more will be added to this poll set.
	 */
	ret = create_thread_poll_set(&events, 2);
	if (ret < 0) {
		goto error;
	}

	/* Add the application registration socket */
	ret = lttng_poll_add(&events, client_sock, LPOLLIN | LPOLLPRI);
	if (ret < 0) {
		goto error;
	}

	/*
	 * Notify parent pid that we are ready to accept command for client side.
	 */
	if (opt_sig_parent) {
		kill(ppid, SIGCHLD);
	}

	while (1) {
		DBG("Accepting client command ...");

		nb_fd = LTTNG_POLL_GETNB(&events);

		/* Inifinite blocking call, waiting for transmission */
		ret = lttng_poll_wait(&events, -1);
		if (ret < 0) {
			goto error;
		}

		for (i = 0; i < nb_fd; i++) {
			/* Fetch once the poll data */
			revents = LTTNG_POLL_GETEV(&events, i);
			pollfd = LTTNG_POLL_GETFD(&events, i);

			/* Thread quit pipe has been closed. Killing thread. */
			ret = check_thread_quit_pipe(pollfd, revents);
			if (ret) {
				goto error;
			}

			/* Event on the registration socket */
			if (pollfd == client_sock) {
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Client socket poll error");
					goto error;
				}
			}
		}

		DBG("Wait for client response");

		sock = lttcomm_accept_unix_sock(client_sock);
		if (sock < 0) {
			goto error;
		}

		/* Allocate context command to process the client request */
		cmd_ctx = malloc(sizeof(struct command_ctx));
		if (cmd_ctx == NULL) {
			perror("malloc cmd_ctx");
			goto error;
		}

		/* Allocate data buffer for reception */
		cmd_ctx->lsm = malloc(sizeof(struct lttcomm_session_msg));
		if (cmd_ctx->lsm == NULL) {
			perror("malloc cmd_ctx->lsm");
			goto error;
		}

		cmd_ctx->llm = NULL;
		cmd_ctx->session = NULL;

		/*
		 * Data is received from the lttng client. The struct
		 * lttcomm_session_msg (lsm) contains the command and data request of
		 * the client.
		 */
		DBG("Receiving data from client ...");
		ret = lttcomm_recv_unix_sock(sock, cmd_ctx->lsm,
				sizeof(struct lttcomm_session_msg));
		if (ret <= 0) {
			DBG("Nothing recv() from client... continuing");
			close(sock);
			free(cmd_ctx);
			continue;
		}

		// TODO: Validate cmd_ctx including sanity check for
		// security purpose.

		/*
		 * This function dispatch the work to the kernel or userspace tracer
		 * libs and fill the lttcomm_lttng_msg data structure of all the needed
		 * informations for the client. The command context struct contains
		 * everything this function may needs.
		 */
		ret = process_client_msg(cmd_ctx);
		if (ret < 0) {
			/*
			 * TODO: Inform client somehow of the fatal error. At
			 * this point, ret < 0 means that a malloc failed
			 * (ENOMEM). Error detected but still accept command.
			 */
			clean_command_ctx(&cmd_ctx);
			continue;
		}

		DBG("Sending response (size: %d, retcode: %s)",
				cmd_ctx->lttng_msg_size,
				lttng_get_readable_code(-cmd_ctx->llm->ret_code));
		ret = send_unix_sock(sock, cmd_ctx->llm, cmd_ctx->lttng_msg_size);
		if (ret < 0) {
			ERR("Failed to send data back to client");
		}

		clean_command_ctx(&cmd_ctx);

		/* End of transmission */
		close(sock);
	}

error:
	DBG("Client thread dying");
	unlink(client_unix_sock_path);
	close(client_sock);
	close(sock);

	lttng_poll_clean(&events);
	clean_command_ctx(&cmd_ctx);
	return NULL;
}


/*
 * usage function on stderr
 */
static void usage(void)
{
	fprintf(stderr, "Usage: %s OPTIONS\n\nOptions:\n", progname);
	fprintf(stderr, "  -h, --help                         Display this usage.\n");
	fprintf(stderr, "  -c, --client-sock PATH             Specify path for the client unix socket\n");
	fprintf(stderr, "  -a, --apps-sock PATH               Specify path for apps unix socket\n");
	fprintf(stderr, "      --kconsumerd-err-sock PATH     Specify path for the kernel consumer error socket\n");
	fprintf(stderr, "      --kconsumerd-cmd-sock PATH     Specify path for the kernel consumer command socket\n");
	fprintf(stderr, "      --ustconsumerd-err-sock PATH   Specify path for the UST consumer error socket\n");
	fprintf(stderr, "      --ustconsumerd-cmd-sock PATH   Specify path for the UST consumer command socket\n");
	fprintf(stderr, "  -d, --daemonize                    Start as a daemon.\n");
	fprintf(stderr, "  -g, --group NAME                   Specify the tracing group name. (default: tracing)\n");
	fprintf(stderr, "  -V, --version                      Show version number.\n");
	fprintf(stderr, "  -S, --sig-parent                   Send SIGCHLD to parent pid to notify readiness.\n");
	fprintf(stderr, "  -q, --quiet                        No output at all.\n");
	fprintf(stderr, "  -v, --verbose                      Verbose mode. Activate DBG() macro.\n");
	fprintf(stderr, "      --verbose-consumer             Verbose mode for consumer. Activate DBG() macro.\n");
}

/*
 * daemon argument parsing
 */
static int parse_args(int argc, char **argv)
{
	int c;

	static struct option long_options[] = {
		{ "client-sock", 1, 0, 'c' },
		{ "apps-sock", 1, 0, 'a' },
		{ "kconsumerd-cmd-sock", 1, 0, 'C' },
		{ "kconsumerd-err-sock", 1, 0, 'E' },
		{ "ustconsumerd-cmd-sock", 1, 0, 'D' },
		{ "ustconsumerd-err-sock", 1, 0, 'F' },
		{ "daemonize", 0, 0, 'd' },
		{ "sig-parent", 0, 0, 'S' },
		{ "help", 0, 0, 'h' },
		{ "group", 1, 0, 'g' },
		{ "version", 0, 0, 'V' },
		{ "quiet", 0, 0, 'q' },
		{ "verbose", 0, 0, 'v' },
		{ "verbose-consumer", 0, 0, 'Z' },
		{ NULL, 0, 0, 0 }
	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "dhqvVS" "a:c:g:s:C:E:D:F:Z",
				long_options, &option_index);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 0:
			fprintf(stderr, "option %s", long_options[option_index].name);
			if (optarg) {
				fprintf(stderr, " with arg %s\n", optarg);
			}
			break;
		case 'c':
			snprintf(client_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'a':
			snprintf(apps_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'd':
			opt_daemon = 1;
			break;
		case 'g':
			opt_tracing_group = strdup(optarg);
			break;
		case 'h':
			usage();
			exit(EXIT_FAILURE);
		case 'V':
			fprintf(stdout, "%s\n", VERSION);
			exit(EXIT_SUCCESS);
		case 'S':
			opt_sig_parent = 1;
			break;
		case 'E':
			snprintf(kconsumer_data.err_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'C':
			snprintf(kconsumer_data.cmd_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'F':
			snprintf(ustconsumer_data.err_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'D':
			snprintf(ustconsumer_data.cmd_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'q':
			opt_quiet = 1;
			break;
		case 'v':
			/* Verbose level can increase using multiple -v */
			opt_verbose += 1;
			break;
		case 'Z':
			opt_verbose_consumer += 1;
			break;
		default:
			/* Unknown option or other error.
			 * Error is printed by getopt, just return */
			return -1;
		}
	}

	return 0;
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
	client_sock = lttcomm_create_unix_sock(client_unix_sock_path);
	if (client_sock < 0) {
		ERR("Create unix sock failed: %s", client_unix_sock_path);
		ret = -1;
		goto end;
	}

	/* File permission MUST be 660 */
	ret = chmod(client_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", client_unix_sock_path);
		perror("chmod");
		goto end;
	}

	/* Create the application unix socket */
	apps_sock = lttcomm_create_unix_sock(apps_unix_sock_path);
	if (apps_sock < 0) {
		ERR("Create unix sock failed: %s", apps_unix_sock_path);
		ret = -1;
		goto end;
	}

	/* File permission MUST be 666 */
	ret = chmod(apps_unix_sock_path,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", apps_unix_sock_path);
		perror("chmod");
		goto end;
	}

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
	if (access(client_unix_sock_path, F_OK) < 0 &&
			access(apps_unix_sock_path, F_OK) < 0) {
		return 0;
	}

	/* Is there anybody out there ? */
	if (lttng_session_daemon_alive()) {
		return -EEXIST;
	} else {
		return 0;
	}
}

/*
 * Set the tracing group gid onto the client socket.
 *
 * Race window between mkdir and chown is OK because we are going from more
 * permissive (root.root) to les permissive (root.tracing).
 */
static int set_permissions(void)
{
	int ret;
	gid_t gid;

	gid = allowed_group();
	if (gid < 0) {
		if (is_root) {
			WARN("No tracing group detected");
			ret = 0;
		} else {
			ERR("Missing tracing group. Aborting execution.");
			ret = -1;
		}
		goto end;
	}

	/* Set lttng run dir */
	ret = chown(LTTNG_RUNDIR, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on " LTTNG_RUNDIR);
		perror("chown");
	}

	/* lttng client socket path */
	ret = chown(client_unix_sock_path, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", client_unix_sock_path);
		perror("chown");
	}

	/* kconsumer error socket path */
	ret = chown(kconsumer_data.err_unix_sock_path, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", kconsumer_data.err_unix_sock_path);
		perror("chown");
	}

	/* ustconsumer error socket path */
	ret = chown(ustconsumer_data.err_unix_sock_path, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", ustconsumer_data.err_unix_sock_path);
		perror("chown");
	}

	DBG("All permissions are set");

end:
	return ret;
}

/*
 * Create the pipe used to wake up the kernel thread.
 */
static int create_kernel_poll_pipe(void)
{
	return pipe2(kernel_poll_pipe, O_CLOEXEC);
}

/*
 * Create the application command pipe to wake thread_manage_apps.
 */
static int create_apps_cmd_pipe(void)
{
	return pipe2(apps_cmd_pipe, O_CLOEXEC);
}

/*
 * Create the lttng run directory needed for all global sockets and pipe.
 */
static int create_lttng_rundir(void)
{
	int ret;

	ret = mkdir(LTTNG_RUNDIR, S_IRWXU | S_IRWXG );
	if (ret < 0) {
		if (errno != EEXIST) {
			ERR("Unable to create " LTTNG_RUNDIR);
			goto error;
		} else {
			ret = 0;
		}
	}

error:
	return ret;
}

/*
 * Setup sockets and directory needed by the kconsumerd communication with the
 * session daemon.
 */
static int set_consumer_sockets(struct consumer_data *consumer_data)
{
	int ret;
	const char *path = consumer_data->type == LTTNG_CONSUMER_KERNEL ?
			KCONSUMERD_PATH : USTCONSUMERD_PATH;

	if (strlen(consumer_data->err_unix_sock_path) == 0) {
		snprintf(consumer_data->err_unix_sock_path, PATH_MAX,
			consumer_data->type == LTTNG_CONSUMER_KERNEL ?
				KCONSUMERD_ERR_SOCK_PATH :
				USTCONSUMERD_ERR_SOCK_PATH);
	}

	if (strlen(consumer_data->cmd_unix_sock_path) == 0) {
		snprintf(consumer_data->cmd_unix_sock_path, PATH_MAX,
			consumer_data->type == LTTNG_CONSUMER_KERNEL ?
				KCONSUMERD_CMD_SOCK_PATH :
				USTCONSUMERD_CMD_SOCK_PATH);
	}

	ret = mkdir(path, S_IRWXU | S_IRWXG);
	if (ret < 0) {
		if (errno != EEXIST) {
			ERR("Failed to create %s", path);
			goto error;
		}
		ret = 0;
	}

	/* Create the kconsumerd error unix socket */
	consumer_data->err_sock =
		lttcomm_create_unix_sock(consumer_data->err_unix_sock_path);
	if (consumer_data->err_sock < 0) {
		ERR("Create unix sock failed: %s", consumer_data->err_unix_sock_path);
		ret = -1;
		goto error;
	}

	/* File permission MUST be 660 */
	ret = chmod(consumer_data->err_unix_sock_path,
			S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", consumer_data->err_unix_sock_path);
		perror("chmod");
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
	case SIGPIPE:
		DBG("SIGPIPE catched");
		return;
	case SIGINT:
		DBG("SIGINT catched");
		stop_threads();
		break;
	case SIGTERM:
		DBG("SIGTERM catched");
		stop_threads();
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
		perror("sigemptyset");
		return ret;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGINT, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	if ((ret = sigaction(SIGPIPE, &sa, NULL)) < 0) {
		perror("sigaction");
		return ret;
	}

	DBG("Signal handler set for SIGTERM, SIGPIPE and SIGINT");

	return ret;
}

/*
 * Set open files limit to unlimited. This daemon can open a large number of
 * file descriptors in order to consumer multiple kernel traces.
 */
static void set_ulimit(void)
{
	int ret;
	struct rlimit lim;

	/* The kernel does not allowed an infinite limit for open files */
	lim.rlim_cur = 65535;
	lim.rlim_max = 65535;

	ret = setrlimit(RLIMIT_NOFILE, &lim);
	if (ret < 0) {
		perror("failed to set open files limit");
	}
}

/*
 * main
 */
int main(int argc, char **argv)
{
	int ret = 0;
	void *status;
	const char *home_path;

	/* Create thread quit pipe */
	if ((ret = init_thread_quit_pipe()) < 0) {
		goto error;
	}

	/* Parse arguments */
	progname = argv[0];
	if ((ret = parse_args(argc, argv) < 0)) {
		goto error;
	}

	/* Daemonize */
	if (opt_daemon) {
		ret = daemon(0, 0);
		if (ret < 0) {
			perror("daemon");
			goto error;
		}
	}

	/* Check if daemon is UID = 0 */
	is_root = !getuid();

	if (is_root) {
		ret = create_lttng_rundir();
		if (ret < 0) {
			goto error;
		}

		if (strlen(apps_unix_sock_path) == 0) {
			snprintf(apps_unix_sock_path, PATH_MAX,
					DEFAULT_GLOBAL_APPS_UNIX_SOCK);
		}

		if (strlen(client_unix_sock_path) == 0) {
			snprintf(client_unix_sock_path, PATH_MAX,
					DEFAULT_GLOBAL_CLIENT_UNIX_SOCK);
		}

		/* Set global SHM for ust */
		if (strlen(wait_shm_path) == 0) {
			snprintf(wait_shm_path, PATH_MAX,
					DEFAULT_GLOBAL_APPS_WAIT_SHM_PATH);
		}
	} else {
		home_path = get_home_dir();
		if (home_path == NULL) {
			/* TODO: Add --socket PATH option */
			ERR("Can't get HOME directory for sockets creation.");
			ret = -EPERM;
			goto error;
		}

		if (strlen(apps_unix_sock_path) == 0) {
			snprintf(apps_unix_sock_path, PATH_MAX,
					DEFAULT_HOME_APPS_UNIX_SOCK, home_path);
		}

		/* Set the cli tool unix socket path */
		if (strlen(client_unix_sock_path) == 0) {
			snprintf(client_unix_sock_path, PATH_MAX,
					DEFAULT_HOME_CLIENT_UNIX_SOCK, home_path);
		}

		/* Set global SHM for ust */
		if (strlen(wait_shm_path) == 0) {
			snprintf(wait_shm_path, PATH_MAX,
					DEFAULT_HOME_APPS_WAIT_SHM_PATH, geteuid());
		}
	}

	DBG("Client socket path %s", client_unix_sock_path);
	DBG("Application socket path %s", apps_unix_sock_path);

	/*
	 * See if daemon already exist.
	 */
	if ((ret = check_existing_daemon()) < 0) {
		ERR("Already running daemon.\n");
		/*
		 * We do not goto exit because we must not cleanup()
		 * because a daemon is already running.
		 */
		goto error;
	}

	/* After this point, we can safely call cleanup() with "goto exit" */

	/*
	 * These actions must be executed as root. We do that *after* setting up
	 * the sockets path because we MUST make the check for another daemon using
	 * those paths *before* trying to set the kernel consumer sockets and init
	 * kernel tracer.
	 */
	if (is_root) {
		ret = set_consumer_sockets(&kconsumer_data);
		if (ret < 0) {
			goto exit;
		}
		ret = set_consumer_sockets(&ustconsumer_data);
		if (ret < 0) {
			goto exit;
		}
		/* Setup kernel tracer */
		init_kernel_tracer();

		/* Set ulimit for open files */
		set_ulimit();
	}

	if ((ret = set_signal_handler()) < 0) {
		goto exit;
	}

	/* Setup the needed unix socket */
	if ((ret = init_daemon_socket()) < 0) {
		goto exit;
	}

	/* Set credentials to socket */
	if (is_root && ((ret = set_permissions()) < 0)) {
		goto exit;
	}

	/* Get parent pid if -S, --sig-parent is specified. */
	if (opt_sig_parent) {
		ppid = getppid();
	}

	/* Setup the kernel pipe for waking up the kernel thread */
	if ((ret = create_kernel_poll_pipe()) < 0) {
		goto exit;
	}

	/* Setup the thread apps communication pipe. */
	if ((ret = create_apps_cmd_pipe()) < 0) {
		goto exit;
	}

	/* Init UST command queue. */
	cds_wfq_init(&ust_cmd_queue.queue);

	/*
	 * Get session list pointer. This pointer MUST NOT be free(). This list is
	 * statically declared in session.c
	 */
	session_list_ptr = session_get_list();

	/* Set up max poll set size */
	lttng_poll_set_max_size();

	/* Create thread to manage the client socket */
	ret = pthread_create(&client_thread, NULL,
			thread_manage_clients, (void *) NULL);
	if (ret != 0) {
		perror("pthread_create clients");
		goto exit_client;
	}

	/* Create thread to dispatch registration */
	ret = pthread_create(&dispatch_thread, NULL,
			thread_dispatch_ust_registration, (void *) NULL);
	if (ret != 0) {
		perror("pthread_create dispatch");
		goto exit_dispatch;
	}

	/* Create thread to manage application registration. */
	ret = pthread_create(&reg_apps_thread, NULL,
			thread_registration_apps, (void *) NULL);
	if (ret != 0) {
		perror("pthread_create registration");
		goto exit_reg_apps;
	}

	/* Create thread to manage application socket */
	ret = pthread_create(&apps_thread, NULL,
			thread_manage_apps, (void *) NULL);
	if (ret != 0) {
		perror("pthread_create apps");
		goto exit_apps;
	}

	/* Create kernel thread to manage kernel event */
	ret = pthread_create(&kernel_thread, NULL,
			thread_manage_kernel, (void *) NULL);
	if (ret != 0) {
		perror("pthread_create kernel");
		goto exit_kernel;
	}

	ret = pthread_join(kernel_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;	/* join error, exit without cleanup */
	}

exit_kernel:
	ret = pthread_join(apps_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;	/* join error, exit without cleanup */
	}

exit_apps:
	ret = pthread_join(reg_apps_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;	/* join error, exit without cleanup */
	}

exit_reg_apps:
	ret = pthread_join(dispatch_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;	/* join error, exit without cleanup */
	}

exit_dispatch:
	ret = pthread_join(client_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;	/* join error, exit without cleanup */
	}

	ret = join_consumer_thread(&kconsumer_data);
	if (ret != 0) {
		perror("join_consumer");
		goto error;	/* join error, exit without cleanup */
	}

exit_client:
exit:
	/*
	 * cleanup() is called when no other thread is running.
	 */
	cleanup();
	if (!ret)
		exit(EXIT_SUCCESS);
error:
	exit(EXIT_FAILURE);
}
