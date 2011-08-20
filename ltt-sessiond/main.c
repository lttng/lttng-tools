/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>

#include <urcu/list.h>		/* URCU list library (-lurcu) */
#include <lttng/lttng.h>
#include <lttng/lttng-kconsumerd.h>
#include <lttng-sessiond-comm.h>

#include "context.h"
#include "ltt-sessiond.h"
#include "lttngerr.h"
#include "kernel-ctl.h"
#include "ust-ctl.h"
#include "session.h"
#include "traceable-app.h"
#include "ltt-kconsumerd.h"
#include "utils.h"

/* Const values */
const char default_home_dir[] = DEFAULT_HOME_DIR;
const char default_tracing_group[] = LTTNG_DEFAULT_TRACING_GROUP;
const char default_ust_sock_dir[] = DEFAULT_UST_SOCK_DIR;
const char default_global_apps_pipe[] = DEFAULT_GLOBAL_APPS_PIPE;

/* Variables */
int opt_verbose;    /* Not static for lttngerr.h */
int opt_verbose_kconsumerd;    /* Not static for lttngerr.h */
int opt_quiet;      /* Not static for lttngerr.h */

const char *progname;
const char *opt_tracing_group;
static int opt_sig_parent;
static int opt_daemon;
static int is_root;			/* Set to 1 if the daemon is running as root */
static pid_t ppid;          /* Parent PID for --sig-parent option */
static pid_t kconsumerd_pid;
static struct pollfd *kernel_pollfd;

static char apps_unix_sock_path[PATH_MAX];				/* Global application Unix socket path */
static char client_unix_sock_path[PATH_MAX];			/* Global client Unix socket path */
static char kconsumerd_err_unix_sock_path[PATH_MAX];	/* kconsumerd error Unix socket path */
static char kconsumerd_cmd_unix_sock_path[PATH_MAX];	/* kconsumerd command Unix socket path */

/* Sockets and FDs */
static int client_sock;
static int apps_sock;
static int kconsumerd_err_sock;
static int kconsumerd_cmd_sock;
static int kernel_tracer_fd;
static int kernel_poll_pipe[2];

/*
 * Quit pipe for all threads. This permits a single cancellation point
 * for all threads when receiving an event on the pipe.
 */
static int thread_quit_pipe[2];

/* Pthread, Mutexes and Semaphores */
static pthread_t kconsumerd_thread;
static pthread_t apps_thread;
static pthread_t client_thread;
static pthread_t kernel_thread;
static sem_t kconsumerd_sem;

static pthread_mutex_t kconsumerd_pid_mutex;	/* Mutex to control kconsumerd pid assignation */

static int modprobe_remove_kernel_modules(void);

/*
 * Pointer initialized before thread creation.
 *
 * This points to the tracing session list containing the session count and a
 * mutex lock. The lock MUST be taken if you iterate over the list. The lock
 * MUST NOT be taken if you call a public function in session.c.
 *
 * The lock is nested inside the structure: session_list_ptr->lock. Please use
 * lock_session_list and unlock_session_list for lock acquisition.
 */
static struct ltt_session_list *session_list_ptr;

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
 * Init quit pipe.
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
		if (session->kernel_session->consumer_fd != kconsumerd_cmd_sock) {
			lttcomm_close_unix_sock(session->kernel_session->consumer_fd);
		}

		trace_destroy_kernel_session(session->kernel_session);
		/* Extra precaution */
		session->kernel_session = NULL;
	}
}

static void stop_threads(void)
{
	/* Stopping all threads */
	DBG("Terminating all threads");
	close(thread_quit_pipe[0]);
	close(thread_quit_pipe[1]);
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
	MSG("\n%c[%d;%dm*** assert failed *** ==> %c[%dm%c[%d;%dm"
		"Matthew, BEET driven development works!%c[%dm",
		27, 1, 31, 27, 0, 27, 1, 33, 27, 0);
	/* </fun> */

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

	DBG("Cleaning up all session");

	/* Destroy session list mutex */
	if (session_list_ptr != NULL) {
		pthread_mutex_destroy(&session_list_ptr->lock);

		/* Cleanup ALL session */
		cds_list_for_each_entry_safe(sess, stmp, &session_list_ptr->head, list) {
			teardown_kernel_session(sess);
			// TODO complete session cleanup (including UST)
		}
	}

	pthread_mutex_destroy(&kconsumerd_pid_mutex);

	DBG("Closing kernel fd");
	close(kernel_tracer_fd);

	DBG("Unloading kernel modules");
	modprobe_remove_kernel_modules();
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
static int send_kconsumerd_channel_fds(int sock, struct ltt_kernel_channel *channel)
{
	int ret;
	size_t nb_fd;
	struct ltt_kernel_stream *stream;
	struct lttcomm_kconsumerd_header lkh;
	struct lttcomm_kconsumerd_msg lkm;

	DBG("Sending fds of channel %s to kernel consumer", channel->channel->name);

	nb_fd = channel->stream_count;

	/* Setup header */
	lkh.payload_size = nb_fd * sizeof(struct lttcomm_kconsumerd_msg);
	lkh.cmd_type = ADD_STREAM;

	DBG("Sending kconsumerd header");

	ret = lttcomm_send_unix_sock(sock, &lkh, sizeof(struct lttcomm_kconsumerd_header));
	if (ret < 0) {
		perror("send kconsumerd header");
		goto error;
	}

	cds_list_for_each_entry(stream, &channel->stream_list.head, list) {
		if (stream->fd != 0) {
			lkm.fd = stream->fd;
			lkm.state = stream->state;
			lkm.max_sb_size = channel->channel->attr.subbuf_size;
			lkm.output = channel->channel->attr.output;
			strncpy(lkm.path_name, stream->pathname, PATH_MAX);
			lkm.path_name[PATH_MAX - 1] = '\0';

			DBG("Sending fd %d to kconsumerd", lkm.fd);

			ret = lttcomm_send_fds_unix_sock(sock, &lkm, &lkm.fd, 1, sizeof(lkm));
			if (ret < 0) {
				perror("send kconsumerd fd");
				goto error;
			}
		}
	}

	DBG("Kconsumerd channel fds sent");

	return 0;

error:
	return ret;
}

/*
 * Send all stream fds of the kernel session to the consumer.
 */
static int send_kconsumerd_fds(struct ltt_kernel_session *session)
{
	int ret;
	struct ltt_kernel_channel *chan;
	struct lttcomm_kconsumerd_header lkh;
	struct lttcomm_kconsumerd_msg lkm;

	/* Setup header */
	lkh.payload_size = sizeof(struct lttcomm_kconsumerd_msg);
	lkh.cmd_type = ADD_STREAM;

	DBG("Sending kconsumerd header for metadata");

	ret = lttcomm_send_unix_sock(session->consumer_fd, &lkh, sizeof(struct lttcomm_kconsumerd_header));
	if (ret < 0) {
		perror("send kconsumerd header");
		goto error;
	}

	DBG("Sending metadata stream fd");

	/* Extra protection. It's NOT suppose to be set to 0 at this point */
	if (session->consumer_fd == 0) {
		session->consumer_fd = kconsumerd_cmd_sock;
	}

	if (session->metadata_stream_fd != 0) {
		/* Send metadata stream fd first */
		lkm.fd = session->metadata_stream_fd;
		lkm.state = ACTIVE_FD;
		lkm.max_sb_size = session->metadata->conf->attr.subbuf_size;
		lkm.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		strncpy(lkm.path_name, session->metadata->pathname, PATH_MAX);
		lkm.path_name[PATH_MAX - 1] = '\0';

		ret = lttcomm_send_fds_unix_sock(session->consumer_fd, &lkm, &lkm.fd, 1, sizeof(lkm));
		if (ret < 0) {
			perror("send kconsumerd fd");
			goto error;
		}
	}

	cds_list_for_each_entry(chan, &session->channel_list.head, list) {
		ret = send_kconsumerd_channel_fds(session->consumer_fd, chan);
		if (ret < 0) {
			goto error;
		}
	}

	DBG("Kconsumerd fds (metadata and channel streams) sent");

	return 0;

error:
	return ret;
}

#ifdef DISABLED
/*
 * Return a socket connected to the libust communication socket of the
 * application identified by the pid.
 *
 * If the pid is not found in the traceable list, return -1 to indicate error.
 */
static int ust_connect_app(pid_t pid)
{
	int sock;
	struct ltt_traceable_app *lta;

	DBG("Connect to application pid %d", pid);

	lta = find_app_by_pid(pid);
	if (lta == NULL) {
		/* App not found */
		DBG("Application pid %d not found", pid);
		return -1;
	}

	sock = ustctl_connect_pid(lta->pid);
	if (sock < 0) {
		ERR("Fail connecting to the PID %d", pid);
	}

	return sock;
}
#endif	/* DISABLED */

/*
 * Notify apps by writing 42 to a named pipe using name. Every applications
 * waiting for a ltt-sessiond will be notified and re-register automatically to
 * the session daemon.
 *
 * Return open or write error value.
 */
static int notify_apps(const char *name)
{
	int fd;
	int ret = -1;

	DBG("Notify the global application pipe");

	/* Try opening the global pipe */
	fd = open(name, O_WRONLY);
	if (fd < 0) {
		goto error;
	}

	/* Notify by writing on the pipe */
	ret = write(fd, "42", 2);
	if (ret < 0) {
		perror("write");
	}

error:
	return ret;
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
 * Update the kernel pollfd set of all channel fd available over all tracing
 * session. Add the wakeup pipe at the end of the set.
 */
static int update_kernel_pollfd(void)
{
	int i = 0;
	/*
	 * The wakup pipe and the quit pipe are needed so the number of fds starts
	 * at 2 for those pipes.
	 */
	unsigned int nb_fd = 2;
	struct ltt_session *session;
	struct ltt_kernel_channel *channel;

	DBG("Updating kernel_pollfd");

	/* Get the number of channel of all kernel session */
	lock_session_list();
	cds_list_for_each_entry(session, &session_list_ptr->head, list) {
		lock_session(session);
		if (session->kernel_session == NULL) {
			unlock_session(session);
			continue;
		}
		nb_fd += session->kernel_session->channel_count;
		unlock_session(session);
	}

	DBG("Resizing kernel_pollfd to size %d", nb_fd);

	kernel_pollfd = realloc(kernel_pollfd, nb_fd * sizeof(struct pollfd));
	if (kernel_pollfd == NULL) {
		perror("malloc kernel_pollfd");
		goto error;
	}

	cds_list_for_each_entry(session, &session_list_ptr->head, list) {
		lock_session(session);
		if (session->kernel_session == NULL) {
			unlock_session(session);
			continue;
		}
		if (i >= nb_fd) {
			ERR("To much channel for kernel_pollfd size");
			unlock_session(session);
			break;
		}
		cds_list_for_each_entry(channel, &session->kernel_session->channel_list.head, list) {
			kernel_pollfd[i].fd = channel->fd;
			kernel_pollfd[i].events = POLLIN | POLLRDNORM;
			i++;
		}
		unlock_session(session);
	}
	unlock_session_list();

	/* Adding wake up pipe */
	kernel_pollfd[nb_fd - 2].fd = kernel_poll_pipe[0];
	kernel_pollfd[nb_fd - 2].events = POLLIN;

	/* Adding the quit pipe */
	kernel_pollfd[nb_fd - 1].fd = thread_quit_pipe[0];

	return nb_fd;

error:
	unlock_session_list();
	return -1;
}

/*
 * Find the channel fd from 'fd' over all tracing session.  When found, check
 * for new channel stream and send those stream fds to the kernel consumer.
 *
 * Useful for CPU hotplug feature.
 */
static int update_kernel_stream(int fd)
{
	int ret = 0;
	struct ltt_session *session;
	struct ltt_kernel_channel *channel;

	DBG("Updating kernel streams for channel fd %d", fd);

	lock_session_list();
	cds_list_for_each_entry(session, &session_list_ptr->head, list) {
		lock_session(session);
		if (session->kernel_session == NULL) {
			unlock_session(session);
			continue;
		}

		/* This is not suppose to be 0 but this is an extra security check */
		if (session->kernel_session->consumer_fd == 0) {
			session->kernel_session->consumer_fd = kconsumerd_cmd_sock;
		}

		cds_list_for_each_entry(channel, &session->kernel_session->channel_list.head, list) {
			if (channel->fd == fd) {
				DBG("Channel found, updating kernel streams");
				ret = kernel_open_channel_stream(channel);
				if (ret < 0) {
					goto end;
				}

				/*
				 * Have we already sent fds to the consumer? If yes, it means that
				 * tracing is started so it is safe to send our updated stream fds.
				 */
				if (session->kernel_session->kconsumer_fds_sent == 1) {
					ret = send_kconsumerd_channel_fds(session->kernel_session->consumer_fd,
							channel);
					if (ret < 0) {
						goto end;
					}
				}
				goto end;
			}
		}
		unlock_session(session);
	}

end:
	unlock_session_list();
	if (session) {
		unlock_session(session);
	}
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
	int ret, i, nb_fd = 0;
	char tmp;
	int update_poll_flag = 1;

	DBG("Thread manage kernel started");

	while (1) {
		if (update_poll_flag == 1) {
			nb_fd = update_kernel_pollfd();
			if (nb_fd < 0) {
				goto error;
			}
			update_poll_flag = 0;
		}

		DBG("Polling on %d fds", nb_fd);

		/* Poll infinite value of time */
		ret = poll(kernel_pollfd, nb_fd, -1);
		if (ret < 0) {
			perror("poll kernel thread");
			goto error;
		} else if (ret == 0) {
			/* Should not happen since timeout is infinite */
			continue;
		}

		/* Thread quit pipe has been closed. Killing thread. */
		if (kernel_pollfd[nb_fd - 1].revents == POLLNVAL) {
			goto error;
		}

		DBG("Kernel poll event triggered");

		/*
		 * Check if the wake up pipe was triggered. If so, the kernel_pollfd
		 * must be updated.
		 */
		switch (kernel_pollfd[nb_fd - 2].revents) {
		case POLLIN:
			ret = read(kernel_poll_pipe[0], &tmp, 1);
			update_poll_flag = 1;
			continue;
		case POLLERR:
			goto error;
		default:
			break;
		}

		for (i = 0; i < nb_fd; i++) {
			switch (kernel_pollfd[i].revents) {
			/*
			 * New CPU detected by the kernel. Adding kernel stream to kernel
			 * session and updating the kernel consumer
			 */
			case POLLIN | POLLRDNORM:
				ret = update_kernel_stream(kernel_pollfd[i].fd);
				if (ret < 0) {
					continue;
				}
				break;
			}
		}
	}

error:
	DBG("Kernel thread dying");
	if (kernel_pollfd) {
		free(kernel_pollfd);
	}

	close(kernel_poll_pipe[0]);
	close(kernel_poll_pipe[1]);
	return NULL;
}

/*
 * This thread manage the kconsumerd error sent back to the session daemon.
 */
static void *thread_manage_kconsumerd(void *data)
{
	int sock = 0, ret;
	enum lttcomm_return_code code;
	struct pollfd pollfd[2];

	DBG("[thread] Manage kconsumerd started");

	ret = lttcomm_listen_unix_sock(kconsumerd_err_sock);
	if (ret < 0) {
		goto error;
	}

	/* First fd is always the quit pipe */
	pollfd[0].fd = thread_quit_pipe[0];

	/* Apps socket */
	pollfd[1].fd = kconsumerd_err_sock;
	pollfd[1].events = POLLIN;

	/* Inifinite blocking call, waiting for transmission */
	ret = poll(pollfd, 2, -1);
	if (ret < 0) {
		perror("poll kconsumerd thread");
		goto error;
	}

	/* Thread quit pipe has been closed. Killing thread. */
	if (pollfd[0].revents == POLLNVAL) {
		goto error;
	} else if (pollfd[1].revents == POLLERR) {
		ERR("Kconsumerd err socket poll error");
		goto error;
	}

	sock = lttcomm_accept_unix_sock(kconsumerd_err_sock);
	if (sock < 0) {
		goto error;
	}

	/* Getting status code from kconsumerd */
	ret = lttcomm_recv_unix_sock(sock, &code, sizeof(enum lttcomm_return_code));
	if (ret <= 0) {
		goto error;
	}

	if (code == KCONSUMERD_COMMAND_SOCK_READY) {
		kconsumerd_cmd_sock = lttcomm_connect_unix_sock(kconsumerd_cmd_unix_sock_path);
		if (kconsumerd_cmd_sock < 0) {
			sem_post(&kconsumerd_sem);
			perror("kconsumerd connect");
			goto error;
		}
		/* Signal condition to tell that the kconsumerd is ready */
		sem_post(&kconsumerd_sem);
		DBG("Kconsumerd command socket ready");
	} else {
		DBG("Kconsumerd error when waiting for SOCK_READY : %s",
				lttcomm_get_readable_code(-code));
		goto error;
	}

	/* Kconsumerd err socket */
	pollfd[1].fd = sock;
	pollfd[1].events = POLLIN;

	/* Inifinite blocking call, waiting for transmission */
	ret = poll(pollfd, 2, -1);
	if (ret < 0) {
		perror("poll kconsumerd thread");
		goto error;
	}

	/* Thread quit pipe has been closed. Killing thread. */
	if (pollfd[0].revents == POLLNVAL) {
		goto error;
	} else if (pollfd[1].revents == POLLERR) {
		ERR("Kconsumerd err socket second poll error");
		goto error;
	}

	/* Wait for any kconsumerd error */
	ret = lttcomm_recv_unix_sock(sock, &code, sizeof(enum lttcomm_return_code));
	if (ret <= 0) {
		ERR("Kconsumerd closed the command socket");
		goto error;
	}

	ERR("Kconsumerd return code : %s", lttcomm_get_readable_code(-code));

error:
	DBG("Kconsumerd thread dying");
	if (kconsumerd_err_sock) {
		close(kconsumerd_err_sock);
	}
	if (kconsumerd_cmd_sock) {
		close(kconsumerd_cmd_sock);
	}
	if (sock) {
		close(sock);
	}

	unlink(kconsumerd_err_unix_sock_path);
	unlink(kconsumerd_cmd_unix_sock_path);

	kconsumerd_pid = 0;
	return NULL;
}

/*
 * 	This thread manage the application socket communication
 */
static void *thread_manage_apps(void *data)
{
	int sock = 0, ret;
	struct pollfd pollfd[2];

	/* TODO: Something more elegant is needed but fine for now */
	/* FIXME: change all types to either uint8_t, uint32_t, uint64_t
	 * for 32-bit vs 64-bit compat processes. */
	/* replicate in ust with version number */
	struct {
		int reg;	/* 1:register, 0:unregister */
		pid_t pid;
		uid_t uid;
	} reg_msg;

	DBG("[thread] Manage apps started");

	ret = lttcomm_listen_unix_sock(apps_sock);
	if (ret < 0) {
		goto error;
	}

	/* First fd is always the quit pipe */
	pollfd[0].fd = thread_quit_pipe[0];

	/* Apps socket */
	pollfd[1].fd = apps_sock;
	pollfd[1].events = POLLIN;

	/* Notify all applications to register */
	notify_apps(default_global_apps_pipe);

	while (1) {
		DBG("Accepting application registration");

		/* Inifinite blocking call, waiting for transmission */
		ret = poll(pollfd, 2, -1);
		if (ret < 0) {
			perror("poll apps thread");
			goto error;
		}

		/* Thread quit pipe has been closed. Killing thread. */
		if (pollfd[0].revents == POLLNVAL) {
			goto error;
		} else if (pollfd[1].revents == POLLERR) {
			ERR("Apps socket poll error");
			goto error;
		}

		sock = lttcomm_accept_unix_sock(apps_sock);
		if (sock < 0) {
			goto error;
		}

		/*
		 * Using message-based transmissions to ensure we don't
		 * have to deal with partially received messages.
		 */
		ret = lttcomm_recv_unix_sock(sock, &reg_msg, sizeof(reg_msg));
		if (ret < 0) {
			perror("recv");
			continue;
		}

		/* Add application to the global traceable list */
		if (reg_msg.reg == 1) {
			/* Registering */
			/*
			 * TODO: socket should be either passed to a
			 * listener thread (for more messages) or
			 * closed. It currently leaks.
			 */
			ret = register_traceable_app(reg_msg.pid, reg_msg.uid);
			if (ret < 0) {
				/* register_traceable_app only return an error with
				 * ENOMEM. At this point, we better stop everything.
				 */
				goto error;
			}
		} else {
			/* Unregistering */
			unregister_traceable_app(reg_msg.pid);
		}
	}

error:
	DBG("Apps thread dying");
	if (apps_sock) {
		close(apps_sock);
	}
	if (sock) {
		close(sock);
	}

	unlink(apps_unix_sock_path);
	return NULL;
}

/*
 * Start the thread_manage_kconsumerd. This must be done after a kconsumerd
 * exec or it will fails.
 */
static int spawn_kconsumerd_thread(void)
{
	int ret;

	/* Setup semaphore */
	sem_init(&kconsumerd_sem, 0, 0);

	ret = pthread_create(&kconsumerd_thread, NULL, thread_manage_kconsumerd, (void *) NULL);
	if (ret != 0) {
		perror("pthread_create kconsumerd");
		goto error;
	}

	/* Wait for the kconsumerd thread to be ready */
	sem_wait(&kconsumerd_sem);

	if (kconsumerd_pid == 0) {
		ERR("Kconsumerd did not start");
		goto error;
	}

	return 0;

error:
	ret = LTTCOMM_KERN_CONSUMER_FAIL;
	return ret;
}

/*
 * Join kernel consumer thread
 */
static int join_kconsumerd_thread(void)
{
	void *status;
	int ret;

	if (kconsumerd_pid != 0) {
		ret = kill(kconsumerd_pid, SIGTERM);
		if (ret) {
			ERR("Error killing kconsumerd");
			return ret;
		}
		return pthread_join(kconsumerd_thread, &status);
	} else {
		return 0;
	}
}

/*
 * Fork and exec a kernel consumer daemon (kconsumerd).
 *
 * Return pid if successful else -1.
 */
static pid_t spawn_kconsumerd(void)
{
	int ret;
	pid_t pid;
	const char *verbosity;

	DBG("Spawning kconsumerd");

	pid = fork();
	if (pid == 0) {
		/*
		 * Exec kconsumerd.
		 */
		if (opt_verbose > 1 || opt_verbose_kconsumerd) {
			verbosity = "--verbose";
		} else {
			verbosity = "--quiet";
		}
		execl(INSTALL_BIN_PATH "/ltt-kconsumerd", "ltt-kconsumerd", verbosity, NULL);
		if (errno != 0) {
			perror("kernel start consumer exec");
		}
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		ret = pid;
		goto error;
	} else {
		perror("kernel start consumer fork");
		ret = -errno;
		goto error;
	}

error:
	return ret;
}

/*
 * Spawn the kconsumerd daemon and session daemon thread.
 */
static int start_kconsumerd(void)
{
	int ret;

	pthread_mutex_lock(&kconsumerd_pid_mutex);
	if (kconsumerd_pid != 0) {
		pthread_mutex_unlock(&kconsumerd_pid_mutex);
		goto end;
	}

	ret = spawn_kconsumerd();
	if (ret < 0) {
		ERR("Spawning kconsumerd failed");
		ret = LTTCOMM_KERN_CONSUMER_FAIL;
		pthread_mutex_unlock(&kconsumerd_pid_mutex);
		goto error;
	}

	/* Setting up the global kconsumerd_pid */
	kconsumerd_pid = ret;
	pthread_mutex_unlock(&kconsumerd_pid_mutex);

	DBG("Kconsumerd pid %d", ret);

	DBG("Spawning kconsumerd thread");
	ret = spawn_kconsumerd_thread();
	if (ret < 0) {
		ERR("Fatal error spawning kconsumerd thread");
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
 * modprobe_remove_kernel_modules
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
 * mount_debugfs
 */
static int mount_debugfs(char *path)
{
	int ret;
	char *type = "debugfs";

	ret = mkdir_recursive(path, S_IRWXU | S_IRWXG, geteuid(), getegid());
	if (ret < 0) {
		goto error;
	}

	ret = mount(type, path, type, 0, NULL);
	if (ret < 0) {
		perror("mount debugfs");
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
	char *debugfs_path = NULL, *lttng_path;
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
 * Start tracing by creating trace directory and sending FDs to the kernel
 * consumer.
 */
static int start_kernel_trace(struct ltt_kernel_session *session)
{
	int ret = 0;

	if (session->kconsumer_fds_sent == 0) {
		/*
		 * Assign default kernel consumer if no consumer assigned to the kernel
		 * session. At this point, it's NOT suppose to be 0 but this is an extra
		 * security check.
		 */
		if (session->consumer_fd == 0) {
			session->consumer_fd = kconsumerd_cmd_sock;
		}

		ret = send_kconsumerd_fds(session);
		if (ret < 0) {
			ERR("Send kconsumerd fds failed");
			ret = LTTCOMM_KERN_CONSUMER_FAIL;
			goto error;
		}

		session->kconsumer_fds_sent = 1;
	}

error:
	return ret;
}

/*
 * Notify kernel thread to update it's pollfd.
 */
static int notify_kernel_pollfd(void)
{
	int ret;

	/* Inform kernel thread of the new kernel channel */
	ret = write(kernel_poll_pipe[1], "!", 1);
	if (ret < 0) {
		perror("write kernel poll pipe");
	}

	return ret;
}

/*
 * Allocate a channel structure and fill it.
 */
static struct lttng_channel *init_default_channel(enum lttng_domain_type domain_type,
						char *name)
{
	struct lttng_channel *chan;

	chan = malloc(sizeof(struct lttng_channel));
	if (chan == NULL) {
		perror("init channel malloc");
		goto error;
	}

	if (snprintf(chan->name, NAME_MAX, "%s", name) < 0) {
		perror("snprintf channel name");
		goto error;
	}

	chan->attr.overwrite = DEFAULT_CHANNEL_OVERWRITE;
	chan->attr.switch_timer_interval = DEFAULT_CHANNEL_SWITCH_TIMER;
	chan->attr.read_timer_interval = DEFAULT_CHANNEL_READ_TIMER;

	switch (domain_type) {
	case LTTNG_DOMAIN_KERNEL:
		chan->attr.subbuf_size = DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE;
		chan->attr.num_subbuf = DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM;
		chan->attr.output = DEFAULT_KERNEL_CHANNEL_OUTPUT;
		break;
		/* TODO: add UST */
	default:
		goto error;	/* Not implemented */
	}

	return chan;

error:
	free(chan);
	return NULL;
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
	if (kconsumerd_cmd_sock) {
		session->kernel_session->consumer_fd = kconsumerd_cmd_sock;
	}

	ret = asprintf(&session->kernel_session->trace_path, "%s/kernel",
			session->path);
	if (ret < 0) {
		perror("asprintf kernel traces path");
		goto error;
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
 * lock_session_list() and unlock_session_list().
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
		cds_list_for_each_entry(kchan, &session->kernel_session->channel_list.head, list) {
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
		}
		i++;
	}
}

/*
 * Process the command requested by the lttng client within the command
 * context structure. This function make sure that the return structure (llm)
 * is set and ready for transmission before returning.
 *
 * 	Return any error encountered or 0 for success.
 */
static int process_client_msg(struct command_ctx *cmd_ctx)
{
	int ret = LTTCOMM_OK;

	DBG("Processing client command %d", cmd_ctx->lsm->cmd_type);

	/*
	 * Commands that DO NOT need a session.
	 */
	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_CREATE_SESSION:
	case LTTNG_LIST_SESSIONS:
	case LTTNG_LIST_TRACEPOINTS:
	case LTTNG_CALIBRATE:
		break;
	default:
		DBG("Getting session %s by name", cmd_ctx->lsm->session.name);
		cmd_ctx->session = find_session_by_name(cmd_ctx->lsm->session.name);
		if (cmd_ctx->session == NULL) {
			/* If session name not found */
			if (cmd_ctx->lsm->session.name != NULL) {
				ret = LTTCOMM_SESS_NOT_FOUND;
			} else {	/* If no session name specified */
				ret = LTTCOMM_SELECT_SESS;
			}
			goto error;
		} else {
			/* Acquire lock for the session */
			lock_session(cmd_ctx->session);
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
			init_kernel_tracer();
			if (kernel_tracer_fd == 0) {
				ret = LTTCOMM_KERN_NA;
				goto error;
			}
		}

		/* Need a session for kernel command */
		switch (cmd_ctx->lsm->cmd_type) {
		case LTTNG_CALIBRATE:
		case LTTNG_CREATE_SESSION:
		case LTTNG_LIST_SESSIONS:
		case LTTNG_LIST_TRACEPOINTS:
			break;
		default:
			if (cmd_ctx->session->kernel_session == NULL) {
				ret = create_kernel_session(cmd_ctx->session);
				if (ret < 0) {
					ret = LTTCOMM_KERN_SESS_FAIL;
					goto error;
				}

				/* Start the kernel consumer daemon */

				if (kconsumerd_pid == 0 &&
						cmd_ctx->lsm->cmd_type != LTTNG_REGISTER_CONSUMER) {
					ret = start_kconsumerd();
					if (ret < 0) {
						goto error;
					}
				}
			}
		}
		break;
	default:
		break;
	}

	/* Process by command type */
	switch (cmd_ctx->lsm->cmd_type) {
	case LTTNG_ADD_CONTEXT:
	{
		struct lttng_kernel_context kctx;

		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			/* Create Kernel context */
			kctx.ctx = cmd_ctx->lsm->u.context.ctx.ctx;
			kctx.u.perf_counter.type = cmd_ctx->lsm->u.context.ctx.u.perf_counter.type;
			kctx.u.perf_counter.config = cmd_ctx->lsm->u.context.ctx.u.perf_counter.config;
			strncpy(kctx.u.perf_counter.name,
					cmd_ctx->lsm->u.context.ctx.u.perf_counter.name,
					LTTNG_SYMBOL_NAME_LEN);
			kctx.u.perf_counter.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';

			/* Add kernel context to kernel tracer. See context.c */
			ret = add_kernel_context(cmd_ctx->session->kernel_session, &kctx,
					cmd_ctx->lsm->u.context.event_name,
					cmd_ctx->lsm->u.context.channel_name);
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
		break;
	}
	case LTTNG_DISABLE_CHANNEL:
	{
		struct ltt_kernel_channel *kchan;

		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			kchan = get_kernel_channel_by_name(cmd_ctx->lsm->u.disable.channel_name,
					cmd_ctx->session->kernel_session);
			if (kchan == NULL) {
				ret = LTTCOMM_KERN_CHAN_NOT_FOUND;
				goto error;
			} else if (kchan->enabled == 1) {
				ret = kernel_disable_channel(kchan);
				if (ret < 0) {
					if (ret != EEXIST) {
						ret = LTTCOMM_KERN_CHAN_DISABLE_FAIL;
					}
					goto error;
				}
			}
			kernel_wait_quiescent(kernel_tracer_fd);
			break;
		default:
			/* TODO: Userspace tracing */
			ret = LTTCOMM_NOT_IMPLEMENTED;
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_DISABLE_EVENT:
	{
		struct ltt_kernel_channel *kchan;
		struct ltt_kernel_event *kevent;

		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			kchan = get_kernel_channel_by_name(cmd_ctx->lsm->u.disable.channel_name,
					cmd_ctx->session->kernel_session);
			if (kchan == NULL) {
				ret = LTTCOMM_KERN_CHAN_NOT_FOUND;
				goto error;
			}

			kevent = get_kernel_event_by_name(cmd_ctx->lsm->u.disable.name, kchan);
			if (kevent != NULL) {
				DBG("Disabling kernel event %s for channel %s.", kevent->event->name,
						kchan->channel->name);
				ret = kernel_disable_event(kevent);
				if (ret < 0) {
					ret = LTTCOMM_KERN_ENABLE_FAIL;
					goto error;
				}
			}

			kernel_wait_quiescent(kernel_tracer_fd);
			break;
		default:
			/* TODO: Userspace tracing */
			ret = LTTCOMM_NOT_IMPLEMENTED;
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_DISABLE_ALL_EVENT:
	{
		struct ltt_kernel_channel *kchan;
		struct ltt_kernel_event *kevent;

		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			DBG("Disabling all enabled kernel events");
			kchan = get_kernel_channel_by_name(cmd_ctx->lsm->u.disable.channel_name,
					cmd_ctx->session->kernel_session);
			if (kchan == NULL) {
				ret = LTTCOMM_KERN_CHAN_NOT_FOUND;
				goto error;
			}

			/* For each event in the kernel session */
			cds_list_for_each_entry(kevent, &kchan->events_list.head, list) {
				DBG("Disabling kernel event %s for channel %s.",
						kevent->event->name, kchan->channel->name);
				ret = kernel_disable_event(kevent);
				if (ret < 0) {
					continue;
				}
			}

			/* Quiescent wait after event disable */
			kernel_wait_quiescent(kernel_tracer_fd);
			break;
		default:
			/* TODO: Userspace tracing */
			ret = LTTCOMM_NOT_IMPLEMENTED;
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_ENABLE_CHANNEL:
	{
		struct ltt_kernel_channel *kchan;

		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			kchan = get_kernel_channel_by_name(cmd_ctx->lsm->u.enable.channel_name,
					cmd_ctx->session->kernel_session);
			if (kchan == NULL) {
				/* Channel not found, creating it */
				DBG("Creating kernel channel");

				ret = kernel_create_channel(cmd_ctx->session->kernel_session,
						&cmd_ctx->lsm->u.channel.chan,
						cmd_ctx->session->kernel_session->trace_path);
				if (ret < 0) {
					ret = LTTCOMM_KERN_CHAN_FAIL;
					goto error;
				}

				/* Notify kernel thread that there is a new channel */
				ret = notify_kernel_pollfd();
				if (ret < 0) {
					ret = LTTCOMM_FATAL;
					goto error;
				}
			} else if (kchan->enabled == 0) {
				ret = kernel_enable_channel(kchan);
				if (ret < 0) {
					if (ret != EEXIST) {
						ret = LTTCOMM_KERN_CHAN_ENABLE_FAIL;
					}
					goto error;
				}
			}

			kernel_wait_quiescent(kernel_tracer_fd);
			break;
		default:
			/* TODO: Userspace tracing */
			ret = LTTCOMM_NOT_IMPLEMENTED;
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_ENABLE_EVENT:
	{
		char *channel_name;
		struct ltt_kernel_channel *kchan;
		struct ltt_kernel_event *kevent;
		struct lttng_channel *chan;

		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		channel_name = cmd_ctx->lsm->u.enable.channel_name;

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			kchan = get_kernel_channel_by_name(channel_name,
					cmd_ctx->session->kernel_session);
			if (kchan == NULL) {
				DBG("Channel not found. Creating channel %s", channel_name);

				chan = init_default_channel(cmd_ctx->lsm->domain.type, channel_name);
				if (chan == NULL) {
					ret = LTTCOMM_FATAL;
					goto error;
				}

				ret = kernel_create_channel(cmd_ctx->session->kernel_session,
						chan, cmd_ctx->session->kernel_session->trace_path);
				if (ret < 0) {
					ret = LTTCOMM_KERN_CHAN_FAIL;
					goto error;
				}
				kchan = get_kernel_channel_by_name(channel_name,
						cmd_ctx->session->kernel_session);
				if (kchan == NULL) {
					ERR("Channel %s not found after creation. Internal error, giving up.",
						channel_name);
					ret = LTTCOMM_FATAL;
					goto error;
				}
			}

			kevent = get_kernel_event_by_name(cmd_ctx->lsm->u.enable.event.name, kchan);
			if (kevent == NULL) {
				DBG("Creating kernel event %s for channel %s.",
						cmd_ctx->lsm->u.enable.event.name, channel_name);
				ret = kernel_create_event(&cmd_ctx->lsm->u.enable.event, kchan);
			} else {
				DBG("Enabling kernel event %s for channel %s.",
						kevent->event->name, channel_name);
				ret = kernel_enable_event(kevent);
				if (ret == -EEXIST) {
					ret = LTTCOMM_KERN_EVENT_EXIST;
					goto error;
				}
			}

			if (ret < 0) {
				ret = LTTCOMM_KERN_ENABLE_FAIL;
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
		break;
	}
	case LTTNG_ENABLE_ALL_EVENT:
	{
		int size, i;
		char *channel_name;
		struct ltt_kernel_channel *kchan;
		struct ltt_kernel_event *kevent;
		struct lttng_event *event_list;
		struct lttng_channel *chan;

		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		DBG("Enabling all kernel event");

		channel_name = cmd_ctx->lsm->u.enable.channel_name;

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			kchan = get_kernel_channel_by_name(channel_name,
					cmd_ctx->session->kernel_session);
			if (kchan == NULL) {
				DBG("Channel not found. Creating channel %s", channel_name);

				chan = init_default_channel(cmd_ctx->lsm->domain.type, channel_name);
				if (chan == NULL) {
					ret = LTTCOMM_FATAL;
					goto error;
				}

				ret = kernel_create_channel(cmd_ctx->session->kernel_session,
						chan, cmd_ctx->session->kernel_session->trace_path);
				if (ret < 0) {
					ret = LTTCOMM_KERN_CHAN_FAIL;
					goto error;
				}
				kchan = get_kernel_channel_by_name(channel_name,
						cmd_ctx->session->kernel_session);
				if (kchan == NULL) {
					ERR("Channel %s not found after creation. Internal error, giving up.",
						channel_name);
					ret = LTTCOMM_FATAL;
					goto error;
				}
			}

			/* For each event in the kernel session */
			cds_list_for_each_entry(kevent, &kchan->events_list.head, list) {
				DBG("Enabling kernel event %s for channel %s.",
						kevent->event->name, channel_name);
				ret = kernel_enable_event(kevent);
				if (ret < 0) {
					continue;
				}
			}

			size = kernel_list_events(kernel_tracer_fd, &event_list);
			if (size < 0) {
				ret = LTTCOMM_KERN_LIST_FAIL;
				goto error;
			}

			for (i = 0; i < size; i++) {
				kevent = get_kernel_event_by_name(event_list[i].name, kchan);
				if (kevent == NULL) {
					/* Default event type for enable all */
					event_list[i].type = LTTNG_EVENT_TRACEPOINT;
					/* Enable each single tracepoint event */
					ret = kernel_create_event(&event_list[i], kchan);
					if (ret < 0) {
						/* Ignore error here and continue */
					}
				}
			}

			free(event_list);

			/* Quiescent wait after event enable */
			kernel_wait_quiescent(kernel_tracer_fd);
			break;
		default:
			/* TODO: Userspace tracing */
			ret = LTTCOMM_NOT_IMPLEMENTED;
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_LIST_TRACEPOINTS:
	{
		struct lttng_event *events;
		ssize_t nb_events = 0;

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			DBG("Listing kernel events");
			nb_events = kernel_list_events(kernel_tracer_fd, &events);
			if (nb_events < 0) {
				ret = LTTCOMM_KERN_LIST_FAIL;
				goto error;
			}
			break;
		default:
			/* TODO: Userspace listing */
			ret = LTTCOMM_NOT_IMPLEMENTED;
			break;
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
		struct ltt_kernel_channel *chan;

		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		/* Kernel tracing */
		if (cmd_ctx->session->kernel_session != NULL) {
			if (cmd_ctx->session->kernel_session->metadata == NULL) {
				DBG("Open kernel metadata");
				ret = kernel_open_metadata(cmd_ctx->session->kernel_session,
						cmd_ctx->session->kernel_session->trace_path);
				if (ret < 0) {
					ret = LTTCOMM_KERN_META_FAIL;
					goto error;
				}
			}

			if (cmd_ctx->session->kernel_session->metadata_stream_fd == 0) {
				DBG("Opening kernel metadata stream");
				if (cmd_ctx->session->kernel_session->metadata_stream_fd == 0) {
					ret = kernel_open_metadata_stream(cmd_ctx->session->kernel_session);
					if (ret < 0) {
						ERR("Kernel create metadata stream failed");
						ret = LTTCOMM_KERN_STREAM_FAIL;
						goto error;
					}
				}
			}

			/* For each channel */
			cds_list_for_each_entry(chan,
					&cmd_ctx->session->kernel_session->channel_list.head, list) {
				if (chan->stream_count == 0) {
					ret = kernel_open_channel_stream(chan);
					if (ret < 0) {
						ERR("Kernel create channel stream failed");
						ret = LTTCOMM_KERN_STREAM_FAIL;
						goto error;
					}
					/* Update the stream global counter */
					cmd_ctx->session->kernel_session->stream_count_global += ret;
				}
			}

			ret = start_kernel_trace(cmd_ctx->session->kernel_session);
			if (ret < 0) {
				ret = LTTCOMM_KERN_START_FAIL;
				goto error;
			}

			DBG("Start kernel tracing");
			ret = kernel_start_session(cmd_ctx->session->kernel_session);
			if (ret < 0) {
				ERR("Kernel start session failed");
				ret = LTTCOMM_KERN_START_FAIL;
				goto error;
			}

			/* Quiescent wait after starting trace */
			kernel_wait_quiescent(kernel_tracer_fd);
		}

		/* TODO: Start all UST traces */

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_STOP_TRACE:
	{
		struct ltt_kernel_channel *chan;
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		/* Kernel tracer */
		if (cmd_ctx->session->kernel_session != NULL) {
			DBG("Stop kernel tracing");

			ret = kernel_metadata_flush_buffer(cmd_ctx->session->kernel_session->metadata_stream_fd);
			if (ret < 0) {
				ERR("Kernel metadata flush failed");
			}

			cds_list_for_each_entry(chan, &cmd_ctx->session->kernel_session->channel_list.head, list) {
				ret = kernel_flush_buffer(chan);
				if (ret < 0) {
					ERR("Kernel flush buffer error");
				}
			}

			ret = kernel_stop_session(cmd_ctx->session->kernel_session);
			if (ret < 0) {
				ERR("Kernel stop session failed");
				ret = LTTCOMM_KERN_STOP_FAIL;
				goto error;
			}

			/* Quiescent wait after stopping trace */
			kernel_wait_quiescent(kernel_tracer_fd);
		}

		/* TODO : User-space tracer */

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_CREATE_SESSION:
	{
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		ret = create_session(cmd_ctx->lsm->session.name, cmd_ctx->lsm->session.path);
		if (ret < 0) {
			if (ret == -EEXIST) {
				ret = LTTCOMM_EXIST_SESS;
			} else {
				ret = LTTCOMM_FATAL;
			}
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_DESTROY_SESSION:
	{
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		/* Clean kernel session teardown */
		teardown_kernel_session(cmd_ctx->session);

		ret = destroy_session(cmd_ctx->lsm->session.name);
		if (ret < 0) {
			ret = LTTCOMM_FATAL;
			goto error;
		}

		/*
		 * Must notify the kernel thread here to update it's pollfd in order to
		 * remove the channel(s)' fd just destroyed.
		 */
		ret = notify_kernel_pollfd();
		if (ret < 0) {
			ret = LTTCOMM_FATAL;
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_LIST_DOMAINS:
	{
		size_t nb_dom = 0;

		if (cmd_ctx->session->kernel_session != NULL) {
			nb_dom++;
		}

		nb_dom += cmd_ctx->session->ust_trace_count;

		ret = setup_lttng_msg(cmd_ctx, sizeof(struct lttng_domain) * nb_dom);
		if (ret < 0) {
			goto setup_error;
		}

		((struct lttng_domain *)(cmd_ctx->llm->payload))[0].type =
			LTTNG_DOMAIN_KERNEL;

		/* TODO: User-space tracer domain support */
		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_LIST_CHANNELS:
	{
		/*
		 * TODO: Only kernel channels are listed here. UST listing
		 * is needed on lttng-ust 2.0 release.
		 */
		size_t nb_chan = 0;
		if (cmd_ctx->session->kernel_session != NULL) {
			nb_chan += cmd_ctx->session->kernel_session->channel_count;
		}

		ret = setup_lttng_msg(cmd_ctx,
				sizeof(struct lttng_channel) * nb_chan);
		if (ret < 0) {
			goto setup_error;
		}

		list_lttng_channels(cmd_ctx->session,
				(struct lttng_channel *)(cmd_ctx->llm->payload));

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_LIST_EVENTS:
	{
		/*
		 * TODO: Only kernel events are listed here. UST listing
		 * is needed on lttng-ust 2.0 release.
		 */
		size_t nb_event = 0;
		struct ltt_kernel_channel *kchan = NULL;

		if (cmd_ctx->session->kernel_session != NULL) {
			kchan = get_kernel_channel_by_name(cmd_ctx->lsm->u.list.channel_name,
					cmd_ctx->session->kernel_session);
			if (kchan == NULL) {
				ret = LTTCOMM_KERN_CHAN_NOT_FOUND;
				goto error;
			}
			nb_event += kchan->event_count;
		}

		ret = setup_lttng_msg(cmd_ctx,
				sizeof(struct lttng_event) * nb_event);
		if (ret < 0) {
			goto setup_error;
		}

		DBG("Listing events (%zu events)", nb_event);

		list_lttng_events(kchan,
				(struct lttng_event *)(cmd_ctx->llm->payload));

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_LIST_SESSIONS:
	{
		lock_session_list();

		if (session_list_ptr->count == 0) {
			ret = LTTCOMM_NO_SESSION;
			unlock_session_list();
			goto error;
		}

		ret = setup_lttng_msg(cmd_ctx, sizeof(struct lttng_session) *
				session_list_ptr->count);
		if (ret < 0) {
			unlock_session_list();
			goto setup_error;
		}

		/* Filled the session array */
		list_lttng_sessions((struct lttng_session *)(cmd_ctx->llm->payload));

		unlock_session_list();

		ret = LTTCOMM_OK;
		break;
	}
	case LTTNG_CALIBRATE:
	{
		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
		{
			struct lttng_kernel_calibrate kcalibrate;

			kcalibrate.type = cmd_ctx->lsm->u.calibrate.type;
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
		break;
	}
	case LTTNG_REGISTER_CONSUMER:
	{
		int sock;

		/* Setup lttng message with no payload */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		switch (cmd_ctx->lsm->domain.type) {
		case LTTNG_DOMAIN_KERNEL:
			{
				/* Can't register a consumer if there is already one */
				if (cmd_ctx->session->kernel_session->consumer_fd != 0) {
					ret = LTTCOMM_CONNECT_FAIL;
					goto error;
				}

				sock = lttcomm_connect_unix_sock(cmd_ctx->lsm->u.reg.path);
				if (sock < 0) {
					ret = LTTCOMM_CONNECT_FAIL;
					goto error;
				}

				cmd_ctx->session->kernel_session->consumer_fd = sock;
				break;
			}
		default:
			/* TODO: Userspace tracing */
			ret = LTTCOMM_NOT_IMPLEMENTED;
			goto error;
		}

		ret = LTTCOMM_OK;
		break;
	}

	default:
		/* Undefined command */
		ret = setup_lttng_msg(cmd_ctx, 0);
		if (ret < 0) {
			goto setup_error;
		}

		ret = LTTCOMM_UND;
		break;
	}

	/* Set return code */
	cmd_ctx->llm->ret_code = ret;

	if (cmd_ctx->session) {
		unlock_session(cmd_ctx->session);
	}

	return ret;

error:
	if (cmd_ctx->llm == NULL) {
		DBG("Missing llm structure. Allocating one.");
		if (setup_lttng_msg(cmd_ctx, 0) < 0) {
			goto setup_error;
		}
	}
	/* Notify client of error */
	cmd_ctx->llm->ret_code = ret;

setup_error:
	if (cmd_ctx->session) {
		unlock_session(cmd_ctx->session);
	}
	return ret;
}

/*
 * This thread manage all clients request using the unix client socket for
 * communication.
 */
static void *thread_manage_clients(void *data)
{
	int sock = 0, ret;
	struct command_ctx *cmd_ctx = NULL;
	struct pollfd pollfd[2];

	DBG("[thread] Manage client started");

	ret = lttcomm_listen_unix_sock(client_sock);
	if (ret < 0) {
		goto error;
	}

	/* First fd is always the quit pipe */
	pollfd[0].fd = thread_quit_pipe[0];

	/* Apps socket */
	pollfd[1].fd = client_sock;
	pollfd[1].events = POLLIN;

	/* Notify parent pid that we are ready
	 * to accept command for client side.
	 */
	if (opt_sig_parent) {
		kill(ppid, SIGCHLD);
	}

	while (1) {
		DBG("Accepting client command ...");

		/* Inifinite blocking call, waiting for transmission */
		ret = poll(pollfd, 2, -1);
		if (ret < 0) {
			perror("poll client thread");
			goto error;
		}

		/* Thread quit pipe has been closed. Killing thread. */
		if (pollfd[0].revents == POLLNVAL) {
			goto error;
		} else if (pollfd[1].revents == POLLERR) {
			ERR("Client socket poll error");
			goto error;
		}

		sock = lttcomm_accept_unix_sock(client_sock);
		if (sock < 0) {
			goto error;
		}

		/* Allocate context command to process the client request */
		cmd_ctx = malloc(sizeof(struct command_ctx));

		/* Allocate data buffer for reception */
		cmd_ctx->lsm = malloc(sizeof(struct lttcomm_session_msg));
		cmd_ctx->llm = NULL;
		cmd_ctx->session = NULL;

		/*
		 * Data is received from the lttng client. The struct
		 * lttcomm_session_msg (lsm) contains the command and data request of
		 * the client.
		 */
		DBG("Receiving data from client ...");
		ret = lttcomm_recv_unix_sock(sock, cmd_ctx->lsm, sizeof(struct lttcomm_session_msg));
		if (ret <= 0) {
			continue;
		}

		// TODO: Validate cmd_ctx including sanity check for security purpose.

		/*
		 * This function dispatch the work to the kernel or userspace tracer
		 * libs and fill the lttcomm_lttng_msg data structure of all the needed
		 * informations for the client. The command context struct contains
		 * everything this function may needs.
		 */
		ret = process_client_msg(cmd_ctx);
		if (ret < 0) {
			/* TODO: Inform client somehow of the fatal error. At this point,
			 * ret < 0 means that a malloc failed (ENOMEM). */
			/* Error detected but still accept command */
			clean_command_ctx(&cmd_ctx);
			continue;
		}

		DBG("Sending response (size: %d, retcode: %d)",
				cmd_ctx->lttng_msg_size, cmd_ctx->llm->ret_code);
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
	if (client_sock) {
		close(client_sock);
	}
	if (sock) {
		close(sock);
	}

	unlink(client_unix_sock_path);

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
	fprintf(stderr, "  -d, --daemonize                    Start as a daemon.\n");
	fprintf(stderr, "  -g, --group NAME                   Specify the tracing group name. (default: tracing)\n");
	fprintf(stderr, "  -V, --version                      Show version number.\n");
	fprintf(stderr, "  -S, --sig-parent                   Send SIGCHLD to parent pid to notify readiness.\n");
	fprintf(stderr, "  -q, --quiet                        No output at all.\n");
	fprintf(stderr, "  -v, --verbose                      Verbose mode. Activate DBG() macro.\n");
	fprintf(stderr, "      --verbose-kconsumerd           Verbose mode for kconsumerd. Activate DBG() macro.\n");
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
		{ "kconsumerd-cmd-sock", 1, 0, 0 },
		{ "kconsumerd-err-sock", 1, 0, 0 },
		{ "daemonize", 0, 0, 'd' },
		{ "sig-parent", 0, 0, 'S' },
		{ "help", 0, 0, 'h' },
		{ "group", 1, 0, 'g' },
		{ "version", 0, 0, 'V' },
		{ "quiet", 0, 0, 'q' },
		{ "verbose", 0, 0, 'v' },
		{ "verbose-kconsumerd", 0, 0, 'Z' },
		{ NULL, 0, 0, 0 }
	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "dhqvVS" "a:c:g:s:E:C:Z", long_options, &option_index);
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
			snprintf(kconsumerd_err_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'C':
			snprintf(kconsumerd_cmd_unix_sock_path, PATH_MAX, "%s", optarg);
			break;
		case 'q':
			opt_quiet = 1;
			break;
		case 'v':
			/* Verbose level can increase using multiple -v */
			opt_verbose += 1;
			break;
		case 'Z':
			opt_verbose_kconsumerd += 1;
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
	ret = chmod(apps_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
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
 * Check if the global socket is available, and if a daemon is answering
 * at the other side. If yes, error is returned.
 */
static int check_existing_daemon(void)
{
	if (access(client_unix_sock_path, F_OK) < 0 &&
	    access(apps_unix_sock_path, F_OK) < 0)
		return 0;
	/* Is there anybody out there ? */
	if (lttng_session_daemon_alive())
		return -EEXIST;
	else
		return 0;
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

	/* kconsumerd error socket path */
	ret = chown(kconsumerd_err_unix_sock_path, 0, gid);
	if (ret < 0) {
		ERR("Unable to set group on %s", kconsumerd_err_unix_sock_path);
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
static int set_kconsumerd_sockets(void)
{
	int ret;

	if (strlen(kconsumerd_err_unix_sock_path) == 0) {
		snprintf(kconsumerd_err_unix_sock_path, PATH_MAX, KCONSUMERD_ERR_SOCK_PATH);
	}

	if (strlen(kconsumerd_cmd_unix_sock_path) == 0) {
		snprintf(kconsumerd_cmd_unix_sock_path, PATH_MAX, KCONSUMERD_CMD_SOCK_PATH);
	}

	ret = mkdir(KCONSUMERD_PATH, S_IRWXU | S_IRWXG);
	if (ret < 0) {
		if (errno != EEXIST) {
			ERR("Failed to create " KCONSUMERD_PATH);
			goto error;
		}
		ret = 0;
	}

	/* Create the kconsumerd error unix socket */
	kconsumerd_err_sock = lttcomm_create_unix_sock(kconsumerd_err_unix_sock_path);
	if (kconsumerd_err_sock < 0) {
		ERR("Create unix sock failed: %s", kconsumerd_err_unix_sock_path);
		ret = -1;
		goto error;
	}

	/* File permission MUST be 660 */
	ret = chmod(kconsumerd_err_unix_sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", kconsumerd_err_unix_sock_path);
		perror("chmod");
		goto error;
	}

error:
	return ret;
}

/*
 * Signal handler for the daemon
 *
 * Simply stop all worker threads, leaving main() return gracefully
 * after joining all threads and calling cleanup().
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

	/* After this point, we can safely call cleanup() so goto error is used */

	/*
	 * These actions must be executed as root. We do that *after* setting up
	 * the sockets path because we MUST make the check for another daemon using
	 * those paths *before* trying to set the kernel consumer sockets and init
	 * kernel tracer.
	 */
	if (is_root) {
		ret = set_kconsumerd_sockets();
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

	/*
	 * Get session list pointer. This pointer MUST NOT be free().
	 * This list is statically declared in session.c
	 */
	session_list_ptr = get_session_list();

	/* Create thread to manage the client socket */
	ret = pthread_create(&client_thread, NULL, thread_manage_clients, (void *) NULL);
	if (ret != 0) {
		perror("pthread_create");
		goto exit_client;
	}

	/* Create thread to manage application socket */
	ret = pthread_create(&apps_thread, NULL, thread_manage_apps, (void *) NULL);
	if (ret != 0) {
		perror("pthread_create");
		goto exit_apps;
	}

	/* Create kernel thread to manage kernel event */
	ret = pthread_create(&kernel_thread, NULL, thread_manage_kernel, (void *) NULL);
	if (ret != 0) {
		perror("pthread_create");
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
	ret = pthread_join(client_thread, &status);
	if (ret != 0) {
		perror("pthread_join");
		goto error;	/* join error, exit without cleanup */
	}

	ret = join_kconsumerd_thread();
	if (ret != 0) {
		perror("join_kconsumerd");
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
