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
#include <common/dynamic-buffer.h>
#include <lttng/event-internal.h>

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
#include "rotation-thread.h"
#include "lttng-syscall.h"
#include "agent.h"
#include "ht-cleanup.h"
#include "sessiond-config.h"
#include "timer.h"
#include "thread.h"
#include "client.h"

static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-sessiond.8.h>
#else
NULL
#endif
;

const char *progname;
static int lockfile_fd = -1;

/* Set to 1 when a SIGUSR1 signal is received. */
static int recv_child_signal;

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

/* Command line options to ignore from configuration file */
static const char *config_ignore_options[] = { "help", "version", "config" };

/* Shared between threads */
static int dispatch_thread_exit;

static int apps_sock = -1;

/*
 * This pipe is used to inform the thread managing application communication
 * that a command is queued and ready to be processed.
 */
static int apps_cmd_pipe[2] = { -1, -1 };

/* Pthread, Mutexes and Semaphores */
static pthread_t apps_thread;
static pthread_t apps_notify_thread;
static pthread_t reg_apps_thread;
static pthread_t kernel_thread;
static pthread_t dispatch_thread;
static pthread_t agent_reg_thread;
static pthread_t load_session_thread;

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

static const char *module_proc_lttng = "/proc/lttng";

/* Load session thread information to operate. */
static struct load_session_thread_data *load_info;

/*
 * Section name to look for in the daemon configuration file.
 */
static const char * const config_section_name = "sessiond";

/* Am I root or not. Set to 1 if the daemon is running as root */
static int is_root;

/*
 * Stop all threads by closing the thread quit pipe.
 */
static void stop_threads(void)
{
	int ret;

	/* Stopping all threads */
	DBG("Terminating all threads");
	ret = sessiond_notify_quit_pipe();
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
	struct ltt_session_list *session_list = session_get_list();

	DBG("Cleanup sessiond");

	/*
	 * Close the thread quit pipe. It has already done its job,
	 * since we are now called.
	 */
	sessiond_close_quit_pipe();

	ret = remove(config.pid_file_path.value);
	if (ret < 0) {
		PERROR("remove pidfile %s", config.pid_file_path.value);
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

	pthread_mutex_destroy(&session_list->lock);

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
 * Update the kernel poll set of all channel fd available over all tracing
 * session. Add the wakeup pipe at the end of the set.
 */
static int update_kernel_poll(struct lttng_poll_event *events)
{
	int ret;
	struct ltt_kernel_channel *channel;
	struct ltt_session *session;
	const struct ltt_session_list *session_list = session_get_list();

	DBG("Updating kernel poll set");

	session_lock_list();
	cds_list_for_each_entry(session, &session_list->head, list) {
		if (!session_get(session)) {
			continue;
		}
		session_lock(session);
		if (session->kernel_session == NULL) {
			session_unlock(session);
			session_put(session);
			continue;
		}

		cds_list_for_each_entry(channel,
				&session->kernel_session->channel_list.head, list) {
			/* Add channel fd to the kernel poll set */
			ret = lttng_poll_add(events, channel->fd, LPOLLIN | LPOLLRDNORM);
			if (ret < 0) {
				session_unlock(session);
				session_put(session);
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
static int update_kernel_stream(int fd)
{
	int ret = 0;
	struct ltt_session *session;
	struct ltt_kernel_session *ksess;
	struct ltt_kernel_channel *channel;
	const struct ltt_session_list *session_list = session_get_list();

	DBG("Updating kernel streams for channel fd %d", fd);

	session_lock_list();
	cds_list_for_each_entry(session, &session_list->head, list) {
		if (!session_get(session)) {
			continue;
		}
		session_lock(session);
		if (session->kernel_session == NULL) {
			session_unlock(session);
			session_put(session);
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
				ret = kernel_consumer_send_channel_streams(socket,
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
		session_put(session);
	}
	session_unlock_list();
	return ret;

error:
	session_unlock(session);
	session_put(session);
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
	const struct ltt_session_list *session_list = session_get_list();

	/* Consumer is in an ERROR state. Stop any application update. */
	if (uatomic_read(&ust_consumerd_state) == CONSUMER_ERROR) {
		/* Stop the update process since the consumer is dead. */
		return;
	}

	/* For all tracing session(s) */
	cds_list_for_each_entry_safe(sess, stmp, &session_list->head, list) {
		struct ust_app *app;

		if (!session_get(sess)) {
			continue;
		}
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
		session_put(sess);
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
					ret = update_kernel_stream(pollfd);
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
void *thread_manage_consumer(void *data)
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
	 * Transfer the write-end of the channel monitoring and rotate pipe
	 * to the consumer by issuing a SET_CHANNEL_MONITOR_PIPE command.
	 */
	cmd_socket_wrapper = consumer_allocate_socket(&consumer_data->cmd_sock);
	if (!cmd_socket_wrapper) {
		goto error;
	}
	cmd_socket_wrapper->lock = &consumer_data->lock;

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
	ret = kernel_validate_version(kernel_tracer_fd, &kernel_tracer_version,
			&kernel_tracer_abi_version);
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
		config.quiet = true;
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
			config.agent_tcp_port.begin = config.agent_tcp_port.end = (int) v;
			DBG3("Agent TCP port set to non default: %i", (int) v);
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
 * Creates the application socket.
 */
static int init_daemon_socket(void)
{
	int ret = 0;
	mode_t old_umask;

	old_umask = umask(0);

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

	DBG3("Session daemon application socket %d created",
			apps_sock);

end:
	umask(old_umask);
	return ret;
}

/*
 * Create lockfile using the rundir and return its fd.
 */
static int create_lockfile(void)
{
        return utils_create_lock_file(config.lock_file_path.value);
}

/*
 * Check if the global socket is available, and if a daemon is answering at the
 * other side. If yes, error is returned.
 *
 * Also attempts to create and hold the lock file.
 */
static int check_existing_daemon(void)
{
	int ret = 0;

	/* Is there anybody out there ? */
	if (lttng_session_daemon_alive()) {
		ret = -EEXIST;
		goto end;
	}

	lockfile_fd = create_lockfile();
	if (lockfile_fd < 0) {
		ret = -EEXIST;
		goto end;
	}
end:
	return ret;
}

static void sessiond_cleanup_lock_file(void)
{
	int ret;

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

static void destroy_all_sessions_and_wait(void)
{
	struct ltt_session *session, *tmp;
	struct ltt_session_list *session_list;

	session_list = session_get_list();
	DBG("Initiating destruction of all sessions");

	if (!session_list) {
		return;
	}

	session_lock_list();
	/* Initiate the destruction of all sessions. */
	cds_list_for_each_entry_safe(session, tmp,
			&session_list->head, list) {
		if (!session_get(session)) {
			continue;
		}

		session_lock(session);
		if (session->destroyed) {
			goto unlock_session;
		}
		(void) cmd_destroy_session(session,
				notification_thread_handle);
	unlock_session:
		session_unlock(session);
		session_put(session);
	}
	session_unlock_list();

	/* Wait for the destruction of all sessions to complete. */
	DBG("Waiting for the destruction of all sessions to complete");
	session_list_wait_empty();
	DBG("Destruction of all sessions completed");
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
	struct lttng_thread *ht_cleanup_thread = NULL;
	struct timer_thread_parameters timer_thread_parameters;
	/* Rotation thread handle. */
	struct rotation_thread_handle *rotation_thread_handle = NULL;
	/* Queue of rotation jobs populated by the sessiond-timer. */
	struct rotation_thread_timer_queue *rotation_timer_queue = NULL;
	struct lttng_thread *client_thread = NULL;

	init_kernel_workarounds();

	rcu_register_thread();

	if (set_signal_handler()) {
		retval = -1;
		goto exit_set_signal_handler;
	}

	if (timer_signal_init()) {
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
	 * Init config from environment variables.
	 * Command line option override env configuration per-doc. Do env first.
	 */
	sessiond_config_apply_env_config(&config);

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

	if (create_lttng_rundir()) {
		retval = -1;
		goto exit_options;
	}

	/* Abort launch if a session daemon is already running. */
	if (check_existing_daemon()) {
		ERR("A session daemon is already running.");
		retval = -1;
		goto exit_options;
	}

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
		 * descriptors than the standard ones and the lock file.
		 */
		for (i = 3; i < sysconf(_SC_OPEN_MAX); i++) {
			if (i == lockfile_fd) {
				continue;
			}
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
	ht_cleanup_thread = launch_ht_cleanup_thread();
	if (!ht_cleanup_thread) {
		retval = -1;
		goto exit_ht_cleanup;
	}

	/* Create thread quit pipe */
	if (sessiond_init_thread_quit_pipe()) {
		retval = -1;
		goto exit_init_data;
	}

	/* Check if daemon is UID = 0 */
	is_root = !getuid();
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

	/*
	 * The rotation_thread_timer_queue structure is shared between the
	 * sessiond timer thread and the rotation thread. The main thread keeps
	 * its ownership and destroys it when both threads have been joined.
	 */
	rotation_timer_queue = rotation_thread_timer_queue_create();
	if (!rotation_timer_queue) {
		retval = -1;
		goto exit_init_data;
	}
	timer_thread_parameters.rotation_thread_job_queue =
			rotation_timer_queue;

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
	if (!launch_health_management_thread()) {
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
		goto exit_notification;
	}

	/* Create notification thread. */
	if (!launch_notification_thread(notification_thread_handle)) {
		retval = -1;
		goto exit_notification;
	}

	/* Create timer thread. */
	if (!launch_timer_thread(&timer_thread_parameters)) {
		retval = -1;
		goto exit_notification;
	}

	/* rotation_thread_data acquires the pipes' read side. */
	rotation_thread_handle = rotation_thread_handle_create(
			rotation_timer_queue,
			notification_thread_handle);
	if (!rotation_thread_handle) {
		retval = -1;
		ERR("Failed to create rotation thread shared data");
		stop_threads();
		goto exit_rotation;
	}

	/* Create rotation thread. */
	if (!launch_rotation_thread(rotation_thread_handle)) {
		retval = -1;
		goto exit_rotation;
	}

	/* Create thread to manage the client socket */
	client_thread = launch_client_thread();
	if (!client_thread) {
		retval = -1;
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

	/* Initiate teardown once activity occurs on the quit pipe. */
	sessiond_wait_for_quit_pipe(-1U);

	/*
	 * Ensure that the client thread is no longer accepting new commands,
	 * which could cause new sessions to be created.
	 */
	if (!lttng_thread_shutdown(client_thread)) {
		ERR("Failed to shutdown the client thread, continuing teardown");
		lttng_thread_put(client_thread);
		client_thread = NULL;
	}

	destroy_all_sessions_and_wait();
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
exit_client:
exit_rotation:
exit_notification:
	lttng_thread_list_shutdown_orphans();
exit_health:
exit_init_data:
	if (client_thread) {
		lttng_thread_put(client_thread);
	}

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

	if (ht_cleanup_thread) {
		lttng_thread_shutdown(ht_cleanup_thread);
		lttng_thread_put(ht_cleanup_thread);
	}

	rcu_thread_offline();
	rcu_unregister_thread();

	if (rotation_thread_handle) {
		rotation_thread_handle_destroy(rotation_thread_handle);
	}

	/*
	 * After the rotation and timer thread have quit, we can safely destroy
	 * the rotation_timer_queue.
	 */
	rotation_thread_timer_queue_destroy(rotation_timer_queue);
	/*
	 * The teardown of the notification system is performed after the
	 * session daemon's teardown in order to allow it to be notified
	 * of the active session and channels at the moment of the teardown.
	 */
	if (notification_thread_handle) {
		notification_thread_handle_destroy(notification_thread_handle);
	}
	lttng_pipe_destroy(ust32_channel_monitor_pipe);
	lttng_pipe_destroy(ust64_channel_monitor_pipe);
	lttng_pipe_destroy(kernel_channel_monitor_pipe);
exit_ht_cleanup:

	health_app_destroy(health_sessiond);
exit_health_sessiond_cleanup:
exit_create_run_as_worker_cleanup:

exit_options:
	sessiond_cleanup_lock_file();
	sessiond_cleanup_options();

exit_set_signal_handler:
	if (!retval) {
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}
