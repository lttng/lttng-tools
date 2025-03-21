/*
 * SPDX-FileCopyrightText: 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "health-sessiond.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "notification-thread-commands.hpp"
#include "notification-thread-events.hpp"
#include "notification-thread.hpp"
#include "testpoint.hpp"
#include "thread.hpp"

#include <common/align.hpp>
#include <common/config/session-config.hpp>
#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/time.hpp>
#include <common/utils.hpp>

#include <lttng/condition/buffer-usage-internal.hpp>
#include <lttng/condition/condition-internal.hpp>
#include <lttng/notification/channel-internal.hpp>
#include <lttng/notification/notification-internal.hpp>
#include <lttng/trigger/trigger.h>

#include <signal.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <time.h>
#include <urcu.h>
#include <urcu/list.h>
#include <urcu/rculfhash.h>

/*
 * Flag used to temporarily pause data consumption from testpoints.
 *
 * This variable is dlsym-ed from a test, so needs to be exported.
 */
LTTNG_EXPORT int notifier_consumption_paused;

/*
 * Destroy the thread data previously created by the init function.
 */
void notification_thread_handle_destroy(struct notification_thread_handle *handle)
{
	int ret;

	if (!handle) {
		goto end;
	}

	LTTNG_ASSERT(cds_list_empty(&handle->cmd_queue.list));
	pthread_mutex_destroy(&handle->cmd_queue.lock);
	sem_destroy(&handle->ready);

	if (handle->cmd_queue.event_fd >= 0) {
		ret = close(handle->cmd_queue.event_fd);
		if (ret < 0) {
			PERROR("Failed to close notification command queue event fd");
		}
	}
	if (handle->channel_monitoring_pipes.ust32_consumer >= 0) {
		ret = close(handle->channel_monitoring_pipes.ust32_consumer);
		if (ret) {
			PERROR("close 32-bit consumer channel monitoring pipe");
		}
	}
	if (handle->channel_monitoring_pipes.ust64_consumer >= 0) {
		ret = close(handle->channel_monitoring_pipes.ust64_consumer);
		if (ret) {
			PERROR("close 64-bit consumer channel monitoring pipe");
		}
	}
	if (handle->channel_monitoring_pipes.kernel_consumer >= 0) {
		ret = close(handle->channel_monitoring_pipes.kernel_consumer);
		if (ret) {
			PERROR("close kernel consumer channel monitoring pipe");
		}
	}

end:
	free(handle);
}

struct notification_thread_handle *
notification_thread_handle_create(struct lttng_pipe *ust32_channel_monitor_pipe,
				  struct lttng_pipe *ust64_channel_monitor_pipe,
				  struct lttng_pipe *kernel_channel_monitor_pipe)
{
	int ret;
	struct notification_thread_handle *handle;
	int event_fd = -1;

	handle = zmalloc<notification_thread_handle>();
	if (!handle) {
		goto end;
	}

	sem_init(&handle->ready, 0, 0);

	event_fd = eventfd(0, EFD_CLOEXEC | EFD_SEMAPHORE);
	if (event_fd < 0) {
		PERROR("event_fd creation");
		goto error;
	}

	handle->cmd_queue.event_fd = event_fd;

	CDS_INIT_LIST_HEAD(&handle->cmd_queue.list);
	ret = pthread_mutex_init(&handle->cmd_queue.lock, nullptr);
	if (ret) {
		goto error;
	}

	if (ust32_channel_monitor_pipe) {
		handle->channel_monitoring_pipes.ust32_consumer =
			lttng_pipe_release_readfd(ust32_channel_monitor_pipe);
		if (handle->channel_monitoring_pipes.ust32_consumer < 0) {
			goto error;
		}
	} else {
		handle->channel_monitoring_pipes.ust32_consumer = -1;
	}
	if (ust64_channel_monitor_pipe) {
		handle->channel_monitoring_pipes.ust64_consumer =
			lttng_pipe_release_readfd(ust64_channel_monitor_pipe);
		if (handle->channel_monitoring_pipes.ust64_consumer < 0) {
			goto error;
		}
	} else {
		handle->channel_monitoring_pipes.ust64_consumer = -1;
	}
	if (kernel_channel_monitor_pipe) {
		handle->channel_monitoring_pipes.kernel_consumer =
			lttng_pipe_release_readfd(kernel_channel_monitor_pipe);
		if (handle->channel_monitoring_pipes.kernel_consumer < 0) {
			goto error;
		}
	} else {
		handle->channel_monitoring_pipes.kernel_consumer = -1;
	}

end:
	return handle;
error:
	notification_thread_handle_destroy(handle);
	return nullptr;
}

static char *get_notification_channel_sock_path()
{
	auto sock_path = lttng::make_unique_wrapper<char, lttng::memory::free>(
		zmalloc<char>(LTTNG_PATH_MAX));
	if (!sock_path) {
		ERR("Failed to allocate notification channel socket path");
		return nullptr;
	}

	auto rundir_path =
		lttng::make_unique_wrapper<char, lttng::memory::free>(utils_get_rundir(0));
	if (!rundir_path) {
		ERR("Can't get RUNDIR directory for socket creation");
		return nullptr;
	}

	const auto fmt_ret = snprintf(sock_path.get(),
				      LTTNG_PATH_MAX,
				      DEFAULT_NOTIFICATION_CHANNEL_UNIX_SOCK,
				      rundir_path.get());
	if (fmt_ret < 0) {
		return nullptr;
	}

	return sock_path.release();
}

static void notification_channel_socket_destroy(int fd)
{
	int ret;
	char *sock_path = get_notification_channel_sock_path();

	DBG("Destroying notification channel socket");

	if (sock_path) {
		ret = unlink(sock_path);
		free(sock_path);
		if (ret < 0) {
			PERROR("unlink notification channel socket");
		}
	}

	ret = close(fd);
	if (ret) {
		PERROR("close notification channel socket");
	}
}

static int notification_channel_socket_create()
{
	int fd = -1, ret;
	char *sock_path = get_notification_channel_sock_path();

	DBG("Creating notification channel UNIX socket at %s", sock_path);

	ret = lttcomm_create_unix_sock(sock_path);
	if (ret < 0) {
		ERR("Failed to create notification socket");
		goto error;
	}
	fd = ret;

	ret = chmod(sock_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	if (ret < 0) {
		ERR("Set file permissions failed: %s", sock_path);
		PERROR("chmod notification channel socket");
		goto error;
	}

	if (getuid() == 0) {
		gid_t gid;

		ret = utils_get_group_id(the_config.tracing_group_name.value, true, &gid);
		if (ret) {
			/* Default to root group. */
			gid = 0;
		}

		ret = chown(sock_path, 0, gid);
		if (ret) {
			ERR("Failed to set the notification channel socket's group");
			ret = -1;
			goto error;
		}
	}

	DBG("Notification channel UNIX socket created (fd = %i)", fd);
	free(sock_path);
	return fd;
error:
	if (fd >= 0 && close(fd) < 0) {
		PERROR("close notification channel socket");
	}
	free(sock_path);
	return ret;
}

static int init_poll_set(struct lttng_poll_event *poll_set,
			 struct notification_thread_handle *handle,
			 int notification_channel_socket)
{
	int ret;

	/*
	 * Create pollset with size 5:
	 *	- notification channel socket (listen for new connections),
	 *	- command queue event fd (internal sessiond commands),
	 *	- consumerd (32-bit user space) channel monitor pipe,
	 *	- consumerd (64-bit user space) channel monitor pipe,
	 *	- consumerd (kernel) channel monitor pipe.
	 */
	ret = lttng_poll_create(poll_set, 5, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto end;
	}

	ret = lttng_poll_add(poll_set, notification_channel_socket, LPOLLIN | LPOLLRDHUP);
	if (ret < 0) {
		ERR("Failed to add notification channel socket to pollset");
		goto error;
	}
	ret = lttng_poll_add(poll_set, handle->cmd_queue.event_fd, LPOLLIN);
	if (ret < 0) {
		ERR("Failed to add notification command queue event fd to pollset");
		goto error;
	}
	ret = lttng_poll_add(poll_set, handle->channel_monitoring_pipes.ust32_consumer, LPOLLIN);
	if (ret < 0) {
		ERR("Failed to add ust-32 channel monitoring pipe fd to pollset");
		goto error;
	}
	ret = lttng_poll_add(poll_set, handle->channel_monitoring_pipes.ust64_consumer, LPOLLIN);
	if (ret < 0) {
		ERR("Failed to add ust-64 channel monitoring pipe fd to pollset");
		goto error;
	}
	if (handle->channel_monitoring_pipes.kernel_consumer < 0) {
		goto end;
	}
	ret = lttng_poll_add(poll_set, handle->channel_monitoring_pipes.kernel_consumer, LPOLLIN);
	if (ret < 0) {
		ERR("Failed to add kernel channel monitoring pipe fd to pollset");
		goto error;
	}
end:
	return ret;
error:
	lttng_poll_clean(poll_set);
	return ret;
}

static void fini_thread_state(struct notification_thread_state *state)
{
	int ret;

	if (state->client_socket_ht) {
		ret = handle_notification_thread_client_disconnect_all(state);
		LTTNG_ASSERT(!ret);
		ret = cds_lfht_destroy(state->client_socket_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->client_id_ht) {
		ret = cds_lfht_destroy(state->client_id_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->triggers_ht) {
		ret = handle_notification_thread_trigger_unregister_all(state);
		LTTNG_ASSERT(!ret);
		ret = cds_lfht_destroy(state->triggers_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->channel_triggers_ht) {
		ret = cds_lfht_destroy(state->channel_triggers_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->channel_state_ht) {
		ret = cds_lfht_destroy(state->channel_state_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->notification_trigger_clients_ht) {
		ret = cds_lfht_destroy(state->notification_trigger_clients_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->channels_ht) {
		ret = cds_lfht_destroy(state->channels_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->sessions_ht) {
		ret = cds_lfht_destroy(state->sessions_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->triggers_by_name_uid_ht) {
		ret = cds_lfht_destroy(state->triggers_by_name_uid_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->trigger_tokens_ht) {
		ret = cds_lfht_destroy(state->trigger_tokens_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	/*
	 * Must be destroyed after all channels have been destroyed.
	 * See comment in struct lttng_session_trigger_list.
	 */
	if (state->session_triggers_ht) {
		ret = cds_lfht_destroy(state->session_triggers_ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	if (state->notification_channel_socket >= 0) {
		notification_channel_socket_destroy(state->notification_channel_socket);
	}

	LTTNG_ASSERT(cds_list_empty(&state->tracer_event_sources_list));

	if (state->executor) {
		action_executor_destroy(state->executor);
	}
	lttng_poll_clean(&state->events);
}

static void mark_thread_as_ready(struct notification_thread_handle *handle)
{
	DBG("Marking notification thread as ready");
	sem_post(&handle->ready);
}

static void wait_until_thread_is_ready(struct notification_thread_handle *handle)
{
	DBG("Waiting for notification thread to be ready");
	sem_wait(&handle->ready);
	DBG("Notification thread is ready");
}

static int init_thread_state(struct notification_thread_handle *handle,
			     struct notification_thread_state *state)
{
	int ret;

	memset(state, 0, sizeof(*state));
	state->notification_channel_socket = -1;
	state->trigger_id.next_tracer_token = 1;
	lttng_poll_init(&state->events);

	ret = notification_channel_socket_create();
	if (ret < 0) {
		goto end;
	}
	state->notification_channel_socket = ret;

	ret = init_poll_set(&state->events, handle, state->notification_channel_socket);
	if (ret) {
		goto end;
	}

	DBG("Listening on notification channel socket");
	ret = lttcomm_listen_unix_sock(state->notification_channel_socket);
	if (ret < 0) {
		ERR("Listen failed on notification channel socket");
		goto error;
	}

	state->client_socket_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->client_socket_ht) {
		goto error;
	}

	state->client_id_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->client_id_ht) {
		goto error;
	}

	state->channel_triggers_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->channel_triggers_ht) {
		goto error;
	}

	state->session_triggers_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->session_triggers_ht) {
		goto error;
	}

	state->channel_state_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->channel_state_ht) {
		goto error;
	}

	state->notification_trigger_clients_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->notification_trigger_clients_ht) {
		goto error;
	}

	state->channels_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->channels_ht) {
		goto error;
	}
	state->sessions_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->sessions_ht) {
		goto error;
	}
	state->triggers_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->triggers_ht) {
		goto error;
	}
	state->triggers_by_name_uid_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->triggers_by_name_uid_ht) {
		goto error;
	}

	state->trigger_tokens_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!state->trigger_tokens_ht) {
		goto error;
	}

	CDS_INIT_LIST_HEAD(&state->tracer_event_sources_list);

	state->executor = action_executor_create(handle);
	if (!state->executor) {
		goto error;
	}

	state->restart_poll = false;

	mark_thread_as_ready(handle);
end:
	return 0;
error:
	fini_thread_state(state);
	return -1;
}

static int handle_channel_monitoring_pipe(int fd,
					  uint32_t revents,
					  struct notification_thread_handle *handle,
					  struct notification_thread_state *state)
{
	int ret = 0;
	enum lttng_domain_type domain;

	if (fd == handle->channel_monitoring_pipes.ust32_consumer ||
	    fd == handle->channel_monitoring_pipes.ust64_consumer) {
		domain = LTTNG_DOMAIN_UST;
	} else if (fd == handle->channel_monitoring_pipes.kernel_consumer) {
		domain = LTTNG_DOMAIN_KERNEL;
	} else {
		abort();
	}

	if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
		ret = lttng_poll_del(&state->events, fd);
		if (ret) {
			ERR("Failed to remove consumer monitoring pipe from poll set");
		}
		goto end;
	}

	ret = handle_notification_thread_channel_sample(state, fd, domain);
	if (ret) {
		ERR("Consumer sample handling error occurred");
		ret = -1;
		goto end;
	}
end:
	return ret;
}

static int handle_event_notification_pipe(int event_source_fd,
					  enum lttng_domain_type domain,
					  uint32_t revents,
					  struct notification_thread_state *state)
{
	int ret = 0;

	if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
		ret = handle_notification_thread_tracer_event_source_died(state, event_source_fd);
		if (ret) {
			ERR("Failed to remove event notification pipe from poll set: fd = %d",
			    event_source_fd);
		}
		goto end;
	}

	if (testpoint(sessiond_handle_notifier_event_pipe)) {
		ret = 0;
		goto end;
	}

	if (caa_unlikely(notifier_consumption_paused)) {
		DBG("Event notifier notification consumption paused, sleeping...");
		sleep(1);
		goto end;
	}

	ret = handle_notification_thread_event_notification(state, event_source_fd, domain);
	if (ret) {
		ERR("Event notification handling error occurred for fd: %d", event_source_fd);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 * Return the event source domain type via parameter.
 */
static bool fd_is_event_notification_source(const struct notification_thread_state *state,
					    int fd,
					    enum lttng_domain_type *domain)
{
	struct notification_event_tracer_event_source_element *source_element;

	LTTNG_ASSERT(domain);

	cds_list_for_each_entry (source_element, &state->tracer_event_sources_list, node) {
		if (source_element->fd != fd) {
			continue;
		}

		*domain = source_element->domain;
		return true;
	}

	return false;
}

/*
 * This thread services notification channel clients and commands received
 * from various lttng-sessiond components over a command queue.
 */
static void *thread_notification(void *data)
{
	int ret;
	struct notification_thread_handle *handle = (notification_thread_handle *) data;
	struct notification_thread_state state;
	enum lttng_domain_type domain;

	DBG("Started notification thread");

	health_register(the_health_sessiond, HEALTH_SESSIOND_TYPE_NOTIFICATION);
	rcu_register_thread();
	rcu_thread_online();

	if (!handle) {
		ERR("Invalid thread context provided");
		goto end;
	}

	health_code_update();

	ret = init_thread_state(handle, &state);
	if (ret) {
		goto end;
	}

	if (testpoint(sessiond_thread_notification)) {
		goto end;
	}

	while (true) {
		int fd_count, i;

		health_poll_entry();
		DBG("Entering poll wait");
		ret = lttng_poll_wait(&state.events, -1);
		DBG("Poll wait returned (%i)", ret);
		health_poll_exit();
		if (ret < 0) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				continue;
			}
			ERR("Error encountered during lttng_poll_wait (%i)", ret);
			goto error;
		}

		/*
		 * Reset restart_poll flag so that calls below might turn it
		 * on.
		 */
		state.restart_poll = false;

		fd_count = ret;
		for (i = 0; i < fd_count; i++) {
			const int fd = LTTNG_POLL_GETFD(&state.events, i);
			const uint32_t revents = LTTNG_POLL_GETEV(&state.events, i);

			DBG("Handling fd (%i) activity (%u)", fd, revents);

			if (fd == state.notification_channel_socket) {
				if (revents & LPOLLIN) {
					ret = handle_notification_thread_client_connect(&state);
					if (ret < 0) {
						goto error;
					}
				} else if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					ERR("Notification socket poll error");
					goto error;
				} else {
					ERR("Unexpected poll events %u for notification socket %i",
					    revents,
					    fd);
					goto error;
				}
			} else if (fd == handle->cmd_queue.event_fd) {
				ret = handle_notification_thread_command(handle, &state);
				if (ret < 0) {
					DBG("Error encountered while servicing command queue");
					goto error;
				} else if (ret > 0) {
					goto exit;
				}
			} else if (fd == handle->channel_monitoring_pipes.ust32_consumer ||
				   fd == handle->channel_monitoring_pipes.ust64_consumer ||
				   fd == handle->channel_monitoring_pipes.kernel_consumer) {
				ret = handle_channel_monitoring_pipe(fd, revents, handle, &state);
				if (ret) {
					goto error;
				}
			} else if (fd_is_event_notification_source(&state, fd, &domain)) {
				ret = handle_event_notification_pipe(fd, domain, revents, &state);
				if (ret) {
					goto error;
				}
			} else {
				/* Activity on a client's socket. */
				if (revents & (LPOLLERR | LPOLLHUP | LPOLLRDHUP)) {
					/*
					 * It doesn't matter if a command was
					 * pending on the client socket at this
					 * point since it now has no way to
					 * receive the notifications to which
					 * it was subscribing or unsubscribing.
					 */
					ret = handle_notification_thread_client_disconnect(fd,
											   &state);
					if (ret) {
						goto error;
					}
				} else {
					if (revents & LPOLLIN) {
						ret = handle_notification_thread_client_in(&state,
											   fd);
						if (ret) {
							goto error;
						}
					}

					if (revents & LPOLLOUT) {
						ret = handle_notification_thread_client_out(&state,
											    fd);
						if (ret) {
							goto error;
						}
					}
				}
			}

			/*
			 * Calls above might have changed the state of the
			 * FDs in `state.events`. Call _poll_wait() again to
			 * ensure we have a consistent state.
			 */
			if (state.restart_poll) {
				break;
			}
		}
	}
exit:
error:
	fini_thread_state(&state);
end:
	rcu_thread_offline();
	rcu_unregister_thread();
	health_unregister(the_health_sessiond);
	return nullptr;
}

static bool shutdown_notification_thread(void *thread_data)
{
	struct notification_thread_handle *handle = (notification_thread_handle *) thread_data;

	notification_thread_command_quit(handle);
	return true;
}

struct lttng_thread *launch_notification_thread(struct notification_thread_handle *handle)
{
	struct lttng_thread *thread;

	thread = lttng_thread_create(
		"Notification", thread_notification, shutdown_notification_thread, nullptr, handle);
	if (!thread) {
		goto error;
	}

	/*
	 * Wait for the thread to be marked as "ready" before returning
	 * as other subsystems depend on the notification subsystem
	 * (e.g. rotation thread).
	 */
	wait_until_thread_is_ready(handle);
	return thread;
error:
	return nullptr;
}
