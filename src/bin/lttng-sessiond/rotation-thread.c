/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <lttng/trigger/trigger.h>
#include <common/error.h>
#include <common/config/session-config.h>
#include <common/defaults.h>
#include <common/utils.h>
#include <common/futex.h>
#include <common/align.h>
#include <common/time.h>
#include <common/hashtable/utils.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <inttypes.h>

#include <common/kernel-ctl/kernel-ctl.h>
#include <lttng/notification/channel-internal.h>
#include <lttng/rotate-internal.h>

#include "rotation-thread.h"
#include "lttng-sessiond.h"
#include "health-sessiond.h"
#include "rotate.h"
#include "cmd.h"
#include "session.h"
#include "timer.h"
#include "notification-thread-commands.h"
#include "utils.h"
#include "thread.h"

#include <urcu.h>
#include <urcu/list.h>

struct lttng_notification_channel *rotate_notification_channel = NULL;

struct rotation_thread {
	struct lttng_poll_event events;
};

struct rotation_thread_job {
	enum rotation_thread_job_type type;
	struct ltt_session *session;
	/* List member in struct rotation_thread_timer_queue. */
	struct cds_list_head head;
};

/*
 * The timer thread enqueues jobs and wakes up the rotation thread.
 * When the rotation thread wakes up, it empties the queue.
 */
struct rotation_thread_timer_queue {
	struct lttng_pipe *event_pipe;
	struct cds_list_head list;
	pthread_mutex_t lock;
};

struct rotation_thread_handle {
	struct rotation_thread_timer_queue *rotation_timer_queue;
	/* Access to the notification thread cmd_queue */
	struct notification_thread_handle *notification_thread_handle;
	/* Thread-specific quit pipe. */
	struct lttng_pipe *quit_pipe;
};

static
const char *get_job_type_str(enum rotation_thread_job_type job_type)
{
	switch (job_type) {
	case ROTATION_THREAD_JOB_TYPE_CHECK_PENDING_ROTATION:
		return "CHECK_PENDING_ROTATION";
	case ROTATION_THREAD_JOB_TYPE_SCHEDULED_ROTATION:
		return "SCHEDULED_ROTATION";
	default:
		abort();
	}
}

struct rotation_thread_timer_queue *rotation_thread_timer_queue_create(void)
{
	struct rotation_thread_timer_queue *queue = NULL;

	queue = zmalloc(sizeof(*queue));
	if (!queue) {
		PERROR("Failed to allocate timer rotate queue");
		goto end;
	}

	queue->event_pipe = lttng_pipe_open(FD_CLOEXEC | O_NONBLOCK);
	CDS_INIT_LIST_HEAD(&queue->list);
	pthread_mutex_init(&queue->lock, NULL);
end:
	return queue;
}

void log_job_destruction(const struct rotation_thread_job *job)
{
	enum lttng_error_level log_level;
	const char *job_type_str = get_job_type_str(job->type);

	switch (job->type) {
	case ROTATION_THREAD_JOB_TYPE_SCHEDULED_ROTATION:
		/*
		 * Not a problem, the scheduled rotation is racing with the teardown
		 * of the daemon. In this case, the rotation will not happen, which
		 * is not a problem (or at least, not important enough to delay
		 * the shutdown of the session daemon).
		 */
		log_level = PRINT_DBG;
		break;
	case ROTATION_THREAD_JOB_TYPE_CHECK_PENDING_ROTATION:
		/* This is not expected to happen; warn the user. */
		log_level = PRINT_WARN;
		break;
	default:
		abort();
	}

	LOG(log_level, "Rotation thread timer queue still contains job of type %s targeting session \"%s\" on destruction",
			job_type_str, job->session->name);
}

void rotation_thread_timer_queue_destroy(
		struct rotation_thread_timer_queue *queue)
{
	if (!queue) {
		return;
	}

	lttng_pipe_destroy(queue->event_pipe);

	pthread_mutex_lock(&queue->lock);
	assert(cds_list_empty(&queue->list));
	pthread_mutex_unlock(&queue->lock);
	pthread_mutex_destroy(&queue->lock);
	free(queue);
}

/*
 * Destroy the thread data previously created by the init function.
 */
void rotation_thread_handle_destroy(
		struct rotation_thread_handle *handle)
{
	lttng_pipe_destroy(handle->quit_pipe);
	free(handle);
}

struct rotation_thread_handle *rotation_thread_handle_create(
		struct rotation_thread_timer_queue *rotation_timer_queue,
		struct notification_thread_handle *notification_thread_handle)
{
	struct rotation_thread_handle *handle;

	handle = zmalloc(sizeof(*handle));
	if (!handle) {
		goto end;
	}

	handle->rotation_timer_queue = rotation_timer_queue;
	handle->notification_thread_handle = notification_thread_handle;
	handle->quit_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!handle->quit_pipe) {
		goto error;
	}

end:
	return handle;
error:
	rotation_thread_handle_destroy(handle);
	return NULL;
}

/*
 * Called with the rotation_thread_timer_queue lock held.
 * Return true if the same timer job already exists in the queue, false if not.
 */
static
bool timer_job_exists(const struct rotation_thread_timer_queue *queue,
		enum rotation_thread_job_type job_type,
		struct ltt_session *session)
{
	bool exists = false;
	struct rotation_thread_job *job;

	cds_list_for_each_entry(job, &queue->list, head) {
		if (job->session == session && job->type == job_type) {
			exists = true;
			goto end;
		}
	}
end:
	return exists;
}

void rotation_thread_enqueue_job(struct rotation_thread_timer_queue *queue,
		enum rotation_thread_job_type job_type,
		struct ltt_session *session)
{
	int ret;
	const char * const dummy = "!";
	struct rotation_thread_job *job = NULL;
	const char *job_type_str = get_job_type_str(job_type);

	pthread_mutex_lock(&queue->lock);
	if (timer_job_exists(queue, job_type, session)) {
		/*
		 * This timer job is already pending, we don't need to add
		 * it.
		 */
		goto end;
	}

	job = zmalloc(sizeof(struct rotation_thread_job));
	if (!job) {
		PERROR("Failed to allocate rotation thread job of type \"%s\" for session \"%s\"",
				job_type_str, session->name);
		goto end;
	}
	/* No reason for this to fail as the caller must hold a reference. */
	(void) session_get(session);

	job->session = session;
	job->type = job_type;
	cds_list_add_tail(&job->head, &queue->list);

	ret = lttng_write(lttng_pipe_get_writefd(queue->event_pipe), dummy,
			1);
	if (ret < 0) {
		/*
		 * We do not want to block in the timer handler, the job has
		 * been enqueued in the list, the wakeup pipe is probably full,
		 * the job will be processed when the rotation_thread catches
		 * up.
		 */
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/*
			 * Not an error, but would be surprising and indicate
			 * that the rotation thread can't keep up with the
			 * current load.
			 */
			DBG("Wake-up pipe of rotation thread job queue is full");
			goto end;
		}
		PERROR("Failed to wake-up the rotation thread after pushing a job of type \"%s\" for session \"%s\"",
				job_type_str, session->name);
		goto end;
	}

end:
	pthread_mutex_unlock(&queue->lock);
}

static
int init_poll_set(struct lttng_poll_event *poll_set,
		struct rotation_thread_handle *handle)
{
	int ret;

	/*
	 * Create pollset with size 3:
	 *	- rotation thread quit pipe,
	 *	- rotation thread timer queue pipe,
	 *	- notification channel sock,
	 */
	ret = lttng_poll_create(poll_set, 5, LTTNG_CLOEXEC);
	if (ret < 0) {
		goto error;
	}

	ret = lttng_poll_add(poll_set,
			lttng_pipe_get_readfd(handle->quit_pipe),
			LPOLLIN | LPOLLERR);
	if (ret < 0) {
		ERR("[rotation-thread] Failed to add quit pipe read fd to poll set");
		goto error;
	}

	ret = lttng_poll_add(poll_set,
			lttng_pipe_get_readfd(handle->rotation_timer_queue->event_pipe),
			LPOLLIN | LPOLLERR);
	if (ret < 0) {
		ERR("[rotation-thread] Failed to add rotate_pending fd to poll set");
		goto error;
	}

	return ret;
error:
	lttng_poll_clean(poll_set);
	return ret;
}

static
void fini_thread_state(struct rotation_thread *state)
{
	lttng_poll_clean(&state->events);
	if (rotate_notification_channel) {
		lttng_notification_channel_destroy(rotate_notification_channel);
	}
}

static
int init_thread_state(struct rotation_thread_handle *handle,
		struct rotation_thread *state)
{
	int ret;

	memset(state, 0, sizeof(*state));
	lttng_poll_init(&state->events);

	ret = init_poll_set(&state->events, handle);
	if (ret) {
		ERR("[rotation-thread] Failed to initialize rotation thread poll set");
		goto end;
	}

	rotate_notification_channel = lttng_notification_channel_create(
			lttng_session_daemon_notification_endpoint);
	if (!rotate_notification_channel) {
		ERR("[rotation-thread] Could not create notification channel");
		ret = -1;
		goto end;
	}
	ret = lttng_poll_add(&state->events, rotate_notification_channel->socket,
			LPOLLIN | LPOLLERR);
	if (ret < 0) {
		ERR("[rotation-thread] Failed to add notification fd to pollset");
		goto end;
	}

end:
	return ret;
}

static
void check_session_rotation_pending_on_consumers(struct ltt_session *session,
		bool *_rotation_completed)
{
	int ret = 0;
	struct consumer_socket *socket;
	struct cds_lfht_iter iter;
	enum consumer_trace_chunk_exists_status exists_status;
	uint64_t relayd_id;
	bool chunk_exists_on_peer = false;
	enum lttng_trace_chunk_status chunk_status;

	assert(session->chunk_being_archived);

	/*
	 * Check for a local pending rotation on all consumers (32-bit
	 * user space, 64-bit user space, and kernel).
	 */
	rcu_read_lock();
	if (!session->ust_session) {
		goto skip_ust;
	}
	cds_lfht_for_each_entry(session->ust_session->consumer->socks->ht,
			&iter, socket, node.node) {
		relayd_id = session->ust_session->consumer->type == CONSUMER_DST_LOCAL ?
				-1ULL :
				session->ust_session->consumer->net_seq_index;

		pthread_mutex_lock(socket->lock);
		ret = consumer_trace_chunk_exists(socket,
				relayd_id,
				session->id, session->chunk_being_archived,
				&exists_status);
		if (ret) {
			pthread_mutex_unlock(socket->lock);
			ERR("Error occured while checking rotation status on consumer daemon");
			goto end;
		}

                if (exists_status != CONSUMER_TRACE_CHUNK_EXISTS_STATUS_UNKNOWN_CHUNK) {
			pthread_mutex_unlock(socket->lock);
			chunk_exists_on_peer = true;
			goto end;
                }
		pthread_mutex_unlock(socket->lock);
        }

skip_ust:
	if (!session->kernel_session) {
		goto skip_kernel;
	}
	cds_lfht_for_each_entry(session->kernel_session->consumer->socks->ht,
				&iter, socket, node.node) {
		pthread_mutex_lock(socket->lock);
		relayd_id = session->kernel_session->consumer->type == CONSUMER_DST_LOCAL ?
				-1ULL :
				session->kernel_session->consumer->net_seq_index;

		ret = consumer_trace_chunk_exists(socket,
				relayd_id,
				session->id, session->chunk_being_archived,
				&exists_status);
		if (ret) {
			pthread_mutex_unlock(socket->lock);
			ERR("Error occured while checking rotation status on consumer daemon");
			goto end;
		}

                if (exists_status != CONSUMER_TRACE_CHUNK_EXISTS_STATUS_UNKNOWN_CHUNK) {
			pthread_mutex_unlock(socket->lock);
			chunk_exists_on_peer = true;
			goto end;
                }
		pthread_mutex_unlock(socket->lock);
	}
skip_kernel:
end:
	rcu_read_unlock();

	if (!chunk_exists_on_peer) {
		uint64_t chunk_being_archived_id;

		chunk_status = lttng_trace_chunk_get_id(
				session->chunk_being_archived,
				&chunk_being_archived_id);
		assert(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);
		DBG("[rotation-thread] Rotation of trace archive %" PRIu64 " of session \"%s\" is complete on all consumers",
				chunk_being_archived_id,
				session->name);
	}
	*_rotation_completed = !chunk_exists_on_peer;
	if (ret) {
		ret = session_reset_rotation_state(session,
				LTTNG_ROTATION_STATE_ERROR);
		if (ret) {
			ERR("Failed to reset rotation state of session \"%s\"",
					session->name);
		}
	}
}

/*
 * Check if the last rotation was completed, called with session lock held.
 * Should only return non-zero in the event of a fatal error. Doing so will
 * shutdown the thread.
 */
static
int check_session_rotation_pending(struct ltt_session *session,
		struct notification_thread_handle *notification_thread_handle)
{
	int ret;
	struct lttng_trace_archive_location *location;
	enum lttng_trace_chunk_status chunk_status;
	bool rotation_completed = false;
	const char *archived_chunk_name;
	uint64_t chunk_being_archived_id;

	chunk_status = lttng_trace_chunk_get_id(session->chunk_being_archived,
			&chunk_being_archived_id);
	assert(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);

	DBG("[rotation-thread] Checking for pending rotation on session \"%s\", trace archive %" PRIu64,
			session->name, chunk_being_archived_id);

	if (!session->chunk_being_archived) {
		ret = 0;
		goto end;
	}

	/*
	 * The rotation-pending check timer of a session is launched in
	 * one-shot mode. If the rotation is incomplete, the rotation
	 * thread will re-enable the pending-check timer.
	 *
	 * The timer thread can't stop the timer itself since it is involved
	 * in the check for the timer's quiescence.
	 */
	ret = timer_session_rotation_pending_check_stop(session);
	if (ret) {
		goto end;
	}

	check_session_rotation_pending_on_consumers(session,
			&rotation_completed);

	if (!rotation_completed ||
			session->rotation_state == LTTNG_ROTATION_STATE_ERROR) {
		goto end;
	}

	/*
	 * Now we can clear the "ONGOING" state in the session. New
	 * rotations can start now.
	 */
	chunk_status = lttng_trace_chunk_get_name(session->chunk_being_archived,
			&archived_chunk_name, NULL);
	assert(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);
	free(session->last_archived_chunk_name);
	session->last_archived_chunk_name = strdup(archived_chunk_name);
	if (!session->last_archived_chunk_name) {
		PERROR("Failed to duplicate archived chunk name");
	}
	session_reset_rotation_state(session, LTTNG_ROTATION_STATE_COMPLETED);

	location = session_get_trace_archive_location(session);
	/* Ownership of location is transferred. */
	ret = notification_thread_command_session_rotation_completed(
			notification_thread_handle,
			session->name,
			session->uid,
			session->gid,
			session->last_archived_chunk_id.value,
			location);
	if (ret != LTTNG_OK) {
		ERR("[rotation-thread] Failed to notify notification thread of completed rotation for session %s",
				session->name);
	}

	if (!session->active) {
		/*
		 * A stop command was issued during the rotation, it is
		 * up to the rotation completion check to perform the
		 * renaming of the last chunk that was produced.
		 */
		ret = notification_thread_command_session_rotation_ongoing(
				notification_thread_handle,
				session->name,
				session->uid,
				session->gid,
				session->most_recent_chunk_id.value);
		if (ret != LTTNG_OK) {
			ERR("[rotation-thread] Failed to notify notification thread of completed rotation for session %s",
					session->name);
		}

		/* Ownership of location is transferred. */
		location = session_get_trace_archive_location(session);
		ret = notification_thread_command_session_rotation_completed(
				notification_thread_handle,
				session->name,
				session->uid,
				session->gid,
				session->most_recent_chunk_id.value,
				location);
		if (ret != LTTNG_OK) {
			ERR("[rotation-thread] Failed to notify notification thread of completed rotation for session %s",
					session->name);
		}
	}

	ret = 0;
end:
	if (session->rotation_state == LTTNG_ROTATION_STATE_ONGOING) {
		uint64_t chunk_being_archived_id;

		chunk_status = lttng_trace_chunk_get_id(
				session->chunk_being_archived,
				&chunk_being_archived_id);
		assert(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);

		DBG("[rotation-thread] Rotation of trace archive %" PRIu64 " is still pending for session %s",
				chunk_being_archived_id, session->name);
		ret = timer_session_rotation_pending_check_start(session,
				DEFAULT_ROTATE_PENDING_TIMER);
		if (ret) {
			ERR("Failed to re-enable rotation pending timer");
			ret = -1;
			goto end;
		}
	}

	return ret;
}

/* Call with the session and session_list locks held. */
static
int launch_session_rotation(struct ltt_session *session)
{
	int ret;
	struct lttng_rotate_session_return rotation_return;

	DBG("[rotation-thread] Launching scheduled time-based rotation on session \"%s\"",
			session->name);

	ret = cmd_rotate_session(session, &rotation_return);
	if (ret == LTTNG_OK) {
		DBG("[rotation-thread] Scheduled time-based rotation successfully launched on session \"%s\"",
				session->name);
	} else {
		/* Don't consider errors as fatal. */
		DBG("[rotation-thread] Scheduled time-based rotation aborted for session %s: %s",
				session->name, lttng_strerror(ret));
	}
	return 0;
}

static
int run_job(struct rotation_thread_job *job, struct ltt_session *session,
		struct notification_thread_handle *notification_thread_handle)
{
	int ret;

	switch (job->type) {
	case ROTATION_THREAD_JOB_TYPE_SCHEDULED_ROTATION:
	        ret = launch_session_rotation(session);
		break;
	case ROTATION_THREAD_JOB_TYPE_CHECK_PENDING_ROTATION:
		ret = check_session_rotation_pending(session,
				notification_thread_handle);
		break;
	default:
		abort();
	}
	return ret;
}

static
int handle_job_queue(struct rotation_thread_handle *handle,
		struct rotation_thread *state,
		struct rotation_thread_timer_queue *queue)
{
	int ret = 0;

	for (;;) {
		struct ltt_session *session;
		struct rotation_thread_job *job;

		/* Take the queue lock only to pop an element from the list. */
		pthread_mutex_lock(&queue->lock);
		if (cds_list_empty(&queue->list)) {
			pthread_mutex_unlock(&queue->lock);
			break;
		}
		job = cds_list_first_entry(&queue->list,
				typeof(*job), head);
		cds_list_del(&job->head);
		pthread_mutex_unlock(&queue->lock);

		session_lock_list();
		session = job->session;
		if (!session) {
			DBG("[rotation-thread] Session \"%s\" not found",
					session->name);
			/*
			 * This is a non-fatal error, and we cannot report it to
			 * the user (timer), so just print the error and
			 * continue the processing.
			 *
			 * While the timer thread will purge pending signals for
			 * a session on the session's destruction, it is
			 * possible for a job targeting that session to have
			 * already been queued before it was destroyed.
			 */
			free(job);
			session_put(session);
			session_unlock_list();
			continue;
		}

		session_lock(session);
	        ret = run_job(job, session, handle->notification_thread_handle);
		session_unlock(session);
		/* Release reference held by the job. */
		session_put(session);
		session_unlock_list();
		free(job);
		if (ret) {
			goto end;
		}
	}

	ret = 0;

end:
	return ret;
}

static
int handle_condition(const struct lttng_condition *condition,
		const struct lttng_evaluation *evaluation,
		struct notification_thread_handle *notification_thread_handle)
{
	int ret = 0;
	const char *condition_session_name = NULL;
	enum lttng_condition_type condition_type;
	enum lttng_condition_status condition_status;
	enum lttng_evaluation_status evaluation_status;
	uint64_t consumed;
	struct ltt_session *session;

	condition_type = lttng_condition_get_type(condition);

	if (condition_type != LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE) {
		ret = -1;
		ERR("[rotation-thread] Condition type and session usage type are not the same");
		goto end;
	}

	/* Fetch info to test */
	condition_status = lttng_condition_session_consumed_size_get_session_name(
			condition, &condition_session_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ERR("[rotation-thread] Session name could not be fetched");
		ret = -1;
		goto end;
	}
	evaluation_status = lttng_evaluation_session_consumed_size_get_consumed_size(evaluation,
			&consumed);
	if (evaluation_status != LTTNG_EVALUATION_STATUS_OK) {
		ERR("[rotation-thread] Failed to get evaluation");
		ret = -1;
		goto end;
	}

	session_lock_list();
	session = session_find_by_name(condition_session_name);
	if (!session) {
		ret = -1;
		session_unlock_list();
		ERR("[rotation-thread] Session \"%s\" not found",
				condition_session_name);
		goto end;
	}
	session_lock(session);

	ret = unsubscribe_session_consumed_size_rotation(session,
			notification_thread_handle);
	if (ret) {
		goto end_unlock;
	}

	ret = cmd_rotate_session(session, NULL);
	if (ret == -LTTNG_ERR_ROTATION_PENDING) {
		DBG("Rotate already pending, subscribe to the next threshold value");
	} else if (ret != LTTNG_OK) {
		ERR("[rotation-thread] Failed to rotate on size notification with error: %s",
				lttng_strerror(ret));
		ret = -1;
		goto end_unlock;
	}
	ret = subscribe_session_consumed_size_rotation(session,
			consumed + session->rotate_size,
			notification_thread_handle);
	if (ret) {
		ERR("[rotation-thread] Failed to subscribe to session consumed size condition");
		goto end_unlock;
	}
	ret = 0;

end_unlock:
	session_unlock(session);
	session_put(session);
	session_unlock_list();
end:
	return ret;
}

static
int handle_notification_channel(int fd,
		struct rotation_thread_handle *handle,
		struct rotation_thread *state)
{
	int ret;
	bool notification_pending;
	struct lttng_notification *notification = NULL;
	enum lttng_notification_channel_status status;
	const struct lttng_evaluation *notification_evaluation;
	const struct lttng_condition *notification_condition;

	status = lttng_notification_channel_has_pending_notification(
			rotate_notification_channel, &notification_pending);
	if (status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		ERR("[rotation-thread ]Error occurred while checking for pending notification");
		ret = -1;
		goto end;
	}

	if (!notification_pending) {
		ret = 0;
		goto end;
	}

	/* Receive the next notification. */
	status = lttng_notification_channel_get_next_notification(
			rotate_notification_channel,
			&notification);

	switch (status) {
	case LTTNG_NOTIFICATION_CHANNEL_STATUS_OK:
		break;
	case LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED:
		/* Not an error, we will wait for the next one */
		ret = 0;
		goto end;;
	case LTTNG_NOTIFICATION_CHANNEL_STATUS_CLOSED:
		ERR("Notification channel was closed");
		ret = -1;
		goto end;
	default:
		/* Unhandled conditions / errors. */
		ERR("Unknown notification channel status");
		ret = -1;
		goto end;
	}

	notification_condition = lttng_notification_get_condition(notification);
	notification_evaluation = lttng_notification_get_evaluation(notification);

	ret = handle_condition(notification_condition, notification_evaluation,
			handle->notification_thread_handle);

end:
	lttng_notification_destroy(notification);
	return ret;
}

void *thread_rotation(void *data)
{
	int ret;
	struct rotation_thread_handle *handle = data;
	struct rotation_thread thread;
	const int queue_pipe_fd = lttng_pipe_get_readfd(
			handle->rotation_timer_queue->event_pipe);

	DBG("[rotation-thread] Started rotation thread");

	if (!handle) {
		ERR("[rotation-thread] Invalid thread context provided");
		goto end;
	}

	rcu_register_thread();
	rcu_thread_online();

	health_register(health_sessiond, HEALTH_SESSIOND_TYPE_ROTATION);
	health_code_update();

	ret = init_thread_state(handle, &thread);
	if (ret) {
		goto error;
	}

	while (true) {
		int fd_count, i;

		health_poll_entry();
		DBG("[rotation-thread] Entering poll wait");
		ret = lttng_poll_wait(&thread.events, -1);
		DBG("[rotation-thread] Poll wait returned (%i)", ret);
		health_poll_exit();
		if (ret < 0) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				continue;
			}
			ERR("[rotation-thread] Error encountered during lttng_poll_wait (%i)", ret);
			goto error;
		}

		fd_count = ret;
		for (i = 0; i < fd_count; i++) {
			int fd = LTTNG_POLL_GETFD(&thread.events, i);
			uint32_t revents = LTTNG_POLL_GETEV(&thread.events, i);

			DBG("[rotation-thread] Handling fd (%i) activity (%u)",
					fd, revents);

			if (revents & LPOLLERR) {
				ERR("[rotation-thread] Polling returned an error on fd %i", fd);
				goto error;
			}

			if (fd == rotate_notification_channel->socket) {
				ret = handle_notification_channel(fd, handle,
						&thread);
				if (ret) {
					ERR("[rotation-thread] Error occurred while handling activity on notification channel socket");
					goto error;
				}
			} else {
				/* Job queue or quit pipe activity. */

				/*
				 * The job queue is serviced if there is
				 * activity on the quit pipe to ensure it is
				 * flushed and all references held in the queue
				 * are released.
				 */
				ret = handle_job_queue(handle, &thread,
						handle->rotation_timer_queue);
				if (ret) {
					ERR("[rotation-thread] Failed to handle rotation timer pipe event");
					goto error;
				}

				if (fd == queue_pipe_fd) {
					char buf;

					ret = lttng_read(fd, &buf, 1);
					if (ret != 1) {
						ERR("[rotation-thread] Failed to read from wakeup pipe (fd = %i)", fd);
						ret = -1;
						goto error;
					}
				} else {
					DBG("[rotation-thread] Quit pipe activity");
					goto exit;
				}
			}
		}
	}
exit:
error:
	DBG("[rotation-thread] Exit");
	fini_thread_state(&thread);
	health_unregister(health_sessiond);
	rcu_thread_offline();
	rcu_unregister_thread();
end:
	return NULL;
}

static
bool shutdown_rotation_thread(void *thread_data)
{
	struct rotation_thread_handle *handle = thread_data;
	const int write_fd = lttng_pipe_get_writefd(handle->quit_pipe);

	return notify_thread_pipe(write_fd) == 1;
}

bool launch_rotation_thread(struct rotation_thread_handle *handle)
{
	struct lttng_thread *thread;

	thread = lttng_thread_create("Rotation",
			thread_rotation,
			shutdown_rotation_thread,
			NULL,
			handle);
	if (!thread) {
		goto error;
	}
	lttng_thread_put(thread);
	return true;
error:
	return false;
}
