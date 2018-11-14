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

#include <urcu.h>
#include <urcu/list.h>

struct lttng_notification_channel *rotate_notification_channel = NULL;

struct rotation_thread {
	struct lttng_poll_event events;
};

struct rotation_thread_job {
	enum rotation_thread_job_type type;
	uint64_t session_id;
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
	sem_t *notification_thread_ready;
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

	LOG(log_level, "Rotation thread timer queue still contains job of type %s targeting session %" PRIu64 " on destruction",
			job_type_str, job->session_id);
}

void rotation_thread_timer_queue_destroy(
		struct rotation_thread_timer_queue *queue)
{
	struct rotation_thread_job *job, *tmp_job;

	if (!queue) {
		return;
	}

	lttng_pipe_destroy(queue->event_pipe);

	pthread_mutex_lock(&queue->lock);
	/* Empty wait queue. */
	cds_list_for_each_entry_safe(job, tmp_job, &queue->list, head) {
		log_job_destruction(job);
		cds_list_del(&job->head);
		free(job);
	}
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
	free(handle);
}

struct rotation_thread_handle *rotation_thread_handle_create(
		struct rotation_thread_timer_queue *rotation_timer_queue,
		struct notification_thread_handle *notification_thread_handle,
		sem_t *notification_thread_ready)
{
	struct rotation_thread_handle *handle;

	handle = zmalloc(sizeof(*handle));
	if (!handle) {
		goto end;
	}

	handle->rotation_timer_queue = rotation_timer_queue;
	handle->notification_thread_handle = notification_thread_handle;
	handle->notification_thread_ready = notification_thread_ready;

end:
	return handle;
}

/*
 * Called with the rotation_thread_timer_queue lock held.
 * Return true if the same timer job already exists in the queue, false if not.
 */
static
bool timer_job_exists(const struct rotation_thread_timer_queue *queue,
		enum rotation_thread_job_type job_type, uint64_t session_id)
{
	bool exists = false;
	struct rotation_thread_job *job;

	cds_list_for_each_entry(job, &queue->list, head) {
		if (job->session_id == session_id && job->type == job_type) {
			exists = true;
			goto end;
		}
	}
end:
	return exists;
}

void rotation_thread_enqueue_job(struct rotation_thread_timer_queue *queue,
		enum rotation_thread_job_type job_type, uint64_t session_id)
{
	int ret;
	const char * const dummy = "!";
	struct rotation_thread_job *job = NULL;
	const char *job_type_str = get_job_type_str(job_type);

	pthread_mutex_lock(&queue->lock);
	if (timer_job_exists(queue, session_id, job_type)) {
		/*
		 * This timer job is already pending, we don't need to add
		 * it.
		 */
		goto end;
	}

	job = zmalloc(sizeof(struct rotation_thread_job));
	if (!job) {
		PERROR("Failed to allocate rotation thread job of type \"%s\" for session id %" PRIu64,
				job_type_str, session_id);
		goto end;
	}
	job->type = job_type;
	job->session_id = session_id;
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
		PERROR("Failed to wake-up the rotation thread after pushing a job of type \"%s\" for session id %" PRIu64,
				job_type_str, session_id);
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
	 * Create pollset with size 2:
	 *	- quit pipe,
	 *	- rotation thread timer queue pipe,
	 */
	ret = sessiond_set_thread_pollset(poll_set, 2);
	if (ret) {
		goto error;
	}
	ret = lttng_poll_add(poll_set,
			lttng_pipe_get_readfd(handle->rotation_timer_queue->event_pipe),
			LPOLLIN | LPOLLERR);
	if (ret < 0) {
		ERR("[rotation-thread] Failed to add rotate_pending fd to pollset");
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

	/*
	 * We wait until the notification thread is ready to create the
	 * notification channel and add it to the poll_set.
	 */
	sem_wait(handle->notification_thread_ready);
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
int check_session_rotation_pending_local_on_consumer(
		const struct ltt_session *session,
		struct consumer_socket *socket, bool *rotation_completed)
{
	int ret;

	pthread_mutex_lock(socket->lock);
	DBG("[rotation-thread] Checking for locally pending rotation on the %s consumer for session %s",
			lttng_consumer_type_str(socket->type),
			session->name);
	ret = consumer_check_rotation_pending_local(socket,
			session->id,
			session->current_archive_id - 1);
	pthread_mutex_unlock(socket->lock);

	if (ret == 0) {
		/* Rotation was completed on this consumer. */
		DBG("[rotation-thread] Local rotation of trace archive %" PRIu64 " of session \"%s\" was completed on the %s consumer",
				session->current_archive_id - 1,
				session->name,
				lttng_consumer_type_str(socket->type));
		*rotation_completed = true;
	} else if (ret == 1) {
		/* Rotation pending on this consumer. */
		DBG("[rotation-thread] Local rotation of trace archive %" PRIu64 " of session \"%s\" is pending on the %s consumer",
				session->current_archive_id - 1,
				session->name,
				lttng_consumer_type_str(socket->type));
		*rotation_completed = false;
		ret = 0;
	} else {
		/* Not a fatal error. */
		ERR("[rotation-thread] Encountered an error when checking if local rotation of trace archive %" PRIu64 " of session \"%s\" is pending on the %s consumer",
				session->current_archive_id - 1,
				session->name,
				lttng_consumer_type_str(socket->type));
		*rotation_completed = false;
	}
	return ret;
}

static
int check_session_rotation_pending_local(struct ltt_session *session)
{
	int ret = 0;
	struct consumer_socket *socket;
	struct cds_lfht_iter iter;
	bool rotation_completed = true;

	/*
	 * Check for a local pending rotation on all consumers (32-bit
	 * user space, 64-bit user space, and kernel).
	 */
	DBG("[rotation-thread] Checking for pending local rotation on session \"%s\", trace archive %" PRIu64,
			session->name, session->current_archive_id - 1);

	rcu_read_lock();
	if (!session->ust_session) {
		goto skip_ust;
	}
	cds_lfht_for_each_entry(session->ust_session->consumer->socks->ht,
			&iter, socket, node.node) {
		ret = check_session_rotation_pending_local_on_consumer(session,
				socket, &rotation_completed);
		if (ret || !rotation_completed) {
			goto end;
		}
	}

skip_ust:
	if (!session->kernel_session) {
		goto skip_kernel;
	}
	cds_lfht_for_each_entry(session->kernel_session->consumer->socks->ht,
				&iter, socket, node.node) {
		ret = check_session_rotation_pending_local_on_consumer(session,
				socket, &rotation_completed);
		if (ret || !rotation_completed) {
			goto end;
		}
	}
skip_kernel:
end:
	rcu_read_unlock();

	if (rotation_completed) {
		DBG("[rotation-thread] Local rotation of trace archive %" PRIu64 " of session \"%s\" is complete on all consumers",
				session->current_archive_id - 1,
				session->name);
		session->rotation_pending_local = false;
	}
	if (ret) {
		ret = session_reset_rotation_state(session,
				LTTNG_ROTATION_STATE_ERROR);
		if (ret) {
			ERR("Failed to reset rotation state of session \"%s\"",
					session->name);
		}
	}
	return 0;
}

static
int check_session_rotation_pending_relay(struct ltt_session *session)
{
	int ret;
	struct consumer_socket *socket;
	struct cds_lfht_iter iter;
	bool rotation_completed = true;
	const struct consumer_output *output;

	/*
	 * Check for a pending rotation on any consumer as we only use
	 * it as a "tunnel" to the relayd.
	 */

	rcu_read_lock();
	if (session->ust_session) {
		cds_lfht_first(session->ust_session->consumer->socks->ht,
				&iter);
		output = session->ust_session->consumer;
	} else {
		cds_lfht_first(session->kernel_session->consumer->socks->ht,
				&iter);
		output = session->kernel_session->consumer;
	}
	assert(cds_lfht_iter_get_node(&iter));

	socket = caa_container_of(cds_lfht_iter_get_node(&iter),
			typeof(*socket), node.node);

	pthread_mutex_lock(socket->lock);
	DBG("[rotation-thread] Checking for pending relay rotation on session \"%s\", trace archive %" PRIu64 " through the %s consumer",
			session->name, session->current_archive_id - 1,
			lttng_consumer_type_str(socket->type));
	ret = consumer_check_rotation_pending_relay(socket,
			output,
			session->id,
			session->current_archive_id - 1);
	pthread_mutex_unlock(socket->lock);

	if (ret == 0) {
		/* Rotation was completed on the relay. */
		DBG("[rotation-thread] Relay rotation of trace archive %" PRIu64 " of session \"%s\" was completed",
				session->current_archive_id - 1,
				session->name);
	} else if (ret == 1) {
		/* Rotation pending on relay. */
		DBG("[rotation-thread] Relay rotation of trace archive %" PRIu64 " of session \"%s\" is pending",
				session->current_archive_id - 1,
				session->name);
		rotation_completed = false;
	} else {
		/* Not a fatal error. */
		ERR("[rotation-thread] Encountered an error when checking if rotation of trace archive %" PRIu64 " of session \"%s\" is pending on the relay",
				session->current_archive_id - 1,
				session->name);
		ret = session_reset_rotation_state(session,
				LTTNG_ROTATION_STATE_ERROR);
		if (ret) {
			ERR("Failed to reset rotation state of session \"%s\"",
					session->name);
		}
		rotation_completed = false;
	}

	rcu_read_unlock();

	if (rotation_completed) {
		DBG("[rotation-thread] Totation of trace archive %" PRIu64 " of session \"%s\" is complete on the relay",
				session->current_archive_id - 1,
				session->name);
		session->rotation_pending_relay = false;
	}
	return 0;
}

/*
 * Check if the last rotation was completed, called with session lock held.
 */
static
int check_session_rotation_pending(struct ltt_session *session,
		struct notification_thread_handle *notification_thread_handle)
{
	int ret;
	struct lttng_trace_archive_location *location;
	time_t now;

	DBG("[rotation-thread] Checking for pending rotation on session \"%s\", trace archive %" PRIu64,
			session->name, session->current_archive_id - 1);

	if (session->rotation_pending_local) {
		/* Updates session->rotation_pending_local as needed. */
		ret = check_session_rotation_pending_local(session);
		if (ret) {
			goto end;
		}

		/*
		 * No need to check for a pending rotation on the relay
		 * since the rotation is not even completed locally yet.
		 */
		if (session->rotation_pending_local) {
			goto end;
		}
	}

	if (session->rotation_pending_relay) {
		/* Updates session->rotation_pending_relay as needed. */
		ret = check_session_rotation_pending_relay(session);
		if (ret) {
			goto end;
		}

		if (session->rotation_pending_relay) {
			goto end;
		}
	}

	DBG("[rotation-thread] Rotation of trace archive %" PRIu64 " completed for "
			"session %s", session->current_archive_id - 1,
			session->name);

	/* Rename the completed trace archive's location. */
	now = time(NULL);
	if (now == (time_t) -1) {
		ret = session_reset_rotation_state(session,
				LTTNG_ROTATION_STATE_ERROR);
		if (ret) {
			ERR("Failed to reset rotation state of session \"%s\"",
					session->name);
		}
		ret = LTTNG_ERR_UNK;
		goto end;
	}

	ret = rename_completed_chunk(session, now);
	if (ret < 0) {
		ERR("Failed to rename completed rotation chunk");
		goto end;
	}
	session->last_chunk_start_ts = session->current_chunk_start_ts;

	/*
	 * Now we can clear the "ONGOING" state in the session. New
	 * rotations can start now.
	 */
	session->rotation_state = LTTNG_ROTATION_STATE_COMPLETED;

	/* Ownership of location is transferred. */
	location = session_get_trace_archive_location(session);
	ret = notification_thread_command_session_rotation_completed(
			notification_thread_handle,
			session->name,
			session->uid,
			session->gid,
			session->current_archive_id,
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
				session->current_archive_id);
		if (ret != LTTNG_OK) {
			ERR("[rotation-thread] Failed to notify notification thread of completed rotation for session %s",
					session->name);
		}

		ret = rename_active_chunk(session);
		if (ret < 0) {
			ERR("[rotation-thread] Failed to rename active rotation chunk");
			goto end;
		}

		/* Ownership of location is transferred. */
		location = session_get_trace_archive_location(session);
		ret = notification_thread_command_session_rotation_completed(
				notification_thread_handle,
				session->name,
				session->uid,
				session->gid,
				session->current_archive_id,
				location);
		if (ret != LTTNG_OK) {
			ERR("[rotation-thread] Failed to notify notification thread of completed rotation for session %s",
					session->name);
		}
	}

	ret = 0;
end:
	if (session->rotation_state == LTTNG_ROTATION_STATE_ONGOING) {
		DBG("[rotation-thread] Rotation of trace archive %" PRIu64 " is still pending for session %s",
				session->current_archive_id - 1, session->name);
		ret = timer_session_rotation_pending_check_start(session,
				DEFAULT_ROTATE_PENDING_TIMER);
		if (ret) {
			ERR("Re-enabling rotate pending timer");
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
	int fd = lttng_pipe_get_readfd(queue->event_pipe);
	struct ltt_session *session;
	char buf;

	ret = lttng_read(fd, &buf, 1);
	if (ret != 1) {
		ERR("[rotation-thread] Failed to read from wakeup pipe (fd = %i)", fd);
		ret = -1;
		goto end;
	}

	for (;;) {
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
		session = session_find_by_id(job->session_id);
		if (!session) {
			DBG("[rotation-thread] Session %" PRIu64 " not found",
					job->session_id);
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
			session_unlock_list();
			free(job);
			continue;
		}

		session_lock(session);
	        ret = run_job(job, session, handle->notification_thread_handle);
		session_unlock(session);
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
	session_unlock_list();

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
		ERR("[rotation-thread ]Error occured while checking for pending notification");
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

	/* Ready to handle client connections. */
	sessiond_notify_ready();

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

			if (sessiond_check_thread_quit_pipe(fd, revents)) {
				DBG("[rotation-thread] Quit pipe activity");
				/* TODO flush the queue. */
				goto exit;
			} else if (fd == lttng_pipe_get_readfd(handle->rotation_timer_queue->event_pipe)) {
				ret = handle_job_queue(handle, &thread,
						handle->rotation_timer_queue);
				if (ret) {
					ERR("[rotation-thread] Failed to handle rotation timer pipe event");
					goto error;
				}
			} else if (fd == rotate_notification_channel->socket) {
				ret = handle_notification_channel(fd, handle,
						&thread);
				if (ret) {
					ERR("[rotation-thread] Error occured while handling activity on notification channel socket");
					goto error;
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
