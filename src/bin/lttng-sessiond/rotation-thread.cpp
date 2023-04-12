/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "cmd.hpp"
#include "health-sessiond.hpp"
#include "lttng-sessiond.hpp"
#include "notification-thread-commands.hpp"
#include "rotation-thread.hpp"
#include "session.hpp"
#include "thread.hpp"
#include "timer.hpp"
#include "utils.hpp"

#include <common/align.hpp>
#include <common/config/session-config.hpp>
#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/eventfd.hpp>
#include <common/exception.hpp>
#include <common/file-descriptor.hpp>
#include <common/format.hpp>
#include <common/futex.hpp>
#include <common/hashtable/utils.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/locked-reference.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/pthread-lock.hpp>
#include <common/scope-exit.hpp>
#include <common/time.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

#include <lttng/action/action-internal.hpp>
#include <lttng/condition/condition-internal.hpp>
#include <lttng/location-internal.hpp>
#include <lttng/notification/channel-internal.hpp>
#include <lttng/notification/notification-internal.hpp>
#include <lttng/rotate-internal.hpp>
#include <lttng/trigger/trigger.h>

#include <inttypes.h>
#include <memory>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <time.h>
#include <urcu.h>
#include <urcu/list.h>

namespace ls = lttng::sessiond;

/*
 * The timer thread enqueues jobs and wakes up the rotation thread.
 * When the rotation thread wakes up, it empties the queue.
 */
struct ls::rotation_thread_timer_queue {
	struct lttng_pipe *event_pipe;
	struct cds_list_head list;
	pthread_mutex_t lock;
};

namespace {
struct rotation_thread_job {
	using uptr = std::unique_ptr<
		rotation_thread_job,
		lttng::details::create_unique_class<rotation_thread_job, lttng::free>>;

	enum ls::rotation_thread_job_type type;
	struct ltt_session *session;
	/* List member in struct rotation_thread_timer_queue. */
	struct cds_list_head head;
};

const char *get_job_type_str(enum ls::rotation_thread_job_type job_type)
{
	switch (job_type) {
	case ls::rotation_thread_job_type::CHECK_PENDING_ROTATION:
		return "CHECK_PENDING_ROTATION";
	case ls::rotation_thread_job_type::SCHEDULED_ROTATION:
		return "SCHEDULED_ROTATION";
	default:
		abort();
	}
}

/*
 * Called with the rotation_thread_timer_queue lock held.
 * Return true if the same timer job already exists in the queue, false if not.
 */
bool timer_job_exists(const ls::rotation_thread_timer_queue *queue,
		      ls::rotation_thread_job_type job_type,
		      ltt_session *session)
{
	bool exists = false;
	struct rotation_thread_job *job;

	cds_list_for_each_entry (job, &queue->list, head) {
		if (job->session == session && job->type == job_type) {
			exists = true;
			goto end;
		}
	}
end:
	return exists;
}

void check_session_rotation_pending_on_consumers(ltt_session& session, bool& _rotation_completed)
{
	int ret = 0;
	struct consumer_socket *socket;
	struct cds_lfht_iter iter;
	enum consumer_trace_chunk_exists_status exists_status;
	uint64_t relayd_id;
	bool chunk_exists_on_peer = false;
	enum lttng_trace_chunk_status chunk_status;
	lttng::urcu::read_lock_guard read_lock;

	LTTNG_ASSERT(session.chunk_being_archived);

	/*
	 * Check for a local pending rotation on all consumers (32-bit
	 * user space, 64-bit user space, and kernel).
	 */
	if (!session.ust_session) {
		goto skip_ust;
	}

	cds_lfht_for_each_entry (
		session.ust_session->consumer->socks->ht, &iter, socket, node.node) {
		relayd_id = session.ust_session->consumer->type == CONSUMER_DST_LOCAL ?
			-1ULL :
			session.ust_session->consumer->net_seq_index;

		lttng::pthread::lock_guard socket_lock(*socket->lock);
		ret = consumer_trace_chunk_exists(socket,
						  relayd_id,
						  session.id,
						  session.chunk_being_archived,
						  &exists_status);
		if (ret) {
			ERR("Error occurred while checking rotation status on consumer daemon");
			goto end;
		}

		if (exists_status != CONSUMER_TRACE_CHUNK_EXISTS_STATUS_UNKNOWN_CHUNK) {
			chunk_exists_on_peer = true;
			goto end;
		}
	}

skip_ust:
	if (!session.kernel_session) {
		goto skip_kernel;
	}

	cds_lfht_for_each_entry (
		session.kernel_session->consumer->socks->ht, &iter, socket, node.node) {
		lttng::pthread::lock_guard socket_lock(*socket->lock);

		relayd_id = session.kernel_session->consumer->type == CONSUMER_DST_LOCAL ?
			-1ULL :
			session.kernel_session->consumer->net_seq_index;

		ret = consumer_trace_chunk_exists(socket,
						  relayd_id,
						  session.id,
						  session.chunk_being_archived,
						  &exists_status);
		if (ret) {
			ERR("Error occurred while checking rotation status on consumer daemon");
			goto end;
		}

		if (exists_status != CONSUMER_TRACE_CHUNK_EXISTS_STATUS_UNKNOWN_CHUNK) {
			chunk_exists_on_peer = true;
			goto end;
		}
	}
skip_kernel:
end:

	if (!chunk_exists_on_peer) {
		uint64_t chunk_being_archived_id;

		chunk_status = lttng_trace_chunk_get_id(session.chunk_being_archived,
							&chunk_being_archived_id);
		LTTNG_ASSERT(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);
		DBG("Rotation of trace archive %" PRIu64
		    " of session \"%s\" is complete on all consumers",
		    chunk_being_archived_id,
		    session.name);
	}

	_rotation_completed = !chunk_exists_on_peer;
	if (ret) {
		ret = session_reset_rotation_state(session, LTTNG_ROTATION_STATE_ERROR);
		if (ret) {
			ERR("Failed to reset rotation state of session \"%s\"", session.name);
		}
	}
}

/*
 * Check if the last rotation was completed, called with session lock held.
 * Should only return non-zero in the event of a fatal error. Doing so will
 * shutdown the thread.
 */
int check_session_rotation_pending(ltt_session& session,
				   notification_thread_handle& notification_thread_handle)
{
	int ret;
	struct lttng_trace_archive_location *location;
	enum lttng_trace_chunk_status chunk_status;
	bool rotation_completed = false;
	const char *archived_chunk_name;
	uint64_t chunk_being_archived_id;

	if (!session.chunk_being_archived) {
		ret = 0;
		goto end;
	}

	chunk_status =
		lttng_trace_chunk_get_id(session.chunk_being_archived, &chunk_being_archived_id);
	LTTNG_ASSERT(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);

	DBG("Checking for pending rotation on session \"%s\", trace archive %" PRIu64,
	    session.name,
	    chunk_being_archived_id);

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
		goto check_ongoing_rotation;
	}

	check_session_rotation_pending_on_consumers(session, rotation_completed);
	if (!rotation_completed || session.rotation_state == LTTNG_ROTATION_STATE_ERROR) {
		goto check_ongoing_rotation;
	}

	/*
	 * Now we can clear the "ONGOING" state in the session. New
	 * rotations can start now.
	 */
	chunk_status = lttng_trace_chunk_get_name(
		session.chunk_being_archived, &archived_chunk_name, nullptr);
	LTTNG_ASSERT(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);
	free(session.last_archived_chunk_name);
	session.last_archived_chunk_name = strdup(archived_chunk_name);
	if (!session.last_archived_chunk_name) {
		PERROR("Failed to duplicate archived chunk name");
	}

	session_reset_rotation_state(session, LTTNG_ROTATION_STATE_COMPLETED);

	if (!session.quiet_rotation) {
		location = session_get_trace_archive_location(&session);
		ret = notification_thread_command_session_rotation_completed(
			&notification_thread_handle,
			session.id,
			session.last_archived_chunk_id.value,
			location);
		lttng_trace_archive_location_put(location);
		if (ret != LTTNG_OK) {
			ERR("Failed to notify notification thread of completed rotation for session %s",
			    session.name);
		}
	}

	ret = 0;
check_ongoing_rotation:
	if (session.rotation_state == LTTNG_ROTATION_STATE_ONGOING) {
		chunk_status = lttng_trace_chunk_get_id(session.chunk_being_archived,
							&chunk_being_archived_id);
		LTTNG_ASSERT(chunk_status == LTTNG_TRACE_CHUNK_STATUS_OK);

		DBG("Rotation of trace archive %" PRIu64 " is still pending for session %s",
		    chunk_being_archived_id,
		    session.name);
		ret = timer_session_rotation_pending_check_start(&session,
								 DEFAULT_ROTATE_PENDING_TIMER);
		if (ret) {
			ERR("Failed to re-enable rotation pending timer");
			ret = -1;
			goto end;
		}
	}

end:
	return ret;
}

/* Call with the session and session_list locks held. */
int launch_session_rotation(ltt_session& session)
{
	int ret;
	struct lttng_rotate_session_return rotation_return;

	DBG("Launching scheduled time-based rotation on session \"%s\"", session.name);

	ASSERT_SESSION_LIST_LOCKED();
	ASSERT_LOCKED(session.lock);

	ret = cmd_rotate_session(&session,
				 &rotation_return,
				 false,
				 LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED);
	if (ret == LTTNG_OK) {
		DBG("Scheduled time-based rotation successfully launched on session \"%s\"",
		    session.name);
	} else {
		/* Don't consider errors as fatal. */
		DBG("Scheduled time-based rotation aborted for session %s: %s",
		    session.name,
		    lttng_strerror(ret));
	}

	return 0;
}

int run_job(const rotation_thread_job& job,
	    ltt_session& session,
	    notification_thread_handle& notification_thread_handle)
{
	int ret;

	switch (job.type) {
	case ls::rotation_thread_job_type::SCHEDULED_ROTATION:
		ret = launch_session_rotation(session);
		break;
	case ls::rotation_thread_job_type::CHECK_PENDING_ROTATION:
		ret = check_session_rotation_pending(session, notification_thread_handle);
		break;
	default:
		abort();
	}

	return ret;
}

bool shutdown_rotation_thread(void *thread_data)
{
	auto *handle = reinterpret_cast<const ls::rotation_thread *>(thread_data);

	return handle->shutdown();
}
} /* namespace */

ls::rotation_thread_timer_queue *ls::rotation_thread_timer_queue_create()
{
	auto queue = zmalloc<ls::rotation_thread_timer_queue>();
	if (!queue) {
		PERROR("Failed to allocate timer rotate queue");
		goto end;
	}

	queue->event_pipe = lttng_pipe_open(FD_CLOEXEC | O_NONBLOCK);
	CDS_INIT_LIST_HEAD(&queue->list);
	pthread_mutex_init(&queue->lock, nullptr);
end:
	return queue;
}

void ls::rotation_thread_timer_queue_destroy(struct rotation_thread_timer_queue *queue)
{
	if (!queue) {
		return;
	}

	lttng_pipe_destroy(queue->event_pipe);

	{
		lttng::pthread::lock_guard queue_lock(queue->lock);

		LTTNG_ASSERT(cds_list_empty(&queue->list));
	}

	pthread_mutex_destroy(&queue->lock);
	free(queue);
}

ls::rotation_thread::rotation_thread(rotation_thread_timer_queue& rotation_timer_queue,
				     notification_thread_handle& notification_thread_handle) :
	_rotation_timer_queue{ rotation_timer_queue },
	_notification_thread_handle{ notification_thread_handle }
{
	_quit_pipe.reset([]() {
		auto raw_pipe = lttng_pipe_open(FD_CLOEXEC);
		if (!raw_pipe) {
			LTTNG_THROW_POSIX("Failed to rotation thread's quit pipe", errno);
		}

		return raw_pipe;
	}());

	_notification_channel.reset([]() {
		auto channel = lttng_notification_channel_create(
			lttng_session_daemon_notification_endpoint);
		if (!channel) {
			LTTNG_THROW_ERROR(
				"Failed to create notification channel of rotation thread");
		}

		return channel;
	}());

	lttng_poll_init(&_events);

	/*
	 * Create pollset with size 4:
	 *	- rotation thread quit pipe,
	 *	- rotation thread timer queue pipe,
	 *	- notification channel sock,
	 *	- subscribtion change event fd
	 */
	if (lttng_poll_create(&_events, 4, LTTNG_CLOEXEC) < 0) {
		LTTNG_THROW_ERROR("Failed to create poll object for rotation thread");
	}

	if (lttng_poll_add(&_events, lttng_pipe_get_readfd(_quit_pipe.get()), LPOLLIN) < 0) {
		LTTNG_THROW_ERROR("Failed to add quit pipe read fd to poll set");
	}

	if (lttng_poll_add(&_events,
			   lttng_pipe_get_readfd(_rotation_timer_queue.event_pipe),
			   LPOLLIN) < 0) {
		LTTNG_THROW_ERROR("Failed to add rotation timer queue event pipe fd to poll set");
	}

	if (lttng_poll_add(&_events,
			   _notification_channel_subscribtion_change_eventfd.fd(),
			   LPOLLIN) < 0) {
		LTTNG_THROW_ERROR(
			"Failed to add rotation thread notification channel subscription change eventfd to poll set");
	}

	if (lttng_poll_add(&_events, _notification_channel->socket, LPOLLIN) < 0) {
		LTTNG_THROW_ERROR("Failed to add notification channel socket fd to pollset");
	}
}

ls::rotation_thread::~rotation_thread()
{
	lttng_poll_clean(&_events);
}

void ls::rotation_thread_enqueue_job(ls::rotation_thread_timer_queue *queue,
				     ls::rotation_thread_job_type job_type,
				     ltt_session *session)
{
	const char dummy = '!';
	struct rotation_thread_job *job = nullptr;
	const char *job_type_str = get_job_type_str(job_type);
	lttng::pthread::lock_guard queue_lock(queue->lock);

	if (timer_job_exists(queue, job_type, session)) {
		/*
		 * This timer job is already pending, we don't need to add
		 * it.
		 */
		return;
	}

	job = zmalloc<rotation_thread_job>();
	if (!job) {
		PERROR("Failed to allocate rotation thread job of type \"%s\" for session \"%s\"",
		       job_type_str,
		       session->name);
		return;
	}

	/* No reason for this to fail as the caller must hold a reference. */
	(void) session_get(session);

	job->session = session;
	job->type = job_type;
	cds_list_add_tail(&job->head, &queue->list);

	const int write_ret =
		lttng_write(lttng_pipe_get_writefd(queue->event_pipe), &dummy, sizeof(dummy));
	if (write_ret < 0) {
		/*
		 * We do not want to block in the timer handler, the job has
		 * been enqueued in the list, the wakeup pipe is probably full,
		 * the job will be processed when the rotation_thread catches
		 * up.
		 */
		DIAGNOSTIC_PUSH
		DIAGNOSTIC_IGNORE_LOGICAL_OP
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			DIAGNOSTIC_POP
			/*
			 * Not an error, but would be surprising and indicate
			 * that the rotation thread can't keep up with the
			 * current load.
			 */
			DBG("Wake-up pipe of rotation thread job queue is full");
			return;
		}

		PERROR("Failed to wake-up the rotation thread after pushing a job of type \"%s\" for session \"%s\"",
		       job_type_str,
		       session->name);
		return;
	}
}

void ls::rotation_thread::_handle_job_queue()
{
	for (;;) {
		rotation_thread_job::uptr job;

		{
			/* Take the queue lock only to pop an element from the list. */
			lttng::pthread::lock_guard rotation_timer_queue_lock(
				_rotation_timer_queue.lock);
			if (cds_list_empty(&_rotation_timer_queue.list)) {
				break;
			}

			job.reset(cds_list_first_entry(
				&_rotation_timer_queue.list, typeof(rotation_thread_job), head));
			cds_list_del(&job->head);
		}

		session_lock_list();
		const auto unlock_list =
			lttng::make_scope_exit([]() noexcept { session_unlock_list(); });

		/* locked_ptr will unlock the session and release the ref held by the job. */
		session_lock(job->session);
		auto session = ltt_session::locked_ptr(job->session);

		if (run_job(*job, *session, _notification_thread_handle)) {
			return;
		}
	}
}

void ls::rotation_thread::_handle_notification(const lttng_notification& notification)
{
	int ret = 0;
	const char *condition_session_name = nullptr;
	enum lttng_condition_status condition_status;
	enum lttng_evaluation_status evaluation_status;
	uint64_t consumed;
	auto *condition = lttng_notification_get_const_condition(&notification);
	auto *evaluation = lttng_notification_get_const_evaluation(&notification);
	const auto condition_type = lttng_condition_get_type(condition);

	if (condition_type != LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE) {
		LTTNG_THROW_ERROR("Unexpected condition type");
	}

	/* Fetch info to test. */
	condition_status = lttng_condition_session_consumed_size_get_session_name(
		condition, &condition_session_name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		LTTNG_THROW_ERROR("Session name could not be fetched from notification");
	}

	evaluation_status =
		lttng_evaluation_session_consumed_size_get_consumed_size(evaluation, &consumed);
	if (evaluation_status != LTTNG_EVALUATION_STATUS_OK) {
		LTTNG_THROW_ERROR("Failed to get consumed size from evaluation");
	}

	DBG_FMT("Handling session consumed size condition: session_name=`{}`, consumed_size={}",
		condition_session_name,
		consumed);

	session_lock_list();
	const auto unlock_list = lttng::make_scope_exit([]() noexcept { session_unlock_list(); });

	ltt_session::locked_ptr session{ [&condition_session_name]() {
		auto raw_session_ptr = session_find_by_name(condition_session_name);

		if (raw_session_ptr) {
			session_lock(raw_session_ptr);
		}

		return raw_session_ptr;
	}() };
	if (!session) {
		DBG_FMT("Failed to find session while handling notification: notification_type={}, session name=`{}`",
			lttng_condition_type_str(condition_type),
			condition_session_name);
		/*
		 * Not a fatal error: a session can be destroyed before we get
		 * the chance to handle the notification.
		 */
		return;
	}

	if (!lttng_trigger_is_equal(session->rotate_trigger,
				    lttng_notification_get_const_trigger(&notification))) {
		DBG("Notification does not originate from the internal size-based scheduled rotation trigger, skipping");
		return;
	}

	unsubscribe_session_consumed_size_rotation(*session);

	ret = cmd_rotate_session(
		session.get(), nullptr, false, LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED);
	switch (ret) {
	case LTTNG_OK:
		break;
	case -LTTNG_ERR_ROTATION_PENDING:
		DBG("Rotate already pending, subscribe to the next threshold value");
		break;
	case -LTTNG_ERR_ROTATION_MULTIPLE_AFTER_STOP:
		DBG("Rotation already happened since last stop, subscribe to the next threshold value");
		break;
	case -LTTNG_ERR_ROTATION_AFTER_STOP_CLEAR:
		DBG("Rotation already happened since last stop and clear, subscribe to the next threshold value");
		break;
	default:
		LTTNG_THROW_CTL("Failed to rotate on consumed size notification",
				static_cast<lttng_error_code>(-ret));
	}

	subscribe_session_consumed_size_rotation(*session, consumed + session->rotate_size);
}

void ls::rotation_thread::_handle_notification_channel_activity()
{
	bool notification_pending = true;

	/*
	 * A notification channel may have multiple notifications queued-up internally in
	 * its buffers. This is because a notification channel multiplexes command replies
	 * and notifications. The current protocol specifies that multiple notifications can be
	 * received before the reply to a command.
	 *
	 * In such cases, the notification channel client implementation internally queues them and
	 * provides them on the next calls to lttng_notification_channel_get_next_notification().
	 * This is correct with respect to the public API, which is intended to be used in "blocking
	 * mode".
	 *
	 * However, this internal user relies on poll/epoll to wake-up when data is available
	 * on the notification channel's socket. As such, it can't assume that a wake-up means only
	 * one notification is available for consumption since many of them may have been queued in
	 * the channel's internal buffers.
	 */
	while (notification_pending) {
		const auto pending_status = lttng_notification_channel_has_pending_notification(
			_notification_channel.get(), &notification_pending);
		if (pending_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
			LTTNG_THROW_ERROR("Error occurred while checking for pending notification");
		}

		if (!notification_pending) {
			return;
		}

		/* Receive the next notification. */
		lttng_notification::uptr notification;
		enum lttng_notification_channel_status next_notification_status;

		{
			struct lttng_notification *raw_notification_ptr;

			next_notification_status = lttng_notification_channel_get_next_notification(
				_notification_channel.get(), &raw_notification_ptr);
			notification.reset(raw_notification_ptr);
		}

		switch (next_notification_status) {
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_OK:
			break;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED:
			WARN("Dropped notification detected on notification channel used by the rotation management thread.");
			return;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_CLOSED:
			LTTNG_THROW_ERROR("Notification channel was closed");
		default:
			/* Unhandled conditions / errors. */
			LTTNG_THROW_ERROR("Unknown notification channel status");
		}

		_handle_notification(*notification);
	}
}

void ls::rotation_thread::_thread_function() noexcept
{
	DBG("Started rotation thread");

	try {
		_run();
	} catch (const std::exception& e) {
		ERR_FMT("Fatal rotation thread error: {}", e.what());
	}

	DBG("Thread exit");
}

void ls::rotation_thread::_run()
{
	rcu_register_thread();
	const auto unregister_rcu_thread =
		lttng::make_scope_exit([]() noexcept { rcu_unregister_thread(); });

	rcu_thread_online();
	const auto offline_rcu_thread =
		lttng::make_scope_exit([]() noexcept { rcu_thread_offline(); });

	health_register(the_health_sessiond, HEALTH_SESSIOND_TYPE_ROTATION);
	health_code_update();
	const auto unregister_health =
		lttng::make_scope_exit([]() noexcept { health_unregister(the_health_sessiond); });

	const auto queue_pipe_fd = lttng_pipe_get_readfd(_rotation_timer_queue.event_pipe);

	while (true) {
		health_poll_entry();
		DBG("Entering poll wait");
		auto poll_wait_ret = lttng_poll_wait(&_events, -1);
		DBG_FMT("Poll wait returned: ret={}", poll_wait_ret);
		health_poll_exit();
		if (poll_wait_ret < 0) {
			/*
			 * Restart interrupted system call.
			 */
			if (errno == EINTR) {
				continue;
			}

			LTTNG_THROW_POSIX("Error encountered during lttng_poll_wait", errno);
		}

		const auto fd_count = poll_wait_ret;
		for (int i = 0; i < fd_count; i++) {
			const auto fd = LTTNG_POLL_GETFD(&_events, i);
			const auto revents = LTTNG_POLL_GETEV(&_events, i);

			DBG_FMT("Handling descriptor activity: fd={}, events={:b}", fd, revents);

			if (revents & LPOLLERR) {
				LTTNG_THROW_ERROR(
					fmt::format("Polling returned an error on fd: fd={}", fd));
			}

			if (fd == _notification_channel->socket ||
			    fd == _notification_channel_subscribtion_change_eventfd.fd()) {
				try {
					_handle_notification_channel_activity();
				} catch (const lttng::ctl::error& e) {
					/*
					 * The only non-fatal error (rotation failed), others
					 * are caught at the top-level.
					 */
					DBG_FMT("Control error occurred while handling activity on notification channel socket: {}",
						e.what());
					continue;
				}

				if (fd == _notification_channel_subscribtion_change_eventfd.fd()) {
					_notification_channel_subscribtion_change_eventfd
						.decrement();
				}
			} else {
				/* Job queue or quit pipe activity. */

				/*
				 * The job queue is serviced if there is
				 * activity on the quit pipe to ensure it is
				 * flushed and all references held in the queue
				 * are released.
				 */
				_handle_job_queue();
				if (fd == queue_pipe_fd) {
					char buf;

					if (lttng_read(fd, &buf, 1) != 1) {
						LTTNG_THROW_POSIX(
							fmt::format(
								"Failed to read from wakeup pipe: fd={}",
								fd),
							errno);
					}
				} else {
					DBG("Quit pipe activity");
					return;
				}
			}
		}
	}
}

bool ls::rotation_thread::shutdown() const noexcept
{
	const int write_fd = lttng_pipe_get_writefd(_quit_pipe.get());

	return notify_thread_pipe(write_fd) == 1;
}

void ls::rotation_thread::launch_thread()
{
	auto thread = lttng_thread_create(
		"Rotation",
		[](void *ptr) {
			auto handle = reinterpret_cast<rotation_thread *>(ptr);

			handle->_thread_function();
			return static_cast<void *>(nullptr);
		},
		shutdown_rotation_thread,
		nullptr,
		this);
	if (!thread) {
		LTTNG_THROW_ERROR("Failed to launch rotation thread");
	}

	lttng_thread_put(thread);
}

void ls::rotation_thread::subscribe_session_consumed_size_rotation(ltt_session& session,
								   std::uint64_t size)
{
	const struct lttng_credentials session_creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(session.uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE(session.gid),
	};

	ASSERT_LOCKED(session.lock);

	auto rotate_condition = lttng::make_unique_wrapper<lttng_condition, lttng_condition_put>(
		lttng_condition_session_consumed_size_create());
	if (!rotate_condition) {
		LTTNG_THROW_POSIX("Failed to create session consumed size condition object", errno);
	}

	auto condition_status =
		lttng_condition_session_consumed_size_set_threshold(rotate_condition.get(), size);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		LTTNG_THROW_ERROR(fmt::format(
			"Could not set session consumed size condition threshold: size={}", size));
	}

	condition_status = lttng_condition_session_consumed_size_set_session_name(
		rotate_condition.get(), session.name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		LTTNG_THROW_ERROR(fmt::format(
			"Could not set session consumed size condition session name: name=`{}`",
			session.name));
	}

	auto notify_action = lttng::make_unique_wrapper<lttng_action, lttng_action_put>(
		lttng_action_notify_create());
	if (!notify_action) {
		LTTNG_THROW_POSIX("Could not create notify action", errno);
	}

	LTTNG_ASSERT(!session.rotate_trigger);
	/* trigger acquires its own reference to condition and action on success. */
	auto trigger = lttng::make_unique_wrapper<lttng_trigger, lttng_trigger_put>(
		lttng_trigger_create(rotate_condition.get(), notify_action.get()));
	if (!trigger) {
		LTTNG_THROW_POSIX("Could not create size-based rotation trigger", errno);
	}

	/* Ensure this trigger is not visible to external users. */
	lttng_trigger_set_hidden(trigger.get());
	lttng_trigger_set_credentials(trigger.get(), &session_creds);

	auto nc_status = lttng_notification_channel_subscribe(_notification_channel.get(),
							      rotate_condition.get());
	if (nc_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		LTTNG_THROW_ERROR("Could not subscribe to session consumed size notification");
	}

	/*
	 * Ensure any notification queued during the subscription are consumed by queueing an
	 * event.
	 */
	_notification_channel_subscribtion_change_eventfd.increment();

	const auto register_ret = notification_thread_command_register_trigger(
		&_notification_thread_handle, trigger.get(), true);
	if (register_ret != LTTNG_OK) {
		LTTNG_THROW_CTL(
			fmt::format(
				"Failed to register trigger for automatic size-based rotation: session_name{}, size={}",
				session.name,
				size),
			register_ret);
	}

	/* Ownership transferred to the session. */
	session.rotate_trigger = trigger.release();
}

void ls::rotation_thread::unsubscribe_session_consumed_size_rotation(ltt_session& session)
{
	LTTNG_ASSERT(session.rotate_trigger);

	const auto remove_session_trigger = lttng::make_scope_exit([&session]() noexcept {
		lttng_trigger_put(session.rotate_trigger);
		session.rotate_trigger = nullptr;
	});

	const auto unsubscribe_status = lttng_notification_channel_unsubscribe(
		_notification_channel.get(),
		lttng_trigger_get_const_condition(session.rotate_trigger));
	if (unsubscribe_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		LTTNG_THROW_ERROR(fmt::format(
			"Failed to unsubscribe from consumed size condition used to control automatic size-based rotations: session_name=`{}` return_code={}",
			session.name,
			static_cast<int>(unsubscribe_status)));
	}

	/*
	 * Ensure any notification queued during the un-subscription are consumed by queueing an
	 * event.
	 */
	_notification_channel_subscribtion_change_eventfd.increment();

	const auto unregister_status = notification_thread_command_unregister_trigger(
		&_notification_thread_handle, session.rotate_trigger);
	if (unregister_status != LTTNG_OK) {
		LTTNG_THROW_CTL(
			fmt::format(
				"Failed to unregister trigger for automatic size-based rotation: session_name{}",
				session.name),
			unregister_status);
	}
}
