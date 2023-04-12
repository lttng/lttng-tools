/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef ROTATION_THREAD_H
#define ROTATION_THREAD_H

#include "notification-thread.hpp"
#include "session.hpp"

#include <common/compat/poll.hpp>
#include <common/eventfd.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/pipe.hpp>

#include <lttng/domain.h>
#include <lttng/notification/channel-internal.hpp>

#include <memory>
#include <pthread.h>
#include <semaphore.h>
#include <urcu.h>
#include <urcu/list.h>
#include <urcu/rculfhash.h>

namespace lttng {
namespace sessiond {

enum class rotation_thread_job_type { SCHEDULED_ROTATION, CHECK_PENDING_ROTATION };

struct rotation_thread_timer_queue;

class rotation_thread {
public:
	using uptr = std::unique_ptr<rotation_thread>;

	rotation_thread(rotation_thread_timer_queue& rotation_timer_queue,
			notification_thread_handle& notification_thread_handle);
	~rotation_thread();

	/* Only use through the lttng_thread facilities. */
	void launch_thread();
	bool shutdown() const noexcept;

	/*
	 * Subscribe/unsubscribe the rotation_thread's notification_channel to/from
	 * session usage notifications to perform size-based rotations.
	 */
	void subscribe_session_consumed_size_rotation(ltt_session& session, std::uint64_t size);
	void unsubscribe_session_consumed_size_rotation(ltt_session& session);

private:
	void _thread_function() noexcept;
	void _run();
	void _handle_job_queue();
	void _handle_notification(const lttng_notification& notification);
	void _handle_notification_channel_activity();

	struct rotation_thread_timer_queue& _rotation_timer_queue;
	/* Access to the notification thread cmd_queue */
	notification_thread_handle& _notification_thread_handle;
	/* Thread-specific quit pipe. */
	lttng_pipe::uptr _quit_pipe;
	lttng_notification_channel::uptr _notification_channel;
	/*
	 * Use an event_fd to wake-up the rotation thread whenever a command
	 * completes on the notification channel. This ensures that any
	 * notification that was queued while waiting for a reply to the command is
	 * eventually consumed.
	 */
	lttng::eventfd _notification_channel_subscribtion_change_eventfd;
	lttng_poll_event _events;
};

struct rotation_thread_timer_queue *rotation_thread_timer_queue_create(void);
void rotation_thread_timer_queue_destroy(struct rotation_thread_timer_queue *queue);
void rotation_thread_enqueue_job(struct rotation_thread_timer_queue *queue,
				 enum rotation_thread_job_type job_type,
				 struct ltt_session *session);

} /* namespace sessiond */
} /* namespace lttng */

#endif /* ROTATION_THREAD_H */
