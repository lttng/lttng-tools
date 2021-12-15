/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef ROTATION_THREAD_H
#define ROTATION_THREAD_H

#include <urcu/list.h>
#include <urcu.h>
#include <urcu/rculfhash.h>
#include <lttng/domain.h>
#include <common/pipe.hpp>
#include <common/compat/poll.hpp>
#include <common/hashtable/hashtable.hpp>
#include <pthread.h>
#include <semaphore.h>
#include "session.hpp"
#include "notification-thread.hpp"

extern struct lttng_notification_channel *rotate_notification_channel;

enum rotation_thread_job_type {
	ROTATION_THREAD_JOB_TYPE_SCHEDULED_ROTATION,
	ROTATION_THREAD_JOB_TYPE_CHECK_PENDING_ROTATION
};

struct rotation_thread_timer_queue;
struct rotation_thread_handle;

struct rotation_thread_timer_queue *rotation_thread_timer_queue_create(void);
void rotation_thread_timer_queue_destroy(
		struct rotation_thread_timer_queue *queue);

struct rotation_thread_handle *rotation_thread_handle_create(
		struct rotation_thread_timer_queue *rotation_timer_queue,
		struct notification_thread_handle *notification_thread_handle);

void rotation_thread_handle_destroy(
		struct rotation_thread_handle *handle);

void rotation_thread_enqueue_job(struct rotation_thread_timer_queue *queue,
		enum rotation_thread_job_type job_type,
		struct ltt_session *session);

bool launch_rotation_thread(struct rotation_thread_handle *handle);

#endif /* ROTATION_THREAD_H */
