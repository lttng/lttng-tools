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

#ifndef ROTATION_THREAD_H
#define ROTATION_THREAD_H

#include <urcu/list.h>
#include <urcu.h>
#include <urcu/rculfhash.h>
#include <lttng/domain.h>
#include <common/pipe.h>
#include <common/compat/poll.h>
#include <common/hashtable/hashtable.h>
#include <pthread.h>
#include <semaphore.h>
#include "session.h"
#include "notification-thread.h"

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
		int thread_quit_pipe,
		struct rotation_thread_timer_queue *rotation_timer_queue,
		struct notification_thread_handle *notification_thread_handle,
		sem_t *notification_thread_ready);

void rotation_thread_handle_destroy(
		struct rotation_thread_handle *handle);

void rotation_thread_enqueue_job(struct rotation_thread_timer_queue *queue,
		enum rotation_thread_job_type job_type, uint64_t session_id);

void *thread_rotation(void *data);

#endif /* ROTATION_THREAD_H */
