/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
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
#include "session.h"

struct rotation_thread_handle {
	/*
	 * Read side of pipes used to communicate with the rotation thread.
	 */
	/* Notification from the consumers */
	int ust32_consumer;
	int ust64_consumer;
	int kernel_consumer;
	/* quit pipe */
	int thread_quit_pipe;
};

struct rotation_thread_handle *rotation_thread_handle_create(
		struct lttng_pipe *ust32_channel_rotate_pipe,
		struct lttng_pipe *ust64_channel_rotate_pipe,
		struct lttng_pipe *kernel_channel_rotate_pipe,
		int thread_quit_pipe);

void rotation_thread_handle_destroy(
		struct rotation_thread_handle *handle);

void *thread_rotation(void *data);

#endif /* ROTATION_THREAD_H */
