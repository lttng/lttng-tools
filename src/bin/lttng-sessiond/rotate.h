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

#ifndef ROTATE_H
#define ROTATE_H

#include "rotation-thread.h"
#include <stdint.h>

/*
 * Subscribe/unsubscribe the notification_channel from the rotation_thread to
 * session usage notifications to perform size-based rotations.
 */
int subscribe_session_consumed_size_rotation(struct ltt_session *session,
		uint64_t size,
		struct notification_thread_handle *notification_thread_handle);
int unsubscribe_session_consumed_size_rotation(struct ltt_session *session,
		struct notification_thread_handle *notification_thread_handle);

#endif /* ROTATE_H */
