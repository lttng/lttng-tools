/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef ROTATE_H
#define ROTATE_H

#include "rotation-thread.hpp"
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
