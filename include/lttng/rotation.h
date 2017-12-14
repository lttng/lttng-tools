/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_ROTATION_H
#define LTTNG_ROTATION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Return codes for lttng_rotate_session_get_output_path.
 */
enum lttng_rotation_status {
	/*
	 * After starting a rotation.
	 */
	LTTNG_ROTATION_STATUS_STARTED = 0,
	/*
	 * When the rotation is complete.
	 */
	LTTNG_ROTATION_STATUS_COMPLETED = 1,
	/*
	 * If the handle does not match the last rotate command, we cannot
	 * retrieve the path for the chunk.
	 */
	LTTNG_ROTATION_STATUS_EXPIRED = 2,
	/*
	 * On error.
	 */
	LTTNG_ROTATION_STATUS_ERROR = 3,
	/*
	 * If no rotation occured during this session.
	 */
	LTTNG_ROTATION_STATUS_NO_ROTATION = 4,
};

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ROTATION_H */
