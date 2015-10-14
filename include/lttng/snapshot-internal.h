/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
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

#ifndef LTTNG_SNAPSHOT_INTERNAL_ABI_H
#define LTTNG_SNAPSHOT_INTERNAL_ABI_H

#include <limits.h>
#include <stdint.h>
#include <lttng/constant.h>

/*
 * Object used for the snapshot API. This is opaque to the public library.
 */
struct lttng_snapshot_output {
	/*
	 * ID of the snapshot output. This is only used when they are listed. It is
	 * assigned by the session daemon so when adding an output, this value will
	 * not be used.
	 */
	uint32_t id;
	/*
	 * Maximum size in bytes of the snapshot meaning the total size of all
	 * stream combined. A value of 0 is unlimited.
	 */
	uint64_t max_size;
	/* Name of the output so it can be recognized easily when listing them. */
	char name[LTTNG_NAME_MAX];
	/* Destination of the output. See lttng(1) for URL format. */
	char ctrl_url[PATH_MAX];
	/* Destination of the output. See lttng(1) for URL format. */
	char data_url[PATH_MAX];
};

/*
 * Snapshot output list object opaque to the user.
 */
struct lttng_snapshot_output_list {
	/*
	 * The position in the output array. This is changed by a get_next call.
	 */
	int index;

	/*
	 * Number of element in the array.
	 */
	size_t count;

	/*
	 * Containes snapshot output object.
	 */
	struct lttng_snapshot_output *array;
};

#endif /* LTTNG_SNAPSHOT_INTERNAL_ABI_H */
