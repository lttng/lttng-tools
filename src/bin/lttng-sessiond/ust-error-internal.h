#ifndef _LTTNG_UST_ERROR_H
#define _LTTNG_UST_ERROR_H

/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Julien Desfossez <julien.desfossez@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * This header is meant for liblttng and libust internal use ONLY.
 * These declarations should NOT be considered stable API.
 */

#include <limits.h>
#include <unistd.h>

#include "lttng-ust-abi.h"

/*
 * ustcomm error code.
 */
enum lttng_ust_error_code {
	LTTNG_UST_OK = 0,			/* Ok */
	LTTNG_UST_ERR = 1024,			/* Unknown Error */
	LTTNG_UST_ERR_NOENT = 1025,		/* No entry */
	LTTNG_UST_ERR_EXIST = 1026,		/* Object exists */
	LTTNG_UST_ERR_INVAL = 1027,		/* Invalid argument */
	LTTNG_UST_ERR_PERM  = 1028,		/* Permission denied */
	LTTNG_UST_ERR_NOSYS = 1029,		/* Not implemented */
	LTTNG_UST_ERR_EXITING = 1030,		/* Process is exiting */

	LTTNG_UST_ERR_INVAL_MAGIC = 1031,	/* Invalid magic number */
	LTTNG_UST_ERR_INVAL_SOCKET_TYPE = 1032,	/* Invalid socket type */
	LTTNG_UST_ERR_UNSUP_MAJOR = 1033,	/* Unsupported major version */

	/* MUST be last element */
	LTTNG_UST_ERR_NR,			/* Last element */
};

/*
 * Return a human-readable error message for an lttng-ust error code.
 * code must be a positive value (or 0).
 */
extern const char *lttng_ust_strerror(int code);

#endif	/* _LTTNG_UST_ERROR_H */
