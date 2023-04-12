/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _LTTNG_UST_ERROR_H
#define _LTTNG_UST_ERROR_H

/*
 * This header is meant for liblttng and libust internal use ONLY.
 * These declarations should NOT be considered stable API.
 */

#include "lttng-ust-abi.hpp"

#include <limits.h>
#include <unistd.h>

/*
 * ustcomm error code.
 */
enum lttng_ust_error_code {
	LTTNG_UST_OK = 0, /* Ok */
	LTTNG_UST_ERR = 1024, /* Unknown Error */
	LTTNG_UST_ERR_NOENT = 1025, /* No entry */
	LTTNG_UST_ERR_EXIST = 1026, /* Object exists */
	LTTNG_UST_ERR_INVAL = 1027, /* Invalid argument */
	LTTNG_UST_ERR_PERM = 1028, /* Permission denied */
	LTTNG_UST_ERR_NOSYS = 1029, /* Not implemented */
	LTTNG_UST_ERR_EXITING = 1030, /* Process is exiting */

	LTTNG_UST_ERR_INVAL_MAGIC = 1031, /* Invalid magic number */
	LTTNG_UST_ERR_INVAL_SOCKET_TYPE = 1032, /* Invalid socket type */
	LTTNG_UST_ERR_UNSUP_MAJOR = 1033, /* Unsupported major version */

	/* MUST be last element */
	LTTNG_UST_ERR_NR, /* Last element */
};

/*
 * Return a human-readable error message for an lttng-ust error code.
 * code must be a positive value (or 0).
 */
extern const char *lttng_ust_strerror(int code);

#endif /* _LTTNG_UST_ERROR_H */
