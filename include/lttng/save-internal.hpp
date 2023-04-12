/*
 * Copyright (C) 2013 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_SAVE_INTERNAL_ABI_H
#define LTTNG_SAVE_INTERNAL_ABI_H

#include <common/macros.hpp>

#include <lttng/constant.h>

#include <limits.h>
#include <stdint.h>

/*
 * Object used by the save_session API. This is opaque to the public library.
 */
struct lttng_save_session_attr {
	/* Name of the session to save, empty string means all. */
	char session_name[LTTNG_NAME_MAX];
	/* Destination of the session configuration. See lttng(1) for URL format. */
	char configuration_url[PATH_MAX];
	/* Overwrite the session configuration file if it exists. */
	uint8_t overwrite;
	/* Omit the sessions' name(s). */
	uint8_t omit_name;
	/* Omit the sessions' output(s). */
	uint8_t omit_output;
} LTTNG_PACKED;

#endif /* LTTNG_SAVE_INTERNAL_ABI_H */
