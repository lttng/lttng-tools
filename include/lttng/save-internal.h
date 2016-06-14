/*
 * Copyright (C) 2013 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef LTTNG_SAVE_INTERNAL_ABI_H
#define LTTNG_SAVE_INTERNAL_ABI_H

#include <limits.h>
#include <stdint.h>

#include <lttng/constant.h>
#include <common/macros.h>

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
