/*
 * Copyright (C) 2014 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
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

#ifndef LTTNG_LOAD_INTERNAL_ABI_H
#define LTTNG_LOAD_INTERNAL_ABI_H

#include <limits.h>
#include <stdint.h>

#include <lttng/constant.h>
#include <common/macros.h>
#include <common/config/session-config.h>

/*
 * Object used by the load_session API. This is opaque to the public library.
 */
struct lttng_load_session_attr {
	/* Name of the session to load, empty string means all. */
	char session_name[LTTNG_NAME_MAX];
	/* URL of the session configuration file to load. */
	char input_url[PATH_MAX];
	/* Overwrite the session if it exists. */
	uint32_t overwrite;
	/* The raw override url for getter */
	char *raw_override_url;
	/* The raw override path url for getter */
	char *raw_override_path_url;
	/* The raw override ctrl url for getter */
	char *raw_override_ctrl_url;
	/* The raw override data url for getter */
	char *raw_override_data_url;
	/* Override struct */
	struct config_load_session_override_attr *override_attr;
} LTTNG_PACKED;

#endif /* LTTNG_LOAD_INTERNAL_ABI_H */
