/*
 * Copyright (C) 2014 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2014 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_LOAD_INTERNAL_ABI_H
#define LTTNG_LOAD_INTERNAL_ABI_H

#include <common/config/session-config.hpp>
#include <common/macros.hpp>

#include <lttng/constant.h>

#include <limits.h>
#include <stdint.h>

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
