/*
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_LOGLEVEL_UTILS_H
#define _LTTNG_LOGLEVEL_UTILS_H

#include <lttng/lttng.h>
#include <common/macros.h>

LTTNG_HIDDEN
int loglevel_name_to_value(const char *name, enum lttng_loglevel *loglevel);

LTTNG_HIDDEN
int loglevel_log4j_name_to_value(
		const char *name, enum lttng_loglevel_log4j *loglevel);

LTTNG_HIDDEN
int loglevel_jul_name_to_value(
		const char *name, enum lttng_loglevel_jul *loglevel);

LTTNG_HIDDEN
int loglevel_python_name_to_value(
		const char *name, enum lttng_loglevel_python *loglevel);

#endif /* _LTTNG_LOGLEVEL_UTILS_H */
