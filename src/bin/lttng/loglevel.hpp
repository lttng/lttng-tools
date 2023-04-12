/*
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_LOGLEVEL_UTILS_H
#define _LTTNG_LOGLEVEL_UTILS_H

#include <common/macros.hpp>

#include <lttng/lttng.h>

int loglevel_name_to_value(const char *name, enum lttng_loglevel *loglevel);

bool loglevel_parse_range_string(const char *str,
				 enum lttng_loglevel *min,
				 enum lttng_loglevel *max);

int loglevel_log4j_name_to_value(const char *name, enum lttng_loglevel_log4j *loglevel);

bool loglevel_log4j_parse_range_string(const char *str,
				       enum lttng_loglevel_log4j *min,
				       enum lttng_loglevel_log4j *max);

int loglevel_jul_name_to_value(const char *name, enum lttng_loglevel_jul *loglevel);

bool loglevel_jul_parse_range_string(const char *str,
				     enum lttng_loglevel_jul *min,
				     enum lttng_loglevel_jul *max);

int loglevel_python_name_to_value(const char *name, enum lttng_loglevel_python *loglevel);

bool loglevel_python_parse_range_string(const char *str,
					enum lttng_loglevel_python *min,
					enum lttng_loglevel_python *max);

const char *loglevel_value_to_name(int loglevel);

const char *loglevel_log4j_value_to_name(int loglevel);

const char *loglevel_jul_value_to_name(int loglevel);

const char *loglevel_python_value_to_name(int loglevel);

#endif /* _LTTNG_LOGLEVEL_UTILS_H */
