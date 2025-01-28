/*
 * SPDX-FileCopyrightText: 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
				 enum lttng_loglevel *least_severe,
				 enum lttng_loglevel *most_severe);

int loglevel_log4j_name_to_value(const char *name, enum lttng_loglevel_log4j *loglevel);

bool loglevel_log4j_parse_range_string(const char *str,
				       enum lttng_loglevel_log4j *least_severe,
				       enum lttng_loglevel_log4j *most_severe);

int loglevel_log4j2_name_to_value(const char *name, enum lttng_loglevel_log4j2 *loglevel);

bool loglevel_log4j2_parse_range_string(const char *str,
					enum lttng_loglevel_log4j2 *least_severe,
					enum lttng_loglevel_log4j2 *most_severe);

int loglevel_jul_name_to_value(const char *name, enum lttng_loglevel_jul *loglevel);

bool loglevel_jul_parse_range_string(const char *str,
				     enum lttng_loglevel_jul *least_severe,
				     enum lttng_loglevel_jul *most_severe);

int loglevel_python_name_to_value(const char *name, enum lttng_loglevel_python *loglevel);

bool loglevel_python_parse_range_string(const char *str,
					enum lttng_loglevel_python *least_severe,
					enum lttng_loglevel_python *most_severe);

const char *loglevel_value_to_name(int loglevel);

const char *loglevel_log4j_value_to_name(int loglevel);

const char *loglevel_log4j2_value_to_name(int loglevel);

const char *loglevel_jul_value_to_name(int loglevel);

const char *loglevel_python_value_to_name(int loglevel);

#endif /* _LTTNG_LOGLEVEL_UTILS_H */
