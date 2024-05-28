/*
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "loglevel.hpp"

#include <ctype.h>
#include <string.h>
#include <strings.h>

namespace {
struct loglevel_name_value {
	const char *name;
	int value;
};
} /* namespace */

static const struct loglevel_name_value loglevel_values[] = {
	{ .name = "EMERG", .value = LTTNG_LOGLEVEL_EMERG },
	{ .name = "TRACE_EMERG", .value = LTTNG_LOGLEVEL_EMERG },
	{ .name = "ALERT", .value = LTTNG_LOGLEVEL_ALERT },
	{ .name = "TRACE_ALERT", .value = LTTNG_LOGLEVEL_ALERT },
	{ .name = "CRIT", .value = LTTNG_LOGLEVEL_CRIT },
	{ .name = "TRACE_CRIT", .value = LTTNG_LOGLEVEL_CRIT },
	{ .name = "ERR", .value = LTTNG_LOGLEVEL_ERR },
	{ .name = "TRACE_ERR", .value = LTTNG_LOGLEVEL_ERR },
	{ .name = "WARNING", .value = LTTNG_LOGLEVEL_WARNING },
	{ .name = "TRACE_WARNING", .value = LTTNG_LOGLEVEL_WARNING },
	{ .name = "NOTICE", .value = LTTNG_LOGLEVEL_NOTICE },
	{ .name = "TRACE_NOTICE", .value = LTTNG_LOGLEVEL_NOTICE },
	{ .name = "INFO", .value = LTTNG_LOGLEVEL_INFO },
	{ .name = "TRACE_INFO", .value = LTTNG_LOGLEVEL_INFO },
	{ .name = "DEBUG_SYSTEM", .value = LTTNG_LOGLEVEL_DEBUG_SYSTEM },
	{ .name = "TRACE_DEBUG_SYSTEM", .value = LTTNG_LOGLEVEL_DEBUG_SYSTEM },
	{ .name = "SYSTEM", .value = LTTNG_LOGLEVEL_DEBUG_SYSTEM },
	{ .name = "DEBUG_PROGRAM", .value = LTTNG_LOGLEVEL_DEBUG_PROGRAM },
	{ .name = "TRACE_DEBUG_PROGRAM", .value = LTTNG_LOGLEVEL_DEBUG_PROGRAM },
	{ .name = "PROGRAM", .value = LTTNG_LOGLEVEL_DEBUG_PROGRAM },
	{ .name = "DEBUG_PROCESS", .value = LTTNG_LOGLEVEL_DEBUG_PROCESS },
	{ .name = "TRACE_DEBUG_PROCESS", .value = LTTNG_LOGLEVEL_DEBUG_PROCESS },
	{ .name = "PROCESS", .value = LTTNG_LOGLEVEL_DEBUG_PROCESS },
	{ .name = "DEBUG_MODULE", .value = LTTNG_LOGLEVEL_DEBUG_MODULE },
	{ .name = "TRACE_DEBUG_MODULE", .value = LTTNG_LOGLEVEL_DEBUG_MODULE },
	{ .name = "MODULE", .value = LTTNG_LOGLEVEL_DEBUG_MODULE },
	{ .name = "DEBUG_UNIT", .value = LTTNG_LOGLEVEL_DEBUG_UNIT },
	{ .name = "TRACE_DEBUG_UNIT", .value = LTTNG_LOGLEVEL_DEBUG_UNIT },
	{ .name = "UNIT", .value = LTTNG_LOGLEVEL_DEBUG_UNIT },
	{ .name = "DEBUG_FUNCTION", .value = LTTNG_LOGLEVEL_DEBUG_FUNCTION },
	{ .name = "TRACE_DEBUG_FUNCTION", .value = LTTNG_LOGLEVEL_DEBUG_FUNCTION },
	{ .name = "FUNCTION", .value = LTTNG_LOGLEVEL_DEBUG_FUNCTION },
	{ .name = "DEBUG_LINE", .value = LTTNG_LOGLEVEL_DEBUG_LINE },
	{ .name = "TRACE_DEBUG_LINE", .value = LTTNG_LOGLEVEL_DEBUG_LINE },
	{ .name = "LINE", .value = LTTNG_LOGLEVEL_DEBUG_LINE },
	{ .name = "DEBUG", .value = LTTNG_LOGLEVEL_DEBUG },
	{ .name = "TRACE_DEBUG", .value = LTTNG_LOGLEVEL_DEBUG },
};

static const struct loglevel_name_value loglevel_log4j_values[] = {
	{ .name = "OFF", .value = LTTNG_LOGLEVEL_LOG4J_OFF },
	{ .name = "LOG4J_OFF", .value = LTTNG_LOGLEVEL_LOG4J_OFF },
	{ .name = "FATAL", .value = LTTNG_LOGLEVEL_LOG4J_FATAL },
	{ .name = "LOG4J_FATAL", .value = LTTNG_LOGLEVEL_LOG4J_FATAL },
	{ .name = "ERROR", .value = LTTNG_LOGLEVEL_LOG4J_ERROR },
	{ .name = "LOG4J_ERROR", .value = LTTNG_LOGLEVEL_LOG4J_ERROR },
	{ .name = "WARN", .value = LTTNG_LOGLEVEL_LOG4J_WARN },
	{ .name = "LOG4J_WARN", .value = LTTNG_LOGLEVEL_LOG4J_WARN },
	{ .name = "INFO", .value = LTTNG_LOGLEVEL_LOG4J_INFO },
	{ .name = "LOG4J_INFO", .value = LTTNG_LOGLEVEL_LOG4J_INFO },
	{ .name = "DEBUG", .value = LTTNG_LOGLEVEL_LOG4J_DEBUG },
	{ .name = "LOG4J_DEBUG", .value = LTTNG_LOGLEVEL_LOG4J_DEBUG },
	{ .name = "TRACE", .value = LTTNG_LOGLEVEL_LOG4J_TRACE },
	{ .name = "LOG4J_TRACE", .value = LTTNG_LOGLEVEL_LOG4J_TRACE },
	{ .name = "ALL", .value = LTTNG_LOGLEVEL_LOG4J_ALL },
	{ .name = "LOG4J_ALL", .value = LTTNG_LOGLEVEL_LOG4J_ALL },
};

static const struct loglevel_name_value loglevel_log4j2_values[] = {
	{ .name = "OFF", .value = LTTNG_LOGLEVEL_LOG4J2_OFF },
	{ .name = "LOG4J2_OFF", .value = LTTNG_LOGLEVEL_LOG4J2_OFF },
	{ .name = "FATAL", .value = LTTNG_LOGLEVEL_LOG4J2_FATAL },
	{ .name = "LOG4J2_FATAL", .value = LTTNG_LOGLEVEL_LOG4J2_FATAL },
	{ .name = "ERROR", .value = LTTNG_LOGLEVEL_LOG4J2_ERROR },
	{ .name = "LOG4J2_ERROR", .value = LTTNG_LOGLEVEL_LOG4J2_ERROR },
	{ .name = "WARN", .value = LTTNG_LOGLEVEL_LOG4J2_WARN },
	{ .name = "LOG4J2_WARN", .value = LTTNG_LOGLEVEL_LOG4J2_WARN },
	{ .name = "INFO", .value = LTTNG_LOGLEVEL_LOG4J2_INFO },
	{ .name = "LOG4J2_INFO", .value = LTTNG_LOGLEVEL_LOG4J2_INFO },
	{ .name = "DEBUG", .value = LTTNG_LOGLEVEL_LOG4J2_DEBUG },
	{ .name = "LOG4J2_DEBUG", .value = LTTNG_LOGLEVEL_LOG4J2_DEBUG },
	{ .name = "TRACE", .value = LTTNG_LOGLEVEL_LOG4J2_TRACE },
	{ .name = "LOG4J2_TRACE", .value = LTTNG_LOGLEVEL_LOG4J2_TRACE },
	{ .name = "ALL", .value = LTTNG_LOGLEVEL_LOG4J2_ALL },
	{ .name = "LOG4J2_ALL", .value = LTTNG_LOGLEVEL_LOG4J2_ALL },
};

static const struct loglevel_name_value loglevel_jul_values[] = {
	{ .name = "OFF", .value = LTTNG_LOGLEVEL_JUL_OFF },
	{ .name = "JUL_OFF", .value = LTTNG_LOGLEVEL_JUL_OFF },
	{ .name = "SEVERE", .value = LTTNG_LOGLEVEL_JUL_SEVERE },
	{ .name = "JUL_SEVERE", .value = LTTNG_LOGLEVEL_JUL_SEVERE },
	{ .name = "WARNING", .value = LTTNG_LOGLEVEL_JUL_WARNING },
	{ .name = "JUL_WARNING", .value = LTTNG_LOGLEVEL_JUL_WARNING },
	{ .name = "INFO", .value = LTTNG_LOGLEVEL_JUL_INFO },
	{ .name = "JUL_INFO", .value = LTTNG_LOGLEVEL_JUL_INFO },
	{ .name = "CONFIG", .value = LTTNG_LOGLEVEL_JUL_CONFIG },
	{ .name = "JUL_CONFIG", .value = LTTNG_LOGLEVEL_JUL_CONFIG },
	{ .name = "FINE", .value = LTTNG_LOGLEVEL_JUL_FINE },
	{ .name = "JUL_FINE", .value = LTTNG_LOGLEVEL_JUL_FINE },
	{ .name = "FINER", .value = LTTNG_LOGLEVEL_JUL_FINER },
	{ .name = "JUL_FINER", .value = LTTNG_LOGLEVEL_JUL_FINER },
	{ .name = "FINEST", .value = LTTNG_LOGLEVEL_JUL_FINEST },
	{ .name = "JUL_FINEST", .value = LTTNG_LOGLEVEL_JUL_FINEST },
	{ .name = "ALL", .value = LTTNG_LOGLEVEL_JUL_ALL },
	{ .name = "JUL_ALL", .value = LTTNG_LOGLEVEL_JUL_ALL },
};

static const struct loglevel_name_value loglevel_python_values[] = {
	{ .name = "CRITICAL", .value = LTTNG_LOGLEVEL_PYTHON_CRITICAL },
	{ .name = "PYTHON_CRITICAL", .value = LTTNG_LOGLEVEL_PYTHON_CRITICAL },
	{ .name = "ERROR", .value = LTTNG_LOGLEVEL_PYTHON_ERROR },
	{ .name = "PYTHON_ERROR", .value = LTTNG_LOGLEVEL_PYTHON_ERROR },
	{ .name = "WARNING", .value = LTTNG_LOGLEVEL_PYTHON_WARNING },
	{ .name = "PYTHON_WARNING", .value = LTTNG_LOGLEVEL_PYTHON_WARNING },
	{ .name = "INFO", .value = LTTNG_LOGLEVEL_PYTHON_INFO },
	{ .name = "PYTHON_INFO", .value = LTTNG_LOGLEVEL_PYTHON_INFO },
	{ .name = "DEBUG", .value = LTTNG_LOGLEVEL_PYTHON_DEBUG },
	{ .name = "PYTNON_DEBUG", .value = LTTNG_LOGLEVEL_PYTHON_DEBUG },
	{ .name = "NOTSET", .value = LTTNG_LOGLEVEL_PYTHON_NOTSET },
	{ .name = "PYTHON_NOTSET", .value = LTTNG_LOGLEVEL_PYTHON_NOTSET },
};

static bool string_equal_insensitive(const char *a, const char *b)
{
	return strcasecmp(a, b) == 0;
}

static int lookup_value_from_name(const struct loglevel_name_value values[],
				  size_t values_count,
				  const char *name)
{
	size_t i;
	int ret = -1;

	if (!name) {
		goto end;
	}

	for (i = 0; i < values_count; i++) {
		if (string_equal_insensitive(values[i].name, name)) {
			/* Match found. */
			ret = values[i].value;
			goto end;
		}
	}

end:
	return ret;
}

static bool loglevel_parse_range_string_common(const char *str,
					       const struct loglevel_name_value *nvs,
					       size_t nvs_count,
					       int default_most_severe,
					       int *least_severe,
					       int *most_severe)
{
	bool ret;
	int i;
	const struct loglevel_name_value *nv;

	/*
	 * Look for a valid loglevel name value at the beginning of 'str'.
	 */
	for (i = 0; i < nvs_count; i++) {
		nv = &nvs[i];

		if (strncmp(str, nv->name, strlen(nv->name)) == 0) {
			break;
		}
	}

	/*
	 * Found no valid loglevel name value at the beginning of 'str'.
	 */
	if (i == nvs_count) {
		goto error;
	}

	/*
	 * Record the least_severe value and skip over the loglevel name found
	 * previously.
	 */
	*least_severe = nv->value;
	str += strlen(nv->name);

	/*
	 * If we are at the end of 'str', only one loglevel name was specified,
	 * it is also the most_severe.
	 */
	if (*str == '\0') {
		*most_severe = nv->value;
		ret = true;
		goto end;
	}

	/*
	 * Invalid 'str', no loglevel name separator.
	 */
	if (strncmp(str, "..", strlen("..")) != 0) {
		goto error;
	}

	str += strlen("..");

	/*
	 * If we are at the end of 'str' after the separator, set the default
	 * most_severe value for the domain as the most_severe.
	 */
	if (*str == '\0') {
		*most_severe = default_most_severe;
		ret = true;
		goto end;
	}

	/*
	 * Look for a valid loglevel name value after the separator in 'str'.
	 */
	for (i = 0; i < nvs_count; i++) {
		nv = &nvs[i];

		if (strcmp(str, nv->name) == 0) {
			break;
		}
	}

	/*
	 * Found no valid loglevel name value after the separator.
	 */
	if (i == nvs_count) {
		goto error;
	}

	/*
	 * Record the most_severe value for the loglevel found in 'str'.
	 */
	*most_severe = nv->value;

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

int loglevel_name_to_value(const char *name, enum lttng_loglevel *loglevel)
{
	int ret = lookup_value_from_name(loglevel_values, ARRAY_SIZE(loglevel_values), name);

	if (ret >= 0) {
		*loglevel = (typeof(*loglevel)) ret;
		ret = 0;
	}

	return ret;
}

bool loglevel_parse_range_string(const char *str,
				 enum lttng_loglevel *least_severe,
				 enum lttng_loglevel *most_severe)
{
	int least_severe_int, most_severe_int;
	const bool ret = loglevel_parse_range_string_common(str,
							    loglevel_values,
							    ARRAY_SIZE(loglevel_values),
							    LTTNG_LOGLEVEL_EMERG,
							    &least_severe_int,
							    &most_severe_int);

	*least_severe = (lttng_loglevel) least_severe_int;
	*most_severe = (lttng_loglevel) most_severe_int;

	return ret;
}

int loglevel_log4j_name_to_value(const char *name, enum lttng_loglevel_log4j *loglevel)
{
	int ret = lookup_value_from_name(
		loglevel_log4j_values, ARRAY_SIZE(loglevel_log4j_values), name);

	if (ret >= 0) {
		*loglevel = (typeof(*loglevel)) ret;
		ret = 0;
	}

	return ret;
}

bool loglevel_log4j_parse_range_string(const char *str,
				       enum lttng_loglevel_log4j *least_severe,
				       enum lttng_loglevel_log4j *most_severe)
{
	int least_severe_int, most_severe_int;
	const bool ret = loglevel_parse_range_string_common(str,
							    loglevel_log4j_values,
							    ARRAY_SIZE(loglevel_log4j_values),
							    LTTNG_LOGLEVEL_LOG4J_FATAL,
							    &least_severe_int,
							    &most_severe_int);

	*least_severe = (lttng_loglevel_log4j) least_severe_int;
	*most_severe = (lttng_loglevel_log4j) most_severe_int;

	return ret;
}

int loglevel_log4j2_name_to_value(const char *name, enum lttng_loglevel_log4j2 *loglevel)
{
	int ret = lookup_value_from_name(
		loglevel_log4j2_values, ARRAY_SIZE(loglevel_log4j2_values), name);

	if (ret >= 0) {
		*loglevel = (typeof(*loglevel)) ret;
		ret = 0;
	}

	return ret;
}

bool loglevel_log4j2_parse_range_string(const char *str,
					enum lttng_loglevel_log4j2 *least_severe,
					enum lttng_loglevel_log4j2 *most_severe)
{
	int least_severe_int, most_severe_int;
	bool ret = loglevel_parse_range_string_common(str,
						      loglevel_log4j2_values,
						      ARRAY_SIZE(loglevel_log4j2_values),
						      LTTNG_LOGLEVEL_LOG4J2_FATAL,
						      &least_severe_int,
						      &most_severe_int);

	*least_severe = (lttng_loglevel_log4j2) least_severe_int;
	*most_severe = (lttng_loglevel_log4j2) most_severe_int;

	return ret;
}

int loglevel_jul_name_to_value(const char *name, enum lttng_loglevel_jul *loglevel)
{
	int ret =
		lookup_value_from_name(loglevel_jul_values, ARRAY_SIZE(loglevel_jul_values), name);

	if (ret >= 0) {
		*loglevel = (typeof(*loglevel)) ret;
		ret = 0;
	}

	return ret;
}

bool loglevel_jul_parse_range_string(const char *str,
				     enum lttng_loglevel_jul *least_severe,
				     enum lttng_loglevel_jul *most_severe)
{
	int least_severe_int, most_severe_int;
	const bool ret = loglevel_parse_range_string_common(str,
							    loglevel_jul_values,
							    ARRAY_SIZE(loglevel_jul_values),
							    LTTNG_LOGLEVEL_JUL_SEVERE,
							    &least_severe_int,
							    &most_severe_int);

	*least_severe = (lttng_loglevel_jul) least_severe_int;
	*most_severe = (lttng_loglevel_jul) most_severe_int;

	return ret;
}

int loglevel_python_name_to_value(const char *name, enum lttng_loglevel_python *loglevel)
{
	int ret = lookup_value_from_name(
		loglevel_python_values, ARRAY_SIZE(loglevel_python_values), name);

	if (ret >= 0) {
		*loglevel = (typeof(*loglevel)) ret;
		ret = 0;
	}

	return ret;
}

bool loglevel_python_parse_range_string(const char *str,
					enum lttng_loglevel_python *least_severe,
					enum lttng_loglevel_python *most_severe)
{
	int least_severe_int, most_severe_int;
	const bool ret = loglevel_parse_range_string_common(str,
							    loglevel_python_values,
							    ARRAY_SIZE(loglevel_python_values),
							    LTTNG_LOGLEVEL_PYTHON_CRITICAL,
							    &least_severe_int,
							    &most_severe_int);

	*least_severe = (lttng_loglevel_python) least_severe_int;
	*most_severe = (lttng_loglevel_python) most_severe_int;

	return ret;
}

static const char *
lookup_name_from_value(const struct loglevel_name_value values[], size_t values_count, int loglevel)
{
	size_t i;
	const char *name = nullptr;

	for (i = 0; i < values_count; i++) {
		if (values[i].value == loglevel) {
			/* Match found. */
			name = values[i].name;
			goto end;
		}
	}

end:
	return name;
}

const char *loglevel_value_to_name(int loglevel)
{
	return lookup_name_from_value(loglevel_values, ARRAY_SIZE(loglevel_values), loglevel);
}

const char *loglevel_log4j_value_to_name(int loglevel)
{
	return lookup_name_from_value(
		loglevel_log4j_values, ARRAY_SIZE(loglevel_log4j_values), loglevel);
}

const char *loglevel_log4j2_value_to_name(int loglevel)
{
	return lookup_name_from_value(
		loglevel_log4j2_values, ARRAY_SIZE(loglevel_log4j2_values), loglevel);
}

const char *loglevel_jul_value_to_name(int loglevel)
{
	return lookup_name_from_value(
		loglevel_jul_values, ARRAY_SIZE(loglevel_jul_values), loglevel);
}

const char *loglevel_python_value_to_name(int loglevel)
{
	return lookup_name_from_value(
		loglevel_python_values, ARRAY_SIZE(loglevel_python_values), loglevel);
}
