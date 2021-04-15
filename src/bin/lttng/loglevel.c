/*
 * Copyright (C) 2021 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "loglevel.h"
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <assert.h>

struct loglevel_name_value {
	const char *name;
	int value;
};

static
const struct loglevel_name_value loglevel_values[] = {
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

static
const struct loglevel_name_value loglevel_log4j_values[] = {
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

static
const struct loglevel_name_value loglevel_jul_values[] = {
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

static
const struct loglevel_name_value loglevel_python_values[] = {
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

static
bool string_equal_insensitive(const char *a, const char *b)
{
	return strcasecmp(a, b) == 0;
}

static
int lookup_value_from_name(const struct loglevel_name_value values[],
		size_t values_count, const char *name)
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
		int *min,
		int *max)
{
	bool ret;
	int i;
	const struct loglevel_name_value *nv;

	for (i = 0; i < nvs_count; i++) {
		nv = &nvs[i];

		if (strncmp(str, nv->name, strlen(nv->name)) == 0) {
			break;
		}
	}

	if (i == nvs_count) {
		goto error;
	}

	*min = nv->value;
	str += strlen(nv->name);

	if (*str == '\0') {
		*max = nv->value;
		ret = true;
		goto end;
	}

	if (strncmp(str, "..", strlen("..")) != 0) {
		goto error;
	}

	str += strlen("..");

	if (*str == '\0') {
		*max = LTTNG_LOGLEVEL_EMERG;
		ret = true;
		goto end;
	}

	for (i = 0; i < nvs_count; i++) {
		nv = &nvs[i];

		if (strcmp(str, nv->name) == 0) {
			break;
		}
	}

	if (i == nvs_count) {
		goto error;
	}

	*max = nv->value;

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

LTTNG_HIDDEN
int loglevel_name_to_value(const char *name, enum lttng_loglevel *loglevel)
{
	int ret = lookup_value_from_name(loglevel_values,
			ARRAY_SIZE(loglevel_values), name);

	if (ret >= 0) {
		*loglevel = (typeof(*loglevel)) ret;
		ret = 0;
	}

	return ret;
}

LTTNG_HIDDEN
bool loglevel_parse_range_string(const char *str,
		enum lttng_loglevel *min,
		enum lttng_loglevel *max)
{
	int min_int, max_int;
	bool ret = loglevel_parse_range_string_common(str, loglevel_values,
			ARRAY_SIZE(loglevel_values), &min_int, &max_int);

	*min = min_int;
	*max = max_int;

	return ret;
}

LTTNG_HIDDEN
int loglevel_log4j_name_to_value(
		const char *name, enum lttng_loglevel_log4j *loglevel)
{
	int ret = lookup_value_from_name(loglevel_log4j_values,
			ARRAY_SIZE(loglevel_log4j_values),
			name);

	if (ret >= 0) {
		*loglevel = (typeof(*loglevel)) ret;
		ret = 0;
	}

	return ret;
}

LTTNG_HIDDEN
bool loglevel_log4j_parse_range_string(const char *str,
		enum lttng_loglevel_log4j *min,
		enum lttng_loglevel_log4j *max)
{
	int min_int, max_int;
	bool ret = loglevel_parse_range_string_common(str,
			loglevel_log4j_values,
			ARRAY_SIZE(loglevel_log4j_values), &min_int, &max_int);

	*min = min_int;
	*max = max_int;

	return ret;
}

LTTNG_HIDDEN
int loglevel_jul_name_to_value(
		const char *name, enum lttng_loglevel_jul *loglevel)
{
	int ret = lookup_value_from_name(loglevel_jul_values,
			ARRAY_SIZE(loglevel_jul_values),
			name);

	if (ret >= 0) {
		*loglevel = (typeof(*loglevel)) ret;
		ret = 0;
	}

	return ret;
}

LTTNG_HIDDEN
bool loglevel_jul_parse_range_string(const char *str,
		enum lttng_loglevel_jul *min,
		enum lttng_loglevel_jul *max)
{
	int min_int, max_int;
	bool ret = loglevel_parse_range_string_common(str, loglevel_jul_values,
			ARRAY_SIZE(loglevel_jul_values), &min_int, &max_int);

	*min = min_int;
	*max = max_int;

	return ret;
}

LTTNG_HIDDEN
int loglevel_python_name_to_value(
		const char *name, enum lttng_loglevel_python *loglevel)
{
	int ret = lookup_value_from_name(loglevel_python_values,
			ARRAY_SIZE(loglevel_python_values),
			name);

	if (ret >= 0) {
		*loglevel = (typeof(*loglevel)) ret;
		ret = 0;
	}

	return ret;
}

LTTNG_HIDDEN
bool loglevel_python_parse_range_string(const char *str,
		enum lttng_loglevel_python *min,
		enum lttng_loglevel_python *max)
{
	int min_int, max_int;
	bool ret = loglevel_parse_range_string_common(str,
			loglevel_python_values,
			ARRAY_SIZE(loglevel_python_values), &min_int, &max_int);

	*min = min_int;
	*max = max_int;

	return ret;
}

static
const char *lookup_name_from_value(const struct loglevel_name_value values[],
		size_t values_count, int loglevel)
{
	size_t i;
	const char *name = NULL;

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

LTTNG_HIDDEN
const char *loglevel_value_to_name(int loglevel)
{
	return lookup_name_from_value(
			loglevel_values, ARRAY_SIZE(loglevel_values), loglevel);
}

LTTNG_HIDDEN
const char *loglevel_log4j_value_to_name(int loglevel)
{
	return lookup_name_from_value(loglevel_log4j_values,
			ARRAY_SIZE(loglevel_log4j_values), loglevel);
}

LTTNG_HIDDEN
const char *loglevel_jul_value_to_name(int loglevel)
{
	return lookup_name_from_value(loglevel_jul_values,
			ARRAY_SIZE(loglevel_jul_values), loglevel);
}

LTTNG_HIDDEN
const char *loglevel_python_value_to_name(int loglevel)
{
	return lookup_name_from_value(loglevel_python_values,
			ARRAY_SIZE(loglevel_python_values), loglevel);
}
