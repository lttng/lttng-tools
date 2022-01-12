/*
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _STRING_UTILS_H
#define _STRING_UTILS_H

#include <stdbool.h>
#include <common/macros.h>

LTTNG_HIDDEN
void strutils_normalize_star_glob_pattern(char *pattern);

LTTNG_HIDDEN
bool strutils_is_star_glob_pattern(const char *pattern);

LTTNG_HIDDEN
bool strutils_is_star_at_the_end_only_glob_pattern(const char *pattern);

LTTNG_HIDDEN
char *strutils_unescape_string(const char *input, char only_char);

LTTNG_HIDDEN
char **strutils_split(const char *input, char delim, bool escape_delim);

LTTNG_HIDDEN
void strutils_free_null_terminated_array_of_strings(char **array);

LTTNG_HIDDEN
size_t strutils_array_of_strings_len(char * const *array);

#endif /* _STRING_UTILS_H */
