/*
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _STRING_UTILS_H
#define _STRING_UTILS_H

#include <stdbool.h>
#include <common/macros.h>
#include <common/dynamic-array.h>

void strutils_normalize_star_glob_pattern(char *pattern);

bool strutils_is_star_glob_pattern(const char *pattern);

bool strutils_is_star_at_the_end_only_glob_pattern(const char *pattern);

char *strutils_unescape_string(const char *input, char only_char);

int strutils_split(const char *input, char delim, bool escape_delim,
		struct lttng_dynamic_pointer_array *out_strings);

void strutils_free_null_terminated_array_of_strings(char **array);

size_t strutils_array_of_strings_len(char * const *array);

#endif /* _STRING_UTILS_H */
