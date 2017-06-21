/*
 * Copyright (C) 2017 - Philippe Proulx <pproulx@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
