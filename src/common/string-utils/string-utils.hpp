/*
 * SPDX-FileCopyrightText: 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef _STRING_UTILS_H
#define _STRING_UTILS_H

#include <common/dynamic-array.hpp>
#include <common/macros.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <cstddef>
#include <stdbool.h>
#include <string>

void strutils_normalize_star_glob_pattern(char *pattern);

bool strutils_is_star_glob_pattern(const char *pattern);

bool strutils_is_star_at_the_end_only_glob_pattern(const char *pattern);

char *strutils_unescape_string(const char *input, char only_char);

int strutils_split(const char *input,
		   char delim,
		   bool escape_delim,
		   struct lttng_dynamic_pointer_array *out_strings);

void strutils_free_null_terminated_array_of_strings(char **array);

size_t strutils_array_of_strings_len(char *const *array);

/*
 * Append `append` to the malloc-end string `str`.
 *
 * On success, `str` is free'd (if not NULL) and assigned a new malloc-ed
 * string.  On failure, `str` is not modified.
 *
 * Return 0 on success, -ENOMEM on failure.
 */
C_LINKAGE int strutils_append_str(char **str, const char *append);

/*
 * Like `strutils_append_str`, but the appended string is formatted using
 * `fmt` and the following arguments.
 */
C_LINKAGE ATTR_FORMAT_PRINTF(2, 3) int strutils_appendf(char **s, const char *fmt, ...);

namespace lttng {
namespace utils {

/*
 * Wraps `text` between words to fit `line_width` columns (one per UTF-8
 * code point), assuming `indent` columns precede the first line and
 * indenting the other lines with `indent` spaces.
 *
 * Wrap plain text only, since escape sequences would count as columns.
 */
std::string wrap_text(lttng::c_string_view text, std::size_t line_width, std::size_t indent = 0);

} /* namespace utils */
} /* namespace lttng */

#endif /* _STRING_UTILS_H */
