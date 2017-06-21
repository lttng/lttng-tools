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

#define _LGPL_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "string-utils.h"
#include "../macros.h"

enum star_glob_pattern_type_flags {
	STAR_GLOB_PATTERN_TYPE_FLAG_NONE = 0,
	STAR_GLOB_PATTERN_TYPE_FLAG_PATTERN = 1,
	STAR_GLOB_PATTERN_TYPE_FLAG_END_ONLY = 2,
};

/*
 * Normalizes the star-only globbing pattern `pattern`, that is, crushes
 * consecutive `*` characters into a single `*`, avoiding `\*`.
 */
LTTNG_HIDDEN
void strutils_normalize_star_glob_pattern(char *pattern)
{
	const char *p;
	char *np;
	bool got_star = false;

	assert(pattern);

	for (p = pattern, np = pattern; *p != '\0'; p++) {
		switch (*p) {
		case '*':
			if (got_star) {
				/* Avoid consecutive stars. */
				continue;
			}

			got_star = true;
			break;
		case '\\':
			/* Copy backslash character. */
			*np = *p;
			np++;
			p++;

			if (*p == '\0') {
				goto end;
			}

			/* Fall through default case. */
		default:
			got_star = false;
			break;
		}

		/* Copy single character. */
		*np = *p;
		np++;
	}

end:
	*np = '\0';
}

static
enum star_glob_pattern_type_flags strutils_test_glob_pattern(const char *pattern)
{
	enum star_glob_pattern_type_flags ret =
		STAR_GLOB_PATTERN_TYPE_FLAG_NONE;
	const char *p;

	assert(pattern);

	for (p = pattern; *p != '\0'; p++) {
		switch (*p) {
		case '*':
			ret = STAR_GLOB_PATTERN_TYPE_FLAG_PATTERN;

			if (p[1] == '\0') {
				ret |= STAR_GLOB_PATTERN_TYPE_FLAG_END_ONLY;
			}

			goto end;
		case '\\':
			p++;

			if (*p == '\0') {
				goto end;
			}
			break;
		default:
			break;
		}
	}

end:
	return ret;
}

/*
 * Returns true if `pattern` is a star-only globbing pattern, that is,
 * it contains at least one non-escaped `*`.
 */
LTTNG_HIDDEN
bool strutils_is_star_glob_pattern(const char *pattern)
{
	return strutils_test_glob_pattern(pattern) &
		STAR_GLOB_PATTERN_TYPE_FLAG_PATTERN;
}

/*
 * Returns true if `pattern` is a globbing pattern with a globbing,
 * non-escaped star only at its very end.
 */
LTTNG_HIDDEN
bool strutils_is_star_at_the_end_only_glob_pattern(const char *pattern)
{
	return strutils_test_glob_pattern(pattern) &
		STAR_GLOB_PATTERN_TYPE_FLAG_END_ONLY;
}

/*
 * Unescapes the input string `input`, that is, in a `\x` sequence,
 * removes `\`. If `only_char` is not 0, only this character is
 * escaped.
 */
LTTNG_HIDDEN
char *strutils_unescape_string(const char *input, char only_char)
{
	char *output;
	char *o;
	const char *i;

	assert(input);
	output = zmalloc(strlen(input) + 1);
	if (!output) {
		goto end;
	}

	for (i = input, o = output; *i != '\0'; i++) {
		switch (*i) {
		case '\\':
			if (only_char && i[1] != only_char) {
				break;
			}

			i++;

			if (*i == '\0') {
				/* Copy last `\`. */
				*o = '\\';
				o++;
				goto end;
			}
		default:
			break;
		}

		/* Copy single character. */
		*o = *i;
		o++;
	}

end:
	return output;
}

/*
 * Frees a null-terminated array of strings, including each contained
 * string.
 */
LTTNG_HIDDEN
void strutils_free_null_terminated_array_of_strings(char **array)
{
	char **item;

	if (!array) {
		return;
	}

	for (item = array; *item; item++) {
		free(*item);
	}

	free(array);
}

/*
 * Splits the input string `input` using the given delimiter `delim`.
 *
 * The return value is an allocated null-terminated array of the
 * resulting substrings (also allocated). You can free this array and
 * its content with strutils_free_null_terminated_array_of_strings(). You
 * can get the number of substrings in it with
 * strutils_array_of_strings_len().
 *
 * Empty substrings are part of the result. For example:
 *
 *     Input: ,hello,,there,
 *     Result:
 *       ``
 *       `hello`
 *       ``
 *       `there`
 *       ``
 *
 * If `escape_delim` is true, then `\,`, where `,` is the delimiter,
 * escapes the delimiter and is copied as `,` only in the resulting
 * substring. For example:
 *
 *     Input: hello\,world,zoom,\,hi
 *     Result:
 *       `hello,world`
 *       `zoom`
 *       `,hi`
 *
 * Other characters are not escaped (this is the caller's job if
 * needed). However they are considering during the parsing, that is,
 * `\x`, where `x` is any character, is copied as is to the resulting
 * substring, e.g.:
 *
 *     Input: hello\,wo\rld\\,zoom\,
 *     Result:
 *       `hello,wo\rld\\`
 *       `zoom,`
 *
 * If `escape_delim` is false, nothing at all is escaped, and `delim`,
 * when found in `input`, is always a delimiter, e.g.:
 *
 *     Input: hello\,world,zoom,\,hi
 *     Result:
 *       `hello\`
 *       `world`
 *       `zoom`
 *       `\`
 *       `hi`
 *
 * Returns NULL if there's an error.
 */
LTTNG_HIDDEN
char **strutils_split(const char *input, char delim, bool escape_delim)
{
	size_t at;
	size_t number_of_substrings = 1;
	size_t longest_substring_len = 0;
	const char *s;
	const char *last;
	char **substrings = NULL;

	assert(input);
	assert(!(escape_delim && delim == '\\'));
	assert(delim != '\0');

	/* First pass: count the number of substrings. */
	for (s = input, last = input - 1; *s != '\0'; s++) {
		if (escape_delim && *s == '\\') {
			/* Ignore following (escaped) character. */
			s++;

			if (*s == '\0') {
				break;
			}

			continue;
		}

		if (*s == delim) {
			size_t last_len = s - last - 1;
			last = s;
			number_of_substrings++;

			if (last_len > longest_substring_len) {
				longest_substring_len = last_len;
			}
		}
	}

	if ((s - last - 1) > longest_substring_len) {
		longest_substring_len = s - last - 1;
	}

	substrings = calloc(number_of_substrings + 1, sizeof(*substrings));
	if (!substrings) {
		goto error;
	}

	/* Second pass: actually split and copy substrings. */
	for (at = 0, s = input; at < number_of_substrings; at++) {
		const char *ss;
		char *d;

		substrings[at] = zmalloc(longest_substring_len + 1);
		if (!substrings[at]) {
			goto error;
		}

		/*
		 * Copy characters to substring until we find the next
		 * delimiter or the end of the input string.
		 */
		for (ss = s, d = substrings[at]; *ss != '\0'; ss++) {
			if (escape_delim && *ss == '\\') {
				if (ss[1] == delim) {
					/*
					 * '\' followed by delimiter and
					 * we need to escape this ('\'
					 * won't be part of the
					 * resulting substring).
					 */
					ss++;
					*d = *ss;
					d++;
					continue;
				} else {
					/*
					 * Copy '\' and the following
					 * character.
					 */
					*d = *ss;
					d++;
					ss++;

					if (*ss == '\0') {
						break;
					}
				}
			} else if (*ss == delim) {
				/* We're done with this substring. */
				break;
			}

			*d = *ss;
			d++;
		}

		/* Next substring starts after the last delimiter. */
		s = ss + 1;
	}

	goto end;

error:
	strutils_free_null_terminated_array_of_strings(substrings);
	substrings = NULL;
end:
	return substrings;
}

LTTNG_HIDDEN
size_t strutils_array_of_strings_len(char * const *array)
{
	char * const *item;
	size_t count = 0;

	assert(array);

	for (item = array; *item; item++) {
		count++;
	}

	return count;
}
