/*
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <type_traits>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>

#include "string-utils.hpp"
#include "../macros.hpp"

enum star_glob_pattern_type_flags {
	STAR_GLOB_PATTERN_TYPE_FLAG_NONE = 0,
	STAR_GLOB_PATTERN_TYPE_FLAG_PATTERN = 1,
	STAR_GLOB_PATTERN_TYPE_FLAG_END_ONLY = 2,
};

static
star_glob_pattern_type_flags &operator|=(star_glob_pattern_type_flags &l,
		star_glob_pattern_type_flags r)
{
	using T = std::underlying_type<star_glob_pattern_type_flags>::type;
	l = static_cast<star_glob_pattern_type_flags> (
		static_cast<T> (l) | static_cast<T> (r));
	return l;
}

/*
 * Normalizes the star-only globbing pattern `pattern`, that is, crushes
 * consecutive `*` characters into a single `*`, avoiding `\*`.
 */
void strutils_normalize_star_glob_pattern(char *pattern)
{
	const char *p;
	char *np;
	bool got_star = false;

	LTTNG_ASSERT(pattern);

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

			/* fall through */
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

	LTTNG_ASSERT(pattern);

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
bool strutils_is_star_glob_pattern(const char *pattern)
{
	return strutils_test_glob_pattern(pattern) &
		STAR_GLOB_PATTERN_TYPE_FLAG_PATTERN;
}

/*
 * Returns true if `pattern` is a globbing pattern with a globbing,
 * non-escaped star only at its very end.
 */
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
char *strutils_unescape_string(const char *input, char only_char)
{
	char *output;
	char *o;
	const char *i;

	LTTNG_ASSERT(input);
	output = calloc<char>(strlen(input) + 1);
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
 * The return value is a dynamic pointer array that is assumed to be empty. The
 * array must be discarded by the caller by invoking
 * lttng_dynamic_pointer_array_reset().
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
 * Returns -1 if there's an error.
 */
int strutils_split(const char *input,
		char delim,
		bool escape_delim,
		struct lttng_dynamic_pointer_array *out_strings)
{
	int ret;
	size_t at;
	size_t number_of_substrings = 1;
	size_t longest_substring_len = 0;
	const char *s;
	const char *last;

	LTTNG_ASSERT(input);
	LTTNG_ASSERT(!(escape_delim && delim == '\\'));
	LTTNG_ASSERT(delim != '\0');
	lttng_dynamic_pointer_array_init(out_strings, free);

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

	/* Second pass: actually split and copy substrings. */
	for (at = 0, s = input; at < number_of_substrings; at++) {
		const char *ss;
		char *d;
		char *substring = calloc<char>(longest_substring_len + 1);

		if (!substring) {
			goto error;
		}

		ret = lttng_dynamic_pointer_array_add_pointer(
				out_strings, substring);
		if (ret) {
			free(substring);
			goto error;
		}

		/*
		 * Copy characters to substring until we find the next
		 * delimiter or the end of the input string.
		 */
		for (ss = s, d = substring; *ss != '\0'; ss++) {
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

	ret = 0;
	goto end;

error:
	ret = -1;
end:
	return ret;
}

size_t strutils_array_of_strings_len(char * const *array)
{
	char * const *item;
	size_t count = 0;

	LTTNG_ASSERT(array);

	for (item = array; *item; item++) {
		count++;
	}

	return count;
}

int strutils_append_str(char **s, const char *append)
{
	char *old = *s;
	char *new_str;
	size_t oldlen = (old == NULL) ? 0 : strlen(old);
	size_t appendlen = strlen(append);

	new_str = zmalloc<char>(oldlen + appendlen + 1);
	if (!new_str) {
		return -ENOMEM;
	}
	if (oldlen) {
		strcpy(new_str, old);
	}
	strcat(new_str, append);
	*s = new_str;
	free(old);
	return 0;
}

int strutils_appendf(char **s, const char *fmt, ...)
{
	char *new_str;
	size_t oldlen = (*s) ? strlen(*s) : 0;
	int ret;
	va_list args;

	/* Compute length of formatted string we append. */
	va_start(args, fmt);
	ret = vsnprintf(NULL, 0, fmt, args);
	va_end(args);

	if (ret == -1) {
		goto end;
	}

	/* Allocate space for old string + new string + \0. */
	new_str = zmalloc<char>(oldlen + ret + 1);
	if (!new_str) {
		ret = -ENOMEM;
		goto end;
	}

	/* Copy old string, if there was one. */
	if (oldlen) {
		strcpy(new_str, *s);
	}

	/* Format new string in-place. */
	va_start(args, fmt);
	ret = vsprintf(&new_str[oldlen], fmt, args); 
	va_end(args);

	if (ret == -1) {
		ret = -1;
		goto end;
	}

	free(*s);
	*s = new_str;
	new_str = NULL;

end:
	return ret;
}
