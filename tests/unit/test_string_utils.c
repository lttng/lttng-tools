/*
 * Copyright (c) - 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by as
 * published by the Free Software Foundation; only version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <common/string-utils/string-utils.h>
#include <tap/tap.h>

/* Number of TAP tests in this file */
#define NUM_TESTS 69

static void test_one_split(const char *input, char delim, bool escape_delim,
		...)
{
	va_list vl;
	char **substrings;
	char * const *substring;
	bool all_ok = true;

	substrings = strutils_split(input, delim, escape_delim);
	assert(substrings);
	va_start(vl, escape_delim);

	for (substring = substrings; *substring; substring++) {
		const char *expected_substring = va_arg(vl, const char *);

		diag("  got `%s`, expecting `%s`", *substring, expected_substring);

		if (!expected_substring) {
			all_ok = false;
			break;
		}

		if (strcmp(*substring, expected_substring) != 0) {
			all_ok = false;
			break;
		}
	}

	strutils_free_null_terminated_array_of_strings(substrings);
	va_end(vl);
	ok(all_ok, "strutils_split() produces the expected substrings: `%s` (delim. `%c`, escape `%d`)",
		input, delim, escape_delim);
}

static void test_split(void)
{
	test_one_split("a/b/c/d/e", '/', false, "a", "b", "c", "d", "e", NULL);
	test_one_split("a/b//d/e", '/', false, "a", "b", "", "d", "e", NULL);
	test_one_split("/b/c/d/e", '/', false, "", "b", "c", "d", "e", NULL);
	test_one_split("a/b/c/d/", '/', false, "a", "b", "c", "d", "", NULL);
	test_one_split("/b/c/d/", '/', false, "", "b", "c", "d", "", NULL);
	test_one_split("", '/', false, "", NULL);
	test_one_split("/", '/', false, "", "", NULL);
	test_one_split("//", '/', false, "", "", "", NULL);
	test_one_split("hello+world", '+', false, "hello", "world", NULL);
	test_one_split("hello\\+world", '+', false, "hello\\", "world", NULL);
	test_one_split("hello\\+world", '+', true, "hello+world", NULL);
	test_one_split("hello\\++world", '+', true, "hello+", "world", NULL);
	test_one_split("hello\\\\++world", '+', true, "hello\\\\", "", "world", NULL);
	test_one_split("hello+world\\", '+', false, "hello", "world\\", NULL);
	test_one_split("hello+world\\", '+', true, "hello", "world\\", NULL);
	test_one_split("\\+", '+', false, "\\", "", NULL);
	test_one_split("\\+", '+', true, "+", NULL);
}

static void test_one_is_star_at_the_end_only_glob_pattern(const char *pattern, bool expected)
{
	ok(strutils_is_star_at_the_end_only_glob_pattern(pattern) == expected,
		"strutils_is_star_at_the_end_only_glob_pattern() returns the expected result: `%s` -> %d",
		pattern, expected);
}

static void test_is_star_at_the_end_only_glob_pattern(void)
{
	test_one_is_star_at_the_end_only_glob_pattern("allo*", true);
	test_one_is_star_at_the_end_only_glob_pattern("allo\\\\*", true);
	test_one_is_star_at_the_end_only_glob_pattern("allo", false);
	test_one_is_star_at_the_end_only_glob_pattern("al*lo", false);
	test_one_is_star_at_the_end_only_glob_pattern("al\\*lo", false);
	test_one_is_star_at_the_end_only_glob_pattern("*allo", false);
	test_one_is_star_at_the_end_only_glob_pattern("al*lo*", false);
	test_one_is_star_at_the_end_only_glob_pattern("allo**", false);
	test_one_is_star_at_the_end_only_glob_pattern("allo*\\*", false);
	test_one_is_star_at_the_end_only_glob_pattern("allo\\*", false);
}

static void test_one_is_star_glob_pattern(const char *pattern, bool expected)
{
	ok(strutils_is_star_glob_pattern(pattern) == expected,
		"strutils_is_star_glob_pattern() returns the expected result: `%s` -> %d",
		pattern, expected);
}

static void test_is_star_glob_pattern(void)
{
	test_one_is_star_glob_pattern("allo*", true);
	test_one_is_star_glob_pattern("*allo", true);
	test_one_is_star_glob_pattern("*allo*", true);
	test_one_is_star_glob_pattern("*al*lo*", true);
	test_one_is_star_glob_pattern("al\\**lo", true);
	test_one_is_star_glob_pattern("al\\*l*o", true);
	test_one_is_star_glob_pattern("all*o\\", true);
	test_one_is_star_glob_pattern("*", true);
	test_one_is_star_glob_pattern("\\\\*", true);
	test_one_is_star_glob_pattern("allo", false);
	test_one_is_star_glob_pattern("allo\\*", false);
	test_one_is_star_glob_pattern("al\\*lo", false);
	test_one_is_star_glob_pattern("\\*allo", false);
	test_one_is_star_glob_pattern("\\*", false);
	test_one_is_star_glob_pattern("allo\\", false);
}

static void test_one_normalize_star_glob_pattern(const char *pattern,
		const char *expected)
{
	char *rw_pattern = strdup(pattern);

	assert(rw_pattern);
	strutils_normalize_star_glob_pattern(rw_pattern);
	ok(strcmp(rw_pattern, expected) == 0,
		"strutils_normalize_star_glob_pattern() produces the expected result: `%s` -> `%s`",
		pattern, expected);
	free(rw_pattern);
}

static void test_normalize_star_glob_pattern(void)
{
	test_one_normalize_star_glob_pattern("salut", "salut");
	test_one_normalize_star_glob_pattern("sal*ut", "sal*ut");
	test_one_normalize_star_glob_pattern("sal**ut", "sal*ut");
	test_one_normalize_star_glob_pattern("sal***ut", "sal*ut");
	test_one_normalize_star_glob_pattern("*salut", "*salut");
	test_one_normalize_star_glob_pattern("**salut", "*salut");
	test_one_normalize_star_glob_pattern("***salut", "*salut");
	test_one_normalize_star_glob_pattern("salut*", "salut*");
	test_one_normalize_star_glob_pattern("salut**", "salut*");
	test_one_normalize_star_glob_pattern("salut***", "salut*");
	test_one_normalize_star_glob_pattern("sa\\*lut", "sa\\*lut");
	test_one_normalize_star_glob_pattern("sa\\**lut", "sa\\**lut");
	test_one_normalize_star_glob_pattern("sa*\\**lut", "sa*\\**lut");
	test_one_normalize_star_glob_pattern("sa*\\***lut", "sa*\\**lut");
	test_one_normalize_star_glob_pattern("\\*salu**t", "\\*salu*t");
	test_one_normalize_star_glob_pattern("\\*salut**", "\\*salut*");
	test_one_normalize_star_glob_pattern("\\*salut**\\*", "\\*salut*\\*");
	test_one_normalize_star_glob_pattern("\\*salut", "\\*salut");
	test_one_normalize_star_glob_pattern("\\***salut", "\\**salut");
	test_one_normalize_star_glob_pattern("salut\\", "salut\\");
	test_one_normalize_star_glob_pattern("salut\\**", "salut\\**");
	test_one_normalize_star_glob_pattern("salut\\\\*", "salut\\\\*");
	test_one_normalize_star_glob_pattern("salut\\\\***", "salut\\\\*");
	test_one_normalize_star_glob_pattern("*", "*");
	test_one_normalize_star_glob_pattern("**", "*");
	test_one_normalize_star_glob_pattern("***", "*");
	test_one_normalize_star_glob_pattern("**\\***", "*\\**");
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);
	diag("String utils unit tests");
	test_normalize_star_glob_pattern();
	test_is_star_glob_pattern();
	test_is_star_at_the_end_only_glob_pattern();
	test_split();

	return exit_status();
}
