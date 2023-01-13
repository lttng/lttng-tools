/*
 * Copyright (C) 2017 Philippe Proulx <pproulx@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/string-utils/string-utils.hpp>

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <tap/tap.h>

/* Number of TAP tests in this file */
#define NUM_TESTS 69

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

static void test_one_split(const char *input, char delim, int escape_delim, ...)
{
	va_list vl;
	bool all_ok = true;
	struct lttng_dynamic_pointer_array strings;
	int split_ret;
	size_t i, string_count;

	split_ret = strutils_split(input, delim, escape_delim, &strings);
	LTTNG_ASSERT(split_ret == 0);
	va_start(vl, escape_delim);

	string_count = lttng_dynamic_pointer_array_get_count(&strings);

	for (i = 0; i < string_count; i++) {
		const char *expected_substring = va_arg(vl, const char *);
		const char *substring =
			(const char *) lttng_dynamic_pointer_array_get_pointer(&strings, i);

		diag("  got `%s`, expecting `%s`", substring, expected_substring);

		if (!expected_substring) {
			all_ok = false;
			break;
		}

		if (strcmp(substring, expected_substring) != 0) {
			all_ok = false;
			break;
		}
	}

	lttng_dynamic_pointer_array_reset(&strings);
	va_end(vl);
	ok(all_ok,
	   "strutils_split() produces the expected substrings: `%s` (delim. `%c`, escape `%d`)",
	   input,
	   delim,
	   escape_delim);
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
	   pattern,
	   expected);
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
	   pattern,
	   expected);
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

static void test_one_normalize_star_glob_pattern(const char *pattern, const char *expected)
{
	char *rw_pattern = strdup(pattern);

	LTTNG_ASSERT(rw_pattern);
	strutils_normalize_star_glob_pattern(rw_pattern);
	ok(strcmp(rw_pattern, expected) == 0,
	   "strutils_normalize_star_glob_pattern() produces the expected result: `%s` -> `%s`",
	   pattern,
	   expected);
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

int main(void)
{
	plan_tests(NUM_TESTS);
	diag("String utils unit tests");
	test_normalize_star_glob_pattern();
	test_is_star_glob_pattern();
	test_is_star_at_the_end_only_glob_pattern();
	test_split();

	return exit_status();
}
