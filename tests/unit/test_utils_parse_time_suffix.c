/*
 * Copyright (C) - 2015 Simon Marchi <simon.marchi@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by as
 * published by the Free Software Foundation; only version 2 of the License.
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

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include <tap/tap.h>

#include <common/utils.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;
int lttng_opt_mi;

struct valid_test_input {
	char *input;
	uint64_t expected_result;
};

/* Valid test cases */
static struct valid_test_input valid_tests_inputs[] = {
		{ "0", 0 },
		{ "1234", 1234 },
		{ "0u", 0 },
		{ "1234u", 1234 },
		{ "16m", 16000 },
		{ "128m", 128000 },
		{ "32s", 32000000 },
		{ "00", 0 },
		{ "0m", 0 },
		{ "0s", 0 },
		{ "00m", 0 },
		{ "00s", 0 },
		{ "12ms", 12000 },
		{ "3597us", 3597 },
		{ "+5", 5 },
		{ "08", 8 },
		{ "0145us", 145 },
};
static const int num_valid_tests = sizeof(valid_tests_inputs) / sizeof(valid_tests_inputs[0]);

/* Invalid test cases */
static char *invalid_tests_inputs[] = {
		"",
		" ",
		"-1",
		"m",
		"4611686018427387904s",
		"0x40M",
		"0x",
		"x0",
		"0xx0",
		"07mm",
		"0xm",
		"0Xs",
		"0x0ss",
		"0a",
		"0B",
		"0x3 s",
		"0xbs ",
		"14ns",
		"0xbs",
		"14ns",
		"14ms garbage after value",
		"0x14s",
};
static const int num_invalid_tests = sizeof(invalid_tests_inputs) / sizeof(invalid_tests_inputs[0]);

static void test_utils_parse_time_suffix(void)
{
	uint64_t result;
	int ret;
	int i;

	/* Test valid cases */
	for (i = 0; i < num_valid_tests; i++) {
		char name[100];

		sprintf(name, "valid test case: %s", valid_tests_inputs[i].input);

		ret = utils_parse_time_suffix(valid_tests_inputs[i].input, &result);
		ok(ret == 0 && result == valid_tests_inputs[i].expected_result, name);
	}

	/* Test invalid cases */
	for (i = 0; i < num_invalid_tests; i++) {
		char name[100];

		sprintf(name, "invalid test case: %s", invalid_tests_inputs[i]);

		ret = utils_parse_time_suffix(invalid_tests_inputs[i], &result);
		ok(ret != 0, name);
	}
}

int main(int argc, char **argv)
{
	plan_tests(num_valid_tests + num_invalid_tests);

	diag("utils_parse_time_suffix tests");

	test_utils_parse_time_suffix();

	return exit_status();
}
