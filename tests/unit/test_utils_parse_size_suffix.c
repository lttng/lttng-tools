/*
 * Copyright (C) - 2013 Simon Marchi <simon.marchi@polymtl.ca>
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
		{ "0x400", 1024 },
		{ "0300", 192 },
		{ "16k", 16384 },
		{ "128K", 131072 },
		{ "0x1234k", 4771840 },
		{ "32M", 33554432 },
		{ "1024G", 1099511627776ULL },
		{ "0X400", 1024 },
		{ "0x40a", 1034 },
		{ "0X40b", 1035 },
		{ "0x40C", 1036 },
		{ "0X40D", 1037 },
		{ "0x40e", 1038 },
		{ "0X40f", 1039 },
		{ "00", 0 },
		{ "0k", 0 },
		{ "0K", 0 },
		{ "0M", 0 },
		{ "0G", 0 },
		{ "00k", 0 },
		{ "00K", 0 },
		{ "00M", 0 },
		{ "00G", 0 },
		{ "0x0", 0 },
		{ "0X0", 0 },
		{ "0x0k", 0 },
		{ "0X0K", 0 },
		{ "0x0M", 0 },
		{ "0X0G", 0 },
		{ "0X40G", 68719476736ULL },
		{ "0300k", 196608 },
		{ "0300K", 196608 },
		{ "030M", 25165824 },
		{ "020G", 17179869184ULL },
		{ "0xa0k", 163840 },
		{ "0xa0K", 163840 },
		{ "0XA0M", 167772160 },
		{ "0xA0G", 171798691840ULL },
};
static const int num_valid_tests = sizeof(valid_tests_inputs) / sizeof(valid_tests_inputs[0]);

/* Invalid test cases */
static char *invalid_tests_inputs[] = {
		"",
		" ",
		"-1",
		"k",
		"4611686018427387904G",
		"0x40g",
		"08",
		"09",
		"0x",
		"x0",
		"0xx0",
		"07kK",
		"0xk",
		"0XM",
		"0xG",
		"0x0MM",
		"0X0GG",
		"0a",
		"0B",
};

static const int num_invalid_tests = sizeof(invalid_tests_inputs) / sizeof(invalid_tests_inputs[0]);

static void test_utils_parse_size_suffix(void)
{
	uint64_t result;
	int ret;
	int i;

	/* Test valid cases */
	for (i = 0; i < num_valid_tests; i++) {
		char name[100];
		sprintf(name, "valid test case: %s", valid_tests_inputs[i].input);

		ret = utils_parse_size_suffix(valid_tests_inputs[i].input, &result);
		ok(ret == 0 && result == valid_tests_inputs[i].expected_result, name);
	}

	/* Test invalid cases */
	for (i = 0; i < num_invalid_tests; i++) {
		char name[100];
		sprintf(name, "invalid test case: %s", invalid_tests_inputs[i]);

		ret = utils_parse_size_suffix(invalid_tests_inputs[i], &result);
		ok(ret != 0, name);
	}
}

int main(int argc, char **argv)
{
	plan_tests(num_valid_tests + num_invalid_tests);

	diag("utils_parse_size_suffix tests");

	test_utils_parse_size_suffix();

	return exit_status();
}
