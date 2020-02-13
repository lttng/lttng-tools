/*
 * Copyright (C) 2015 Simon Marchi <simon.marchi@polymtl.ca>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include <tap/tap.h>

#include <common/utils.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;
int lttng_opt_mi;

struct valid_test_input {
	const char *input;
	uint64_t expected_result;
};

/* Valid test cases */
static struct valid_test_input valid_tests_inputs[] = {
		{ "0", 0 },
		{ "1234", 1234 },
		{ "1234us", 1234 },
		{ "16ms", 16000 },
		{ "128ms", 128000 },
		{ "32s", 32000000 },
		{ "1m", 60000000 },
		{ "20m", 1200000000 },
		{ "1h", 3600000000 },
		{ "5h", 18000000000 },
		{ "00", 0 },
		{ "0us", 0 },
		{ "0ms", 0 },
		{ "0s", 0 },
		{ "0m", 0 },
		{ "0h", 0 },
		{ "00us", 0 },
		{ "00ms", 0 },
		{ "00s", 0 },
		{ "00m", 0 },
		{ "00h", 0 },
		{ "12ms", 12000 },
		{ "3597us", 3597 },
		{ "+5", 5 },
		{ "08", 8 },
		{ "0145us", 145 },
};
static const int num_valid_tests = sizeof(valid_tests_inputs) / sizeof(valid_tests_inputs[0]);

/* Invalid test cases */
static const char *invalid_tests_inputs[] = {
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
		"0u",
		"5mS",
		"5Ms",
		"12ussr",
		"67msrp",
		"14si",
		"12mo",
		"53hi",
};
static const int num_invalid_tests = sizeof(invalid_tests_inputs) / sizeof(invalid_tests_inputs[0]);

static void test_utils_parse_time_suffix(void)
{
	uint64_t result;
	int ret;
	int i;

	/* Test valid cases */
	for (i = 0; i < num_valid_tests; i++) {
		char name[256];

		ret = utils_parse_time_suffix(valid_tests_inputs[i].input, &result);
		sprintf(name, "valid test case: %s expected %" PRIu64, valid_tests_inputs[i].input, result);
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
