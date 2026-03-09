/*
 * SPDX-License-Identifier: GPL-2.0-only
 * SPDX-FileCopyrightText: 2026 Kienan Stewart <kstewart@efficios.com>
 */

#include <common/defaults.hpp>
#include <common/string-utils/c-string-view.hpp>
#include <common/utils.hpp>

#include <array>
#include <stdio.h>
#include <tap/tap.h>

/* For error.h */
bool lttng_opt_is_tui = true;
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;
int lttng_opt_mi;

struct TestCase {
	const char *value;
	unsigned int expected;
	bool should_throw;
};

/* clang-format off */
const std::array<const TestCase, 15> test_cases {{
	{ "0\n", 0, false },
	{ "0-4\n", 4, false },
	{ "12-11\n", 11, false },
	{ "0-2,33-98\n", 98, false },
	{ "22-\n", 0, true },
	{ "9\n", 9, false },
	{ "11\n", 11, false },
	{ "13,", 0, true },
	{ "0", 0, false },
	{ "1-2,3-5", 5, false },
	{ "0", 0, false },
	{ "", 0, true },
	{ "0-2a\n", 0, true },
	{ "-2\n", 2, false },
	{ "a", 0, true },
}};
/* clang-format on */

int main()
{
	const auto test_count = test_cases.size();

	plan_tests(test_count);
	for (int i = 0; i < test_count; i++) {
		const auto& test_case = test_cases[i];
		bool pass = true;

		try {
			const auto result = utils_get_max_cpu_id_from_mask(
				lttng::c_string_view(test_case.value));

			if (result != test_case.expected) {
				diag("Result mis-match, expected=%d, result=%d",
				     test_case.expected,
				     result);
				pass = false;
			}
		} catch (const std::exception& ex) {
			if (!test_case.should_throw) {
				diag("Unexpected exception: %s", ex.what());
				pass = false;
			} else {
				diag("Test case %d received expected exception: %s",
				     i + 1,
				     ex.what());
			}
		}

		std::string v;
		for (int n = 0; n < strlen(test_case.value); n++) {
			if (test_case.value[n] == '\n') {
				v += "\\n";
			} else {
				v += test_case.value[n];
			}
		}

		ok(pass,
		   "Test case %d expected=%d, mask=\"%s\"",
		   i + 1,
		   test_case.expected,
		   v.c_str());
	}

	return exit_status();
}
