/*
 * Copyright (C) - 2013 Raphaël Beamonte <raphael.beamonte@gmail.com>
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
#include <stdlib.h>
#include <limits.h>

#include <tap/tap.h>

#include <src/common/utils.h>

/* For lttngerr.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;

struct valid_test_input {
	char *input;
	char *relative_part;
	char *absolute_part;
};

/* Valid test cases */
static struct valid_test_input valid_tests_inputs[] = {
	{ "/a/b/c/d/e",			"",		"/a/b/c/d/e"	},
	{ "./a/b/c/d/e",		".",		"/a/b/c/d/e"	},
	{ "../a/b/c/d/../e",		"..",		"/a/b/c/e"	},
	{ ".././a/b/c/d/./e",		"..",		"/a/b/c/d/e"	},
	{ "../../a/b/c/d/e",		"../..",	"/a/b/c/d/e"	},
	{ "./a/b/../c/d/../e",		".",		"/a/c/e"	},
	{ "../a/b/../../c/./d/./e",	"..",		"/c/d/e"	},
	{ "../../a/b/../c/d/../../e",	"../..",	"/a/e"		},
	{ "./a/b/c/d/../../../../e",	".",		"/e"		},
	{ ".././a/b/c/d/./e",		"..",		"/a/b/c/d/e"	},
	{ "a/",				".",		"/a/"		},
	{ "a",				".",		"/a"		},
	{ "../../",			"../..",	"/"		},
	{ "../..",			"../..",	""		},
	{ "../",			"..",		"/"		},
	{ "..",				"..",		""		},
	{ "./",				".",		"/"		},
	{ ".",				".",		""		},
};
char **valid_tests_expected_results;
static const int num_valid_tests =
		sizeof(valid_tests_inputs) / sizeof(valid_tests_inputs[0]);

/* Invalid test cases */
static char *invalid_tests_inputs[] = {
	NULL,
	"/../a/b/c/d/e",
	"/a/b/c/d/../../../../../e",
};
static const int num_invalid_tests =
		sizeof(invalid_tests_inputs) / sizeof(invalid_tests_inputs[0]);

int prepare_valid_results()
{
	int i;
	char *relative, *cur_path, *prev_path, *pprev_path, *empty;

	/* Prepare the relative paths */
	cur_path = realpath(".", NULL);
	prev_path = realpath("..", NULL);
	pprev_path = realpath("../..", NULL);
	empty = strdup("");

	/* allocate memory for the expected results */
	valid_tests_expected_results = malloc(sizeof(char *) * num_valid_tests);
	for (i = 0; i < num_valid_tests; i++) {
		valid_tests_expected_results[i] = malloc(PATH_MAX);
		if (valid_tests_expected_results[i] == NULL) {
			fprintf(stderr, "malloc expected results");
			return 1;
		}

		if (strcmp(valid_tests_inputs[i].relative_part, ".") == 0) {
			relative = cur_path;
		} else if (strcmp(valid_tests_inputs[i].relative_part, "..") == 0) {
			relative = prev_path;
		} else if (strcmp(valid_tests_inputs[i].relative_part, "../..") == 0) {
			relative = pprev_path;
		} else {
			relative = empty;
		}

		snprintf(valid_tests_expected_results[i], PATH_MAX,
				"%s%s", relative, valid_tests_inputs[i].absolute_part);
	}

	free(cur_path);
	free(prev_path);
	free(pprev_path);
	free(empty);

	return 0;
}

int free_valid_results()
{
	int i;

	for (i = 0; i < num_valid_tests; i++) {
		free(valid_tests_expected_results[i]);
	}

	free(valid_tests_expected_results);

	return 0;
}

static void test_utils_expand_path(void)
{
	char *result;
	int i;

	/* Test valid cases */
	for (i = 0; i < num_valid_tests; i++) {
		char name[100];
		sprintf(name, "valid test case: %s", valid_tests_inputs[i].input);

		result = utils_expand_path(valid_tests_inputs[i].input);
		ok(strcmp(result, valid_tests_expected_results[i]) == 0, name);

		free(result);
	}

	/* Test invalid cases */
	for (i = 0; i < num_invalid_tests; i++) {
		char name[100];
		sprintf(name, "invalid test case: %s", invalid_tests_inputs[i]);

		result = utils_expand_path(invalid_tests_inputs[i]);
		if (result != NULL) {
			free(result);
		}
		ok(result == NULL, name);
	}
}

int main(int argc, char **argv)
{
	if (prepare_valid_results() != 0) {
		return 1;
	}

	plan_tests(num_valid_tests + num_invalid_tests);

	diag("utils_expand_path tests");

	test_utils_expand_path();

	free_valid_results();
	return exit_status();
}
