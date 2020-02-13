/*
 * Copyright (C) 2013 Raphaël Beamonte <raphael.beamonte@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <tap/tap.h>

#include <common/utils.h>
#include <common/common.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;
int lttng_opt_mi;

struct valid_test_input {
	const char *input;
	const char *relative_part;
	const char *absolute_part;
};

struct tree_symlink {
	const char *orig;
	const char *dest;
};

struct symlink_test_input {
	const char *input;
	const char *expected_result;
};

/* Valid test cases */
static struct valid_test_input valid_tests_inputs[] = {
	{ "/a/b/c/d/e",			"",		"/a/b/c/d/e"	},
	{ "/a//b//c/d/e",		"",		"/a/b/c/d/e"	},
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
	{ "/../a/b/c/d/e",		"",		"/a/b/c/d/e"	},
	{ "/a/b/c/d/../../../../../e",	"",		"/e"		},
	{ "/..",			"",		"/"		},
	{ "/a/..",			"",		"/"		},
};
char **valid_tests_expected_results;
static const int num_valid_tests =
		sizeof(valid_tests_inputs) / sizeof(valid_tests_inputs[0]);

/* Symlinks test cases */
char tree_origin[] = "/tmp/test_utils_expand_path.XXXXXX";

static const char * const tree_dirs[] = {
	"a",
	"a/b",
	"a/b/c",
	"a/e",
};
static const int num_tree_dirs =
		sizeof(tree_dirs) / sizeof(tree_dirs[0]);

static struct tree_symlink tree_symlinks[] = {
	{ "a/d",			"b/c/"		},
	{ "a/g",			"d/"		},
	{ "a/b/f",			"../e/"		},
	{ "a/b/h",			"../g/"		},
	{ "a/b/k",			"c/g/"		},
	{ "a/b/c/g",			"../../../"	},
};
static const int num_tree_symlinks =
		sizeof(tree_symlinks) / sizeof(tree_symlinks[0]);

static struct symlink_test_input symlink_tests_inputs[] = {
	{ "a/g/../l/.",			"a/b/l"		},
	{ "a/g/../l/./",		"a/b/l/"	},
	{ "a/g/../l/..",		"a/b"		},
	{ "a/g/../l/../",		"a/b/"		},
	{ "a/b/h/g/",			""		},
};
static const int num_symlink_tests =
		sizeof(symlink_tests_inputs) / sizeof(symlink_tests_inputs[0]);

/* Invalid test cases */
static char *invalid_tests_inputs[] = {
	NULL,
};
static const int num_invalid_tests =
		sizeof(invalid_tests_inputs) / sizeof(invalid_tests_inputs[0]);

#define PRINT_ERR(fmt, args...)						\
	fprintf(stderr, "test_utils_expand_path: error: " fmt "\n", ## args)

static int prepare_valid_results(void)
{
	int i;
	char *relative, *cur_path = NULL, *prev_path = NULL,
			*pprev_path = NULL, *empty = NULL;
	int ret = 0;

	/* Prepare the relative paths */
	cur_path = realpath(".", NULL);
	prev_path = realpath("..", NULL);
	pprev_path = realpath("../..", NULL);
	empty = strdup("");
	if (!cur_path || !prev_path || !pprev_path || !empty) {
		PRINT_ERR("strdup out of memory");
		ret = -1;
		goto end;
	}

	/* allocate memory for the expected results */
	valid_tests_expected_results = zmalloc(sizeof(char *) * num_valid_tests);
	if (!valid_tests_expected_results) {
		PRINT_ERR("out of memory");
		ret = -1;
		goto end;
	}
	for (i = 0; i < num_valid_tests; i++) {
		valid_tests_expected_results[i] = malloc(PATH_MAX);
		if (valid_tests_expected_results[i] == NULL) {
			PRINT_ERR("malloc expected results");
			ret = -1;
			goto end;
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

end:
	free(cur_path);
	free(prev_path);
	free(pprev_path);
	free(empty);

	return ret;
}

static int free_valid_results(void)
{
	int i;

	for (i = 0; i < num_valid_tests; i++) {
		free(valid_tests_expected_results[i]);
	}

	free(valid_tests_expected_results);

	return 0;
}

static int prepare_symlink_tree(void)
{
	int i;
	char tmppath[PATH_MAX] = {};

	/* Create the temporary directory */
	if (mkdtemp(tree_origin) == NULL) {
		PRINT_ERR("failed to mkdtemp");
		goto error;
	}

	/* Create the directories of the test tree */
	for (i = 0; i < num_tree_dirs; i++) {
		snprintf(tmppath, sizeof(tmppath), "%s/%s", tree_origin,
				tree_dirs[i]);

		if (mkdir(tmppath, 0755) != 0) {
			PRINT_ERR("mkdir failed with path \"%s\"", tmppath);
			goto error;
		}
	}

	/* Create the symlinks of the test tree */
	for (i = 0; i < num_tree_symlinks; i++) {
		snprintf(tmppath, sizeof(tmppath), "%s/%s",
				tree_origin, tree_symlinks[i].orig);

		if (symlink(tree_symlinks[i].dest, tmppath) != 0) {
			PRINT_ERR("failed to symlink \"%s\" to \"%s\"", tmppath,
					tree_symlinks[i].dest);
			goto error;
		}
	}

	return 0;

error:
	return 1;
}

static int free_symlink_tree(void)
{
	int i;
	char tmppath[PATH_MAX];

	/* Remove the symlinks from the test tree */
	for (i =  num_tree_symlinks - 1; i > -1; i--) {
		snprintf(tmppath, PATH_MAX, "%s/%s",
				tree_origin, tree_symlinks[i].orig);

		if (unlink(tmppath) != 0) {
			PRINT_ERR("failed to unlink \"%s\"", tmppath);
			goto error;
		}
	}

	/* Remove the directories from the test tree */
	for (i = num_tree_dirs - 1; i > -1; i--) {
		snprintf(tmppath, PATH_MAX, "%s/%s", tree_origin, tree_dirs[i]);

		if (rmdir(tmppath) != 0) {
			PRINT_ERR("failed to rmdir \"%s\"", tmppath);
			goto error;
		}
	}

	/* Remove the temporary directory */
	if (rmdir(tree_origin) != 0) {
		PRINT_ERR("failed to rmdir \"%s\"", tree_origin);
		goto error;
	}

	return 0;

error:
	return 1;
}

static void test_utils_expand_path(void)
{
	char *result;
	char name[100], tmppath[PATH_MAX], real_tree_origin[PATH_MAX];
	int i, treelen;

	/* Test valid cases */
	for (i = 0; i < num_valid_tests; i++) {
		sprintf(name, "valid test case: %s", valid_tests_inputs[i].input);

		result = utils_expand_path(valid_tests_inputs[i].input);
		ok(result != NULL &&
				strcmp(result, valid_tests_expected_results[i]) == 0, name);

		free(result);
	}

	/*
	 * Get the realpath for the tree_origin since it can itself be a
	 * symlink.
	 */
	result = realpath(tree_origin, real_tree_origin);
	if (!result) {
		fail("realpath failed.");
		return;
	}

	/* Test symlink tree cases */
	treelen = strlen(real_tree_origin) + 1;
	for (i = 0; i < num_symlink_tests; i++) {
		int ret;

		sprintf(name, "symlink tree test case: [tmppath/]%s",
				symlink_tests_inputs[i].input);

		ret = snprintf(tmppath, PATH_MAX, "%s/%s",
				real_tree_origin,
				symlink_tests_inputs[i].input);
		if (ret == -1 || ret >= PATH_MAX) {
			PRINT_ERR("truncation occurred while concatenating paths \"%s\" and \"%s\"",
					real_tree_origin,
					symlink_tests_inputs[i].input);
			fail(name);
			continue;
		}
		result = utils_expand_path(tmppath);
		ok(result != NULL && strcmp(result + treelen,
					symlink_tests_inputs[i].expected_result) == 0, name);

		free(result);
	}

	/* Test invalid cases */
	for (i = 0; i < num_invalid_tests; i++) {
		const char *test_input = invalid_tests_inputs[i];

		sprintf(name, "invalid test case: %s", test_input ?
				test_input : "NULL");

		result = utils_expand_path(test_input);
		if (result != NULL) {
			free(result);
		}
		ok(result == NULL, name);
	}
}

int main(int argc, char **argv)
{
	if (prepare_symlink_tree() != 0) {
		goto error_mkdir;
	}

	if (prepare_valid_results() != 0) {
		goto error_malloc;
	}

	plan_tests(num_valid_tests + num_invalid_tests + num_symlink_tests);

	diag("utils_expand_path tests");

	test_utils_expand_path();

	free_valid_results();
	free_symlink_tree();

	return exit_status();

error_malloc:
	free_valid_results();

error_mkdir:
	free_symlink_tree();

	return 1;
}
