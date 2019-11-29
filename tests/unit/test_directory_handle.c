/*
 * Copyright (C) - 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/compat/directory-handle.h>
#include <common/error.h>
#include <tap/tap.h>

#define TEST_COUNT 9

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;
int lttng_opt_mi;

#define DIR_CREATION_MODE (S_IRWXU | S_IRWXG)

/*
 * Returns the number of tests that ran (irrespective of the result) or a
 * negative value on error (will abort all tests).
 */
typedef int(test_func)(const char *test_base_path);

static test_func test_rmdir_fail_non_empty;
static test_func test_rmdir_skip_non_empty;

static test_func *const test_funcs[] = {
	&test_rmdir_fail_non_empty,
	&test_rmdir_skip_non_empty,
};

static bool dir_exists(const char *path)
{
	int ret;
	struct stat st;

	ret = stat(path, &st);
	return ret == 0 && S_ISDIR(st.st_mode);
}

/*
 * Create a non-empty folder hierarchy from a directory handle:
 *
 * test_root_name
 * └── a
 *     └── b
 *         ├── c
 *         │   └── d
 *         └── e
 *             ├── f
 *             └── file1
 */
static int create_non_empty_hierarchy_with_root(
		struct lttng_directory_handle *test_dir_handle,
		const char *test_root_name)
{
	int ret;
	const int file_flags = O_WRONLY | O_CREAT | O_TRUNC;
	const mode_t file_mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
	char *branch_name = NULL;

	ret = asprintf(&branch_name, "%s/%s", test_root_name, "a/b/c/d");
	if (ret < 0) {
		diag("Failed to format folder path");
		goto end;
	}
	ret = lttng_directory_handle_create_subdirectory_recursive(
			test_dir_handle,
			branch_name,
			DIR_CREATION_MODE);
	if (ret) {
		diag("Failed to create test folder hierarchy %s", branch_name);
		goto end;
	}

	free(branch_name);
	ret = asprintf(&branch_name, "%s/%s", test_root_name, "a/b/e/f");
	if (ret < 0) {
		diag("Failed to format folder path");
		goto end;
	}
	ret = lttng_directory_handle_create_subdirectory_recursive(
			test_dir_handle,
			branch_name,
			DIR_CREATION_MODE);
	if (ret) {
		diag("Failed to create test folder hierarchy %s", branch_name);
		goto end;
	}

	free(branch_name);
	ret = asprintf(&branch_name, "%s/%s", test_root_name, "a/b/e/file1");
	if (ret < 0) {
		diag("Failed to format file path");
		goto end;
	}
	ret = lttng_directory_handle_open_file(
			test_dir_handle, branch_name, file_flags, file_mode);
	if (ret < 0) {
		diag("Failed to create file %s", branch_name);
		goto end;
	}
	ret = close(ret);
	if (ret) {
		PERROR("Failed to close fd to newly created file %s",
				branch_name);
		goto end;
	}
end:
	free(branch_name);
	return ret;
}

/* Remove "file1" from the test folder hierarchy. */
int remove_file_from_hierarchy(struct lttng_directory_handle *test_dir_handle,
		const char *test_root_name)
{
	int ret;
	char *file_name = NULL;

	ret = asprintf(&file_name, "%s/%s", test_root_name, "a/b/e/file1");
	if (ret < 0) {
		diag("Failed to format file path");
		goto end;
	}

	ret = lttng_directory_handle_unlink_file(test_dir_handle,
			file_name);
	if (ret) {
		PERROR("Failed to unlink file %s", file_name);
		goto end;
	}
end:
	free(file_name);
	return ret;
}

static int test_rmdir_fail_non_empty(const char *test_dir)
{
	int ret, tests_ran = 0;
	struct lttng_directory_handle *test_dir_handle;
	char *created_dir = NULL;
	const char test_root_name[] = "fail_non_empty";
	char *test_dir_path = NULL;

	diag("rmdir (fail if non-empty)");

	test_dir_handle = lttng_directory_handle_create(test_dir);
	ok(test_dir_handle, "Initialized directory handle from the test directory");
	tests_ran++;
	if (!test_dir_handle) {
		ret = -1;
		goto end;
	}

	ret = create_non_empty_hierarchy_with_root(test_dir_handle, test_root_name);
	if (ret) {
		diag("Failed to setup folder/file hierarchy to run test");
		goto end;
	}

	ret = lttng_directory_handle_remove_subdirectory_recursive(
			test_dir_handle, test_root_name,
			LTTNG_DIRECTORY_HANDLE_FAIL_NON_EMPTY_FLAG);
	ok(ret == -1, "Error returned when attempting to recursively remove non-empty hierarchy with LTTNG_DIRECTORY_HANDLE_FAIL_NON_EMPTY_FLAG");
	tests_ran++;

	ret = remove_file_from_hierarchy(test_dir_handle, test_root_name);
	if (ret) {
		diag("Failed to remove file from test folder hierarchy");
		goto end;
	}

	ret = lttng_directory_handle_remove_subdirectory_recursive(
			test_dir_handle, test_root_name,
			LTTNG_DIRECTORY_HANDLE_FAIL_NON_EMPTY_FLAG);
	ok(ret == 0, "No error returned when recursively removing empty hierarchy with LTTNG_DIRECTORY_HANDLE_FAIL_NON_EMPTY_FLAG");
	tests_ran++;

	ret = asprintf(&test_dir_path, "%s/%s", test_dir, test_root_name);
	if (ret < 0) {
		diag("Failed to format test directory path");
		goto end;
	}
	ok(!dir_exists(test_dir_path) && errno == ENOENT,
			"Folder hierarchy %s successfully removed",
			test_dir_path);
	tests_ran++;
	ret = 0;
end:
	lttng_directory_handle_put(test_dir_handle);
	free(created_dir);
	free(test_dir_path);
	return ret == 0 ? tests_ran : ret;
}

static int test_rmdir_skip_non_empty(const char *test_dir)
{
	int ret, tests_ran = 0;
	struct lttng_directory_handle *test_dir_handle;
	char *created_dir = NULL;
	const char test_root_name[] = "skip_non_empty";
	char *test_dir_path = NULL;

	diag("rmdir (skip if non-empty)");

	test_dir_handle = lttng_directory_handle_create(test_dir);
	ok(test_dir_handle, "Initialized directory handle from the test directory");
	tests_ran++;
	if (!test_dir_handle) {
		ret = -1;
		goto end;
	}

	ret = create_non_empty_hierarchy_with_root(test_dir_handle, test_root_name);
	if (ret) {
		diag("Failed to setup folder/file hierarchy to run test");
		goto end;
	}

	ret = lttng_directory_handle_remove_subdirectory_recursive(
			test_dir_handle, test_root_name,
			LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG);
	ok(ret == 0, "No error returned when attempting to recursively remove non-empty hierarchy with LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG");
	tests_ran++;

	ret = asprintf(&test_dir_path, "%s/%s", test_dir, test_root_name);
	if (ret < 0) {
		diag("Failed to format test directory path");
		goto end;
	}
	ok(dir_exists(test_dir_path), "Test directory still exists after skip");
	tests_ran++;

	ret = remove_file_from_hierarchy(test_dir_handle, test_root_name);
	if (ret) {
		diag("Failed to remove file from test folder hierarchy");
		goto end;
	}

	ret = lttng_directory_handle_remove_subdirectory_recursive(
			test_dir_handle, test_root_name,
			LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG);
	ok(ret == 0, "No error returned when recursively removing empty hierarchy with LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG");
	tests_ran++;

	ok(!dir_exists(test_dir_path) && errno == ENOENT,
			"Folder hierarchy %s successfully removed",
			test_dir_path);
	tests_ran++;
	ret = 0;
end:
	lttng_directory_handle_put(test_dir_handle);
	free(created_dir);
	free(test_dir_path);
	return ret == 0 ? tests_ran : ret;
}

int main(int argc, char **argv)
{
	int ret;
	char test_dir[] = "/tmp/lttng-XXXXXX";
	int tests_left = TEST_COUNT;
	size_t func_idx;

	plan_tests(TEST_COUNT);

	diag("lttng_directory_handle tests");

	if (!mkdtemp(test_dir)) {
		diag("Failed to generate temporary test directory");
		goto end;
	}

	for (func_idx = 0; func_idx < sizeof(test_funcs) / sizeof(*test_funcs);
			func_idx++) {
		tests_left -= test_funcs[func_idx](test_dir);
	}
	if (tests_left) {
		diag("Skipping %d tests that could not be executed due to a prior error",
				tests_left);
		skip(tests_left, "test due to an error");
	}
end:
	ret = rmdir(test_dir);
	if (ret) {
		diag("Failed to clean-up test directory: %s", strerror(errno));
	}
	return exit_status();
}
