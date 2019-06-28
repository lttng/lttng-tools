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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <tap/tap.h>
#include <common/compat/directory-handle.h>

#define TEST_COUNT 5

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose = 3;
int lttng_opt_mi;

#define DIR_HIERARCHY "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p"
#define DIR_CREATION_MODE (S_IRWXU | S_IRWXG)

bool dir_exists(const char *path)
{
	int ret;
	struct stat st;

	ret = stat(path, &st);
	return ret == 0 && S_ISDIR(st.st_mode);
}

int main(int argc, char **argv)
{
	int ret;
	struct lttng_directory_handle test_dir_handle;
	char test_dir[] = "/tmp/lttng-XXXXXX";
	char *created_dir = NULL;

	plan_tests(TEST_COUNT);

	diag("directory handle tests");

	if (!mkdtemp(test_dir)) {
		diag("Failed to generate temporary test directory");
		goto end;
	}

	ret = lttng_directory_handle_init(&test_dir_handle, test_dir);
	ok(ret == 0, "Initialized directory handle from the test directory");
	if (ret) {
		goto end;
	}

	ret = lttng_directory_handle_create_subdirectory_recursive(
			&test_dir_handle, DIR_HIERARCHY, DIR_CREATION_MODE);
	ok(ret == 0, "Create folder hierarchy %s from handle to %s",
			DIR_HIERARCHY, test_dir);
	ret = asprintf(&created_dir, "%s/%s", test_dir, DIR_HIERARCHY);
	if (ret < 0) {
		diag("Failed to allocate created directory path buffer");
		goto end;
	}
	ok(dir_exists(created_dir), "Folder %s exists", created_dir);

	ret = lttng_directory_handle_remove_subdirectory_recursive(
			&test_dir_handle, "a");
	ok(ret == 0, "Recursively removed directory hierarchy %s by removing %s",
			DIR_HIERARCHY, "a");
end:
	ret = rmdir(test_dir);
	if (ret) {
		diag("Failed to clean-up test directory: %s", strerror(errno));
	}
	ok(ret == 0, "Cleaned-up test directory");
	lttng_directory_handle_fini(&test_dir_handle);
	free(created_dir);
	return exit_status();
}
