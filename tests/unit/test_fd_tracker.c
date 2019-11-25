/*
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <stdlib.h>
#include <inttypes.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <tap/tap.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <urcu.h>

#include <common/compat/directory-handle.h>
#include <common/error.h>
#include <common/fd-tracker/fd-tracker.h>

/* For error.h */
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

/* Number of TAP tests in this file */
#define NUM_TESTS 61
/* 3 for stdin, stdout, and stderr */
#define STDIO_FD_COUNT 3
#define TRACKER_FD_LIMIT 50
#define TMP_DIR_PATTERN "/tmp/fd-tracker-XXXXXX"
#define TEST_UNLINK_DIRECTORY_NAME "unlinked_files"

/*
 * Count of fds, beyond stdin, stderr, stdout that were open
 * at the launch of the test. This allows the test to succeed when
 * run by automake's test runner or valgrind which both open
 * fds behind our back.
 */
int unknown_fds_count;

const char file_contents[] = "Bacon ipsum dolor amet jerky drumstick sirloin "
	"strip steak venison boudin filet mignon picanha doner shoulder. "
	"Strip steak brisket alcatra, venison beef chuck cupim pastrami. "
	"Landjaeger tri-tip salami leberkas ball tip, ham hock chuck sausage "
	"flank jerky cupim. Pig bacon chuck pancetta andouille.";

void get_temporary_directories(char **_test_directory, char **_unlink_directory)
{
	int ret;
	char tmp_path_pattern[] = TMP_DIR_PATTERN;
	char *output_dir;

	output_dir = mkdtemp(tmp_path_pattern);
	if (!output_dir) {
		diag("Failed to create temporary path of the form %s",
				TMP_DIR_PATTERN);
		assert(0);
	}

	*_test_directory = strdup(output_dir);
	assert(*_test_directory);
	ret = asprintf(_unlink_directory, "%s/%s", output_dir,
			TEST_UNLINK_DIRECTORY_NAME);
	if (ret < 0) {
		assert(0);
	}
}

static
int fd_count(void)
{
	DIR *dir;
	struct dirent *entry;
        int count = 0;

	dir = opendir("/proc/self/fd");
	if (!dir) {
		perror("# Failed to enumerate /proc/self/fd/ to count the number of used file descriptors");
	        count = -1;
		goto end;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
	        count++;
	}
	/* Don't account for the file descriptor opened by opendir(). */
        count--;
	if (closedir(dir)) {
		perror("# Failed to close test program's self/fd directory file descriptor");
	}
end:
	return count;
}

static
void check_fd_count(int expected_count)
{
        int count = 0;

        count = fd_count();
	ok(count == expected_count, "Expected %d open file descriptors (%d are open)",
			expected_count, count);
}

static
int noop_open(void *data, int *fds)
{
        *fds = *((int *) data);
	return 0;
}

static
int noop_close(void *data, int *fds)
{
	return 0;
}

static
void track_std_fds(struct fd_tracker *tracker)
{
	int i;
        struct { int fd; const char *name; } files[] = {
		{ .fd = fileno(stdin), .name = "stdin" },
		{ .fd = fileno(stdout), .name = "stdout" },
		{ .fd = fileno(stderr), .name = "stderr" },
	};

	for (i = 0; i < sizeof(files) / sizeof(*files); i++) {
		int out_fd, ret;

		ret = fd_tracker_open_unsuspendable_fd(tracker, &out_fd,
				&files[i].name, 1, noop_open, &files[i].fd);
		assert(out_fd == files[i].fd);

		ok(ret == 0, "Track unsuspendable fd %d (%s)", files[i].fd,
				files[i].name);
	}
}

static
void untrack_std_fds(struct fd_tracker *tracker)
{
	int i;
        struct { int fd; const char *name; } files[] = {
		{ .fd = fileno(stdin), .name = "stdin" },
		{ .fd = fileno(stdout), .name = "stdout" },
		{ .fd = fileno(stderr), .name = "stderr" },
	};
	unsigned int fds_set_to_minus_1 = 0;

	for (i = 0; i < sizeof(files) / sizeof(*files); i++) {
		int fd = files[i].fd;
		int ret = fd_tracker_close_unsuspendable_fd(tracker,
				&files[i].fd, 1, noop_close, NULL);

		ok(ret == 0, "Untrack unsuspendable fd %d (%s)", fd,
				files[i].name);
		fds_set_to_minus_1 += (files[i].fd == -1);
	}
}

/*
 * Basic test opening and closing three unsuspendable fds. 
 */
static
void test_unsuspendable_basic(void)
{
	int ret;
	struct fd_tracker *tracker;
	char *test_directory = NULL, *unlinked_files_directory = NULL;

	get_temporary_directories(&test_directory, &unlinked_files_directory);

        tracker = fd_tracker_create(unlinked_files_directory, TRACKER_FD_LIMIT);
	ok(tracker, "Created an fd tracker with a limit of %d simulateously opened file descriptors",
			TRACKER_FD_LIMIT);
	if (!tracker) {
		goto end;
	}

	track_std_fds(tracker);
	untrack_std_fds(tracker);

	fd_tracker_destroy(tracker);
	ret = rmdir(test_directory);
	ok(ret == 0, "Test directory is empty");
end:
	free(test_directory);
	free(unlinked_files_directory);
}

static
int error_open(void *data, int *fds)
{
	return *((int *) data);
}

static
int error_close(void *data, int *fds)
{
	return *((int *) data);
}

/*
 * Validate that user callback return values are returned to the
 * caller of the fd tracker.
 */
static
void test_unsuspendable_cb_return(void)
{
	int ret, stdout_fd = fileno(stdout), out_fd = 42;
	struct fd_tracker *tracker;
	int expected_error = -ENETDOWN;
	char *test_directory = NULL, *unlinked_files_directory = NULL;

	get_temporary_directories(&test_directory, &unlinked_files_directory);

        tracker = fd_tracker_create(test_directory, TRACKER_FD_LIMIT);
	assert(tracker);

	/* The error_open callback should fail and return 'expected_error'. */
	ret = fd_tracker_open_unsuspendable_fd(tracker, &out_fd,
			NULL, 1, error_open, &expected_error);
	ok(ret == expected_error, "fd_tracker_open_unsuspendable_fd() forwards the user callback's error code");
	ok(out_fd == 42, "Output fd parameter is unaffected on error of fd_tracker_open_unsuspendable_fd()");

	/*
	 * Track a valid fd since we don't want the tracker to fail with an
	 * invalid fd error for this test.
	 */
	ret = fd_tracker_open_unsuspendable_fd(tracker, &out_fd,
			NULL, 1, noop_open, &stdout_fd);
	ok(out_fd == stdout_fd, "fd_tracker_open_unsuspendable_fd() sets the output fd parameter to the newly-tracked fd's value");
	assert(!ret);

	ret = fd_tracker_close_unsuspendable_fd(tracker,
			&stdout_fd, 1, error_close, &expected_error);
	ok(ret == expected_error, "fd_tracker_close_unsuspendable_fd() forwards the user callback's error code");
	ret = fd_tracker_close_unsuspendable_fd(tracker,
			&stdout_fd, 1, noop_close, &expected_error);
	assert(!ret);

	fd_tracker_destroy(tracker);
	ret = rmdir(test_directory);
	ok(ret == 0, "Test directory is empty");
	free(test_directory);
	free(unlinked_files_directory);
}

/*
 * Validate that the tracker refuses to track two identical unsuspendable
 * file descriptors.
 */
static
void test_unsuspendable_duplicate(void)
{
	int ret, stdout_fd = fileno(stdout), out_fd;
	struct fd_tracker *tracker;
	char *test_directory = NULL, *unlinked_files_directory = NULL;

	get_temporary_directories(&test_directory, &unlinked_files_directory);

        tracker = fd_tracker_create(unlinked_files_directory, TRACKER_FD_LIMIT);
	assert(tracker);

	ret = fd_tracker_open_unsuspendable_fd(tracker, &out_fd,
			NULL, 1, noop_open, &stdout_fd);
	assert(!ret);
	ret = fd_tracker_open_unsuspendable_fd(tracker, &out_fd,
			NULL, 1, noop_open, &stdout_fd);
	ok(ret == -EEXIST, "EEXIST reported on open of an already tracked file descriptor");

	ret = fd_tracker_close_unsuspendable_fd(tracker,
			&stdout_fd, 1, noop_close, NULL);
	assert(!ret);

	fd_tracker_destroy(tracker);
	ret = rmdir(test_directory);
	ok(ret == 0, "Test directory is empty");
	free(test_directory);
	free(unlinked_files_directory);
}

static
int open_pipes(void *data, int *out_fds)
{
	unsigned int i;
	const unsigned int pipe_count = TRACKER_FD_LIMIT / 2;

	for (i = 0; i < pipe_count; i++) {
		int ret = pipe(&out_fds[i * 2]);

		if (ret) {
			return -errno;
		}
	}
	return 0;
}

static
int close_pipes(void *data, int *fds)
{
	int i;
	int *pipes = fds;

	for (i = 0; i < TRACKER_FD_LIMIT; i++) {
		int ret = close(pipes[i]);

		if (ret) {
			return -errno;
		}
	}
	return 0;
}

/*
 * Validate that the tracker enforces the open file descriptor limit
 * when unsuspendable file descritptors are being opened.
 */
static
void test_unsuspendable_limit(void)
{
	struct fd_tracker *tracker;
	int ret, stdout_fd = fileno(stdout), out_fd;
	int fds[TRACKER_FD_LIMIT];
	char *test_directory = NULL, *unlinked_files_directory = NULL;

	get_temporary_directories(&test_directory, &unlinked_files_directory);

	/* This test assumes TRACKER_FD_LIMIT is a multiple of 2. */
	assert((TRACKER_FD_LIMIT % 2 == 0) && TRACKER_FD_LIMIT);

        tracker = fd_tracker_create(unlinked_files_directory, TRACKER_FD_LIMIT);
	assert(tracker);

	ret = fd_tracker_open_unsuspendable_fd(tracker, fds,
			NULL, TRACKER_FD_LIMIT, open_pipes, NULL);
	ok(ret == 0, "File descriptor tracker allowed the user to meet its limit with unsuspendable file descritptors (%d)",
			TRACKER_FD_LIMIT);

	ret = fd_tracker_open_unsuspendable_fd(tracker, &out_fd,
			NULL, 1, noop_open, &stdout_fd);
	ok(ret == -EMFILE, "EMFILE reported when exceeding the file descriptor limit while opening an unsuspendable fd");

	ret = fd_tracker_close_unsuspendable_fd(tracker,
			fds, TRACKER_FD_LIMIT, close_pipes, NULL);
	assert(!ret);

	fd_tracker_destroy(tracker);
	ret = rmdir(test_directory);
	ok(ret == 0, "Test directory is empty");
	free(test_directory);
	free(unlinked_files_directory);
}

/*
 * Validate that the tracker refuses to track two identical unsuspendable
 * file descriptors.
 */
static
void test_unsuspendable_close_untracked(void)
{
	int ret, stdout_fd = fileno(stdout), unknown_fds[2], out_fd;
	struct fd_tracker *tracker;
	char *test_directory = NULL, *unlinked_files_directory = NULL;

	get_temporary_directories(&test_directory, &unlinked_files_directory);

        tracker = fd_tracker_create(unlinked_files_directory, TRACKER_FD_LIMIT);
	if (!tracker) {
		goto end;;
	}

	ret = pipe(unknown_fds);
	assert(!ret);
	assert(close(unknown_fds[0]) == 0);
	assert(close(unknown_fds[1]) == 0);

	ret = fd_tracker_open_unsuspendable_fd(tracker, &out_fd,
			NULL, 1, noop_open, &stdout_fd);
	assert(!ret);

	ret = fd_tracker_close_unsuspendable_fd(tracker,
			unknown_fds, 1, noop_close, NULL);
	ok(ret == -EINVAL, "EINVAL reported on close of an untracked file descriptor");

	ret = fd_tracker_close_unsuspendable_fd(tracker,
			&stdout_fd, 1, noop_close, NULL);
	assert(!ret);

	fd_tracker_destroy(tracker);
	ret = rmdir(test_directory);
	ok(ret == 0, "Test directory is empty");
end:
	free(test_directory);
	free(unlinked_files_directory);
}

static int open_files(struct fd_tracker *tracker,
		struct lttng_directory_handle *directory,
		unsigned int count,
		struct fs_handle **handles,
		char **file_paths)
{
	int ret = 0;
	unsigned int i;

	for (i = 0; i < count; i++) {
		int p_ret;
	        char *file_path;
		struct fs_handle *handle;
		mode_t mode = S_IWUSR | S_IRUSR;

		p_ret = asprintf(&file_path, "file-%u", i);
		assert(p_ret >= 0);
	        file_paths[i] = file_path;

		handle = fd_tracker_open_fs_handle(tracker, directory, file_path,
				O_RDWR | O_CREAT, &mode);
		if (!handle) {
			ret = -1;
			break;
		}
		handles[i] = handle;
	}
	return ret;
}

static int open_same_file(struct fd_tracker *tracker,
		struct lttng_directory_handle *directory,
		const char *file,
		unsigned int count,
		struct fs_handle **handles)
{
	int ret = 0;
	unsigned int i;

	for (i = 0; i < count; i++) {
		struct fs_handle *handle;
		mode_t mode = S_IWUSR | S_IRUSR;

		handle = fd_tracker_open_fs_handle(tracker, directory, file,
				O_RDWR | O_CREAT, &mode);
		if (!handle) {
			ret = -1;
			break;
		}
		handles[i] = handle;
	}
	return ret;
}

static
int cleanup_files(struct fd_tracker *tracker, const char *dir,
		unsigned int count, struct fs_handle **handles,
		char **file_paths)
{
	int ret = 0;
	unsigned int i;

	for (i = 0; i < count; i++) {
		char *file_path = file_paths[i];

		if (!file_path) {
			break;
		}
		if (fs_handle_unlink(handles[i])) {
			diag("Failed to unlink fs_handle to file %s", file_path);
			ret = -1;
		}
	        if (fs_handle_close(handles[i])) {
			diag("Failed to close fs_handle to file %s", file_path);
			ret = -1;
		}
		free(file_path);
	}
	return ret;
}

static
void test_suspendable_limit(void)
{
	int ret;
	const int files_to_create = TRACKER_FD_LIMIT * 10;
	struct fd_tracker *tracker;
	char *test_directory = NULL, *unlinked_files_directory = NULL;
	char *output_files[files_to_create];
	struct fs_handle *handles[files_to_create];
	struct lttng_directory_handle *dir_handle = NULL;
	int dir_handle_fd_count;

	memset(output_files, 0, sizeof(output_files));
	memset(handles, 0, sizeof(handles));

	get_temporary_directories(&test_directory, &unlinked_files_directory);

        tracker = fd_tracker_create(unlinked_files_directory, TRACKER_FD_LIMIT);
	if (!tracker) {
		goto end;
	}

	dir_handle = lttng_directory_handle_create(test_directory);
	assert(dir_handle);
	dir_handle_fd_count = !!lttng_directory_handle_uses_fd(dir_handle);

	ret = open_files(tracker, dir_handle, files_to_create, handles,
			output_files);
	ok(!ret, "Created %d files with a limit of %d simultaneously-opened file descriptor",
			files_to_create, TRACKER_FD_LIMIT);
	check_fd_count(TRACKER_FD_LIMIT + STDIO_FD_COUNT + unknown_fds_count +
			dir_handle_fd_count);

	ret = cleanup_files(tracker, test_directory, files_to_create, handles,
			output_files);
	ok(!ret, "Close all opened filesystem handles");
	ret = rmdir(test_directory);
	ok(ret == 0, "Test directory is empty");
	fd_tracker_destroy(tracker);
	lttng_directory_handle_put(dir_handle);
end:
	free(test_directory);
	free(unlinked_files_directory);
}

static
void test_mixed_limit(void)
{
	int ret;
	const int files_to_create = TRACKER_FD_LIMIT;
	struct fd_tracker *tracker;
	char *test_directory = NULL, *unlinked_files_directory = NULL;
	char *output_files[files_to_create];
	struct fs_handle *handles[files_to_create];
	struct lttng_directory_handle *dir_handle = NULL;
	int dir_handle_fd_count;

	memset(output_files, 0, sizeof(output_files));
	memset(handles, 0, sizeof(handles));

	get_temporary_directories(&test_directory, &unlinked_files_directory);

	tracker = fd_tracker_create(unlinked_files_directory, TRACKER_FD_LIMIT);
	if (!tracker) {
		goto end;
	}

	dir_handle = lttng_directory_handle_create(test_directory);
	assert(dir_handle);
	dir_handle_fd_count = !!lttng_directory_handle_uses_fd(dir_handle);

	ret = open_files(tracker, dir_handle, files_to_create, handles,
			output_files);
	ok(!ret, "Created %d files with a limit of %d simultaneously-opened file descriptor",
			files_to_create, TRACKER_FD_LIMIT);
	diag("Check file descriptor count after opening %u files", files_to_create);
	check_fd_count(TRACKER_FD_LIMIT + STDIO_FD_COUNT + unknown_fds_count +
			dir_handle_fd_count);

	/*
	 * Open unsuspendable fds (stdin, stdout, stderr) and verify that the fd
	 * cap is still respected.
	 */
	diag("Check file descriptor count after adding %d unsuspendable fds",
			STDIO_FD_COUNT);
	track_std_fds(tracker);
	check_fd_count(TRACKER_FD_LIMIT + unknown_fds_count +
			dir_handle_fd_count);
	diag("Untrack unsuspendable file descriptors");
	untrack_std_fds(tracker);
	check_fd_count(TRACKER_FD_LIMIT + unknown_fds_count +
			dir_handle_fd_count);

	ret = cleanup_files(tracker, test_directory, files_to_create, handles,
			output_files);
	ok(!ret, "Close all opened filesystem handles");
	ret = rmdir(test_directory);
	ok(ret == 0, "Test directory is empty");
	fd_tracker_destroy(tracker);
	lttng_directory_handle_put(dir_handle);
end:
	free(test_directory);
	free(unlinked_files_directory);
}

/*
 * Open more files than allowed by the fd tracker's cap and write,
 * byte-by-byte, and in round-robin, a string. The goal is to force
 * the fd tracker to suspend and resume the fs_handles often and
 * verify that the fd cap is always respected.
 *
 * The content of the files is also verified at the end.
 */
static
void test_suspendable_restore(void)
{
	int ret;
	const int files_to_create = TRACKER_FD_LIMIT * 10;
	struct fd_tracker *tracker;
	char *output_files[files_to_create];
	struct fs_handle *handles[files_to_create];
	size_t content_index;
	int handle_index;
	bool write_success = true;
	bool fd_cap_respected = true;
	bool content_ok = true;
	struct lttng_directory_handle *dir_handle = NULL;
	int dir_handle_fd_count;
	char *test_directory = NULL, *unlinked_files_directory = NULL;

	memset(output_files, 0, sizeof(output_files));
	memset(handles, 0, sizeof(handles));

	get_temporary_directories(&test_directory, &unlinked_files_directory);

        tracker = fd_tracker_create(unlinked_files_directory, TRACKER_FD_LIMIT);
	if (!tracker) {
		goto end;
	}

	dir_handle = lttng_directory_handle_create(test_directory);
	assert(dir_handle);
	dir_handle_fd_count = !!lttng_directory_handle_uses_fd(dir_handle);

	ret = open_files(tracker, dir_handle, files_to_create, handles,
			output_files);
	ok(!ret, "Created %d files with a limit of %d simultaneously-opened file descriptor",
			files_to_create, TRACKER_FD_LIMIT);
	diag("Check file descriptor count after opening %u files", files_to_create);
	check_fd_count(TRACKER_FD_LIMIT + STDIO_FD_COUNT + unknown_fds_count +
			dir_handle_fd_count);

	for (content_index = 0; content_index < sizeof(file_contents); content_index++) {
		for (handle_index = 0; handle_index < files_to_create; handle_index++) {
			int fd;
			struct fs_handle *handle = handles[handle_index];
			const char *path = output_files[handle_index];

			fd = fs_handle_get_fd(handle);
			if (fd < 0) {
				write_success = false;
			        diag("Failed to restore fs_handle to %s",
					        path);
				goto skip_write;
			}

			do {
				ret = write(fd, file_contents + content_index, 1);
			} while (ret < 0 && errno == EINTR);

			if (ret != 1) {
				write_success = false;
			        PERROR("write() to %s failed", path);
				goto skip_write;
			}

			if (fd_count() > (TRACKER_FD_LIMIT + STDIO_FD_COUNT +
							unknown_fds_count +
							dir_handle_fd_count)) {
				fd_cap_respected = false;
			}

			fs_handle_put_fd(handle);
		}
	}
skip_write:
	ok(write_success, "Wrote reference string to %d files",
			files_to_create);
	ok(fd_cap_respected, "FD tracker enforced the file descriptor cap");

	/* Validate the contents of the files. */
	for (handle_index = 0; handle_index < files_to_create; handle_index++) {
		struct stat fd_stat;
		const char *path = output_files[handle_index];
		char read_buf[sizeof(file_contents)];
		char *read_pos;
		size_t to_read = sizeof(read_buf);
		int fd;

		fd = lttng_directory_handle_open_file(
				dir_handle, path, O_RDONLY, 0);
		assert(fd >= 0);
		ret = fstat(fd, &fd_stat);
		assert(!ret);
		if (fd_stat.st_size != sizeof(file_contents)) {
			diag("Content size of file %s doesn't match, got %" PRId64 ", expected %zu",
					path, (int64_t) fd_stat.st_size,
					sizeof(file_contents));
			content_ok = false;
			(void) close(fd);
			break;
		}

		read_pos = read_buf;
		do {
			ret = read(fd, read_pos, to_read);
			if (ret > 0) {
				to_read -= ret;
				read_pos += ret;
			}
		} while (to_read && (ret < 0 && errno == EINTR));
		if (ret < 0) {
			content_ok = false;
			PERROR("Failed to read file %s", path);
			(void) close(fd);
			break;
		}

		if (strcmp(file_contents, read_buf)) {
			content_ok = false;
			diag("File content doesn't match the expectated string");
			(void) close(fd);
			break;
		}
		(void) close(fd);
	}
	ok(content_ok, "Files contain the expected content");
	ret = cleanup_files(tracker, test_directory, files_to_create, handles,
			output_files);
	ok(!ret, "Close all opened filesystem handles");
	ret = rmdir(test_directory);
	ok(ret == 0, "Test directory is empty");
	fd_tracker_destroy(tracker);
	lttng_directory_handle_put(dir_handle);
end:
	free(test_directory);
	free(unlinked_files_directory);
}

static
void test_unlink(void)
{
	int ret;
	struct fd_tracker *tracker;
	const int handles_to_open = 2;
	struct fs_handle *handles[handles_to_open];
	struct fs_handle *new_handle = NULL;
	struct stat statbuf;
	struct lttng_directory_handle *dir_handle = NULL;
	const char file_name[] = "my_file";
	char *test_directory = NULL, *unlinked_files_directory = NULL;
	char *unlinked_file_zero = NULL, *unlinked_file_one = NULL;
	int fd;

	get_temporary_directories(&test_directory, &unlinked_files_directory);
	ret = asprintf(&unlinked_file_zero, "%s/%u", unlinked_files_directory,
			0);
	assert(ret > 0);
	ret = asprintf(&unlinked_file_one, "%s/%u", unlinked_files_directory,
			1);
	assert(ret > 0);

	tracker = fd_tracker_create(unlinked_files_directory, 1);
	if (!tracker) {
		goto end;
	}

	dir_handle = lttng_directory_handle_create(test_directory);
	assert(dir_handle);

	/* Open two handles to the same file. */
	ret = open_same_file(tracker, dir_handle, file_name, handles_to_open,
			handles);
	ok(!ret, "Successfully opened %i handles to %s/%s", handles_to_open,
			test_directory, file_name);
	if (ret) {
		goto end;
	}

	/*
	 * Unlinking the first handle should cause the file to be renamed
	 * to '0'.
	 */
	ret = fs_handle_unlink(handles[0]);
	ok(!ret, "Successfully unlinked the first handle to %s/%s",
			test_directory, file_name);

	/*
	 * The original file should no longer exist on the file system, and a
	 * new file named '0' should exist.
	 */
	ok(lttng_directory_handle_stat(dir_handle, file_name, &statbuf) == -1 &&
					errno == ENOENT,
			"%s no longer present on file system after unlink",
			file_name);
	ok(lttng_directory_handle_stat(
			dir_handle, unlinked_file_zero, &statbuf) == 0,
			"%s exists on file system after unlink",
			unlinked_file_zero);

	/*
	 * It should be possible to use the file descriptors of both handles.
	 * Since only one file descriptor can be opened at once, this should
	 * force the fd_tracker to suspend and restore the handles.
	 */
	fd = fs_handle_get_fd(handles[0]);
	ok(fd >= 0, "Got fd from first handle");

	fd = fs_handle_get_fd(handles[1]);
	ok (fd < 0, "fd tracker does not allow two fds to be used at once");

	fs_handle_put_fd(handles[0]);
	fd = fs_handle_get_fd(handles[1]);
	ok(fd >= 0, "Got fd from second handle");
	fs_handle_put_fd(handles[1]);

	/* The second unlink should fail with -ENOENT. */
	ret = fs_handle_unlink(handles[1]);
	ok(ret == -ENOENT,
			"ENOENT is reported when attempting to unlink the second handle to %s/%s",
			test_directory, file_name);

	/*
	 * Opening a new handle to 'my_file' should succeed.
	 */
	ret = open_same_file(tracker, dir_handle, file_name, 1, &new_handle);
	ok(!ret, "Successfully opened a new handle to previously unlinked file %s/%s",
			test_directory, file_name);
	assert(new_handle);

	/*
	 * Unlinking the new handle should cause the file to be renamed
	 * to '1' since '0' already exists.
	 */
	ret = fs_handle_unlink(new_handle);
	ok(!ret, "Successfully unlinked the new handle handle to %s/%s",
			test_directory, file_name);
	ok(stat(unlinked_file_one, &statbuf) == 0,
			"%s exists on file system after unlink",
			unlinked_file_one);

	ret = fs_handle_close(handles[0]);
	ok(!ret, "Successfully closed the first handle");
	ret = fs_handle_close(handles[1]);
	ok(!ret, "Successfully closed the second handle");
	ret = fs_handle_close(new_handle);
	ok(!ret, "Successfully closed the third handle");

	ok(lttng_directory_handle_stat(dir_handle, file_name, &statbuf) == -1 &&
					errno == ENOENT,
			"%s no longer present on file system after handle close",
			file_name);
	ok(lttng_directory_handle_stat(
			dir_handle, unlinked_file_zero, &statbuf) == -1 &&
					errno == ENOENT,
			"%s no longer present on file system after handle close",
			unlinked_file_zero);
	ok(lttng_directory_handle_stat(dir_handle, unlinked_file_one,
			&statbuf) == -1 &&
					errno == ENOENT,
			"%s no longer present on file system after handle close",
			unlinked_file_one);

	ret = rmdir(test_directory);
	ok(ret == 0, "Test directory is empty");
end:
	fd_tracker_destroy(tracker);
	free(test_directory);
	free(unlinked_files_directory);
	free(unlinked_file_zero);
	free(unlinked_file_one);
	lttng_directory_handle_put(dir_handle);
}

int main(int argc, char **argv)
{
	plan_tests(NUM_TESTS);
	diag("File descriptor tracker unit tests");

	rcu_register_thread();

	unknown_fds_count = fd_count() - STDIO_FD_COUNT;
	assert(unknown_fds_count >= 0);

	diag("Unsuspendable - basic");
	test_unsuspendable_basic();
	diag("Unsuspendable - callback return values");
	test_unsuspendable_cb_return();
	diag("Unsuspendable - duplicate file descriptors");
	test_unsuspendable_duplicate();
	diag("Unsuspendable - closing an untracked file descriptor");
	test_unsuspendable_close_untracked();
	diag("Unsuspendable - check that file descritptor limit is enforced");
	test_unsuspendable_limit();

	diag("Suspendable - check that file descritptor limit is enforced");
	test_suspendable_limit();
	diag("Suspendable - restoration test");
	test_suspendable_restore();

	diag("Mixed - check that file descritptor limit is enforced");
	test_mixed_limit();

	diag("Suspendable - Unlinking test");
	test_unlink();

	rcu_barrier();
	rcu_unregister_thread();
	return exit_status();
}
