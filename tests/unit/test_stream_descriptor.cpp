/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/exception.hpp>
#include <common/readwrite.hpp>
#include <common/stream-descriptor.hpp>

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <stdlib.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <tap/tap.h>
#include <unistd.h>

/* For error.h */
bool lttng_opt_is_tui = true;
int lttng_opt_quiet = 1;
int lttng_opt_verbose;
int lttng_opt_mi;

namespace {
constexpr int test_count = 38;

constexpr char initial_contents[] = "0123456789abcdef";
constexpr std::size_t initial_contents_size = sizeof(initial_contents) - 1;

constexpr auto oversized_count = static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()) + 1;

/* Regular file which is removed when the instance is destroyed. */
class temporary_file final {
public:
	temporary_file() : _read_write(_create(_path))
	{
	}

	~temporary_file()
	{
		(void) unlink(_path.c_str());
	}

	temporary_file(const temporary_file&) = delete;
	temporary_file(temporary_file&&) = delete;
	temporary_file& operator=(const temporary_file&) = delete;
	temporary_file& operator=(temporary_file&&) = delete;

	const lttng::stream_descriptor& read_write() const noexcept
	{
		return _read_write;
	}

	lttng::input_stream_descriptor open_input(const int flags) const
	{
		return lttng::input_stream_descriptor(_open(flags));
	}

	lttng::output_stream_descriptor open_output(const int flags) const
	{
		return lttng::output_stream_descriptor(_open(flags));
	}

	off_t size() const
	{
		struct stat file_status;

		if (fstat(_read_write.fd(), &file_status) < 0) {
			LTTNG_THROW_POSIX("Failed to get the status of the temporary file");
		}

		return file_status.st_size;
	}

private:
	static int _create(std::string& path)
	{
		const auto fd = mkstemp(&path[0]);

		if (fd < 0) {
			LTTNG_THROW_POSIX("Failed to create a temporary file");
		}

		return fd;
	}

	int _open(const int flags) const
	{
		const auto fd = open(_path.c_str(), flags);

		if (fd < 0) {
			LTTNG_THROW_POSIX("Failed to open the temporary file");
		}

		return fd;
	}

	std::string _path = "/tmp/test_stream_descriptor_XXXXXX";
	const lttng::stream_descriptor _read_write;
};

off_t file_offset(const lttng::file_descriptor& descriptor)
{
	const auto offset = lseek(descriptor.fd(), 0, SEEK_CUR);

	if (offset < 0) {
		LTTNG_THROW_POSIX("Failed to get the file offset of a descriptor");
	}

	return offset;
}

enum class operation_outcome_kind {
	SUCCESS,
	POSIX_ERROR,
	UNSUPPORTED_ERROR,
	OTHER_ERROR,
};

struct operation_outcome {
	operation_outcome_kind kind;
	std::string message;
	int posix_errno_code;
};

template <typename OperationType>
operation_outcome run_operation(const OperationType& operation)
{
	try {
		operation();
		return { operation_outcome_kind::SUCCESS, "", 0 };
	} catch (const lttng::posix_error& ex) {
		return { operation_outcome_kind::POSIX_ERROR, ex.what(), ex.code() };
	} catch (const lttng::unsupported_error& ex) {
		return { operation_outcome_kind::UNSUPPORTED_ERROR, ex.what(), 0 };
	} catch (const std::exception& ex) {
		return { operation_outcome_kind::OTHER_ERROR, ex.what(), 0 };
	}
}

bool is_posix_error(const operation_outcome& outcome, const int expected_errno)
{
	return outcome.kind == operation_outcome_kind::POSIX_ERROR &&
		outcome.posix_errno_code == expected_errno;
}

void test_lttng_pread_lttng_pwrite(const temporary_file& file)
{
	const auto fd = file.read_write().fd();

	ok(lttng_pwrite(fd, initial_contents, initial_contents_size, 0) ==
		   static_cast<ssize_t>(initial_contents_size),
	   "lttng_pwrite() writes the whole buffer");
	ok(lttng_pwrite(fd, "XY", 2, 4) == 2, "lttng_pwrite() writes at an offset");
	ok(file_offset(file.read_write()) == 0, "lttng_pwrite() doesn't change the file offset");

	char read_buffer[32] = {};

	ok(lttng_pread(fd, read_buffer, initial_contents_size, 0) ==
			   static_cast<ssize_t>(initial_contents_size) &&
		   std::memcmp(read_buffer, "0123XY6789abcdef", initial_contents_size) == 0,
	   "lttng_pread() reads the whole file");
	ok(lttng_pread(fd, read_buffer, 3, 9) == 3 && std::memcmp(read_buffer, "9ab", 3) == 0,
	   "lttng_pread() reads at an offset");
	ok(file_offset(file.read_write()) == 0, "lttng_pread() doesn't change the file offset");
	ok(lttng_pread(fd, read_buffer, 8, 12) == 4 && std::memcmp(read_buffer, "cdef", 4) == 0,
	   "lttng_pread() returns a short count when it reaches the end of the file");
	ok(lttng_pread(fd, read_buffer, 8, initial_contents_size) == 0,
	   "lttng_pread() returns 0 at the end of the file");
	ok(lttng_pwrite(fd, "end", 3, 32) == 3 && file.size() == 35,
	   "lttng_pwrite() past the end of the file extends it");

	errno = 0;
	ok(lttng_pread(-1, read_buffer, 8, 0) == -1 && errno == EBADF,
	   "lttng_pread() returns -1 and sets errno to EBADF with an invalid descriptor");

	errno = 0;
	ok(lttng_pwrite(-1, "Z", 1, 0) == -1 && errno == EBADF,
	   "lttng_pwrite() returns -1 and sets errno to EBADF with an invalid descriptor");

	errno = 0;
	ok(lttng_pread(fd, read_buffer, oversized_count, 0) == -1 && errno == EINVAL,
	   "lttng_pread() returns -1 and sets errno to EINVAL when the count exceeds SSIZE_MAX");

	errno = 0;
	ok(lttng_pwrite(fd, "Z", oversized_count, 0) == -1 && errno == EINVAL,
	   "lttng_pwrite() returns -1 and sets errno to EINVAL when the count exceeds SSIZE_MAX");

	const auto write_only = file.open_output(O_WRONLY);

	errno = 0;
	ok(lttng_pread(write_only.fd(), read_buffer, 8, 0) == -1 && errno == EBADF,
	   "lttng_pread() returns -1 and sets errno to EBADF with a write-only descriptor");

	const auto read_only = file.open_input(O_RDONLY);

	errno = 0;
	ok(lttng_pwrite(read_only.fd(), "Z", 1, 0) == -1 && errno == EBADF,
	   "lttng_pwrite() returns -1 and sets errno to EBADF with a read-only descriptor");
}

void test_read_at_write_at(const temporary_file& file)
{
	const auto& read_write = file.read_write();

	ok(run_operation([&read_write]() {
		   read_write.write_at(initial_contents, initial_contents_size, 0);
	   }).kind == operation_outcome_kind::SUCCESS,
	   "write_at() writes the whole buffer");
	ok(run_operation([&read_write]() { read_write.write_at("PQ", 2, 6); }).kind ==
		   operation_outcome_kind::SUCCESS,
	   "write_at() writes at an offset");

	char read_buffer[32] = {};

	ok(run_operation([&read_write, &read_buffer]() {
		   read_write.read_at(read_buffer, initial_contents_size, 0);
	   }).kind == operation_outcome_kind::SUCCESS &&
		   std::memcmp(read_buffer, "012345PQ89abcdef", initial_contents_size) == 0,
	   "read_at() reads the whole file");
	ok(run_operation([&read_write, &read_buffer]() {
		   read_write.read_at(read_buffer, 4, 5);
	   }).kind == operation_outcome_kind::SUCCESS &&
		   std::memcmp(read_buffer, "5PQ8", 4) == 0,
	   "read_at() reads at an offset");
	ok(file_offset(file.read_write()) == 0,
	   "read_at() and write_at() don't change the file offset");

	ok(run_operation([&read_write]() { read_write.write_at("end", 3, 32); }).kind ==
			   operation_outcome_kind::SUCCESS &&
		   file.size() == 35,
	   "write_at() past the end of the file extends it");

	const auto past_end_outcome = run_operation(
		[&read_write, &read_buffer]() { read_write.read_at(read_buffer, 8, 30); });

	ok(past_end_outcome.kind == operation_outcome_kind::OTHER_ERROR &&
		   past_end_outcome.message.find("Unexpected end of file") != std::string::npos,
	   "read_at() reports an end of file error when it can't read the whole range");
	ok(run_operation([&read_write, &read_buffer]() {
		   read_write.read_at(read_buffer, 0, 35);
	   }).kind == operation_outcome_kind::SUCCESS,
	   "read_at() reads zero bytes at the end of the file");

	ok(is_posix_error(run_operation([&read_write, &read_buffer]() {
				  read_write.read_at(read_buffer, oversized_count, 0);
			  }),
			  EINVAL),
	   "read_at() reports EINVAL when the size exceeds SSIZE_MAX");
	ok(is_posix_error(
		   run_operation([&read_write]() { read_write.write_at("Z", oversized_count, 0); }),
		   EINVAL),
	   "write_at() reports EINVAL when the size exceeds SSIZE_MAX");

	const auto write_only = file.open_input(O_WRONLY);

	ok(is_posix_error(run_operation([&write_only, &read_buffer]() {
				  write_only.read_at(read_buffer, 1, 0);
			  }),
			  EBADF),
	   "read_at() reports EBADF with a write-only descriptor");

	const auto read_only = file.open_output(O_RDONLY);

	ok(is_posix_error(run_operation([&read_only]() { read_only.write_at("Z", 1, 0); }), EBADF),
	   "write_at() reports EBADF with a read-only descriptor");
}

void test_read_read_some_write(const temporary_file& file)
{
	auto output = file.open_output(O_WRONLY);

	ok(run_operation([&output]() {
		   output.write(initial_contents, initial_contents_size);
	   }).kind == operation_outcome_kind::SUCCESS &&
		   file.size() == static_cast<off_t>(initial_contents_size) &&
		   file_offset(output) == static_cast<off_t>(initial_contents_size),
	   "write() writes the whole buffer and advances the file offset");
	ok(run_operation([&output]() { output.write("Z", oversized_count); }).kind ==
		   operation_outcome_kind::UNSUPPORTED_ERROR,
	   "write() reports an unsupported error when the size exceeds SSIZE_MAX");

	auto input = file.open_input(O_RDONLY);
	char read_buffer[32] = {};
	std::size_t read_size = 0;

	ok(run_operation([&input, &read_buffer]() { input.read(read_buffer, 4); }).kind ==
			   operation_outcome_kind::SUCCESS &&
		   std::memcmp(read_buffer, "0123", 4) == 0 && file_offset(input) == 4,
	   "read() reads the whole buffer and advances the file offset");
	ok(run_operation([&input, &read_buffer, &read_size]() {
		   read_size = input.read_some(read_buffer, 8);
	   }).kind == operation_outcome_kind::SUCCESS &&
		   read_size == 8 && std::memcmp(read_buffer, "456789ab", 8) == 0 &&
		   file_offset(input) == 12,
	   "read_some() reads the requested size and advances the file offset");
	ok(run_operation([&input, &read_buffer, &read_size]() {
		   read_size = input.read_some(read_buffer, 8);
	   }).kind == operation_outcome_kind::SUCCESS &&
		   read_size == 4 && std::memcmp(read_buffer, "cdef", 4) == 0,
	   "read_some() returns a short count when it reaches the end of the file");
	ok(run_operation([&input, &read_buffer, &read_size]() {
		   read_size = input.read_some(read_buffer, 8);
	   }).kind == operation_outcome_kind::SUCCESS &&
		   read_size == 0,
	   "read_some() returns 0 at the end of the file");

	if (lseek(input.fd(), 12, SEEK_SET) < 0) {
		LTTNG_THROW_POSIX("Failed to set the file offset of the input descriptor");
	}

	const auto short_read_outcome =
		run_operation([&input, &read_buffer]() { input.read(read_buffer, 8); });

	ok(short_read_outcome.kind == operation_outcome_kind::OTHER_ERROR &&
		   short_read_outcome.message.find("Failed to read enough data") !=
			   std::string::npos,
	   "read() reports a non-POSIX error when it can't read the whole buffer");
	ok(run_operation([&input, &read_buffer]() {
		   input.read_some(read_buffer, oversized_count);
	   }).kind == operation_outcome_kind::UNSUPPORTED_ERROR,
	   "read_some() reports an unsupported error when the size exceeds SSIZE_MAX");

	auto write_only = file.open_input(O_WRONLY);

	ok(is_posix_error(run_operation([&write_only, &read_buffer]() {
				  write_only.read(read_buffer, 1);
			  }),
			  EBADF),
	   "read() reports EBADF with a write-only descriptor");
	ok(is_posix_error(run_operation([&write_only, &read_buffer]() {
				  write_only.read_some(read_buffer, 1);
			  }),
			  EBADF),
	   "read_some() reports EBADF with a write-only descriptor");

	auto read_only = file.open_output(O_RDONLY);

	ok(is_posix_error(run_operation([&read_only]() { read_only.write("Z", 1); }), EBADF),
	   "write() reports EBADF with a read-only descriptor");
}
} /* namespace */

int main()
{
	plan_tests(test_count);

	try {
		{
			const temporary_file file;

			test_lttng_pread_lttng_pwrite(file);
		}

		{
			const temporary_file file;

			test_read_at_write_at(file);
		}

		{
			const temporary_file file;

			test_read_read_some_write(file);
		}
	} catch (const std::exception& ex) {
		diag("Unexpected exception: %s", ex.what());
	}

	return exit_status();
}
