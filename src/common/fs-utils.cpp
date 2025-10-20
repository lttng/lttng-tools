/*
 * SPDX-FileCopyrightText: 2025 Olivier Dion <odion@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "fs-utils.hpp"

#include <common/compat/directory-handle.hpp>
#include <common/defaults.hpp>
#include <common/error.hpp>

#include <vendor/optional.hpp>

#include <fcntl.h>
#include <mutex>
#include <sys/mman.h>
#include <tuple>
#include <unistd.h>
#include <unordered_map>

#ifdef __linux__
namespace {
/*
 * MADV_REMOVE is a Linux extension that is available since 2.6.16.
 *
 * Either the kernel is too old, in which case `EINVAL` is returned, or
 * the file-system where `fd` is does not support the advice
 * `MADV_REMOVE` in which case `EOPNOTSUPP` is returned.
 *
 * In all cases, we consider the advice to be supported if and only if
 * zero is returned from `madvise(2)`.
 *
 * NOTE: This function truncates `fd` to the value returned by
 * `sysconf(PAGE_SIZE)` and assume that it was opened with read and write
 * access.
 */
bool fd_supports_madv_remove(int fd)
{
	const long page_size = sysconf(_SC_PAGE_SIZE);

	if (page_size < 0) {
		PWARN_FMT("Failed to get page-size with sysconf()")
		return false;
	}

	if (ftruncate(fd, page_size) != 0) {
		PWARN_FMT("Failed to truncate page in file: fd={}", fd);
		return false;
	}

	void *mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (mem == MAP_FAILED) {
		PWARN_FMT("Failed to mmap() shared file: fd={}", fd);
		return false;
	}

	const bool success = madvise(mem, page_size, MADV_REMOVE) == 0;

	std::ignore = munmap(mem, page_size);

	return success;
}
} /* namespace */

/*
 * Determine if the file-system that contains the directory `shm_path` support
 * the `MADV_REMOVE` advice for `madvise(2)`.
 *
 * If `shm_path` is the null-pointer, then test for the file-system where
 * `shm_open(3)` creates files (usually /dev/shm).
 *
 * The test is done by creating a file in `shm_path`, truncating it to a single
 * page, mapping it in memory and testing if the `MADV_REMOVE` advice works. The
 * tested file is unlink and all references to the memory associated with it are
 * removed before the function returns.
 *
 * NOTE: The function is memoized and could result in wrong returned values if
 * the file-system at `shm_path` location is unmounted and mounted with another
 * type that handles the `MADV_REMOVE` advice differently.
 */
bool lttng::utils::fs_supports_madv_remove(const char *shm_path)
{
	static std::unordered_map<std::string, bool> cache = {};
	static nonstd::optional<bool> default_cache;
	static std::mutex cache_mutex;

	const char test_path[] = DEFAULT_MADV_REMOVE_TEST_FILENAME;

	if (shm_path) {
		{
			const std::lock_guard<std::mutex> lock(cache_mutex);
			if (cache.find(shm_path) != cache.end()) {
				return cache.at(shm_path);
			}
		}

		bool supported = false;
		struct lttng_directory_handle *dir_handle = lttng_directory_handle_create(shm_path);

		if (dir_handle) {
			/* Offset to 1 to skip '/' character. */
			const int fd = lttng_directory_handle_open_file(dir_handle,
									&test_path[1],
									O_RDWR | O_CREAT,
									S_IRUSR | S_IWUSR |
										S_IRGRP | S_IWGRP);

			if (fd >= 0) {
				supported = fd_supports_madv_remove(fd);

				std::ignore = close(fd);
			} else {
				PWARN_FMT("Failed on openat(): dirpath=`{}`, path=`{}`",
					  shm_path,
					  test_path);
			}

			lttng_directory_handle_put(dir_handle);
		} else {
			PWARN_FMT("Failed to open() directory: path=`{}`", shm_path);
		}

		try {
			const std::lock_guard<std::mutex> lock(cache_mutex);
			cache[shm_path] = supported;
		} catch (const std::bad_alloc&) {
			ERR("Failed to add filesystem MADV_REMOVE support entry to the cache due to an allocation failure.");
		}
		return supported;
	}

	{
		const std::lock_guard<std::mutex> lock(cache_mutex);
		if (default_cache) {
			return default_cache.value();
		}
	}

	bool supported = false;

	const int fd = shm_open(test_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

	if (fd >= 0) {
		std::ignore = shm_unlink(test_path);

		supported = fd_supports_madv_remove(fd);

		std::ignore = close(fd);
	} else {
		PWARN_FMT("Failed to shm_open(): path=`{}`", test_path);
	}

	{
		const std::lock_guard<std::mutex> lock(cache_mutex);
		default_cache = supported;
	}

	return supported;
}
#else
/*
 * `MADV_REMOVE` is a Linux extension.
 */
bool lttng::utils::fs_supports_madv_remove(const char *shm_path = nullptr)
{
	return false;
}
#endif /* __linux__ */
