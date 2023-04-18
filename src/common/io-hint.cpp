/*
 * Copyright (C) 2023 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/error.hpp>
#include <common/io-hint.hpp>
#include <common/scope-exit.hpp>

#include <cinttypes>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

/*
 * Use sync_file_range when available.
 */
#ifdef HAVE_SYNC_FILE_RANGE

#include <fcntl.h>

namespace {
int flush_range(int fd, off_t offset, off_t nbytes, unsigned int flags)
{
	int ret;

	ret = sync_file_range(fd, offset, nbytes, flags);
	if (ret) {
		PERROR("Failed to sync file range: fd=%i, offset=%" PRIu64 ", nbytes=%" PRIu64
		       ", flags=%i",
		       fd,
		       static_cast<uint64_t>(offset),
		       static_cast<uint64_t>(nbytes),
		       flags);
	}

	return ret;
}

int flush_range_sync(int fd, off_t offset, off_t nbytes)
{
	return flush_range(fd,
			   offset,
			   nbytes,
			   SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE |
				   SYNC_FILE_RANGE_WAIT_AFTER);
}

int flush_range_async(int fd, off_t offset, off_t nbytes)
{
	return flush_range(fd, offset, nbytes, SYNC_FILE_RANGE_WRITE);
}
} /* namespace */

#else /* HAVE_SYNC_FILE_RANGE */

namespace {
/*
 * Use a memory mapping with msync() to emulate sync_file_range().
 */
int flush_range(int fd, off_t offset, off_t nbytes, int flags)
{
	void *mapped_region = mmap(NULL, nbytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
	if (mapped_region == MAP_FAILED) {
		PERROR("Failed to mmap region to flush range: fd=%i, offset=%" PRIu64
		       ", nbytes=%" PRIu64 ", flags=%i",
		       fd,
		       static_cast<uint64_t>(offset),
		       static_cast<uint64_t>(nbytes),
		       flags);
		return -1;
	}

	const auto munmap_on_exit = lttng::make_scope_exit([&]() noexcept {
		const auto munmap_ret = munmap(mapped_region, nbytes);
		if (munmap_ret) {
			PERROR("Failed to munmap region while flushing range: fd=%i, offset=%" PRIu64
			       ", nbytes=%" PRIu64 ", flags=%i",
			       fd,
			       static_cast<uint64_t>(offset),
			       static_cast<uint64_t>(nbytes),
			       flags);
		}
	});

	const auto msync_ret = msync(mapped_region, nbytes, flags);
	if (msync_ret) {
		PERROR("Failed to msync region while flushing range: fd=%i, offset=%" PRIu64
		       ", nbytes=%" PRIu64 ", flags=%i",
		       fd,
		       static_cast<uint64_t>(offset),
		       static_cast<uint64_t>(nbytes),
		       flags);
		return -1;
	}

	return 0;
}

int flush_range_sync(int fd, off_t offset, off_t nbytes)
{
	return flush_range(fd, offset, nbytes, MS_SYNC);
}

int flush_range_async(int fd, off_t offset, off_t nbytes)
{
	return flush_range(fd, offset, nbytes, MS_ASYNC);
}
} /* namespace */
#endif /* !HAVE_SYNC_FILE_RANGE */

/*
 * Use posix_fadvise when available.
 */
#ifdef HAVE_POSIX_FADVISE
namespace {
int hint_dont_need(int fd, off_t offset, off_t nbytes)
{
	const int ret = posix_fadvise(fd, offset, nbytes, POSIX_FADV_DONTNEED);
	if (ret && ret != -ENOSYS) {
		PERROR("Failed to mark region as DONTNEED with posix_fadvise: fd=%i, offset=%" PRIu64
		       ", nbytes=%" PRIu64,
		       fd,
		       static_cast<uint64_t>(offset),
		       static_cast<uint64_t>(nbytes));
		errno = ret;
	}

	return ret;
}
} /* namespace */

#else /* HAVE_POSIX_FADVISE */

/*
 * Generic noop compat for platforms wihtout posix_fadvise, this is acceptable
 * since we are only giving a hint to the kernel.
 */
namespace {
int hint_dont_need(int fd __attribute__((unused)),
		   off_t offset __attribute__((unused)),
		   off_t nbytes __attribute__((unused)))
{
	return 0;
}
} /* namespace */
#endif /* !HAVE_POSIX_FADVISE */

/*
 * Give a hint to the kernel that we won't need the data at the specified range
 * so it can be dropped from the page cache and wait for it to be flushed to
 * disk.
 */
void lttng::io::hint_flush_range_dont_need_sync(int fd, off_t offset, off_t nbytes)
{
	/* Waited for the page writeback to complete. */
	flush_range_sync(fd, offset, nbytes);

	/*
	 * Give hints to the kernel about how we access the file:
	 * POSIX_FADV_DONTNEED : we won't re-access data in a near future after
	 * we write it.
	 *
	 * We need to call fadvise again after the file grows because the
	 * kernel does not seem to apply fadvise to non-existing parts of the
	 * file.
	 *
	 * Call fadvise _after_ having waited for the page writeback to
	 * complete because the dirty page writeback semantic is not well
	 * defined. So it can be expected to lead to lower throughput in
	 * streaming.
	 */
	hint_dont_need(fd, offset, nbytes);
}

/*
 * Give a hint to the kernel that the data at the specified range should be
 * flushed to disk and wait for it to complete.
 */
void lttng::io::hint_flush_range_sync(int fd, off_t offset, off_t nbytes)
{
	flush_range_sync(fd, offset, nbytes);
}

/*
 * Give a hint to the kernel that the data at the specified range should be
 * flushed to disk and return immediatly.
 */
void lttng::io::hint_flush_range_async(int fd, off_t offset, off_t nbytes)
{
	flush_range_async(fd, offset, nbytes);
}
