/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "index-file.h"
#include "lttng-relayd.h"

#include <common/defaults.h>
#include <common/error.h>
#include <common/utils.h>
#include <common/readwrite.h>
#include <common/fd-tracker/fd-tracker.h>
#include <common/fd-tracker/utils.h>
#include <lttng/constant.h>

#include <inttypes.h>
#include <stdbool.h>
#include <urcu/ref.h>
#include <sys/stat.h>
#include <fcntl.h>

struct relay_index_file {
	struct fs_handle *handle;
	uint32_t major;
	uint32_t minor;
	uint32_t element_len;
	struct urcu_ref ref;
};

/*
 * This unlink wrapper allows the fd_tracker to check if any other
 * fs_handle references the index before unlinking it. If the relay holds
 * this file open, it is essential to unlink it through an fs_handle as this
 * will delay the actual unlink() until all handles have released this file.
 *
 * The file is renamed and unlinked once the last handle to its inode has been
 * released.
 */
static
int unlink_through_handle(const char *path)
{
	int ret = 0, close_ret;
	struct fs_handle *handle;
	/*
	 * Since this operation is only performed to perform the unlink
	 * through the fs_handle and fd-tracker system, the flag is opened
	 * without the O_CREAT. There is no need to perform the unlink if
	 * the file doesn't already exist.
	 */
	int flags = O_RDONLY;

	DBG("Unlinking index at %s through a filesystem handle", path);
	handle = fd_tracker_open_fs_handle(the_fd_tracker, path, flags, NULL);
	if (!handle) {
		/* There is nothing to do. */
		DBG("File %s does not exist, ignoring unlink", path);
		goto end;
	}

	ret = fs_handle_unlink(handle);
	close_ret = fs_handle_close(handle);
	if (close_ret) {
		ERR("Failed to close handle after performing an unlink operation on a filesystem handle");
	}
end:
	if (ret) {
		DBG("Unlinking index at %s failed with error code %i", path, ret);
	}
	return ret;
}

/*
 * Create the index file associated with a trace file.
 *
 * Return allocated struct lttng_index_file, NULL on error.
 */
struct relay_index_file *relay_index_file_create(const char *path_name,
		const char *stream_name, uint64_t size, uint64_t count,
		uint32_t idx_major, uint32_t idx_minor)
{
	struct relay_index_file *index_file;
	struct fs_handle *fs_handle = NULL;
	int ret, fd = -1;
	ssize_t size_ret;
	struct ctf_packet_index_file_hdr hdr;
	char idx_dir_path[LTTNG_PATH_MAX];
	char idx_file_path[LTTNG_PATH_MAX];
	/*
	 * With the session rotation feature on the relay, we might need to seek
	 * and truncate a tracefile, so we need read and write access.
	 */
	int flags = O_RDWR | O_CREAT | O_TRUNC;
	/* Open with 660 mode */
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	index_file = zmalloc(sizeof(*index_file));
	if (!index_file) {
		PERROR("allocating relay_index_file");
		goto error;
	}

	ret = snprintf(idx_dir_path, sizeof(idx_dir_path), "%s/" DEFAULT_INDEX_DIR,
			path_name);
	if (ret < 0) {
		PERROR("snprintf index path");
		goto error;
	}

	/* Create index directory if necessary. */
	ret = utils_mkdir(idx_dir_path, S_IRWXU | S_IRWXG, -1, -1);
	if (ret < 0) {
		if (errno != EEXIST) {
			PERROR("Index trace directory creation error");
			goto error;
		}
	}

	ret = utils_stream_file_name(idx_file_path, idx_dir_path, stream_name,
			size, count, DEFAULT_INDEX_FILE_SUFFIX);
	if (ret < 0) {
		ERR("Could not build path of index file");
		goto error;
	}

	/*
	 * For tracefile rotation. We need to unlink the old
	 * file if present to synchronize with the tail of the
	 * live viewer which could be working on this same file.
	 * By doing so, any reference to the old index file
	 * stays valid even if we re-create a new file with the
	 * same name afterwards.
	 */
	ret = unlink_through_handle(idx_file_path);
	if (ret < 0) {
		goto error;
	}

	fs_handle = fd_tracker_open_fs_handle(the_fd_tracker, idx_file_path,
			flags, &mode);
	if (!fs_handle) {
		goto error;
	}
	index_file->handle = fs_handle;

	fd = fs_handle_get_fd(fs_handle);
	if (fd < 0) {
		goto error;
	}

	ctf_packet_index_file_hdr_init(&hdr, idx_major, idx_minor);
	size_ret = lttng_write(fd, &hdr, sizeof(hdr));
	if (size_ret < sizeof(hdr)) {
		PERROR("write index header");
		goto error;
	}

	index_file->major = idx_major;
	index_file->minor = idx_minor;
	index_file->element_len = ctf_packet_index_len(idx_major, idx_minor);
	urcu_ref_init(&index_file->ref);

	fs_handle_put_fd(fs_handle);

	return index_file;

error:
	if (fd >= 0) {
		fs_handle_put_fd(fs_handle);
	}
	if (fs_handle) {
		int close_ret;

		close_ret = fs_handle_close(fs_handle);
		if (close_ret < 0) {
			PERROR("Failed to close index filesystem handle");
		}
	}
	free(index_file);
	return NULL;
}

struct relay_index_file *relay_index_file_open(const char *path_name,
		const char *channel_name, uint64_t tracefile_count,
		uint64_t tracefile_count_current)
{
	struct relay_index_file *index_file;
	int ret, fd = -1;
	ssize_t read_len;
	char fullpath[PATH_MAX];
	struct ctf_packet_index_file_hdr hdr;
	uint32_t major, minor, element_len;
	int flags = O_RDONLY;
	struct fs_handle *handle = NULL;

	assert(path_name);
	assert(channel_name);

	index_file = zmalloc(sizeof(*index_file));
	if (!index_file) {
		PERROR("Failed to allocate relay_index_file");
		goto error;
	}

	if (tracefile_count > 0) {
		ret = snprintf(fullpath, sizeof(fullpath), "%s/" DEFAULT_INDEX_DIR "/%s_%"
				PRIu64 DEFAULT_INDEX_FILE_SUFFIX, path_name,
				channel_name, tracefile_count_current);
	} else {
		ret = snprintf(fullpath, sizeof(fullpath), "%s/" DEFAULT_INDEX_DIR "/%s"
				DEFAULT_INDEX_FILE_SUFFIX, path_name, channel_name);
	}
	if (ret < 0) {
		PERROR("Failed to build index path");
		goto error;
	}

	DBG("Index opening file %s in read only mode", fullpath);
	handle = fd_tracker_open_fs_handle(the_fd_tracker, fullpath, flags,
			NULL);
	if (!handle) {
		PERROR("Failed to open index file at %s", fullpath);
		goto error;
	}

	fd = fs_handle_get_fd(handle);
	if (fd < 0) {
		PERROR("Failed to get fd of index file at %s", fullpath);
		goto error;
	}

	read_len = lttng_read(fd, &hdr, sizeof(hdr));
	if (read_len < 0) {
		PERROR("Failed to read index header");
		goto error_close;
	}

	if (be32toh(hdr.magic) != CTF_INDEX_MAGIC) {
		ERR("Invalid header magic %#010x, expected %#010x",
				be32toh(hdr.magic), CTF_INDEX_MAGIC);
		goto error_close;
	}
	major = be32toh(hdr.index_major);
	minor = be32toh(hdr.index_minor);
	element_len = be32toh(hdr.packet_index_len);

	if (major != CTF_INDEX_MAJOR) {
		ERR("Invalid header version, major = %" PRIu32 ", expected %i",
				major, CTF_INDEX_MAJOR);
		goto error_close;
	}
	if (element_len > sizeof(struct ctf_packet_index)) {
		ERR("Index element length too long (%" PRIu32 " bytes)",
				element_len);
		goto error_close;
	}

	fs_handle_put_fd(handle);
	index_file->handle = handle;
	index_file->major = major;
	index_file->minor = minor;
	index_file->element_len = element_len;
	urcu_ref_init(&index_file->ref);

	return index_file;

error_close:
	if (fd >= 0) {
		fs_handle_put_fd(handle);
	}
	ret = fs_handle_close(handle);
	if (ret < 0) {
		PERROR("Failed to close index filesystem handle to %s",
				fullpath);
	}

error:
	free(index_file);
	return NULL;
}

int relay_index_file_write(const struct relay_index_file *index_file,
		const struct ctf_packet_index *element)
{
	int fd, ret;
	ssize_t write_ret;

	assert(index_file);
	assert(element);

	fd = fs_handle_get_fd(index_file->handle);
	if (fd < 0) {
		ret = fd;
		goto end;
	}

	write_ret = lttng_write(fd, element, index_file->element_len);
	if (write_ret < index_file->element_len) {
		PERROR("Failed to write packet index to index file");
		ret = -1;
	}
	ret = 0;

	fs_handle_put_fd(index_file->handle);
end:
	return ret;
}

int relay_index_file_read(const struct relay_index_file *index_file,
		struct ctf_packet_index *element)
{
	int fd, ret;
	ssize_t read_ret;

	assert(index_file);
	assert(element);

	fd = fs_handle_get_fd(index_file->handle);
	if (fd < 0) {
		ret = fd;
		goto end;
	}

	read_ret = lttng_read(fd, element, index_file->element_len);
	if (read_ret < index_file->element_len) {
		PERROR("Failed to read packet index from file");
		ret = -1;
	}
	ret = 0;

	fs_handle_put_fd(index_file->handle);
end:
	return ret;
}

int relay_index_file_seek_end(struct relay_index_file *index_file)
{
	int fd, ret = 0;
	off_t lseek_ret;

	fd = fs_handle_get_fd(index_file->handle);
	if (fd < 0) {
		ret = fd;
		goto end;
	}

	lseek_ret = lseek(fd, 0, SEEK_END);
	if (lseek_ret < 0) {
		ret = lseek_ret;
	}

	fs_handle_put_fd(index_file->handle);
end:
	return ret;
}

void relay_index_file_get(struct relay_index_file *index_file)
{
	urcu_ref_get(&index_file->ref);
}

static
void relay_index_file_release(struct urcu_ref *ref)
{
	int ret;
	struct relay_index_file *index_file = caa_container_of(ref,
			struct relay_index_file, ref);

	ret = fs_handle_close(index_file->handle);
	if (ret < 0) {
		PERROR("Failed to close index file");
	}
	free(index_file);
}

void relay_index_file_put(struct relay_index_file *index_file)
{
	urcu_ref_put(&index_file->ref, relay_index_file_release);
}
