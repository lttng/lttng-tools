/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
 *               2016 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#define _LGPL_SOURCE
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/compat/endian.h>
#include <common/utils.h>

#include "index.h"

/*
 * Create the index file associated with a trace file.
 *
 * Return allocated struct lttng_index_file, NULL on error.
 */
struct lttng_index_file *lttng_index_file_create(char *path_name,
		char *stream_name, int uid, int gid,
		uint64_t size, uint64_t count, uint32_t major, uint32_t minor)
{
	struct lttng_index_file *index_file;
	int ret, fd = -1;
	ssize_t size_ret;
	struct ctf_packet_index_file_hdr hdr;
	char fullpath[PATH_MAX];
	uint32_t element_len = ctf_packet_index_len(major, minor);

	index_file = zmalloc(sizeof(*index_file));
	if (!index_file) {
		PERROR("allocating lttng_index_file");
		goto error;
	}

	ret = snprintf(fullpath, sizeof(fullpath), "%s/" DEFAULT_INDEX_DIR,
			path_name);
	if (ret < 0) {
		PERROR("snprintf index path");
		goto error;
	}

	/* Create index directory if necessary. */
	ret = utils_mkdir(fullpath, S_IRWXU | S_IRWXG, uid, gid);
	if (ret < 0) {
		if (errno != EEXIST) {
			PERROR("Index trace directory creation error");
			goto error;
		}
	}

	/*
	 * For tracefile rotation. We need to unlink the old
	 * file if present to synchronize with the tail of the
	 * live viewer which could be working on this same file.
	 * By doing so, any reference to the old index file
	 * stays valid even if we re-create a new file with the
	 * same name afterwards.
	 */
	ret = utils_unlink_stream_file(fullpath, stream_name, size, count, uid,
			gid, DEFAULT_INDEX_FILE_SUFFIX);
	if (ret < 0 && errno != ENOENT) {
		goto error;
	}
	ret = utils_create_stream_file(fullpath, stream_name, size, count, uid,
			gid, DEFAULT_INDEX_FILE_SUFFIX);
	if (ret < 0) {
		goto error;
	}
	fd = ret;

	hdr.magic = htobe32(CTF_INDEX_MAGIC);
	hdr.index_major = htobe32(major);
	hdr.index_minor = htobe32(minor);
	hdr.packet_index_len = htobe32(element_len);

	size_ret = lttng_write(fd, &hdr, sizeof(hdr));
	if (size_ret < sizeof(hdr)) {
		PERROR("write index header");
		goto error;
	}
	index_file->fd = fd;
	index_file->major = major;
	index_file->minor = minor;
	index_file->element_len = element_len;
	urcu_ref_init(&index_file->ref);

	return index_file;

error:
	if (fd >= 0) {
		int close_ret;

		close_ret = close(fd);
		if (close_ret < 0) {
			PERROR("close index fd");
		}
	}
	free(index_file);
	return NULL;
}

/*
 * Write index values to the given index file.
 *
 * Return 0 on success, -1 on error.
 */
int lttng_index_file_write(const struct lttng_index_file *index_file,
		const struct ctf_packet_index *element)
{
	int fd;
	size_t len;
	ssize_t ret;

	assert(index_file);
	assert(element);

	fd = index_file->fd;
	len = index_file->element_len;

	if (fd < 0) {
		goto error;
	}

	ret = lttng_write(fd, element, len);
	if (ret < len) {
		PERROR("writing index file");
		goto error;
	}
	return 0;

error:
	return -1;
}

/*
 * Read index values from the given index file.
 *
 * Return 0 on success, -1 on error.
 */
int lttng_index_file_read(const struct lttng_index_file *index_file,
		struct ctf_packet_index *element)
{
	ssize_t ret;
	int fd = index_file->fd;
	size_t len = index_file->element_len;

	assert(element);

	if (fd < 0) {
		goto error;
	}

	ret = lttng_read(fd, element, len);
	if (ret < len) {
		PERROR("read index file");
		goto error;
	}
	return 0;

error:
	return -1;
}

/*
 * Open index file using a given path, channel name and tracefile count.
 *
 * Return allocated struct lttng_index_file, NULL on error.
 */
struct lttng_index_file *lttng_index_file_open(const char *path_name,
		const char *channel_name, uint64_t tracefile_count,
		uint64_t tracefile_count_current)
{
	struct lttng_index_file *index_file;
	int ret, read_fd;
	ssize_t read_len;
	char fullpath[PATH_MAX];
	struct ctf_packet_index_file_hdr hdr;
	uint32_t major, minor, element_len;

	assert(path_name);
	assert(channel_name);

	index_file = zmalloc(sizeof(*index_file));
	if (!index_file) {
		PERROR("allocating lttng_index_file");
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
		PERROR("snprintf index path");
		goto error;
	}

	DBG("Index opening file %s in read only", fullpath);
	read_fd = open(fullpath, O_RDONLY);
	if (read_fd < 0) {
		PERROR("opening index in read-only");
		goto error;
	}

	read_len = lttng_read(read_fd, &hdr, sizeof(hdr));
	if (read_len < 0) {
		PERROR("Reading index header");
		goto error_close;
	}

	if (be32toh(hdr.magic) != CTF_INDEX_MAGIC) {
		ERR("Invalid header magic");
		goto error_close;
	}
	major = be32toh(hdr.index_major);
	minor = be32toh(hdr.index_minor);
	element_len = be32toh(hdr.packet_index_len);

	if (major != CTF_INDEX_MAJOR) {
		ERR("Invalid header version");
		goto error_close;
	}
	if (element_len > sizeof(struct ctf_packet_index)) {
		ERR("Index element length too long");
		goto error_close;
	}

	index_file->fd = read_fd;
	index_file->major = major;
	index_file->minor = minor;
	index_file->element_len = element_len;
	urcu_ref_init(&index_file->ref);

	return index_file;

error_close:
	if (read_fd >= 0) {
		int close_ret;

		close_ret = close(read_fd);
		if (close_ret < 0) {
			PERROR("close read fd %d", read_fd);
		}
	}

error:
	free(index_file);
	return NULL;
}

void lttng_index_file_get(struct lttng_index_file *index_file)
{
	urcu_ref_get(&index_file->ref);
}

static void lttng_index_file_release(struct urcu_ref *ref)
{
	struct lttng_index_file *index_file = caa_container_of(ref,
			struct lttng_index_file, ref);

	if (close(index_file->fd)) {
		PERROR("close index fd");
	}
	free(index_file);
}

void lttng_index_file_put(struct lttng_index_file *index_file)
{
	urcu_ref_put(&index_file->ref, lttng_index_file_release);
}
