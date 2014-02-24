/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      David Goulet <dgoulet@efficios.com>
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

#define _GNU_SOURCE
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <common/common.h>
#include <common/defaults.h>
#include <common/utils.h>

#include "index.h"

/*
 * Create the index file associated with a trace file.
 *
 * Return fd on success, a negative value on error.
 */
int index_create_file(char *path_name, char *stream_name, int uid, int gid,
		uint64_t size, uint64_t count)
{
	int ret, fd = -1;
	ssize_t size_ret;
	struct ctf_packet_index_file_hdr hdr;
	char fullpath[PATH_MAX];

	ret = snprintf(fullpath, sizeof(fullpath), "%s/" DEFAULT_INDEX_DIR,
			path_name);
	if (ret < 0) {
		PERROR("snprintf index path");
		goto error;
	}

	/* Create index directory if necessary. */
	ret = run_as_mkdir(fullpath, S_IRWXU | S_IRWXG, uid, gid);
	if (ret < 0) {
		if (ret != -EEXIST) {
			PERROR("Index trace directory creation error");
			goto error;
		}
	}

	ret = utils_create_stream_file(fullpath, stream_name, size, count, uid,
			gid, DEFAULT_INDEX_FILE_SUFFIX);
	if (ret < 0) {
		goto error;
	}
	fd = ret;

	hdr.magic = htobe32(CTF_INDEX_MAGIC);
	hdr.index_major = htobe32(CTF_INDEX_MAJOR);
	hdr.index_minor = htobe32(CTF_INDEX_MINOR);
	hdr.packet_index_len = htobe32(sizeof(struct ctf_packet_index));

	size_ret = lttng_write(fd, &hdr, sizeof(hdr));
	if (size_ret < sizeof(hdr)) {
		PERROR("write index header");
		ret = -1;
		goto error;
	}

	return fd;

error:
	if (fd >= 0) {
		int close_ret;

		close_ret = close(fd);
		if (close_ret < 0) {
			PERROR("close index fd");
		}
	}
	return ret;
}

/*
 * Write index values to the given fd of size len.
 *
 * Return "len" on success or else < len on error. errno contains error
 * details.
 */
ssize_t index_write(int fd, struct ctf_packet_index *index, size_t len)
{
	ssize_t ret;

	assert(index);

	if (fd < 0) {
		ret = -EINVAL;
		goto error;
	}

	ret = lttng_write(fd, index, len);
	if (ret < len) {
		PERROR("writing index file");
	}

error:
	return ret;
}

/*
 * Open index file using a given path, channel name and tracefile count.
 *
 * Return read only FD on success or else a negative value.
 */
int index_open(const char *path_name, const char *channel_name,
		uint64_t tracefile_count, uint64_t tracefile_count_current)
{
	int ret, read_fd;
	ssize_t read_len;
	char fullpath[PATH_MAX];
	struct ctf_packet_index_file_hdr hdr;

	assert(path_name);
	assert(channel_name);

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
		if (errno == ENOENT) {
			ret = -ENOENT;
		} else {
			PERROR("opening index in read-only");
		}
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
	if (be32toh(hdr.index_major) != CTF_INDEX_MAJOR ||
			be32toh(hdr.index_minor) != CTF_INDEX_MINOR) {
		ERR("Invalid header version");
		goto error_close;
	}

	return read_fd;

error_close:
	if (read_fd >= 0) {
		int close_ret;

		close_ret = close(read_fd);
		if (close_ret < 0) {
			PERROR("close read fd %d", read_fd);
		}
	}
	ret = -1;

error:
	return ret;
}
