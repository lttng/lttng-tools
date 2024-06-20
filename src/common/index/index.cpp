/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "index.hpp"

#include <common/common.hpp>
#include <common/compat/endian.hpp>
#include <common/defaults.hpp>
#include <common/utils.hpp>

#include <lttng/constant.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#define WRITE_FILE_FLAGS     (O_WRONLY | O_CREAT | O_TRUNC)
#define READ_ONLY_FILE_FLAGS O_RDONLY

static enum lttng_trace_chunk_status
_lttng_index_file_create_from_trace_chunk(struct lttng_trace_chunk *chunk,
					  const char *channel_path,
					  const char *stream_name,
					  uint64_t stream_file_size,
					  uint64_t stream_file_index,
					  uint32_t index_major,
					  uint32_t index_minor,
					  bool unlink_existing_file,
					  int flags,
					  bool expect_no_file,
					  struct lttng_index_file **file)
{
	struct lttng_index_file *index_file;
	enum lttng_trace_chunk_status chunk_status;
	int ret;
	struct fs_handle *fs_handle = nullptr;
	ssize_t size_ret;
	struct ctf_packet_index_file_hdr hdr;
	char index_directory_path[LTTNG_PATH_MAX];
	char index_file_path[LTTNG_PATH_MAX];
	const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
	const bool acquired_reference = lttng_trace_chunk_get(chunk);
	const char *separator;

	LTTNG_ASSERT(acquired_reference);

	index_file = zmalloc<lttng_index_file>();
	if (!index_file) {
		PERROR("Failed to allocate lttng_index_file");
		chunk_status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto error;
	}

	index_file->trace_chunk = chunk;
	if (channel_path[0] == '\0') {
		separator = "";
	} else {
		separator = "/";
	}
	ret = snprintf(index_directory_path,
		       sizeof(index_directory_path),
		       "%s%s" DEFAULT_INDEX_DIR,
		       channel_path,
		       separator);
	if (ret < 0 || ret >= sizeof(index_directory_path)) {
		ERR("Failed to format index directory path");
		chunk_status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto error;
	}

	ret = utils_stream_file_path(index_directory_path,
				     stream_name,
				     stream_file_size,
				     stream_file_index,
				     DEFAULT_INDEX_FILE_SUFFIX,
				     index_file_path,
				     sizeof(index_file_path));
	if (ret) {
		chunk_status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto error;
	}

	if (unlink_existing_file) {
		/*
		 * For tracefile rotation. We need to unlink the old
		 * file if present to synchronize with the tail of the
		 * live viewer which could be working on this same file.
		 * By doing so, any reference to the old index file
		 * stays valid even if we re-create a new file with the
		 * same name afterwards.
		 */
		chunk_status = (lttng_trace_chunk_status) lttng_trace_chunk_unlink_file(
			chunk, index_file_path);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK &&
		    (chunk_status != LTTNG_TRACE_CHUNK_STATUS_ERROR || errno != ENOENT)) {
			goto error;
		}
	}

	chunk_status = lttng_trace_chunk_open_fs_handle(
		chunk, index_file_path, flags, mode, &fs_handle, expect_no_file);
	if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		goto error;
	}

	if (flags == WRITE_FILE_FLAGS) {
		ctf_packet_index_file_hdr_init(&hdr, index_major, index_minor);
		size_ret = fs_handle_write(fs_handle, &hdr, sizeof(hdr));
		if (size_ret < sizeof(hdr)) {
			PERROR("Failed to write index header");
			chunk_status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto error;
		}
		index_file->element_len = ctf_packet_index_len(index_major, index_minor);
	} else {
		uint32_t element_len;

		size_ret = fs_handle_read(fs_handle, &hdr, sizeof(hdr));
		if (size_ret < 0) {
			PERROR("Failed to read index header");
			chunk_status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto error;
		}
		if (be32toh(hdr.magic) != CTF_INDEX_MAGIC) {
			ERR("Invalid header magic");
			chunk_status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto error;
		}
		if (index_major != be32toh(hdr.index_major)) {
			ERR("Index major number mismatch: %u, expect %u",
			    be32toh(hdr.index_major),
			    index_major);
			chunk_status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto error;
		}
		if (index_minor != be32toh(hdr.index_minor)) {
			ERR("Index minor number mismatch: %u, expect %u",
			    be32toh(hdr.index_minor),
			    index_minor);
			chunk_status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto error;
		}
		element_len = be32toh(hdr.packet_index_len);
		if (element_len > sizeof(struct ctf_packet_index)) {
			ERR("Index element length too long");
			chunk_status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto error;
		}
		index_file->element_len = element_len;
	}
	index_file->file = fs_handle;
	index_file->major = index_major;
	index_file->minor = index_minor;
	urcu_ref_init(&index_file->ref);

	*file = index_file;
	return LTTNG_TRACE_CHUNK_STATUS_OK;

error:
	if (fs_handle) {
		ret = fs_handle_close(fs_handle);
		if (ret < 0) {
			PERROR("Failed to close file descriptor of index file");
		}
	}
	lttng_trace_chunk_put(chunk);
	free(index_file);
	return chunk_status;
}

enum lttng_trace_chunk_status
lttng_index_file_create_from_trace_chunk(struct lttng_trace_chunk *chunk,
					 const char *channel_path,
					 const char *stream_name,
					 uint64_t stream_file_size,
					 uint64_t stream_file_index,
					 uint32_t index_major,
					 uint32_t index_minor,
					 bool unlink_existing_file,
					 struct lttng_index_file **file)
{
	return _lttng_index_file_create_from_trace_chunk(chunk,
							 channel_path,
							 stream_name,
							 stream_file_size,
							 stream_file_index,
							 index_major,
							 index_minor,
							 unlink_existing_file,
							 WRITE_FILE_FLAGS,
							 false,
							 file);
}

enum lttng_trace_chunk_status
lttng_index_file_create_from_trace_chunk_read_only(struct lttng_trace_chunk *chunk,
						   const char *channel_path,
						   const char *stream_name,
						   uint64_t stream_file_size,
						   uint64_t stream_file_index,
						   uint32_t index_major,
						   uint32_t index_minor,
						   bool expect_no_file,
						   struct lttng_index_file **file)
{
	return _lttng_index_file_create_from_trace_chunk(chunk,
							 channel_path,
							 stream_name,
							 stream_file_size,
							 stream_file_index,
							 index_major,
							 index_minor,
							 false,
							 READ_ONLY_FILE_FLAGS,
							 expect_no_file,
							 file);
}

/*
 * Write index values to the given index file.
 *
 * Return 0 on success, -1 on error.
 */
int lttng_index_file_write(const struct lttng_index_file *index_file,
			   const struct ctf_packet_index *element)
{
	ssize_t ret;
	const size_t len = index_file->element_len;
	;

	LTTNG_ASSERT(index_file);
	LTTNG_ASSERT(element);

	if (!index_file->file) {
		goto error;
	}

	ret = fs_handle_write(index_file->file, element, len);
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
	const size_t len = index_file->element_len;

	LTTNG_ASSERT(element);

	if (!index_file->file) {
		goto error;
	}

	ret = fs_handle_read(index_file->file, element, len);
	if (ret < 0) {
		PERROR("read index file");
		goto error;
	}
	if (ret < len) {
		ERR("lttng_read expected %zu, returned %zd", len, ret);
		goto error;
	}
	return 0;

error:
	return -1;
}

void lttng_index_file_get(struct lttng_index_file *index_file)
{
	urcu_ref_get(&index_file->ref);
}

static void lttng_index_file_release(struct urcu_ref *ref)
{
	struct lttng_index_file *index_file = caa_container_of(ref, struct lttng_index_file, ref);

	if (fs_handle_close(index_file->file)) {
		PERROR("close index fd");
	}
	lttng_trace_chunk_put(index_file->trace_chunk);
	free(index_file);
}

void lttng_index_file_put(struct lttng_index_file *index_file)
{
	urcu_ref_put(&index_file->ref, lttng_index_file_release);
}
