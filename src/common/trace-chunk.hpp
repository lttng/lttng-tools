/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_TRACE_CHUNK_H
#define LTTNG_TRACE_CHUNK_H

#include <common/compat/directory-handle.hpp>
#include <common/credentials.hpp>
#include <common/fd-tracker/fd-tracker.hpp>
#include <common/macros.hpp>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * A trace chunk is a group of directories and files forming a (or a set of)
 * complete and independant trace(s). For instance, a trace archive chunk,
 * a snapshot, or a regular LTTng trace are all instances of a trace archive.
 *
 * A trace chunk is always contained within a session output directory.
 *
 * This facility is used by the session daemon, consumer daemon(s), and relay
 * daemon to:
 *   - Control file (data stream, metadata, and index) creation relative to
 *     a given output directory,
 *   - Track the use of an output directory by other objects in order to
 *     know if/when an output directory can be safely consumed, renamed,
 *     deleted, etc.
 *
 *
 * OWNER VS USER
 * ---
 *
 * A trace chunk can either be a owner or a user of its
 * "chunk output directory".
 *
 * A "user" trace chunk is provided with a handle to the chunk output directory
 * which can then be used to create subdirectories and files.
 *
 * An "owner" chunk, on top of being able to perform the operations of a "user"
 * chunk can perform operations on its chunk output directory, such as renaming
 * or deleting it.
 *
 * A trace chunk becomes an "owner" or "user" chunk based on which of
 * 'lttng_trace_chunk_set_as_owner()' or 'lttng_trace_chunk_set_as_user()' is
 * used. These methods are _exclusive_ and must only be used once on a
 * trace chunk.
 */

struct lttng_trace_chunk;
struct fd_tracker;

enum lttng_trace_chunk_status {
	LTTNG_TRACE_CHUNK_STATUS_OK,
	LTTNG_TRACE_CHUNK_STATUS_NONE,
	LTTNG_TRACE_CHUNK_STATUS_INVALID_ARGUMENT,
	LTTNG_TRACE_CHUNK_STATUS_INVALID_OPERATION,
	LTTNG_TRACE_CHUNK_STATUS_ERROR,
	LTTNG_TRACE_CHUNK_STATUS_NO_FILE,
};

enum lttng_trace_chunk_command_type {
	LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED = 0,
	LTTNG_TRACE_CHUNK_COMMAND_TYPE_NO_OPERATION = 1,
	LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE = 2,
	LTTNG_TRACE_CHUNK_COMMAND_TYPE_MAX,
};

struct lttng_trace_chunk *lttng_trace_chunk_create_anonymous();

struct lttng_trace_chunk *
lttng_trace_chunk_create(uint64_t chunk_id, time_t chunk_creation_time, const char *path);

void lttng_trace_chunk_set_fd_tracker(struct lttng_trace_chunk *chunk,
				      struct fd_tracker *fd_tracker);

/*
 * Copy a trace chunk. The copy that is returned is always a _user_
 * mode chunk even if the source chunk was an _owner_ as there can never be
 * two _owners_ of the same trace output.
 */
struct lttng_trace_chunk *lttng_trace_chunk_copy(struct lttng_trace_chunk *source_chunk);

enum lttng_trace_chunk_status lttng_trace_chunk_get_id(struct lttng_trace_chunk *chunk,
						       uint64_t *id);

enum lttng_trace_chunk_status
lttng_trace_chunk_get_creation_timestamp(struct lttng_trace_chunk *chunk, time_t *creation_ts);

enum lttng_trace_chunk_status lttng_trace_chunk_get_close_timestamp(struct lttng_trace_chunk *chunk,
								    time_t *close_ts);

enum lttng_trace_chunk_status lttng_trace_chunk_set_close_timestamp(struct lttng_trace_chunk *chunk,
								    time_t close_ts);

enum lttng_trace_chunk_status lttng_trace_chunk_get_name(struct lttng_trace_chunk *chunk,
							 const char **name,
							 bool *name_overridden);

bool lttng_trace_chunk_get_name_overridden(struct lttng_trace_chunk *chunk);

enum lttng_trace_chunk_status lttng_trace_chunk_override_name(struct lttng_trace_chunk *chunk,
							      const char *name);

enum lttng_trace_chunk_status lttng_trace_chunk_rename_path(struct lttng_trace_chunk *chunk,
							    const char *path);

enum lttng_trace_chunk_status
lttng_trace_chunk_get_credentials(struct lttng_trace_chunk *chunk,
				  struct lttng_credentials *credentials);

enum lttng_trace_chunk_status
lttng_trace_chunk_set_credentials(struct lttng_trace_chunk *chunk,
				  const struct lttng_credentials *credentials);

enum lttng_trace_chunk_status
lttng_trace_chunk_set_credentials_current_user(struct lttng_trace_chunk *chunk);

enum lttng_trace_chunk_status
lttng_trace_chunk_set_as_owner(struct lttng_trace_chunk *chunk,
			       struct lttng_directory_handle *session_output_directory);

enum lttng_trace_chunk_status
lttng_trace_chunk_set_as_user(struct lttng_trace_chunk *chunk,
			      struct lttng_directory_handle *chunk_directory);

enum lttng_trace_chunk_status
lttng_trace_chunk_get_session_output_directory_handle(struct lttng_trace_chunk *chunk,
						      struct lttng_directory_handle **handle);

enum lttng_trace_chunk_status
lttng_trace_chunk_borrow_chunk_directory_handle(struct lttng_trace_chunk *chunk,
						const struct lttng_directory_handle **handle);

enum lttng_trace_chunk_status lttng_trace_chunk_create_subdirectory(struct lttng_trace_chunk *chunk,
								    const char *subdirectory_path);

enum lttng_trace_chunk_status lttng_trace_chunk_open_file(struct lttng_trace_chunk *chunk,
							  const char *filename,
							  int flags,
							  mode_t mode,
							  int *out_fd,
							  bool expect_no_file);

enum lttng_trace_chunk_status lttng_trace_chunk_open_fs_handle(struct lttng_trace_chunk *chunk,
							       const char *filename,
							       int flags,
							       mode_t mode,
							       struct fs_handle **out_handle,
							       bool expect_no_file);

int lttng_trace_chunk_unlink_file(struct lttng_trace_chunk *chunk, const char *filename);

enum lttng_trace_chunk_status
lttng_trace_chunk_get_close_command(struct lttng_trace_chunk *chunk,
				    enum lttng_trace_chunk_command_type *command_type);

enum lttng_trace_chunk_status
lttng_trace_chunk_set_close_command(struct lttng_trace_chunk *chunk,
				    enum lttng_trace_chunk_command_type command_type);

const char *lttng_trace_chunk_command_type_get_name(enum lttng_trace_chunk_command_type command);

bool lttng_trace_chunk_ids_equal(const struct lttng_trace_chunk *chunk_a,
				 const struct lttng_trace_chunk *chunk_b);

/* Returns true on success. */
bool lttng_trace_chunk_get(struct lttng_trace_chunk *chunk);

void lttng_trace_chunk_put(struct lttng_trace_chunk *chunk);

#endif /* LTTNG_TRACE_CHUNK_H */
