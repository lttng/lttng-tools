/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_TRACE_CHUNK_H
#define LTTNG_TRACE_CHUNK_H

#include <common/macros.h>
#include <common/credentials.h>
#include <common/compat/directory-handle.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

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

enum lttng_trace_chunk_status {
        LTTNG_TRACE_CHUNK_STATUS_OK,
	LTTNG_TRACE_CHUNK_STATUS_NONE,
	LTTNG_TRACE_CHUNK_STATUS_INVALID_ARGUMENT,
	LTTNG_TRACE_CHUNK_STATUS_INVALID_OPERATION,
	LTTNG_TRACE_CHUNK_STATUS_ERROR,
};

enum lttng_trace_chunk_command_type {
	LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED = 0,
	LTTNG_TRACE_CHUNK_COMMAND_TYPE_MAX
};

LTTNG_HIDDEN
struct lttng_trace_chunk *lttng_trace_chunk_create_anonymous(void);

LTTNG_HIDDEN
struct lttng_trace_chunk *lttng_trace_chunk_create(
		uint64_t chunk_id,
		time_t chunk_creation_time);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_id(
		struct lttng_trace_chunk *chunk, uint64_t *id);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_creation_timestamp(
		struct lttng_trace_chunk *chunk, time_t *creation_ts);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_close_timestamp(
		struct lttng_trace_chunk *chunk, time_t *close_ts);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_close_timestamp(
		struct lttng_trace_chunk *chunk, time_t close_ts);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_name(
		struct lttng_trace_chunk *chunk, const char **name,
		bool *name_overriden);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_override_name(
		struct lttng_trace_chunk *chunk, const char *name);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_credentials(
		struct lttng_trace_chunk *chunk,
		struct lttng_credentials *credentials);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_credentials(
		struct lttng_trace_chunk *chunk,
		const struct lttng_credentials *credentials);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_credentials_current_user(
		struct lttng_trace_chunk *chunk);

/* session_output_directory ownership is transferred to the chunk on success. */
LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_as_owner(
		struct lttng_trace_chunk *chunk,
		struct lttng_directory_handle *session_output_directory);

/* chunk_output_directory ownership is transferred to the chunk on success. */
LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_as_user(
		struct lttng_trace_chunk *chunk,
		struct lttng_directory_handle *chunk_directory);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_chunk_directory_handle(
		struct lttng_trace_chunk *chunk,
		const struct lttng_directory_handle **handle);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_create_subdirectory(
		struct lttng_trace_chunk *chunk,
		const char *subdirectory_path);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_open_file(
		struct lttng_trace_chunk *chunk, const char *filename,
		int flags, mode_t mode, int *out_fd);

LTTNG_HIDDEN
int lttng_trace_chunk_unlink_file(struct lttng_trace_chunk *chunk,
		const char *filename);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_close_command(
		struct lttng_trace_chunk *chunk,
		enum lttng_trace_chunk_command_type *command_type);

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_close_command(
		struct lttng_trace_chunk *chunk,
		enum lttng_trace_chunk_command_type command_type);

LTTNG_HIDDEN
const char *lttng_trace_chunk_command_type_get_name(
		enum lttng_trace_chunk_command_type command);

/* Returns true on success. */
LTTNG_HIDDEN
bool lttng_trace_chunk_get(struct lttng_trace_chunk *chunk);

LTTNG_HIDDEN
void lttng_trace_chunk_put(struct lttng_trace_chunk *chunk);

#endif /* LTTNG_TRACE_CHUNK_H */
