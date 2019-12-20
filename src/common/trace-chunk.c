/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <common/compat/directory-handle.h>
#include <common/credentials.h>
#include <common/defaults.h>
#include <common/dynamic-array.h>
#include <common/error.h>
#include <common/fd-tracker/fd-tracker.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <common/optional.h>
#include <common/string-utils/format.h>
#include <common/time.h>
#include <common/trace-chunk-registry.h>
#include <common/trace-chunk.h>
#include <common/utils.h>
#include <lttng/constant.h>

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/stat.h>
#include <urcu/rculfhash.h>
#include <urcu/ref.h>

/*
 * Two ISO 8601-compatible timestamps, separated by a hypen, followed an
 * index, i.e. <start-iso-8601>-<end-iso-8601>-<id-uint64_t>.
 */
#define GENERATED_CHUNK_NAME_LEN (2 * sizeof("YYYYmmddTHHMMSS+HHMM") + MAX_INT_DEC_LEN(uint64_t))
#define DIR_CREATION_MODE (S_IRWXU | S_IRWXG)

enum trace_chunk_mode {
	TRACE_CHUNK_MODE_USER,
	TRACE_CHUNK_MODE_OWNER,
};

/*
 * Callback to invoke on release of a trace chunk. Note that there is no
 * need to 'lock' the trace chunk during the execution of these callbacks
 * since only one thread may access a chunk during its destruction (the last
 * to release its reference to the chunk).
 */
typedef int (*chunk_command)(struct lttng_trace_chunk *trace_chunk);

/* Move a completed trace chunk to the 'completed' trace archive folder. */
static
int lttng_trace_chunk_move_to_completed_post_release(struct lttng_trace_chunk *trace_chunk);
/* Empty callback. */
static
int lttng_trace_chunk_no_operation(struct lttng_trace_chunk *trace_chunk);
/* Unlink old chunk files. */
static
int lttng_trace_chunk_delete_post_release(struct lttng_trace_chunk *trace_chunk);
static
enum lttng_trace_chunk_status lttng_trace_chunk_rename_path_no_lock(
		struct lttng_trace_chunk *chunk, const char *path);

struct chunk_credentials {
	bool use_current_user;
	struct lttng_credentials user;
};

/*
 * NOTE: Make sure to update:
 * - lttng_trace_chunk_copy(),
 * - lttng_trace_chunk_registry_element_create_from_chunk()
 * if you modify this structure.
 */
struct lttng_trace_chunk {
	pthread_mutex_t lock;
	struct urcu_ref ref;
	LTTNG_OPTIONAL(enum trace_chunk_mode) mode;
	/*
	 * First-level directories created within the trace chunk.
	 * Elements are of type 'char *'.
	 *
	 * Only used by _owner_ mode chunks.
	 */
	struct lttng_dynamic_pointer_array top_level_directories;
	/*
	 * All files contained within the trace chunk.
	 * Array of paths (char *).
	 */
	struct lttng_dynamic_pointer_array files;
	/* Is contained within an lttng_trace_chunk_registry_element? */
	bool in_registry_element;
	bool name_overridden;
	char *name;
	char *path;
	/* An unset id means the chunk is anonymous. */
	LTTNG_OPTIONAL(uint64_t) id;
	LTTNG_OPTIONAL(time_t) timestamp_creation;
	LTTNG_OPTIONAL(time_t) timestamp_close;
	LTTNG_OPTIONAL(struct chunk_credentials) credentials;
	struct lttng_directory_handle *session_output_directory;
	struct lttng_directory_handle *chunk_directory;
	LTTNG_OPTIONAL(enum lttng_trace_chunk_command_type) close_command;
	/*
	 * fd_tracker instance through which file descriptors should be
	 * created/closed.
	 *
	 * An fd_tracker always outlives any trace chunk; there is no
	 * need to perform any reference counting of that object.
	 */
	struct fd_tracker *fd_tracker;
};

/* A trace chunk is uniquely identified by its (session id, chunk id) tuple. */
struct lttng_trace_chunk_registry_element {
	struct lttng_trace_chunk chunk;
	uint64_t session_id;
	/* Weak and only set when added. */
	struct lttng_trace_chunk_registry *registry;
	struct cds_lfht_node trace_chunk_registry_ht_node;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

struct lttng_trace_chunk_registry {
	struct cds_lfht *ht;
};

static const
char *close_command_names[] = {
	[LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED] =
		"move to completed chunk folder",
	[LTTNG_TRACE_CHUNK_COMMAND_TYPE_NO_OPERATION] =
		"no operation",
	[LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE] =
		"delete",
};

static const
chunk_command close_command_post_release_funcs[] = {
	[LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED] =
			lttng_trace_chunk_move_to_completed_post_release,
	[LTTNG_TRACE_CHUNK_COMMAND_TYPE_NO_OPERATION] =
			lttng_trace_chunk_no_operation,
	[LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE] =
			lttng_trace_chunk_delete_post_release,
};

static
bool lttng_trace_chunk_registry_element_equals(
		const struct lttng_trace_chunk_registry_element *a,
		const struct lttng_trace_chunk_registry_element *b)
{
	if (a->session_id != b->session_id) {
		goto not_equal;
	}
	if (a->chunk.id.is_set != b->chunk.id.is_set) {
		goto not_equal;
	}
	if (a->chunk.id.is_set && a->chunk.id.value != b->chunk.id.value) {
		goto not_equal;
	}
	return true;
not_equal:
	return false;
}

static
int lttng_trace_chunk_registry_element_match(struct cds_lfht_node *node,
		const void *key)
{
	const struct lttng_trace_chunk_registry_element *element_a, *element_b;

	element_a = (const struct lttng_trace_chunk_registry_element *) key;
	element_b = caa_container_of(node, typeof(*element_b),
			trace_chunk_registry_ht_node);
	return lttng_trace_chunk_registry_element_equals(element_a, element_b);
}

static
unsigned long lttng_trace_chunk_registry_element_hash(
		const struct lttng_trace_chunk_registry_element *element)
{
	unsigned long hash = hash_key_u64(&element->session_id,
			lttng_ht_seed);

	if (element->chunk.id.is_set) {
		hash ^= hash_key_u64(&element->chunk.id.value, lttng_ht_seed);
	}

	return hash;
}

static
char *generate_chunk_name(uint64_t chunk_id, time_t creation_timestamp,
		const time_t *close_timestamp)
{
	int ret = 0;
	char *new_name= NULL;
	char start_datetime[ISO8601_STR_LEN] = {};
	/* Add 1 for a '-' prefix. */
	char end_datetime_suffix[ISO8601_STR_LEN + 1] = {};

	ret = time_to_iso8601_str(
			creation_timestamp,
			start_datetime, sizeof(start_datetime));
	if (ret) {
		ERR("Failed to format trace chunk start date time");
		goto error;
	}
	if (close_timestamp) {
		*end_datetime_suffix = '-';
		ret = time_to_iso8601_str(
				*close_timestamp,
				end_datetime_suffix + 1,
				sizeof(end_datetime_suffix) - 1);
		if (ret) {
			ERR("Failed to format trace chunk end date time");
			goto error;
		}
	}
	new_name = zmalloc(GENERATED_CHUNK_NAME_LEN);
	if (!new_name) {
		ERR("Failed to allocate buffer for automatically-generated trace chunk name");
		goto error;
	}
	ret = snprintf(new_name, GENERATED_CHUNK_NAME_LEN, "%s%s-%" PRIu64,
			start_datetime, end_datetime_suffix, chunk_id);
	if (ret >= GENERATED_CHUNK_NAME_LEN || ret == -1) {
		ERR("Failed to format trace chunk name");
		goto error;
	}

	return new_name;
error:
	free(new_name);
	return NULL;
}

static
void lttng_trace_chunk_init(struct lttng_trace_chunk *chunk)
{
	urcu_ref_init(&chunk->ref);
	pthread_mutex_init(&chunk->lock, NULL);
	lttng_dynamic_pointer_array_init(&chunk->top_level_directories, free);
	lttng_dynamic_pointer_array_init(&chunk->files, free);
}

static
void lttng_trace_chunk_fini(struct lttng_trace_chunk *chunk)
{
	if (chunk->session_output_directory) {
		lttng_directory_handle_put(
				chunk->session_output_directory);
		chunk->session_output_directory = NULL;
	}
	if (chunk->chunk_directory) {
		lttng_directory_handle_put(chunk->chunk_directory);
	        chunk->chunk_directory = NULL;
	}
	free(chunk->name);
	chunk->name = NULL;
	free(chunk->path);
	chunk->path = NULL;
	lttng_dynamic_pointer_array_reset(&chunk->top_level_directories);
	lttng_dynamic_pointer_array_reset(&chunk->files);
	pthread_mutex_destroy(&chunk->lock);
}

static
struct lttng_trace_chunk *lttng_trace_chunk_allocate(void)
{
	struct lttng_trace_chunk *chunk = NULL;

	chunk = zmalloc(sizeof(*chunk));
	if (!chunk) {
		ERR("Failed to allocate trace chunk");
		goto end;
	}
	lttng_trace_chunk_init(chunk);
end:
	return chunk;
}

LTTNG_HIDDEN
struct lttng_trace_chunk *lttng_trace_chunk_create_anonymous(void)
{
	DBG("Creating anonymous trace chunk");
	return lttng_trace_chunk_allocate();
}

LTTNG_HIDDEN
struct lttng_trace_chunk *lttng_trace_chunk_create(
		uint64_t chunk_id, time_t chunk_creation_time, const char *path)
{
	struct lttng_trace_chunk *chunk;
        char chunk_creation_datetime_buf[16] = {};
	const char *chunk_creation_datetime_str = "(formatting error)";
        struct tm timeinfo_buf, *timeinfo;

	timeinfo = localtime_r(&chunk_creation_time, &timeinfo_buf);
	if (timeinfo) {
		size_t strftime_ret;

		/* Don't fail because of this; it is only used for logging. */
		strftime_ret = strftime(chunk_creation_datetime_buf,
				sizeof(chunk_creation_datetime_buf),
				"%Y%m%d-%H%M%S", timeinfo);
		if (strftime_ret) {
			chunk_creation_datetime_str =
					chunk_creation_datetime_buf;
		}
	}

	DBG("Creating trace chunk: chunk_id = %" PRIu64 ", creation time = %s",
			chunk_id, chunk_creation_datetime_str);
	chunk = lttng_trace_chunk_allocate();
	if (!chunk) {
		goto end;
	}

	LTTNG_OPTIONAL_SET(&chunk->id, chunk_id);
	LTTNG_OPTIONAL_SET(&chunk->timestamp_creation, chunk_creation_time);
	if (chunk_id != 0) {
		chunk->name = generate_chunk_name(chunk_id,
				chunk_creation_time, NULL);
		if (!chunk->name) {
			ERR("Failed to allocate trace chunk name storage");
			goto error;
		}
        }
	if (path) {
		chunk->path = strdup(path);
		if (!chunk->path) {
			goto error;
		}
	} else {
		if (chunk->name) {
			chunk->path = strdup(chunk->name);
			if (!chunk->path) {
				goto error;
			}
		}
	}

        DBG("Chunk name set to \"%s\"", chunk->name ? : "(none)");
end:
	return chunk;
error:
	lttng_trace_chunk_put(chunk);
	return NULL;
}

LTTNG_HIDDEN
void lttng_trace_chunk_set_fd_tracker(struct lttng_trace_chunk *chunk,
		struct fd_tracker *fd_tracker)
{
	assert(!chunk->session_output_directory);
	assert(!chunk->chunk_directory);
	assert(lttng_dynamic_pointer_array_get_count(&chunk->files) == 0);
	chunk->fd_tracker = fd_tracker;
}

LTTNG_HIDDEN
struct lttng_trace_chunk *lttng_trace_chunk_copy(
		struct lttng_trace_chunk *source_chunk)
{
	struct lttng_trace_chunk *new_chunk = lttng_trace_chunk_allocate();

	if (!new_chunk) {
		goto end;
	}

	pthread_mutex_lock(&source_chunk->lock);
	/*
	 * A new chunk is always a user; it shall create no new trace
	 * subdirectories.
	 */
	new_chunk->mode = (typeof(new_chunk->mode)) {
		.is_set = true,
		.value = TRACE_CHUNK_MODE_USER,
	};
	/*
	 * top_level_directories is not copied as it is never used
	 * by _user_ mode chunks.
	 */
	/* The new chunk is not part of a registry (yet, at least). */
	new_chunk->in_registry_element = false;
	new_chunk->name_overridden = source_chunk->name_overridden;
	if (source_chunk->name) {
		new_chunk->name = strdup(source_chunk->name);
		if (!new_chunk->name) {
			ERR("Failed to copy source trace chunk name in %s()",
					__FUNCTION__);
			goto error_unlock;
		}
	}
	if (source_chunk->path) {
		new_chunk->path = strdup(source_chunk->path);
		if (!new_chunk->path) {
			ERR("Failed to copy source trace chunk path in %s()",
					__FUNCTION__);
		}
	}
	new_chunk->id = source_chunk->id;
	new_chunk->timestamp_creation = source_chunk->timestamp_creation;
	new_chunk->timestamp_close = source_chunk->timestamp_close;
	new_chunk->credentials = source_chunk->credentials;
	if (source_chunk->session_output_directory) {
		const bool reference_acquired = lttng_directory_handle_get(
				source_chunk->session_output_directory);

		assert(reference_acquired);
		new_chunk->session_output_directory =
				source_chunk->session_output_directory;
	}
	if (source_chunk->chunk_directory) {
		const bool reference_acquired = lttng_directory_handle_get(
				source_chunk->chunk_directory);

		assert(reference_acquired);
		new_chunk->chunk_directory = source_chunk->chunk_directory;
	}
	new_chunk->close_command = source_chunk->close_command;
	new_chunk->fd_tracker = source_chunk->fd_tracker;
	pthread_mutex_unlock(&source_chunk->lock);
end:
	return new_chunk;
error_unlock:
	pthread_mutex_unlock(&source_chunk->lock);
	lttng_trace_chunk_put(new_chunk);
	return NULL;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_id(
		struct lttng_trace_chunk *chunk, uint64_t *id)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (chunk->id.is_set) {
		*id = chunk->id.value;
	} else {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
	}
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_creation_timestamp(
		struct lttng_trace_chunk *chunk, time_t *creation_ts)

{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (chunk->timestamp_creation.is_set) {
		*creation_ts = chunk->timestamp_creation.value;
	} else {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
	}
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_close_timestamp(
		struct lttng_trace_chunk *chunk, time_t *close_ts)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (chunk->timestamp_close.is_set) {
		*close_ts = chunk->timestamp_close.value;
	} else {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
	}
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_close_timestamp(
		struct lttng_trace_chunk *chunk, time_t close_ts)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (!chunk->timestamp_creation.is_set) {
		ERR("Failed to set trace chunk close timestamp: creation timestamp is unset");
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_OPERATION;
		goto end;
	}
	if (chunk->timestamp_creation.value > close_ts) {
		ERR("Failed to set trace chunk close timestamp: close timestamp is before creation timestamp");
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_ARGUMENT;
		goto end;
	}
	LTTNG_OPTIONAL_SET(&chunk->timestamp_close, close_ts);
	if (!chunk->name_overridden) {
		free(chunk->name);
		chunk->name = generate_chunk_name(LTTNG_OPTIONAL_GET(chunk->id),
				LTTNG_OPTIONAL_GET(chunk->timestamp_creation),
				&close_ts);
		if (!chunk->name) {
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		}
	}
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_name(
		struct lttng_trace_chunk *chunk, const char **name,
		bool *name_overridden)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
        if (name_overridden) {
		*name_overridden = chunk->name_overridden;
        }
        if (!chunk->name) {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
		goto end;
	}
	*name = chunk->name;
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
bool lttng_trace_chunk_get_name_overridden(struct lttng_trace_chunk *chunk)
{
	bool name_overridden;

	pthread_mutex_lock(&chunk->lock);
	name_overridden = chunk->name_overridden;
	pthread_mutex_unlock(&chunk->lock);
	return name_overridden;
}

static
bool is_valid_chunk_name(const char *name)
{
	size_t len;

	if (!name) {
		return false;
	}

	len = lttng_strnlen(name, LTTNG_NAME_MAX);
	if (len == 0 || len == LTTNG_NAME_MAX) {
		return false;
	}

	if (strchr(name, '/') || strchr(name, '.')) {
		return false;
	}

	return true;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_override_name(
		struct lttng_trace_chunk *chunk, const char *name)

{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	char *new_name, *new_path;

	DBG("Override trace chunk name from %s to %s", chunk->name, name);
	if (!is_valid_chunk_name(name)) {
		ERR("Attempted to set an invalid name on a trace chunk: name = %s",
				name ? : "NULL");
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_ARGUMENT;
		goto end;
	}

	pthread_mutex_lock(&chunk->lock);
	if (!chunk->id.is_set) {
		ERR("Attempted to set an override name on an anonymous trace chunk: name = %s",
				name);
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_OPERATION;
		goto end_unlock;
	}

	new_name = strdup(name);
	if (!new_name) {
		ERR("Failed to allocate new trace chunk name");
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end_unlock;
	}
	free(chunk->name);
	chunk->name = new_name;

	new_path = strdup(name);
	if (!new_path) {
		ERR("Failed to allocate new trace chunk path");
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end_unlock;
	}
	free(chunk->path);
	chunk->path = new_path;

	chunk->name_overridden = true;
end_unlock:
	pthread_mutex_unlock(&chunk->lock);
end:
	return status;
}

static
enum lttng_trace_chunk_status lttng_trace_chunk_rename_path_no_lock(
		struct lttng_trace_chunk *chunk, const char *path)

{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	struct lttng_directory_handle *rename_directory = NULL;
	char *new_path, *old_path;
	int ret;

	if (chunk->name_overridden) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}

	old_path = chunk->path;
	DBG("lttng_trace_chunk_rename_path from %s to %s", old_path, path);

	if ((!old_path && !path) ||
			(old_path && path && !strcmp(old_path, path)))  {
		goto end;
	}
	/*
	 * Use chunk name as path if NULL path is specified.
	 */
	if (!path) {
		path = chunk->name;
	}

	/* Renaming from "" to "" is not accepted. */
	if (path[0] == '\0' && old_path[0] == '\0') {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}

	/*
	 * If a rename is performed on a chunk for which the chunk_directory
	 * is not set (yet), or the session_output_directory is not set
	 * (interacting with a relay daemon), there is no rename to perform.
	 */
	if (!chunk->chunk_directory ||
			!chunk->session_output_directory) {
		goto skip_move;
	}

	if (old_path[0] != '\0' && path[0] != '\0') {
		/* Rename chunk directory. */
		ret = lttng_directory_handle_rename_as_user(
			chunk->session_output_directory,
			old_path,
			chunk->session_output_directory,
			path,
			LTTNG_OPTIONAL_GET(chunk->credentials).use_current_user ?
				NULL :
				&chunk->credentials.value.user);
		if (ret) {
			PERROR("Failed to move trace chunk directory \"%s\" to \"%s\"",
					old_path, path);
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}
		rename_directory = lttng_directory_handle_create_from_handle(
				path,
				chunk->session_output_directory);
		if (!rename_directory) {
			ERR("Failed to get handle to trace chunk rename directory");
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}

		/* Release old handle. */
		lttng_directory_handle_put(chunk->chunk_directory);
		/*
		 * Transfer new handle reference to chunk as the current chunk
		 * handle.
		 */
		chunk->chunk_directory = rename_directory;
		rename_directory = NULL;
	} else if (old_path[0] == '\0') {
		size_t i, count = lttng_dynamic_pointer_array_get_count(
				&chunk->top_level_directories);

		ret = lttng_directory_handle_create_subdirectory_as_user(
				chunk->session_output_directory,
				path,
				DIR_CREATION_MODE,
				LTTNG_OPTIONAL_GET(chunk->credentials).use_current_user ?
					NULL :
					&chunk->credentials.value.user);
		if (ret) {
			PERROR("Failed to create trace chunk rename directory \"%s\"",
					path);
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}

		rename_directory = lttng_directory_handle_create_from_handle(
				path, chunk->session_output_directory);
		if (!rename_directory) {
			ERR("Failed to get handle to trace chunk rename directory");
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}

		/* Move toplevel directories. */
		for (i = 0; i < count; i++) {
			const char *top_level_name =
				lttng_dynamic_pointer_array_get_pointer(
					&chunk->top_level_directories, i);

			ret = lttng_directory_handle_rename_as_user(
					chunk->chunk_directory,
					top_level_name,
					rename_directory,
					top_level_name,
					LTTNG_OPTIONAL_GET(chunk->credentials).use_current_user ?
						NULL :
						&chunk->credentials.value.user);
			if (ret) {
				PERROR("Failed to move \"%s\" to trace chunk rename directory",
						top_level_name);
				status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
				goto end;
			}
		}
		/* Release old handle. */
		lttng_directory_handle_put(chunk->chunk_directory);
		/*
		 * Transfer new handle reference to chunk as the current chunk
		 * handle.
		 */
		chunk->chunk_directory = rename_directory;
		rename_directory = NULL;
	} else {
		size_t i, count = lttng_dynamic_pointer_array_get_count(
				&chunk->top_level_directories);
		const bool reference_acquired = lttng_directory_handle_get(
				chunk->session_output_directory);

		assert(reference_acquired);
		rename_directory = chunk->session_output_directory;

		/* Move toplevel directories. */
		for (i = 0; i < count; i++) {
			const char *top_level_name =
				lttng_dynamic_pointer_array_get_pointer(
					&chunk->top_level_directories, i);

			ret = lttng_directory_handle_rename_as_user(
					chunk->chunk_directory,
					top_level_name,
					rename_directory,
					top_level_name,
					LTTNG_OPTIONAL_GET(chunk->credentials).use_current_user ?
						NULL :
						&chunk->credentials.value.user);
			if (ret) {
				PERROR("Failed to move \"%s\" to trace chunk rename directory",
						top_level_name);
				status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
				goto end;
			}
		}
		/* Release old handle. */
		lttng_directory_handle_put(chunk->chunk_directory);
		/*
		 * Transfer new handle reference to chunk as the current chunk
		 * handle.
		 */
		chunk->chunk_directory = rename_directory;
		rename_directory = NULL;

		/* Remove old directory. */
		status = lttng_directory_handle_remove_subdirectory(
				chunk->session_output_directory,
				old_path);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Error removing subdirectory '%s' file when deleting chunk",
				old_path);
			ret = -1;
			goto end;
		}
	}

skip_move:
	if (path) {
		new_path = strdup(path);
		if (!new_path) {
			ERR("Failed to allocate new trace chunk path");
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}
	} else {
		new_path = NULL;
	}
	free(chunk->path);
	chunk->path = new_path;
end:
	lttng_directory_handle_put(rename_directory);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_rename_path(
		struct lttng_trace_chunk *chunk, const char *path)

{
	enum lttng_trace_chunk_status status;

	pthread_mutex_lock(&chunk->lock);
	status = lttng_trace_chunk_rename_path_no_lock(chunk, path);
	pthread_mutex_unlock(&chunk->lock);

	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_credentials(
		struct lttng_trace_chunk *chunk,
		struct lttng_credentials *credentials)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (chunk->credentials.is_set) {
		if (chunk->credentials.value.use_current_user) {
			credentials->uid = geteuid();
			credentials->gid = getegid();
		} else {
			*credentials = chunk->credentials.value.user;
		}
	} else {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
	}
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_credentials(
		struct lttng_trace_chunk *chunk,
		const struct lttng_credentials *user_credentials)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	const struct chunk_credentials credentials = {
		.user = *user_credentials,
		.use_current_user = false,
	};

	pthread_mutex_lock(&chunk->lock);
	if (chunk->credentials.is_set) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	LTTNG_OPTIONAL_SET(&chunk->credentials, credentials);
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_credentials_current_user(
		struct lttng_trace_chunk *chunk)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	const struct chunk_credentials credentials = {
		.use_current_user = true,
	};

	pthread_mutex_lock(&chunk->lock);
	if (chunk->credentials.is_set) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	LTTNG_OPTIONAL_SET(&chunk->credentials, credentials);
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}


LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_as_owner(
		struct lttng_trace_chunk *chunk,
		struct lttng_directory_handle *session_output_directory)
{
	int ret;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	struct lttng_directory_handle *chunk_directory_handle = NULL;
	bool reference_acquired;

	pthread_mutex_lock(&chunk->lock);
	if (chunk->mode.is_set) {
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_OPERATION;
		goto end;
	}
	if (!chunk->credentials.is_set) {
		/*
		 * Fatal error, credentials must be set before a
		 * directory is created.
		 */
		ERR("Credentials of trace chunk are unset: refusing to set session output directory");
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	if (chunk->path[0] != '\0') {
		ret = lttng_directory_handle_create_subdirectory_as_user(
				session_output_directory,
				chunk->path,
				DIR_CREATION_MODE,
				!chunk->credentials.value.use_current_user ?
					&chunk->credentials.value.user : NULL);
		if (ret) {
			PERROR("Failed to create chunk output directory \"%s\"",
				chunk->path);
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}
		chunk_directory_handle =
				lttng_directory_handle_create_from_handle(
					chunk->path,
					session_output_directory);
		if (!chunk_directory_handle) {
			/* The function already logs on all error paths. */
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}
	} else {
		/*
		 * A nameless chunk does not need its own output directory.
		 * The session's output directory will be used.
		 */
		const bool reference_acquired =
				lttng_directory_handle_get(
					session_output_directory);

		assert(reference_acquired);
		chunk_directory_handle = session_output_directory;
	}
	chunk->chunk_directory = chunk_directory_handle;
	chunk_directory_handle = NULL;
	reference_acquired = lttng_directory_handle_get(
			session_output_directory);
	assert(reference_acquired);
	chunk->session_output_directory = session_output_directory;
	LTTNG_OPTIONAL_SET(&chunk->mode, TRACE_CHUNK_MODE_OWNER);
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_as_user(
		struct lttng_trace_chunk *chunk,
		struct lttng_directory_handle *chunk_directory)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	bool reference_acquired;

	pthread_mutex_lock(&chunk->lock);
	if (chunk->mode.is_set) {
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_OPERATION;
		goto end;
	}
	if (!chunk->credentials.is_set) {
		ERR("Credentials of trace chunk are unset: refusing to set chunk output directory");
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	reference_acquired = lttng_directory_handle_get(chunk_directory);
	assert(reference_acquired);
	chunk->chunk_directory = chunk_directory;
	LTTNG_OPTIONAL_SET(&chunk->mode, TRACE_CHUNK_MODE_USER);
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status
lttng_trace_chunk_get_session_output_directory_handle(
		struct lttng_trace_chunk *chunk,
		struct lttng_directory_handle **handle)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (!chunk->session_output_directory) {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
		*handle = NULL;
		goto end;
	} else {
		const bool reference_acquired = lttng_directory_handle_get(
				chunk->session_output_directory);

		assert(reference_acquired);
		*handle = chunk->session_output_directory;
	}
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_borrow_chunk_directory_handle(
		struct lttng_trace_chunk *chunk,
		const struct lttng_directory_handle **handle)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (!chunk->chunk_directory) {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
		goto end;
	}

	*handle = chunk->chunk_directory;
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

/* Add a top-level directory to the trace chunk if it was previously unknown. */
static
int add_top_level_directory_unique(struct lttng_trace_chunk *chunk,
		const char *new_path)
{
	int ret = 0;
	bool found = false;
	size_t i, count = lttng_dynamic_pointer_array_get_count(
			&chunk->top_level_directories);
	const char *new_path_separator_pos = strchr(new_path, '/');
	const ptrdiff_t new_path_top_level_len = new_path_separator_pos ?
			new_path_separator_pos - new_path : strlen(new_path);

	for (i = 0; i < count; i++) {
		const char *path = lttng_dynamic_pointer_array_get_pointer(
				&chunk->top_level_directories, i);
		const ptrdiff_t path_top_level_len = strlen(path);

		if (path_top_level_len != new_path_top_level_len) {
			continue;
		}
		if (!strncmp(path, new_path, path_top_level_len)) {
			found = true;
			break;
		}
	}

	if (!found) {
		char *copy = lttng_strndup(new_path, new_path_top_level_len);

		DBG("Adding new top-level directory \"%s\" to trace chunk \"%s\"",
				new_path, chunk->name ? : "(unnamed)");
		if (!copy) {
			PERROR("Failed to copy path");
			ret = -1;
			goto end;
		}
		ret = lttng_dynamic_pointer_array_add_pointer(
				&chunk->top_level_directories, copy);
		if (ret) {
			ERR("Allocation failure while adding top-level directory entry to a trace chunk");
			free(copy);
			goto end;
		}
	}
end:
	return ret;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_create_subdirectory(
		struct lttng_trace_chunk *chunk,
		const char *path)
{
	int ret;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	DBG("Creating trace chunk subdirectory \"%s\"", path);
	pthread_mutex_lock(&chunk->lock);
	if (!chunk->credentials.is_set) {
		/*
		 * Fatal error, credentials must be set before a
		 * directory is created.
		 */
		ERR("Credentials of trace chunk are unset: refusing to create subdirectory \"%s\"",
				path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	if (!chunk->mode.is_set ||
			chunk->mode.value != TRACE_CHUNK_MODE_OWNER) {
		ERR("Attempted to create trace chunk subdirectory \"%s\" through a non-owner chunk",
				path);
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_OPERATION;
		goto end;
	}
	if (!chunk->chunk_directory) {
		ERR("Attempted to create trace chunk subdirectory \"%s\" before setting the chunk output directory",
				path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	if (*path == '/') {
		ERR("Refusing to create absolute trace chunk directory \"%s\"",
				path);
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_ARGUMENT;
		goto end;
	}
	ret = lttng_directory_handle_create_subdirectory_recursive_as_user(
			chunk->chunk_directory, path,
			DIR_CREATION_MODE,
			chunk->credentials.value.use_current_user ?
					NULL : &chunk->credentials.value.user);
	if (ret) {
		PERROR("Failed to create trace chunk subdirectory \"%s\"",
				path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	ret = add_top_level_directory_unique(chunk, path);
	if (ret) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

/*
 * TODO: Implement O(1) lookup.
 */
static
bool lttng_trace_chunk_find_file(struct lttng_trace_chunk *chunk,
		const char *path, size_t *index)
{
	size_t i, count;

	count = lttng_dynamic_pointer_array_get_count(&chunk->files);
	for (i = 0; i < count; i++) {
		const char *iter_path =
				lttng_dynamic_pointer_array_get_pointer(
					&chunk->files, i);
		if (!strcmp(iter_path, path)) {
			if (index) {
				*index = i;
			}
			return true;
		}
	}
	return false;
}

static
enum lttng_trace_chunk_status lttng_trace_chunk_add_file(
		struct lttng_trace_chunk *chunk,
		const char *path)
{
	char *copy;
	int ret;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	if (lttng_trace_chunk_find_file(chunk, path, NULL)) {
		return LTTNG_TRACE_CHUNK_STATUS_OK;
	}
	DBG("Adding new file \"%s\" to trace chunk \"%s\"",
			path, chunk->name ? : "(unnamed)");
	copy = strdup(path);
	if (!copy) {
		PERROR("Failed to copy path");
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	ret = lttng_dynamic_pointer_array_add_pointer(
			&chunk->files, copy);
	if (ret) {
		ERR("Allocation failure while adding file to a trace chunk");
		free(copy);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
end:
	return status;
}

static
void lttng_trace_chunk_remove_file(
		struct lttng_trace_chunk *chunk,
		const char *path)
{
	size_t index;
	bool found;
	int ret;

	found = lttng_trace_chunk_find_file(chunk, path, &index);
	if (!found) {
		return;
	}
	ret = lttng_dynamic_pointer_array_remove_pointer(
			&chunk->files, index);
	assert(!ret);
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_open_file(
		struct lttng_trace_chunk *chunk, const char *file_path,
		int flags, mode_t mode, int *out_fd, bool expect_no_file)
{
	int ret;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	DBG("Opening trace chunk file \"%s\"", file_path);
	pthread_mutex_lock(&chunk->lock);
	if (!chunk->credentials.is_set) {
		/*
		 * Fatal error, credentials must be set before a
		 * file is created.
		 */
		ERR("Credentials of trace chunk are unset: refusing to open file \"%s\"",
				file_path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	if (!chunk->chunk_directory) {
		ERR("Attempted to open trace chunk file \"%s\" before setting the chunk output directory",
				file_path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	status = lttng_trace_chunk_add_file(chunk, file_path);
	if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
		goto end;
	}
	ret = lttng_directory_handle_open_file_as_user(
			chunk->chunk_directory, file_path, flags, mode,
			chunk->credentials.value.use_current_user ?
					NULL : &chunk->credentials.value.user);
	if (ret < 0) {
		if (errno == ENOENT && expect_no_file) {
			status = LTTNG_TRACE_CHUNK_STATUS_NO_FILE;
		} else {
			PERROR("Failed to open file relative to trace chunk file_path = \"%s\", flags = %d, mode = %d",
				file_path, flags, (int) mode);
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		}
		lttng_trace_chunk_remove_file(chunk, file_path);
		goto end;
	}
	*out_fd = ret;
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
int lttng_trace_chunk_unlink_file(struct lttng_trace_chunk *chunk,
		const char *file_path)
{
	int ret;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	DBG("Unlinking trace chunk file \"%s\"", file_path);
	pthread_mutex_lock(&chunk->lock);
	if (!chunk->credentials.is_set) {
		/*
		 * Fatal error, credentials must be set before a
		 * file is unlinked.
		 */
		ERR("Credentials of trace chunk are unset: refusing to unlink file \"%s\"",
				file_path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	if (!chunk->chunk_directory) {
		ERR("Attempted to unlink trace chunk file \"%s\" before setting the chunk output directory",
				file_path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	ret = lttng_directory_handle_unlink_file_as_user(
			chunk->chunk_directory, file_path,
			chunk->credentials.value.use_current_user ?
					NULL : &chunk->credentials.value.user);
	if (ret < 0) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	lttng_trace_chunk_remove_file(chunk, file_path);
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
int lttng_trace_chunk_remove_subdirectory_recursive(struct lttng_trace_chunk *chunk,
		const char *path)
{
	int ret;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	DBG("Recursively removing trace chunk directory \"%s\"", path);
	pthread_mutex_lock(&chunk->lock);
	if (!chunk->credentials.is_set) {
		/*
		 * Fatal error, credentials must be set before a
		 * directory is removed.
		 */
		ERR("Credentials of trace chunk are unset: refusing to recursively remove directory \"%s\"",
				path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	if (!chunk->chunk_directory) {
		ERR("Attempted to recursively remove trace chunk directory \"%s\" before setting the chunk output directory",
				path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	ret = lttng_directory_handle_remove_subdirectory_recursive_as_user(
			chunk->chunk_directory, path,
			chunk->credentials.value.use_current_user ?
					NULL : &chunk->credentials.value.user,
			LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG);
	if (ret < 0) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

static
int lttng_trace_chunk_move_to_completed_post_release(
		struct lttng_trace_chunk *trace_chunk)
{
	int ret = 0;
	char *archived_chunk_name = NULL;
	const uint64_t chunk_id = LTTNG_OPTIONAL_GET(trace_chunk->id);
	const time_t creation_timestamp =
			LTTNG_OPTIONAL_GET(trace_chunk->timestamp_creation);
	const time_t close_timestamp =
			LTTNG_OPTIONAL_GET(trace_chunk->timestamp_close);
	struct lttng_directory_handle *archived_chunks_directory = NULL;
	enum lttng_trace_chunk_status status;

	if (!trace_chunk->mode.is_set ||
			trace_chunk->mode.value != TRACE_CHUNK_MODE_OWNER ||
			!trace_chunk->session_output_directory) {
		/*
		 * This command doesn't need to run if the output is remote
		 * or if the trace chunk is not owned by this process.
		 */
		goto end;
	}

	assert(trace_chunk->mode.value == TRACE_CHUNK_MODE_OWNER);
	assert(!trace_chunk->name_overridden);
	assert(trace_chunk->path);

	archived_chunk_name = generate_chunk_name(chunk_id, creation_timestamp,
			&close_timestamp);
	if (!archived_chunk_name) {
		ERR("Failed to generate archived trace chunk name while renaming trace chunk");
		ret = -1;
		goto end;
	}

	ret = lttng_directory_handle_create_subdirectory_as_user(
			trace_chunk->session_output_directory,
		        DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY,
			DIR_CREATION_MODE,
			!trace_chunk->credentials.value.use_current_user ?
					&trace_chunk->credentials.value.user :
					NULL);
	if (ret) {
		PERROR("Failed to create \"" DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY
				"\" directory for archived trace chunks");
		goto end;
	}

	archived_chunks_directory = lttng_directory_handle_create_from_handle(
		        DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY,
			trace_chunk->session_output_directory);
	if (!archived_chunks_directory) {
		PERROR("Failed to get handle to archived trace chunks directory");
		ret = -1;
		goto end;
	}

	/*
	 * Make sure chunk is renamed to old directory if not already done by
	 * the creation of the next chunk. This happens if a rotation is
	 * performed while tracing is stopped.
	 */
	if (!trace_chunk->path || strcmp(trace_chunk->path,
			DEFAULT_CHUNK_TMP_OLD_DIRECTORY)) {
		status = lttng_trace_chunk_rename_path_no_lock(trace_chunk,
				DEFAULT_CHUNK_TMP_OLD_DIRECTORY);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Failed to rename chunk to %s", DEFAULT_CHUNK_TMP_OLD_DIRECTORY);
			ret = -1;
			goto end;
		}
	}

	ret = lttng_directory_handle_rename_as_user(
			trace_chunk->session_output_directory,
			trace_chunk->path,
			archived_chunks_directory,
			archived_chunk_name,
			LTTNG_OPTIONAL_GET(trace_chunk->credentials).use_current_user ?
				NULL :
				&trace_chunk->credentials.value.user);
	if (ret) {
		PERROR("Failed to rename folder \"%s\" to \"%s\"",
				trace_chunk->path,
				archived_chunk_name);
	}

end:
	lttng_directory_handle_put(archived_chunks_directory);
	free(archived_chunk_name);
	return ret;
}

static
int lttng_trace_chunk_no_operation(struct lttng_trace_chunk *trace_chunk)
{
	return 0;
}

static
int lttng_trace_chunk_delete_post_release_user(
		struct lttng_trace_chunk *trace_chunk)
{
	int ret = 0;

	DBG("Trace chunk \"delete\" close command post-release (User)");

	/* Unlink all files. */
	while (lttng_dynamic_pointer_array_get_count(&trace_chunk->files) != 0) {
		enum lttng_trace_chunk_status status;
		const char *path;

		/* Remove first. */
		path = lttng_dynamic_pointer_array_get_pointer(
				&trace_chunk->files, 0);
		DBG("Unlink file: %s", path);
		status = lttng_trace_chunk_unlink_file(trace_chunk, path);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Error unlinking file '%s' when deleting chunk", path);
			ret = -1;
			goto end;
		}
	}
end:
	return ret;
}

static
int lttng_trace_chunk_delete_post_release_owner(
		struct lttng_trace_chunk *trace_chunk)
{
	enum lttng_trace_chunk_status status;
	size_t i, count;
	int ret = 0;

	ret = lttng_trace_chunk_delete_post_release_user(trace_chunk);
	if (ret) {
		goto end;
	}

	DBG("Trace chunk \"delete\" close command post-release (Owner)");

	assert(trace_chunk->session_output_directory);
	assert(trace_chunk->chunk_directory);

	/* Remove empty directories. */
	count = lttng_dynamic_pointer_array_get_count(
			&trace_chunk->top_level_directories);

	for (i = 0; i < count; i++) {
		const char *top_level_name =
				lttng_dynamic_pointer_array_get_pointer(
					&trace_chunk->top_level_directories, i);

		status = lttng_trace_chunk_remove_subdirectory_recursive(trace_chunk, top_level_name);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Error recursively removing subdirectory '%s' file when deleting chunk",
					top_level_name);
			ret = -1;
			break;
		}
	}
	if (!ret) {
		lttng_directory_handle_put(trace_chunk->chunk_directory);
		trace_chunk->chunk_directory = NULL;

		if (trace_chunk->path && trace_chunk->path[0] != '\0') {
			status = lttng_directory_handle_remove_subdirectory(
					trace_chunk->session_output_directory,
					trace_chunk->path);
			if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
				ERR("Error removing subdirectory '%s' file when deleting chunk",
					trace_chunk->path);
				ret = -1;
			}
		}
	}
	free(trace_chunk->path);
	trace_chunk->path = NULL;
end:
	return ret;
}

/*
 * For local files, session and consumer daemons all run the delete hook. The
 * consumer daemons have the list of files to unlink, and technically the
 * session daemon is the owner of the chunk. Unlink all files owned by each
 * consumer daemon.
 */
static
int lttng_trace_chunk_delete_post_release(
		struct lttng_trace_chunk *trace_chunk)
{
	if (!trace_chunk->chunk_directory) {
		return 0;
	}

	if (trace_chunk->mode.value == TRACE_CHUNK_MODE_OWNER) {
		return lttng_trace_chunk_delete_post_release_owner(trace_chunk);
	} else {
		return lttng_trace_chunk_delete_post_release_user(trace_chunk);
	}
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_close_command(
		struct lttng_trace_chunk *chunk,
		enum lttng_trace_chunk_command_type *command_type)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (chunk->close_command.is_set) {
		*command_type = chunk->close_command.value;
		status = LTTNG_TRACE_CHUNK_STATUS_OK;
	} else {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
	}
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_set_close_command(
		struct lttng_trace_chunk *chunk,
		enum lttng_trace_chunk_command_type close_command)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	if (close_command < LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED ||
			close_command >= LTTNG_TRACE_CHUNK_COMMAND_TYPE_MAX) {
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_ARGUMENT;
		goto end;
	}

	pthread_mutex_lock(&chunk->lock);
	if (chunk->close_command.is_set) {
		DBG("Overriding trace chunk close command from \"%s\" to \"%s\"",
				close_command_names[chunk->close_command.value],
				close_command_names[close_command]);
        } else {
		DBG("Setting trace chunk close command to \"%s\"",
				close_command_names[close_command]);
        }
	/*
	 * Unset close command for no-op for backward compatibility with relayd
	 * 2.11.
	 */
	if (close_command != LTTNG_TRACE_CHUNK_COMMAND_TYPE_NO_OPERATION) {
		LTTNG_OPTIONAL_SET(&chunk->close_command, close_command);
	} else {
		LTTNG_OPTIONAL_UNSET(&chunk->close_command);
	}
	pthread_mutex_unlock(&chunk->lock);
end:
	return status;
}

LTTNG_HIDDEN
const char *lttng_trace_chunk_command_type_get_name(
		enum lttng_trace_chunk_command_type command)
{
	switch (command) {
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED:
		return "move to completed trace chunk folder";
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_NO_OPERATION:
		return "no operation";
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE:
		return "delete";
	default:
		abort();
	}
}

LTTNG_HIDDEN
bool lttng_trace_chunk_get(struct lttng_trace_chunk *chunk)
{
	return urcu_ref_get_unless_zero(&chunk->ref);
}

static
void free_lttng_trace_chunk_registry_element(struct rcu_head *node)
{
	struct lttng_trace_chunk_registry_element *element =
			container_of(node, typeof(*element), rcu_node);

	lttng_trace_chunk_fini(&element->chunk);
	free(element);
}

static
void lttng_trace_chunk_release(struct urcu_ref *ref)
{
	struct lttng_trace_chunk *chunk = container_of(ref, typeof(*chunk),
			ref);

	if (chunk->close_command.is_set) {
		if (close_command_post_release_funcs[
				chunk->close_command.value](chunk)) {
			ERR("Trace chunk post-release command %s has failed.",
					close_command_names[chunk->close_command.value]);
		}
	}

	if (chunk->in_registry_element) {
		struct lttng_trace_chunk_registry_element *element;

		element = container_of(chunk, typeof(*element), chunk);
		if (element->registry) {
			rcu_read_lock();
			cds_lfht_del(element->registry->ht,
					&element->trace_chunk_registry_ht_node);
			rcu_read_unlock();
			call_rcu(&element->rcu_node,
					free_lttng_trace_chunk_registry_element);
		} else {
			/* Never published, can be free'd immediately. */
			free_lttng_trace_chunk_registry_element(
					&element->rcu_node);
		}
	} else {
		/* Not RCU-protected, free immediately. */
		lttng_trace_chunk_fini(chunk);
		free(chunk);
	}
}

LTTNG_HIDDEN
void lttng_trace_chunk_put(struct lttng_trace_chunk *chunk)
{
	if (!chunk) {
		return;
	}
	assert(chunk->ref.refcount);
	urcu_ref_put(&chunk->ref, lttng_trace_chunk_release);
}

LTTNG_HIDDEN
struct lttng_trace_chunk_registry *lttng_trace_chunk_registry_create(void)
{
	struct lttng_trace_chunk_registry *registry;

	registry = zmalloc(sizeof(*registry));
	if (!registry) {
		goto end;
	}

	registry->ht = cds_lfht_new(DEFAULT_HT_SIZE, 1, 0,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!registry->ht) {
		goto error;
	}
end:
	return registry;
error:
	lttng_trace_chunk_registry_destroy(registry);
	return NULL;
}

LTTNG_HIDDEN
void lttng_trace_chunk_registry_destroy(
		struct lttng_trace_chunk_registry *registry)
{
	if (!registry) {
		return;
	}
	if (registry->ht) {
		int ret = cds_lfht_destroy(registry->ht, NULL);
		assert(!ret);
	}
	free(registry);
}

static
struct lttng_trace_chunk_registry_element *
lttng_trace_chunk_registry_element_create_from_chunk(
		struct lttng_trace_chunk *chunk, uint64_t session_id)
{
	struct lttng_trace_chunk_registry_element *element =
			zmalloc(sizeof(*element));

	if (!element) {
		goto end;
	}
	cds_lfht_node_init(&element->trace_chunk_registry_ht_node);
	element->session_id = session_id;

	element->chunk = *chunk;
	lttng_trace_chunk_init(&element->chunk);
	if (chunk->session_output_directory) {
		/* Transferred ownership. */
		element->chunk.session_output_directory =
				chunk->session_output_directory;
		chunk->session_output_directory = NULL;
	}
	if (chunk->chunk_directory) {
		/* Transferred ownership. */
		element->chunk.chunk_directory = chunk->chunk_directory;
		chunk->chunk_directory = NULL;
	}
	/*
	 * The original chunk becomes invalid; the name and path attributes are
	 * transferred to the new chunk instance.
	 */
	chunk->name = NULL;
	chunk->path = NULL;
	element->chunk.fd_tracker = chunk->fd_tracker;
	element->chunk.in_registry_element = true;
end:
	return element;
}

LTTNG_HIDDEN
struct lttng_trace_chunk *
lttng_trace_chunk_registry_publish_chunk(
		struct lttng_trace_chunk_registry *registry,
		uint64_t session_id, struct lttng_trace_chunk *chunk)
{
	struct lttng_trace_chunk_registry_element *element;
	unsigned long element_hash;

	pthread_mutex_lock(&chunk->lock);
	element = lttng_trace_chunk_registry_element_create_from_chunk(chunk,
			session_id);
	pthread_mutex_unlock(&chunk->lock);
	if (!element) {
		goto end;
	}
	/*
	 * chunk is now invalid, the only valid operation is a 'put' from the
	 * caller.
	 */
	chunk = NULL;
	element_hash = lttng_trace_chunk_registry_element_hash(element);

	rcu_read_lock();
	while (1) {
		struct cds_lfht_node *published_node;
		struct lttng_trace_chunk *published_chunk;
		struct lttng_trace_chunk_registry_element *published_element;

		published_node = cds_lfht_add_unique(registry->ht,
			        element_hash,
				lttng_trace_chunk_registry_element_match,
			        element,
				&element->trace_chunk_registry_ht_node);
		if (published_node == &element->trace_chunk_registry_ht_node) {
			/* Successfully published the new element. */
		        element->registry = registry;
			/* Acquire a reference for the caller. */
			if (lttng_trace_chunk_get(&element->chunk)) {
				break;
			} else {
				/*
				 * Another thread concurrently unpublished the
				 * trace chunk. This is currently unexpected.
				 *
				 * Re-attempt to publish.
				 */
				ERR("Attempt to publish a trace chunk to the chunk registry raced with a trace chunk deletion");
				continue;
			}
		}

		/*
		 * An equivalent trace chunk was published before this trace
		 * chunk. Attempt to acquire a reference to the one that was
		 * already published and release the reference to the copy we
		 * created if successful.
		 */
		published_element = container_of(published_node,
				typeof(*published_element),
				trace_chunk_registry_ht_node);
		published_chunk = &published_element->chunk;
		if (lttng_trace_chunk_get(published_chunk)) {
			lttng_trace_chunk_put(&element->chunk);
			element = published_element;
			break;
		}
		/*
		 * A reference to the previously published trace chunk could not
		 * be acquired. Hence, retry to publish our copy of the trace 
		 * chunk.
		 */
	}
	rcu_read_unlock();
end:
	return element ? &element->chunk : NULL;
}

/*
 * Note that the caller must be registered as an RCU thread.
 * However, it does not need to hold the RCU read lock. The RCU read lock is
 * acquired to perform the look-up in the registry's hash table and held until
 * after a reference to the "found" trace chunk is acquired.
 *
 * IOW, holding a reference guarantees the existence of the object for the
 * caller.
 */
static
struct lttng_trace_chunk *_lttng_trace_chunk_registry_find_chunk(
		const struct lttng_trace_chunk_registry *registry,
		uint64_t session_id, uint64_t *chunk_id)
{
	const struct lttng_trace_chunk_registry_element target_element = {
		.chunk.id.is_set = !!chunk_id,
		.chunk.id.value = chunk_id ? *chunk_id : 0,
		.session_id = session_id,
	};
	const unsigned long element_hash =
			lttng_trace_chunk_registry_element_hash(
				&target_element);
	struct cds_lfht_node *published_node;
	struct lttng_trace_chunk_registry_element *published_element;
	struct lttng_trace_chunk *published_chunk = NULL;
	struct cds_lfht_iter iter;

	rcu_read_lock();
	cds_lfht_lookup(registry->ht,
			element_hash,
			lttng_trace_chunk_registry_element_match,
			&target_element,
			&iter);
	published_node = cds_lfht_iter_get_node(&iter);
	if (!published_node) {
		goto end;
	}

	published_element = container_of(published_node,
			typeof(*published_element),
			trace_chunk_registry_ht_node);
	if (lttng_trace_chunk_get(&published_element->chunk)) {
		published_chunk = &published_element->chunk;
	}
end:
	rcu_read_unlock();
	return published_chunk;
}

LTTNG_HIDDEN
struct lttng_trace_chunk *
lttng_trace_chunk_registry_find_chunk(
		const struct lttng_trace_chunk_registry *registry,
		uint64_t session_id, uint64_t chunk_id)
{
        return _lttng_trace_chunk_registry_find_chunk(registry,
			session_id, &chunk_id);
}

LTTNG_HIDDEN
int lttng_trace_chunk_registry_chunk_exists(
		const struct lttng_trace_chunk_registry *registry,
		uint64_t session_id, uint64_t chunk_id, bool *chunk_exists)
{
	int ret = 0;
	const struct lttng_trace_chunk_registry_element target_element = {
		.chunk.id.is_set = true,
		.chunk.id.value = chunk_id,
		.session_id = session_id,
	};
	const unsigned long element_hash =
			lttng_trace_chunk_registry_element_hash(
				&target_element);
	struct cds_lfht_node *published_node;
	struct cds_lfht_iter iter;

	rcu_read_lock();
	cds_lfht_lookup(registry->ht,
			element_hash,
			lttng_trace_chunk_registry_element_match,
			&target_element,
			&iter);
	published_node = cds_lfht_iter_get_node(&iter);
	if (!published_node) {
		*chunk_exists = false;
		goto end;
	}

	*chunk_exists = !cds_lfht_is_node_deleted(published_node);
end:
	rcu_read_unlock();
	return ret;
}

LTTNG_HIDDEN
struct lttng_trace_chunk *
lttng_trace_chunk_registry_find_anonymous_chunk(
		const struct lttng_trace_chunk_registry *registry,
		uint64_t session_id)
{
        return _lttng_trace_chunk_registry_find_chunk(registry,
			session_id, NULL);
}

LTTNG_HIDDEN
unsigned int lttng_trace_chunk_registry_put_each_chunk(
		const struct lttng_trace_chunk_registry *registry)
{
	struct cds_lfht_iter iter;
	struct lttng_trace_chunk_registry_element *chunk_element;
	unsigned int trace_chunks_left = 0;

	DBG("Releasing trace chunk registry to all trace chunks");
	rcu_read_lock();
	cds_lfht_for_each_entry(registry->ht,
			&iter, chunk_element, trace_chunk_registry_ht_node) {
		const char *chunk_id_str = "none";
		char chunk_id_buf[MAX_INT_DEC_LEN(uint64_t)];

		pthread_mutex_lock(&chunk_element->chunk.lock);
		if (chunk_element->chunk.id.is_set) {
			int fmt_ret;

			fmt_ret = snprintf(chunk_id_buf, sizeof(chunk_id_buf),
					"%" PRIu64,
					chunk_element->chunk.id.value);
			if (fmt_ret < 0 || fmt_ret >= sizeof(chunk_id_buf)) {
				chunk_id_str = "formatting error";
			} else {
				chunk_id_str = chunk_id_buf;
			}
		}

		DBG("Releasing reference to trace chunk: session_id = %" PRIu64
				"chunk_id = %s, name = \"%s\", status = %s",
				chunk_element->session_id,
				chunk_id_str,
				chunk_element->chunk.name ? : "none",
				chunk_element->chunk.close_command.is_set ?
						"open" : "closed");
		pthread_mutex_unlock(&chunk_element->chunk.lock);
		lttng_trace_chunk_put(&chunk_element->chunk);
		trace_chunks_left++;
	}
	rcu_read_unlock();
	DBG("Released reference to %u trace chunks in %s()", trace_chunks_left,
			__FUNCTION__);

	return trace_chunks_left;
}
