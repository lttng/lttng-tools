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

#include <lttng/constant.h>
#include <common/string-utils/format.h>
#include <common/trace-chunk.h>
#include <common/trace-chunk-registry.h>
#include <common/hashtable/utils.h>
#include <common/hashtable/hashtable.h>
#include <common/error.h>
#include <common/utils.h>
#include <common/time.h>
#include <common/optional.h>
#include <common/compat/directory-handle.h>
#include <common/credentials.h>
#include <common/defaults.h>
#include <common/dynamic-array.h>

#include <urcu/ref.h>
#include <urcu/rculfhash.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>

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
typedef void (*chunk_close_command)(struct lttng_trace_chunk *trace_chunk);

/* Move a completed trace chunk to the 'completed' trace archive folder. */
static
void lttng_trace_chunk_move_to_completed(struct lttng_trace_chunk *trace_chunk);

struct chunk_credentials {
	bool use_current_user;
	struct lttng_credentials user;
};

struct lttng_trace_chunk {
	pthread_mutex_t lock;
	struct urcu_ref ref;
	LTTNG_OPTIONAL(enum trace_chunk_mode) mode;
	/*
	 * First-level directories created within the trace chunk.
	 * Elements are of type 'char *'.
	 */
	struct lttng_dynamic_pointer_array top_level_directories;
	/* Is contained within an lttng_trace_chunk_registry_element? */
	bool in_registry_element;
	bool name_overridden;
	char *name;
	/* An unset id means the chunk is anonymous. */
	LTTNG_OPTIONAL(uint64_t) id;
	LTTNG_OPTIONAL(time_t) timestamp_creation;
	LTTNG_OPTIONAL(time_t) timestamp_close;
	LTTNG_OPTIONAL(struct chunk_credentials) credentials;
	LTTNG_OPTIONAL(struct lttng_directory_handle) session_output_directory;
	LTTNG_OPTIONAL(struct lttng_directory_handle) chunk_directory;
	LTTNG_OPTIONAL(enum lttng_trace_chunk_command_type) close_command;
};

/* A trace chunk is uniquely identified by its (session id, chunk id) tuple. */
struct lttng_trace_chunk_registry_element {
	uint64_t session_id;
	struct lttng_trace_chunk chunk;
	/* Weak and only set when added. */
	struct lttng_trace_chunk_registry *registry;
	struct cds_lfht_node trace_chunk_registry_ht_node;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

struct lttng_trace_chunk_registry {
	struct cds_lfht *ht;
};

const char *close_command_names[] = {
	[LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED] =
		"move to completed chunk folder",
};

chunk_close_command close_command_funcs[] = {
	[LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED] =
			lttng_trace_chunk_move_to_completed,
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
	char start_datetime[sizeof("YYYYmmddTHHMMSS+HHMM")] = {};
	char end_datetime_suffix[sizeof("-YYYYmmddTHHMMSS+HHMM")] = {};

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
				sizeof(end_datetime_suffix));
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
}

static
void lttng_trace_chunk_fini(struct lttng_trace_chunk *chunk)
{
	if (chunk->session_output_directory.is_set) {
		lttng_directory_handle_fini(
				&chunk->session_output_directory.value);
	}
	if (chunk->chunk_directory.is_set) {
		lttng_directory_handle_fini(&chunk->chunk_directory.value);
	}
	free(chunk->name);
	chunk->name = NULL;
	lttng_dynamic_pointer_array_reset(&chunk->top_level_directories);
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
		uint64_t chunk_id, time_t chunk_creation_time)
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

        DBG("Chunk name set to \"%s\"", chunk->name ? : "(none)");
end:
	return chunk;
error:
	lttng_trace_chunk_put(chunk);
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
	free(chunk->name);
	chunk->name = generate_chunk_name(LTTNG_OPTIONAL_GET(chunk->id),
			LTTNG_OPTIONAL_GET(chunk->timestamp_creation),
			&close_ts);
	if (!chunk->name) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
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

static
bool is_valid_chunk_name(const char *name)
{
	size_t len;

	if (!name) {
		return false;
	}

	len = strnlen(name, LTTNG_NAME_MAX);
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
	char *new_name;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

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
	chunk->name_overridden = true;
end_unlock:	
	pthread_mutex_unlock(&chunk->lock);
end:
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
	struct lttng_directory_handle chunk_directory_handle;

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

	if (chunk->name) {
		/*
		 * A nameless chunk does not need its own output directory.
		 * The session's output directory will be used.
		 */
		ret = lttng_directory_handle_create_subdirectory_as_user(
				session_output_directory,
				chunk->name,
				DIR_CREATION_MODE,
				!chunk->credentials.value.use_current_user ?
					&chunk->credentials.value.user : NULL);
		if (ret) {
			PERROR("Failed to create chunk output directory \"%s\"",
				chunk->name);
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}
	}
	ret = lttng_directory_handle_init_from_handle(&chunk_directory_handle,
			chunk->name,
			session_output_directory);
	if (ret) {
		/* The function already logs on all error paths. */
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	LTTNG_OPTIONAL_SET(&chunk->session_output_directory,
			lttng_directory_handle_move(session_output_directory));
	LTTNG_OPTIONAL_SET(&chunk->chunk_directory,
			lttng_directory_handle_move(&chunk_directory_handle));
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
	LTTNG_OPTIONAL_SET(&chunk->chunk_directory,
			lttng_directory_handle_move(chunk_directory));
	LTTNG_OPTIONAL_SET(&chunk->mode, TRACE_CHUNK_MODE_USER);
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_get_chunk_directory_handle(
		struct lttng_trace_chunk *chunk,
		const struct lttng_directory_handle **handle)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (!chunk->chunk_directory.is_set) {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
		goto end;
	}

	*handle = &chunk->chunk_directory.value;
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
		char *copy = strndup(new_path, new_path_top_level_len);

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
	if (!chunk->chunk_directory.is_set) {
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
			&chunk->chunk_directory.value, path,
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

LTTNG_HIDDEN
enum lttng_trace_chunk_status lttng_trace_chunk_open_file(
		struct lttng_trace_chunk *chunk, const char *file_path,
		int flags, mode_t mode, int *out_fd)
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
	if (!chunk->chunk_directory.is_set) {
		ERR("Attempted to open trace chunk file \"%s\" before setting the chunk output directory",
				file_path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	ret = lttng_directory_handle_open_file_as_user(
			&chunk->chunk_directory.value, file_path, flags, mode,
			chunk->credentials.value.use_current_user ?
					NULL : &chunk->credentials.value.user);
	if (ret < 0) {
		ERR("Failed to open file relative to trace chunk file_path = \"%s\", flags = %d, mode = %d",
				file_path, flags, (int) mode);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
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
		 * directory is created.
		 */
		ERR("Credentials of trace chunk are unset: refusing to unlink file \"%s\"",
				file_path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	if (!chunk->chunk_directory.is_set) {
		ERR("Attempted to unlink trace chunk file \"%s\" before setting the chunk output directory",
				file_path);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	ret = lttng_directory_handle_unlink_file_as_user(
			&chunk->chunk_directory.value, file_path,
			chunk->credentials.value.use_current_user ?
					NULL : &chunk->credentials.value.user);
	if (ret < 0) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

static
void lttng_trace_chunk_move_to_completed(struct lttng_trace_chunk *trace_chunk)
{
	int ret;
	char *directory_to_rename = NULL;
	bool free_directory_to_rename = false;
	char *archived_chunk_name = NULL;
	const uint64_t chunk_id = LTTNG_OPTIONAL_GET(trace_chunk->id);
	const time_t creation_timestamp =
			LTTNG_OPTIONAL_GET(trace_chunk->timestamp_creation);
	const time_t close_timestamp =
			LTTNG_OPTIONAL_GET(trace_chunk->timestamp_close);
	LTTNG_OPTIONAL(struct lttng_directory_handle) archived_chunks_directory = {};

	if (!trace_chunk->mode.is_set ||
			trace_chunk->mode.value != TRACE_CHUNK_MODE_OWNER ||
			!trace_chunk->session_output_directory.is_set) {
		/*
		 * This command doesn't need to run if the output is remote
		 * or if the trace chunk is not owned by this process.
		 */
		goto end;
	}

	assert(trace_chunk->mode.value == TRACE_CHUNK_MODE_OWNER);
	assert(!trace_chunk->name_overridden);

	/*
	 * The fist trace chunk of a session is directly output to the
	 * session's output folder. In this case, the top level directories
	 * must be moved to a temporary folder before that temporary directory
	 * is renamed to match the chunk's name.
	 */
	if (chunk_id == 0) {
		struct lttng_directory_handle temporary_rename_directory;
		size_t i, count = lttng_dynamic_pointer_array_get_count(
				&trace_chunk->top_level_directories);

		ret = lttng_directory_handle_create_subdirectory_as_user(
				&trace_chunk->session_output_directory.value,
				DEFAULT_TEMPORARY_CHUNK_RENAME_DIRECTORY,
				DIR_CREATION_MODE,
				!trace_chunk->credentials.value.use_current_user ?
					&trace_chunk->credentials.value.user : NULL);
		if (ret) {
			PERROR("Failed to create temporary trace chunk rename directory \"%s\"",
					DEFAULT_TEMPORARY_CHUNK_RENAME_DIRECTORY);
		}

		ret = lttng_directory_handle_init_from_handle(&temporary_rename_directory,
				DEFAULT_TEMPORARY_CHUNK_RENAME_DIRECTORY,
				&trace_chunk->session_output_directory.value);
		if (ret) {
			ERR("Failed to get handle to temporary trace chunk rename directory");
			goto end;
		}

		for (i = 0; i < count; i++) {
			const char *top_level_name =
					lttng_dynamic_pointer_array_get_pointer(
						&trace_chunk->top_level_directories, i);

			ret = lttng_directory_handle_rename_as_user(
					&trace_chunk->session_output_directory.value,
					top_level_name,
					&temporary_rename_directory,
					top_level_name,
					LTTNG_OPTIONAL_GET(trace_chunk->credentials).use_current_user ?
						NULL :
						&trace_chunk->credentials.value.user);
			if (ret) {
				PERROR("Failed to move \"%s\" to temporary trace chunk rename directory",
						top_level_name);
				lttng_directory_handle_fini(
						&temporary_rename_directory);
				goto end;
			}
		}
		lttng_directory_handle_fini(&temporary_rename_directory);
		directory_to_rename = DEFAULT_TEMPORARY_CHUNK_RENAME_DIRECTORY;
		free_directory_to_rename = false;
	} else {
		directory_to_rename = generate_chunk_name(chunk_id,
				creation_timestamp, NULL);
		if (!directory_to_rename) {
			ERR("Failed to generate initial trace chunk name while renaming trace chunk");
		}
		free_directory_to_rename = true;
	}

	archived_chunk_name = generate_chunk_name(chunk_id, creation_timestamp,
			&close_timestamp);
	if (!archived_chunk_name) {
		ERR("Failed to generate archived trace chunk name while renaming trace chunk");
		goto end;
	}

	ret = lttng_directory_handle_create_subdirectory_as_user(
			&trace_chunk->session_output_directory.value,
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

	ret = lttng_directory_handle_init_from_handle(
			&archived_chunks_directory.value,
		        DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY,
			&trace_chunk->session_output_directory.value);
	if (ret) {
		PERROR("Failed to get handle to archived trace chunks directory");
		goto end;
	}
	archived_chunks_directory.is_set = true;

	ret = lttng_directory_handle_rename_as_user(
			&trace_chunk->session_output_directory.value,
			directory_to_rename,
			&archived_chunks_directory.value,
			archived_chunk_name,
			LTTNG_OPTIONAL_GET(trace_chunk->credentials).use_current_user ?
				NULL :
				&trace_chunk->credentials.value.user);
	if (ret) {
		PERROR("Failed to rename folder \"%s\" to \"%s\"",
				directory_to_rename, archived_chunk_name);
	}

end:
	if (archived_chunks_directory.is_set) {
		lttng_directory_handle_fini(&archived_chunks_directory.value);
	}
	free(archived_chunk_name);
	if (free_directory_to_rename) {
		free(directory_to_rename);
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
		goto end_unlock;
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
	LTTNG_OPTIONAL_SET(&chunk->close_command, close_command);
	pthread_mutex_unlock(&chunk->lock);
end_unlock:
	return status;
}

LTTNG_HIDDEN
const char *lttng_trace_chunk_command_type_get_name(
		enum lttng_trace_chunk_command_type command)
{
	switch (command) {
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED:
		return "move to completed trace chunk folder";
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
		close_command_funcs[chunk->close_command.value](chunk);
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
	goto end;
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
	if (chunk->session_output_directory.is_set) {
		element->chunk.session_output_directory.value =
				lttng_directory_handle_move(
					&chunk->session_output_directory.value);
	}
	if (chunk->chunk_directory.is_set) {
		element->chunk.chunk_directory.value =
				lttng_directory_handle_move(
					&chunk->chunk_directory.value);
	}
	/*
	 * The original chunk becomes invalid; the name attribute is transferred
	 * to the new chunk instance.
	 */
	chunk->name = NULL;
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
				ERR("Attemp to publish a trace chunk to the chunk registry raced with a trace chunk deletion");
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
struct lttng_trace_chunk *
lttng_trace_chunk_registry_find_anonymous_chunk(
		const struct lttng_trace_chunk_registry *registry,
		uint64_t session_id)
{
        return _lttng_trace_chunk_registry_find_chunk(registry,
			session_id, NULL);
}

unsigned int lttng_trace_chunk_registry_put_each_chunk(
		struct lttng_trace_chunk_registry *registry)
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
