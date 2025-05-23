/*
 * SPDX-FileCopyrightText: 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/compat/directory-handle.hpp>
#include <common/credentials.hpp>
#include <common/defaults.hpp>
#include <common/dynamic-array.hpp>
#include <common/error.hpp>
#include <common/fd-tracker/fd-tracker.hpp>
#include <common/fd-tracker/utils.hpp>
#include <common/fs-handle-internal.hpp>
#include <common/fs-handle.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/hashtable/utils.hpp>
#include <common/optional.hpp>
#include <common/string-utils/format.hpp>
#include <common/time.hpp>
#include <common/trace-chunk-registry.hpp>
#include <common/trace-chunk.hpp>
#include <common/urcu.hpp>
#include <common/utils.hpp>

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
#define DIR_CREATION_MODE	 (S_IRWXU | S_IRWXG)

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
using chunk_command = int (*)(struct lttng_trace_chunk *);

/* Move a completed trace chunk to the 'completed' trace archive folder. */
static int lttng_trace_chunk_move_to_completed_post_release(struct lttng_trace_chunk *trace_chunk);
/* Empty callback. */
static int lttng_trace_chunk_no_operation(struct lttng_trace_chunk *trace_chunk);
/* Unlink old chunk files. */
static int lttng_trace_chunk_delete_post_release(struct lttng_trace_chunk *trace_chunk);
static enum lttng_trace_chunk_status
lttng_trace_chunk_rename_path_no_lock(struct lttng_trace_chunk *chunk, const char *path);

namespace {
struct chunk_credentials {
	bool use_current_user;
	struct lttng_credentials user;
};
} /* namespace */

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

	/*
	 * The creation and close timestamps are NOT monotonic.
	 * They must not be used in context were monotonicity is required.
	 */
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

namespace {
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
} /* namespace */

struct lttng_trace_chunk_registry {
	struct cds_lfht *ht;
};

namespace {
struct fs_handle_untracked {
	struct fs_handle parent;
	int fd;
	struct {
		struct lttng_directory_handle *directory_handle;
		char *path;
	} location;
};
} /* namespace */

static int fs_handle_untracked_get_fd(struct fs_handle *handle);
static void fs_handle_untracked_put_fd(struct fs_handle *handle);
static int fs_handle_untracked_unlink(struct fs_handle *handle);
static int fs_handle_untracked_close(struct fs_handle *handle);

static const char *lttng_trace_chunk_command_type_str(lttng_trace_chunk_command_type type)
{
	switch (type) {
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED:
		return "move to completed chunk folder";
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_NO_OPERATION:
		return "no operation";
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE:
		return "delete";
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_MAX:
		abort();
	}

	abort();
};

static chunk_command close_command_get_post_release_func(lttng_trace_chunk_command_type type)
{
	switch (type) {
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_MOVE_TO_COMPLETED:
		return lttng_trace_chunk_move_to_completed_post_release;
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_NO_OPERATION:
		return lttng_trace_chunk_no_operation;
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE:
		return lttng_trace_chunk_delete_post_release;
	case LTTNG_TRACE_CHUNK_COMMAND_TYPE_MAX:
		abort();
	}

	abort();
};

static struct fs_handle *fs_handle_untracked_create(struct lttng_directory_handle *directory_handle,
						    const char *path,
						    int fd)
{
	struct fs_handle_untracked *handle = nullptr;
	bool reference_acquired;
	char *path_copy = strdup(path);

	LTTNG_ASSERT(fd >= 0);
	if (!path_copy) {
		PERROR("Failed to copy file path while creating untracked filesystem handle");
		goto end;
	}

	handle = zmalloc<fs_handle_untracked>();
	if (!handle) {
		PERROR("Failed to allocate untracked filesystem handle");
		goto end;
	}

	handle->parent = (typeof(handle->parent)){
		.get_fd = fs_handle_untracked_get_fd,
		.put_fd = fs_handle_untracked_put_fd,
		.unlink = fs_handle_untracked_unlink,
		.close = fs_handle_untracked_close,
	};

	handle->fd = fd;
	reference_acquired = lttng_directory_handle_get(directory_handle);
	LTTNG_ASSERT(reference_acquired);
	handle->location.directory_handle = directory_handle;
	/* Ownership is transferred. */
	handle->location.path = path_copy;
	path_copy = nullptr;
end:
	free(path_copy);
	return handle ? &handle->parent : nullptr;
}

static int fs_handle_untracked_get_fd(struct fs_handle *_handle)
{
	struct fs_handle_untracked *handle =
		lttng::utils::container_of(_handle, &fs_handle_untracked::parent);

	return handle->fd;
}

static void fs_handle_untracked_put_fd(struct fs_handle *_handle __attribute__((unused)))
{
	/* no-op. */
}

static int fs_handle_untracked_unlink(struct fs_handle *_handle)
{
	struct fs_handle_untracked *handle =
		lttng::utils::container_of(_handle, &fs_handle_untracked::parent);

	return lttng_directory_handle_unlink_file(handle->location.directory_handle,
						  handle->location.path);
}

static void fs_handle_untracked_destroy(struct fs_handle_untracked *handle)
{
	lttng_directory_handle_put(handle->location.directory_handle);
	free(handle->location.path);
	free(handle);
}

static int fs_handle_untracked_close(struct fs_handle *_handle)
{
	struct fs_handle_untracked *handle =
		lttng::utils::container_of(_handle, &fs_handle_untracked::parent);
	const int ret = close(handle->fd);

	fs_handle_untracked_destroy(handle);
	return ret;
}

static bool
lttng_trace_chunk_registry_element_equals(const struct lttng_trace_chunk_registry_element *a,
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

static int lttng_trace_chunk_registry_element_match(struct cds_lfht_node *node, const void *key)
{
	const struct lttng_trace_chunk_registry_element *element_a, *element_b;

	element_a = (const struct lttng_trace_chunk_registry_element *) key;
	element_b = caa_container_of(node, typeof(*element_b), trace_chunk_registry_ht_node);
	return lttng_trace_chunk_registry_element_equals(element_a, element_b);
}

static unsigned long
lttng_trace_chunk_registry_element_hash(const struct lttng_trace_chunk_registry_element *element)
{
	unsigned long hash = hash_key_u64(&element->session_id, lttng_ht_seed);

	if (element->chunk.id.is_set) {
		hash ^= hash_key_u64(&element->chunk.id.value, lttng_ht_seed);
	}

	return hash;
}

static char *
generate_chunk_name(uint64_t chunk_id, time_t creation_timestamp, const time_t *close_timestamp)
{
	int ret = 0;
	char *new_name = nullptr;
	char start_datetime[ISO8601_STR_LEN] = {};
	/* Add 1 for a '-' prefix. */
	char end_datetime_suffix[ISO8601_STR_LEN + 1] = {};

	ret = time_to_iso8601_str(creation_timestamp, start_datetime, sizeof(start_datetime));
	if (ret) {
		ERR("Failed to format trace chunk start date time");
		goto error;
	}
	if (close_timestamp) {
		*end_datetime_suffix = '-';
		ret = time_to_iso8601_str(
			*close_timestamp, end_datetime_suffix + 1, sizeof(end_datetime_suffix) - 1);
		if (ret) {
			ERR("Failed to format trace chunk end date time");
			goto error;
		}
	}
	new_name = calloc<char>(GENERATED_CHUNK_NAME_LEN);
	if (!new_name) {
		ERR("Failed to allocate buffer for automatically-generated trace chunk name");
		goto error;
	}
	ret = snprintf(new_name,
		       GENERATED_CHUNK_NAME_LEN,
		       "%s%s-%" PRIu64,
		       start_datetime,
		       end_datetime_suffix,
		       chunk_id);
	if (ret >= GENERATED_CHUNK_NAME_LEN || ret == -1) {
		ERR("Failed to format trace chunk name");
		goto error;
	}

	return new_name;
error:
	free(new_name);
	return nullptr;
}

static void lttng_trace_chunk_init(struct lttng_trace_chunk *chunk)
{
	urcu_ref_init(&chunk->ref);
	pthread_mutex_init(&chunk->lock, nullptr);
	lttng_dynamic_pointer_array_init(&chunk->top_level_directories, free);
	lttng_dynamic_pointer_array_init(&chunk->files, free);
}

static void lttng_trace_chunk_fini(struct lttng_trace_chunk *chunk)
{
	if (chunk->session_output_directory) {
		lttng_directory_handle_put(chunk->session_output_directory);
		chunk->session_output_directory = nullptr;
	}
	if (chunk->chunk_directory) {
		lttng_directory_handle_put(chunk->chunk_directory);
		chunk->chunk_directory = nullptr;
	}
	free(chunk->name);
	chunk->name = nullptr;
	free(chunk->path);
	chunk->path = nullptr;
	lttng_dynamic_pointer_array_reset(&chunk->top_level_directories);
	lttng_dynamic_pointer_array_reset(&chunk->files);
	pthread_mutex_destroy(&chunk->lock);
}

static struct lttng_trace_chunk *lttng_trace_chunk_allocate()
{
	struct lttng_trace_chunk *chunk = nullptr;

	chunk = zmalloc<lttng_trace_chunk>();
	if (!chunk) {
		ERR("Failed to allocate trace chunk");
		goto end;
	}
	lttng_trace_chunk_init(chunk);
end:
	return chunk;
}

struct lttng_trace_chunk *lttng_trace_chunk_create_anonymous()
{
	DBG("Creating anonymous trace chunk");
	return lttng_trace_chunk_allocate();
}

struct lttng_trace_chunk *
lttng_trace_chunk_create(uint64_t chunk_id, time_t chunk_creation_time, const char *path)
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
					"%Y%m%d-%H%M%S",
					timeinfo);
		if (strftime_ret) {
			chunk_creation_datetime_str = chunk_creation_datetime_buf;
		}
	}

	DBG("Creating trace chunk: chunk_id = %" PRIu64 ", creation time = %s",
	    chunk_id,
	    chunk_creation_datetime_str);
	chunk = lttng_trace_chunk_allocate();
	if (!chunk) {
		goto end;
	}

	LTTNG_OPTIONAL_SET(&chunk->id, chunk_id);
	LTTNG_OPTIONAL_SET(&chunk->timestamp_creation, chunk_creation_time);
	if (chunk_id != 0) {
		chunk->name = generate_chunk_name(chunk_id, chunk_creation_time, nullptr);
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

	DBG("Chunk name set to \"%s\"", chunk->name ?: "(none)");
end:
	return chunk;
error:
	lttng_trace_chunk_put(chunk);
	return nullptr;
}

void lttng_trace_chunk_set_fd_tracker(struct lttng_trace_chunk *chunk,
				      struct fd_tracker *fd_tracker)
{
	LTTNG_ASSERT(!chunk->session_output_directory);
	LTTNG_ASSERT(!chunk->chunk_directory);
	LTTNG_ASSERT(lttng_dynamic_pointer_array_get_count(&chunk->files) == 0);
	chunk->fd_tracker = fd_tracker;
}

struct lttng_trace_chunk *lttng_trace_chunk_copy(struct lttng_trace_chunk *source_chunk)
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
	new_chunk->mode = (typeof(new_chunk->mode)){
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
			ERR("Failed to copy source trace chunk name in %s()", __FUNCTION__);
			goto error_unlock;
		}
	}
	if (source_chunk->path) {
		new_chunk->path = strdup(source_chunk->path);
		if (!new_chunk->path) {
			ERR("Failed to copy source trace chunk path in %s()", __FUNCTION__);
		}
	}
	new_chunk->id = source_chunk->id;
	new_chunk->timestamp_creation = source_chunk->timestamp_creation;
	new_chunk->timestamp_close = source_chunk->timestamp_close;
	new_chunk->credentials = source_chunk->credentials;
	if (source_chunk->session_output_directory) {
		const bool reference_acquired =
			lttng_directory_handle_get(source_chunk->session_output_directory);

		LTTNG_ASSERT(reference_acquired);
		new_chunk->session_output_directory = source_chunk->session_output_directory;
	}
	if (source_chunk->chunk_directory) {
		const bool reference_acquired =
			lttng_directory_handle_get(source_chunk->chunk_directory);

		LTTNG_ASSERT(reference_acquired);
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
	return nullptr;
}

enum lttng_trace_chunk_status lttng_trace_chunk_get_id(struct lttng_trace_chunk *chunk,
						       uint64_t *id)
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

enum lttng_trace_chunk_status
lttng_trace_chunk_get_creation_timestamp(struct lttng_trace_chunk *chunk, time_t *creation_ts)

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

enum lttng_trace_chunk_status lttng_trace_chunk_get_close_timestamp(struct lttng_trace_chunk *chunk,
								    time_t *close_ts)
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

enum lttng_trace_chunk_status lttng_trace_chunk_set_close_timestamp(struct lttng_trace_chunk *chunk,
								    time_t close_ts)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (!chunk->timestamp_creation.is_set) {
		ERR("Failed to set trace chunk close timestamp: creation timestamp is unset");
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_OPERATION;
		goto end;
	}

	/*
	 * Note: we do not enforce that the closing timestamp be greater or
	 * equal to the begin timestamp. These timestamps are used for
	 * generating the chunk name and should only be used in context where
	 * the monotonicity of time is not important. The source of those
	 * timestamps is NOT monotonic and represent the system calendar time,
	 * also know as the wall time.
	 */
	if (chunk->timestamp_creation.value > close_ts) {
		WARN("Set trace chunk close timestamp: close timestamp is before creation timestamp, begin : %ld, close : %ld",
		     chunk->timestamp_creation.value,
		     close_ts);
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

enum lttng_trace_chunk_status lttng_trace_chunk_get_name(struct lttng_trace_chunk *chunk,
							 const char **name,
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

bool lttng_trace_chunk_get_name_overridden(struct lttng_trace_chunk *chunk)
{
	bool name_overridden;

	pthread_mutex_lock(&chunk->lock);
	name_overridden = chunk->name_overridden;
	pthread_mutex_unlock(&chunk->lock);
	return name_overridden;
}

static bool is_valid_chunk_name(const char *name)
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

enum lttng_trace_chunk_status lttng_trace_chunk_override_name(struct lttng_trace_chunk *chunk,
							      const char *name)

{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	char *new_name, *new_path;

	DBG("Override trace chunk name from %s to %s", chunk->name, name);
	if (!is_valid_chunk_name(name)) {
		ERR("Attempted to set an invalid name on a trace chunk: name = %s", name ?: "NULL");
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

static enum lttng_trace_chunk_status
lttng_trace_chunk_rename_path_no_lock(struct lttng_trace_chunk *chunk, const char *path)

{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	struct lttng_directory_handle *rename_directory = nullptr;
	char *new_path, *old_path;
	int ret;

	if (chunk->name_overridden) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}

	old_path = chunk->path;
	DBG("lttng_trace_chunk_rename_path from %s to %s", old_path, path);

	if ((!old_path && !path) || (old_path && path && !strcmp(old_path, path))) {
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
	if (!chunk->chunk_directory || !chunk->session_output_directory) {
		goto skip_move;
	}

	if (old_path && old_path[0] != '\0' && path[0] != '\0') {
		/* Rename chunk directory. */
		ret = lttng_directory_handle_rename_as_user(
			chunk->session_output_directory,
			old_path,
			chunk->session_output_directory,
			path,
			LTTNG_OPTIONAL_GET(chunk->credentials).use_current_user ?
				nullptr :
				&chunk->credentials.value.user);
		if (ret) {
			PERROR("Failed to move trace chunk directory \"%s\" to \"%s\"",
			       old_path,
			       path);
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}
		rename_directory = chunk->fd_tracker ?
			fd_tracker_create_directory_handle_from_handle(
				chunk->fd_tracker, chunk->session_output_directory, path) :
			lttng_directory_handle_create_from_handle(path,
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
		rename_directory = nullptr;
	} else if (old_path && old_path[0] == '\0') {
		size_t i,
			count = lttng_dynamic_pointer_array_get_count(
				&chunk->top_level_directories);

		ret = lttng_directory_handle_create_subdirectory_as_user(
			chunk->session_output_directory,
			path,
			DIR_CREATION_MODE,
			LTTNG_OPTIONAL_GET(chunk->credentials).use_current_user ?
				nullptr :
				&chunk->credentials.value.user);
		if (ret) {
			PERROR("Failed to create trace chunk rename directory \"%s\"", path);
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
				(const char *) lttng_dynamic_pointer_array_get_pointer(
					&chunk->top_level_directories, i);

			ret = lttng_directory_handle_rename_as_user(
				chunk->chunk_directory,
				top_level_name,
				rename_directory,
				top_level_name,
				LTTNG_OPTIONAL_GET(chunk->credentials).use_current_user ?
					nullptr :
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
		rename_directory = nullptr;
	} else if (old_path) {
		size_t i,
			count = lttng_dynamic_pointer_array_get_count(
				&chunk->top_level_directories);
		const bool reference_acquired =
			lttng_directory_handle_get(chunk->session_output_directory);

		LTTNG_ASSERT(reference_acquired);
		rename_directory = chunk->session_output_directory;

		/* Move toplevel directories. */
		for (i = 0; i < count; i++) {
			const char *top_level_name =
				(const char *) lttng_dynamic_pointer_array_get_pointer(
					&chunk->top_level_directories, i);

			ret = lttng_directory_handle_rename_as_user(
				chunk->chunk_directory,
				top_level_name,
				rename_directory,
				top_level_name,
				LTTNG_OPTIONAL_GET(chunk->credentials).use_current_user ?
					nullptr :
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
		rename_directory = nullptr;

		/* Remove old directory. */
		status = (lttng_trace_chunk_status) lttng_directory_handle_remove_subdirectory(
			chunk->session_output_directory, old_path);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Error removing subdirectory '%s' file when deleting chunk", old_path);
			goto end;
		}
	} else {
		/* Unexpected !old_path && !path. */
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_ARGUMENT;
		goto end;
	}

skip_move:
	new_path = strdup(path);
	if (!new_path) {
		ERR("Failed to allocate new trace chunk path");
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	free(chunk->path);
	chunk->path = new_path;
end:
	lttng_directory_handle_put(rename_directory);
	return status;
}

enum lttng_trace_chunk_status lttng_trace_chunk_rename_path(struct lttng_trace_chunk *chunk,
							    const char *path)

{
	enum lttng_trace_chunk_status status;

	pthread_mutex_lock(&chunk->lock);
	status = lttng_trace_chunk_rename_path_no_lock(chunk, path);
	pthread_mutex_unlock(&chunk->lock);

	return status;
}

enum lttng_trace_chunk_status
lttng_trace_chunk_get_credentials(struct lttng_trace_chunk *chunk,
				  struct lttng_credentials *credentials)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (chunk->credentials.is_set) {
		if (chunk->credentials.value.use_current_user) {
			LTTNG_OPTIONAL_SET(&credentials->uid, geteuid());
			LTTNG_OPTIONAL_SET(&credentials->gid, getegid());
		} else {
			*credentials = chunk->credentials.value.user;
		}
	} else {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
	}
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

enum lttng_trace_chunk_status
lttng_trace_chunk_set_credentials(struct lttng_trace_chunk *chunk,
				  const struct lttng_credentials *user_credentials)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	const struct chunk_credentials credentials = {
		.use_current_user = false,
		.user = *user_credentials,
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

enum lttng_trace_chunk_status
lttng_trace_chunk_set_credentials_current_user(struct lttng_trace_chunk *chunk)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	const struct chunk_credentials credentials = {
		.use_current_user = true,
		.user = {},
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

enum lttng_trace_chunk_status
lttng_trace_chunk_set_as_owner(struct lttng_trace_chunk *chunk,
			       struct lttng_directory_handle *session_output_directory)
{
	int ret;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;
	struct lttng_directory_handle *chunk_directory_handle = nullptr;
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
	if (chunk->path && chunk->path[0] != '\0') {
		ret = lttng_directory_handle_create_subdirectory_as_user(
			session_output_directory,
			chunk->path,
			DIR_CREATION_MODE,
			!chunk->credentials.value.use_current_user ?
				&chunk->credentials.value.user :
				nullptr);
		if (ret) {
			PERROR("Failed to create chunk output directory \"%s\"", chunk->path);
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
			goto end;
		}
		chunk_directory_handle = chunk->fd_tracker ?
			fd_tracker_create_directory_handle_from_handle(
				chunk->fd_tracker, session_output_directory, chunk->path) :
			lttng_directory_handle_create_from_handle(chunk->path,
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
		reference_acquired = lttng_directory_handle_get(session_output_directory);

		LTTNG_ASSERT(reference_acquired);
		chunk_directory_handle = session_output_directory;
	}
	chunk->chunk_directory = chunk_directory_handle;
	chunk_directory_handle = nullptr;
	reference_acquired = lttng_directory_handle_get(session_output_directory);
	LTTNG_ASSERT(reference_acquired);
	chunk->session_output_directory = session_output_directory;
	LTTNG_OPTIONAL_SET(&chunk->mode, TRACE_CHUNK_MODE_OWNER);
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

enum lttng_trace_chunk_status
lttng_trace_chunk_set_as_user(struct lttng_trace_chunk *chunk,
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
	LTTNG_ASSERT(reference_acquired);
	chunk->chunk_directory = chunk_directory;
	LTTNG_OPTIONAL_SET(&chunk->mode, TRACE_CHUNK_MODE_USER);
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

enum lttng_trace_chunk_status
lttng_trace_chunk_get_session_output_directory_handle(struct lttng_trace_chunk *chunk,
						      struct lttng_directory_handle **handle)
{
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	pthread_mutex_lock(&chunk->lock);
	if (!chunk->session_output_directory) {
		status = LTTNG_TRACE_CHUNK_STATUS_NONE;
		*handle = nullptr;
		goto end;
	} else {
		const bool reference_acquired =
			lttng_directory_handle_get(chunk->session_output_directory);

		LTTNG_ASSERT(reference_acquired);
		*handle = chunk->session_output_directory;
	}
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

enum lttng_trace_chunk_status
lttng_trace_chunk_borrow_chunk_directory_handle(struct lttng_trace_chunk *chunk,
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
static int add_top_level_directory_unique(struct lttng_trace_chunk *chunk, const char *new_path)
{
	int ret = 0;
	bool found = false;
	size_t i, count = lttng_dynamic_pointer_array_get_count(&chunk->top_level_directories);
	const char *new_path_separator_pos = strchr(new_path, '/');
	const ptrdiff_t new_path_top_level_len =
		new_path_separator_pos ? new_path_separator_pos - new_path : strlen(new_path);

	for (i = 0; i < count; i++) {
		const char *path = (const char *) lttng_dynamic_pointer_array_get_pointer(
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
		    new_path,
		    chunk->name ?: "(unnamed)");
		if (!copy) {
			PERROR("Failed to copy path");
			ret = -1;
			goto end;
		}
		ret = lttng_dynamic_pointer_array_add_pointer(&chunk->top_level_directories, copy);
		if (ret) {
			ERR("Allocation failure while adding top-level directory entry to a trace chunk");
			free(copy);
			goto end;
		}
	}
end:
	return ret;
}

enum lttng_trace_chunk_status lttng_trace_chunk_create_subdirectory(struct lttng_trace_chunk *chunk,
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
	if (!chunk->mode.is_set || chunk->mode.value != TRACE_CHUNK_MODE_OWNER) {
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
		ERR("Refusing to create absolute trace chunk directory \"%s\"", path);
		status = LTTNG_TRACE_CHUNK_STATUS_INVALID_ARGUMENT;
		goto end;
	}
	ret = lttng_directory_handle_create_subdirectory_recursive_as_user(
		chunk->chunk_directory,
		path,
		DIR_CREATION_MODE,
		chunk->credentials.value.use_current_user ? nullptr :
							    &chunk->credentials.value.user);
	if (ret) {
		PERROR("Failed to create trace chunk subdirectory \"%s\"", path);
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
static bool
lttng_trace_chunk_find_file(struct lttng_trace_chunk *chunk, const char *path, size_t *index)
{
	size_t i, count;

	count = lttng_dynamic_pointer_array_get_count(&chunk->files);
	for (i = 0; i < count; i++) {
		const char *iter_path =
			(const char *) lttng_dynamic_pointer_array_get_pointer(&chunk->files, i);
		if (!strcmp(iter_path, path)) {
			if (index) {
				*index = i;
			}
			return true;
		}
	}
	return false;
}

static enum lttng_trace_chunk_status lttng_trace_chunk_add_file(struct lttng_trace_chunk *chunk,
								const char *path)
{
	char *copy;
	int ret;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	if (lttng_trace_chunk_find_file(chunk, path, nullptr)) {
		return LTTNG_TRACE_CHUNK_STATUS_OK;
	}
	DBG("Adding new file \"%s\" to trace chunk \"%s\"", path, chunk->name ?: "(unnamed)");
	copy = strdup(path);
	if (!copy) {
		PERROR("Failed to copy path");
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	ret = lttng_dynamic_pointer_array_add_pointer(&chunk->files, copy);
	if (ret) {
		ERR("Allocation failure while adding file to a trace chunk");
		free(copy);
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
end:
	return status;
}

static void lttng_trace_chunk_remove_file(struct lttng_trace_chunk *chunk, const char *path)
{
	size_t index;
	bool found;
	int ret;

	found = lttng_trace_chunk_find_file(chunk, path, &index);
	if (!found) {
		return;
	}
	ret = lttng_dynamic_pointer_array_remove_pointer(&chunk->files, index);
	LTTNG_ASSERT(!ret);
}

static enum lttng_trace_chunk_status
_lttng_trace_chunk_open_fs_handle_locked(struct lttng_trace_chunk *chunk,
					 const char *file_path,
					 int flags,
					 mode_t mode,
					 struct fs_handle **out_handle,
					 bool expect_no_file)
{
	int ret;
	enum lttng_trace_chunk_status status = LTTNG_TRACE_CHUNK_STATUS_OK;

	DBG("Opening trace chunk file \"%s\"", file_path);
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
	if (chunk->fd_tracker) {
		LTTNG_ASSERT(chunk->credentials.value.use_current_user);
		*out_handle = fd_tracker_open_fs_handle(
			chunk->fd_tracker, chunk->chunk_directory, file_path, flags, &mode);
		ret = *out_handle ? 0 : -1;
	} else {
		ret = lttng_directory_handle_open_file_as_user(
			chunk->chunk_directory,
			file_path,
			flags,
			mode,
			chunk->credentials.value.use_current_user ? nullptr :
								    &chunk->credentials.value.user);
		if (ret >= 0) {
			*out_handle =
				fs_handle_untracked_create(chunk->chunk_directory, file_path, ret);
			if (!*out_handle) {
				status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
				goto end;
			}
		}
	}
	if (ret < 0) {
		if (errno == ENOENT && expect_no_file) {
			status = LTTNG_TRACE_CHUNK_STATUS_NO_FILE;
		} else {
			PERROR("Failed to open file relative to trace chunk file_path = \"%s\", flags = %d, mode = %d",
			       file_path,
			       flags,
			       (int) mode);
			status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		}
		lttng_trace_chunk_remove_file(chunk, file_path);
		goto end;
	}
end:
	return status;
}

enum lttng_trace_chunk_status lttng_trace_chunk_open_fs_handle(struct lttng_trace_chunk *chunk,
							       const char *file_path,
							       int flags,
							       mode_t mode,
							       struct fs_handle **out_handle,
							       bool expect_no_file)
{
	enum lttng_trace_chunk_status status;

	pthread_mutex_lock(&chunk->lock);
	status = _lttng_trace_chunk_open_fs_handle_locked(
		chunk, file_path, flags, mode, out_handle, expect_no_file);
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

enum lttng_trace_chunk_status lttng_trace_chunk_open_file(struct lttng_trace_chunk *chunk,
							  const char *file_path,
							  int flags,
							  mode_t mode,
							  int *out_fd,
							  bool expect_no_file)
{
	enum lttng_trace_chunk_status status;
	struct fs_handle *fs_handle;

	pthread_mutex_lock(&chunk->lock);
	/*
	 * Using this method is never valid when an fd_tracker is being
	 * used since the resulting file descriptor would not be tracked.
	 */
	LTTNG_ASSERT(!chunk->fd_tracker);
	status = _lttng_trace_chunk_open_fs_handle_locked(
		chunk, file_path, flags, mode, &fs_handle, expect_no_file);
	pthread_mutex_unlock(&chunk->lock);

	if (status == LTTNG_TRACE_CHUNK_STATUS_OK) {
		*out_fd = fs_handle_get_fd(fs_handle);
		/*
		 * Does not close the fd; we just "unbox" it from the fs_handle.
		 */
		fs_handle_untracked_destroy(
			lttng::utils::container_of(fs_handle, &fs_handle_untracked::parent));
	}

	return status;
}

int lttng_trace_chunk_unlink_file(struct lttng_trace_chunk *chunk, const char *file_path)
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
	ret = lttng_directory_handle_unlink_file_as_user(chunk->chunk_directory,
							 file_path,
							 chunk->credentials.value.use_current_user ?
								 nullptr :
								 &chunk->credentials.value.user);
	if (ret < 0) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
	lttng_trace_chunk_remove_file(chunk, file_path);
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

static int lttng_trace_chunk_remove_subdirectory_recursive(struct lttng_trace_chunk *chunk,
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
		chunk->chunk_directory,
		path,
		chunk->credentials.value.use_current_user ? nullptr :
							    &chunk->credentials.value.user,
		LTTNG_DIRECTORY_HANDLE_SKIP_NON_EMPTY_FLAG);
	if (ret < 0) {
		status = LTTNG_TRACE_CHUNK_STATUS_ERROR;
		goto end;
	}
end:
	pthread_mutex_unlock(&chunk->lock);
	return status;
}

static int lttng_trace_chunk_move_to_completed_post_release(struct lttng_trace_chunk *trace_chunk)
{
	int ret = 0;
	char *archived_chunk_name = nullptr;
	const uint64_t chunk_id = LTTNG_OPTIONAL_GET(trace_chunk->id);
	const time_t creation_timestamp = LTTNG_OPTIONAL_GET(trace_chunk->timestamp_creation);
	const time_t close_timestamp = LTTNG_OPTIONAL_GET(trace_chunk->timestamp_close);
	struct lttng_directory_handle *archived_chunks_directory = nullptr;
	enum lttng_trace_chunk_status status;

	if (!trace_chunk->mode.is_set || trace_chunk->mode.value != TRACE_CHUNK_MODE_OWNER ||
	    !trace_chunk->session_output_directory) {
		/*
		 * This command doesn't need to run if the output is remote
		 * or if the trace chunk is not owned by this process.
		 */
		goto end;
	}

	LTTNG_ASSERT(trace_chunk->mode.value == TRACE_CHUNK_MODE_OWNER);
	LTTNG_ASSERT(!trace_chunk->name_overridden);
	LTTNG_ASSERT(trace_chunk->path);

	archived_chunk_name = generate_chunk_name(chunk_id, creation_timestamp, &close_timestamp);
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
			nullptr);
	if (ret) {
		PERROR("Failed to create \"" DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY
		       "\" directory for archived trace chunks");
		goto end;
	}

	archived_chunks_directory = trace_chunk->fd_tracker ?
		fd_tracker_create_directory_handle_from_handle(
			trace_chunk->fd_tracker,
			trace_chunk->session_output_directory,
			DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY) :
		lttng_directory_handle_create_from_handle(DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY,
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
	if (!trace_chunk->path || strcmp(trace_chunk->path, DEFAULT_CHUNK_TMP_OLD_DIRECTORY) != 0) {
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
			nullptr :
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

static int lttng_trace_chunk_no_operation(struct lttng_trace_chunk *trace_chunk
					  __attribute__((unused)))
{
	return 0;
}

static int lttng_trace_chunk_delete_post_release_user(struct lttng_trace_chunk *trace_chunk)
{
	int ret = 0;

	DBG("Trace chunk \"delete\" close command post-release (User)");

	/* Unlink all files. */
	while (lttng_dynamic_pointer_array_get_count(&trace_chunk->files) != 0) {
		enum lttng_trace_chunk_status status;
		const char *path;

		/* Remove first. */
		path = (const char *) lttng_dynamic_pointer_array_get_pointer(&trace_chunk->files,
									      0);
		DBG("Unlink file: %s", path);
		status =
			(lttng_trace_chunk_status) lttng_trace_chunk_unlink_file(trace_chunk, path);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Error unlinking file '%s' when deleting chunk", path);
			ret = -1;
			goto end;
		}
	}
end:
	return ret;
}

static int lttng_trace_chunk_delete_post_release_owner(struct lttng_trace_chunk *trace_chunk)
{
	enum lttng_trace_chunk_status status;
	size_t i, count;
	int ret = 0;

	ret = lttng_trace_chunk_delete_post_release_user(trace_chunk);
	if (ret) {
		goto end;
	}

	DBG("Trace chunk \"delete\" close command post-release (Owner)");

	LTTNG_ASSERT(trace_chunk->session_output_directory);
	LTTNG_ASSERT(trace_chunk->chunk_directory);

	/* Remove empty directories. */
	count = lttng_dynamic_pointer_array_get_count(&trace_chunk->top_level_directories);

	for (i = 0; i < count; i++) {
		const char *top_level_name = (const char *) lttng_dynamic_pointer_array_get_pointer(
			&trace_chunk->top_level_directories, i);

		status = (lttng_trace_chunk_status) lttng_trace_chunk_remove_subdirectory_recursive(
			trace_chunk, top_level_name);
		if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ERR("Error recursively removing subdirectory '%s' file when deleting chunk",
			    top_level_name);
			ret = -1;
			break;
		}
	}
	if (!ret) {
		lttng_directory_handle_put(trace_chunk->chunk_directory);
		trace_chunk->chunk_directory = nullptr;

		if (trace_chunk->path && trace_chunk->path[0] != '\0') {
			status = (lttng_trace_chunk_status)
				lttng_directory_handle_remove_subdirectory(
					trace_chunk->session_output_directory, trace_chunk->path);
			if (status != LTTNG_TRACE_CHUNK_STATUS_OK) {
				ERR("Error removing subdirectory '%s' file when deleting chunk",
				    trace_chunk->path);
				ret = -1;
			}
		}
	}
	free(trace_chunk->path);
	trace_chunk->path = nullptr;
end:
	return ret;
}

/*
 * For local files, session and consumer daemons all run the delete hook. The
 * consumer daemons have the list of files to unlink, and technically the
 * session daemon is the owner of the chunk. Unlink all files owned by each
 * consumer daemon.
 */
static int lttng_trace_chunk_delete_post_release(struct lttng_trace_chunk *trace_chunk)
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

enum lttng_trace_chunk_status
lttng_trace_chunk_get_close_command(struct lttng_trace_chunk *chunk,
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

enum lttng_trace_chunk_status
lttng_trace_chunk_set_close_command(struct lttng_trace_chunk *chunk,
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
		    lttng_trace_chunk_command_type_str(chunk->close_command.value),
		    lttng_trace_chunk_command_type_str(close_command));
	} else {
		DBG("Setting trace chunk close command to \"%s\"",
		    lttng_trace_chunk_command_type_str(close_command));
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

const char *lttng_trace_chunk_command_type_get_name(enum lttng_trace_chunk_command_type command)
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

bool lttng_trace_chunk_ids_equal(const struct lttng_trace_chunk *chunk_a,
				 const struct lttng_trace_chunk *chunk_b)
{
	bool equal = false;

	if (chunk_a == chunk_b) {
		equal = true;
		goto end;
	}

	if (!!chunk_a ^ !!chunk_b) {
		goto end;
	}

	if (chunk_a->id.is_set ^ chunk_a->id.is_set) {
		/* One id is set and not the other, thus they are not equal. */
		goto end;
	}

	if (!chunk_a->id.is_set) {
		/* Both ids are unset. */
		equal = true;
	} else {
		equal = chunk_a->id.value == chunk_b->id.value;
	}

end:
	return equal;
}

bool lttng_trace_chunk_get(struct lttng_trace_chunk *chunk)
{
	return urcu_ref_get_unless_zero(&chunk->ref);
}

static void free_lttng_trace_chunk_registry_element(struct rcu_head *node)
{
	struct lttng_trace_chunk_registry_element *element =
		lttng::utils::container_of(node, &lttng_trace_chunk_registry_element::rcu_node);

	free(element);
}

static void lttng_trace_chunk_release(struct urcu_ref *ref)
{
	struct lttng_trace_chunk *chunk = lttng::utils::container_of(ref, &lttng_trace_chunk::ref);

	if (chunk->close_command.is_set) {
		chunk_command func =
			close_command_get_post_release_func(chunk->close_command.value);

		if (func(chunk)) {
			ERR("Trace chunk post-release command %s has failed.",
			    lttng_trace_chunk_command_type_str(chunk->close_command.value));
		}
	}

	if (chunk->in_registry_element) {
		struct lttng_trace_chunk_registry_element *element;

		/*
		 * Release internal chunk attributes immediately and
		 * only use the deferred `call_rcu` work to reclaim the
		 * storage.
		 *
		 * This ensures that file handles are released as soon as
		 * possible which works around a problem we encounter with PRAM fs
		 * mounts (and possibly other non-POSIX compliant file systems):
		 * directories that contain files which are open can't be
		 * rmdir().
		 *
		 * This means that the recording of a snapshot could be
		 * completed, but that it would be impossible for the user to
		 * delete it until the deferred clean-up released the file
		 * handles to its contents.
		 */
		lttng_trace_chunk_fini(chunk);

		element = lttng::utils::container_of(chunk,
						     &lttng_trace_chunk_registry_element::chunk);
		if (element->registry) {
			const lttng::urcu::read_lock_guard read_lock;
			cds_lfht_del(element->registry->ht, &element->trace_chunk_registry_ht_node);
			call_rcu(&element->rcu_node, free_lttng_trace_chunk_registry_element);
		} else {
			/* Never published, can be free'd immediately. */
			free_lttng_trace_chunk_registry_element(&element->rcu_node);
		}
	} else {
		/* Not RCU-protected, free immediately. */
		lttng_trace_chunk_fini(chunk);
		free(chunk);
	}
}

void lttng_trace_chunk_put(struct lttng_trace_chunk *chunk)
{
	if (!chunk) {
		return;
	}
	LTTNG_ASSERT(chunk->ref.refcount);
	urcu_ref_put(&chunk->ref, lttng_trace_chunk_release);
}

struct lttng_trace_chunk_registry *lttng_trace_chunk_registry_create()
{
	struct lttng_trace_chunk_registry *registry;

	registry = zmalloc<lttng_trace_chunk_registry>();
	if (!registry) {
		goto end;
	}

	registry->ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!registry->ht) {
		goto error;
	}
end:
	return registry;
error:
	lttng_trace_chunk_registry_destroy(registry);
	return nullptr;
}

void lttng_trace_chunk_registry_destroy(struct lttng_trace_chunk_registry *registry)
{
	if (!registry) {
		return;
	}
	if (registry->ht) {
		const int ret = cds_lfht_destroy(registry->ht, nullptr);
		LTTNG_ASSERT(!ret);
	}
	free(registry);
}

static struct lttng_trace_chunk_registry_element *
lttng_trace_chunk_registry_element_create_from_chunk(struct lttng_trace_chunk *chunk,
						     uint64_t session_id)
{
	struct lttng_trace_chunk_registry_element *element =
		zmalloc<lttng_trace_chunk_registry_element>();

	if (!element) {
		goto end;
	}
	cds_lfht_node_init(&element->trace_chunk_registry_ht_node);
	element->session_id = session_id;

	element->chunk = *chunk;
	lttng_trace_chunk_init(&element->chunk);
	if (chunk->session_output_directory) {
		/* Transferred ownership. */
		element->chunk.session_output_directory = chunk->session_output_directory;
		chunk->session_output_directory = nullptr;
	}
	if (chunk->chunk_directory) {
		/* Transferred ownership. */
		element->chunk.chunk_directory = chunk->chunk_directory;
		chunk->chunk_directory = nullptr;
	}
	/*
	 * The original chunk becomes invalid; the name and path attributes are
	 * transferred to the new chunk instance.
	 */
	chunk->name = nullptr;
	chunk->path = nullptr;
	element->chunk.fd_tracker = chunk->fd_tracker;
	element->chunk.in_registry_element = true;
end:
	return element;
}

struct lttng_trace_chunk *
lttng_trace_chunk_registry_publish_chunk(struct lttng_trace_chunk_registry *registry,
					 uint64_t session_id,
					 struct lttng_trace_chunk *chunk)
{
	bool unused;

	return lttng_trace_chunk_registry_publish_chunk(registry, session_id, chunk, &unused);
}

struct lttng_trace_chunk *
lttng_trace_chunk_registry_publish_chunk(struct lttng_trace_chunk_registry *registry,
					 uint64_t session_id,
					 struct lttng_trace_chunk *chunk,
					 bool *previously_published)
{
	struct lttng_trace_chunk_registry_element *element;
	unsigned long element_hash;

	pthread_mutex_lock(&chunk->lock);
	element = lttng_trace_chunk_registry_element_create_from_chunk(chunk, session_id);
	pthread_mutex_unlock(&chunk->lock);

	const lttng::urcu::read_lock_guard read_lock;
	if (!element) {
		goto end;
	}
	/*
	 * chunk is now invalid, the only valid operation is a 'put' from the
	 * caller.
	 */
	chunk = nullptr;
	element_hash = lttng_trace_chunk_registry_element_hash(element);

	while (true) {
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
				*previously_published = false;
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
		published_element = lttng::utils::container_of(
			published_node,
			&lttng_trace_chunk_registry_element::trace_chunk_registry_ht_node);
		published_chunk = &published_element->chunk;
		if (lttng_trace_chunk_get(published_chunk)) {
			lttng_trace_chunk_put(&element->chunk);
			element = published_element;
			*previously_published = true;
			break;
		}
		/*
		 * A reference to the previously published trace chunk could not
		 * be acquired. Hence, retry to publish our copy of the trace
		 * chunk.
		 */
	}
end:
	return element ? &element->chunk : nullptr;
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
static struct lttng_trace_chunk *_lttng_trace_chunk_registry_find_chunk(
	const struct lttng_trace_chunk_registry *registry, uint64_t session_id, uint64_t *chunk_id)
{
	lttng_trace_chunk_registry_element target_element{};

	target_element.chunk.id.is_set = !!chunk_id;
	target_element.chunk.id.value = chunk_id ? *chunk_id : 0;
	target_element.session_id = session_id;

	const unsigned long element_hash = lttng_trace_chunk_registry_element_hash(&target_element);
	struct cds_lfht_node *published_node;
	struct lttng_trace_chunk_registry_element *published_element;
	struct lttng_trace_chunk *published_chunk = nullptr;
	struct cds_lfht_iter iter;

	const lttng::urcu::read_lock_guard read_lock;
	cds_lfht_lookup(registry->ht,
			element_hash,
			lttng_trace_chunk_registry_element_match,
			&target_element,
			&iter);
	published_node = cds_lfht_iter_get_node(&iter);
	if (!published_node) {
		goto end;
	}

	published_element = lttng::utils::container_of(
		published_node, &lttng_trace_chunk_registry_element::trace_chunk_registry_ht_node);
	if (lttng_trace_chunk_get(&published_element->chunk)) {
		published_chunk = &published_element->chunk;
	}
end:
	return published_chunk;
}

struct lttng_trace_chunk *lttng_trace_chunk_registry_find_chunk(
	const struct lttng_trace_chunk_registry *registry, uint64_t session_id, uint64_t chunk_id)
{
	return _lttng_trace_chunk_registry_find_chunk(registry, session_id, &chunk_id);
}

int lttng_trace_chunk_registry_chunk_exists(const struct lttng_trace_chunk_registry *registry,
					    uint64_t session_id,
					    uint64_t chunk_id,
					    bool *chunk_exists)
{
	const int ret = 0;
	lttng_trace_chunk_registry_element target_element;

	target_element.chunk.id.is_set = true;
	target_element.chunk.id.value = chunk_id;
	target_element.session_id = session_id;

	const unsigned long element_hash = lttng_trace_chunk_registry_element_hash(&target_element);
	struct cds_lfht_node *published_node;
	struct cds_lfht_iter iter;

	const lttng::urcu::read_lock_guard read_lock;
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
	return ret;
}

struct lttng_trace_chunk *
lttng_trace_chunk_registry_find_anonymous_chunk(const struct lttng_trace_chunk_registry *registry,
						uint64_t session_id)
{
	return _lttng_trace_chunk_registry_find_chunk(registry, session_id, nullptr);
}

unsigned int
lttng_trace_chunk_registry_put_each_chunk(const struct lttng_trace_chunk_registry *registry)
{
	unsigned int trace_chunks_left = 0;

	DBG("Releasing trace chunk registry to all trace chunks");

	for (auto *chunk_element : lttng::urcu::lfht_iteration_adapter<
		     lttng_trace_chunk_registry_element,
		     decltype(lttng_trace_chunk_registry_element::trace_chunk_registry_ht_node),
		     &lttng_trace_chunk_registry_element::trace_chunk_registry_ht_node>(
		     *registry->ht)) {
		const char *chunk_id_str = "none";
		char chunk_id_buf[MAX_INT_DEC_LEN(uint64_t)];

		pthread_mutex_lock(&chunk_element->chunk.lock);
		if (chunk_element->chunk.id.is_set) {
			int fmt_ret;

			fmt_ret = snprintf(chunk_id_buf,
					   sizeof(chunk_id_buf),
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
		    chunk_element->chunk.name ?: "none",
		    chunk_element->chunk.close_command.is_set ? "open" : "closed");
		pthread_mutex_unlock(&chunk_element->chunk.lock);
		lttng_trace_chunk_put(&chunk_element->chunk);
		trace_chunks_left++;
	}

	DBG("Released reference to %u trace chunks in %s()", trace_chunks_left, __FUNCTION__);

	return trace_chunks_left;
}
