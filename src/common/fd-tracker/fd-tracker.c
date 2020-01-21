/*
 * Copyright (C) 2018, 2020 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <urcu.h>
#include <urcu/list.h>
#include <urcu/rculfhash.h>

#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <common/defaults.h>
#include <common/error.h>
#include <common/hashtable/hashtable.h>
#include <common/hashtable/utils.h>
#include <common/macros.h>
#include <common/fs-handle-internal.h>

#include "fd-tracker.h"
#include "inode.h"

/* Tracker lock must be taken by the user. */
#define TRACKED_COUNT(tracker)                                 \
	(tracker->count.suspendable.active +                   \
			tracker->count.suspendable.suspended + \
			tracker->count.unsuspendable)

/* Tracker lock must be taken by the user. */
#define ACTIVE_COUNT(tracker) \
	(tracker->count.suspendable.active + tracker->count.unsuspendable)

/* Tracker lock must be taken by the user. */
#define SUSPENDED_COUNT(tracker) (tracker->count.suspendable.suspended)

/* Tracker lock must be taken by the user. */
#define SUSPENDABLE_COUNT(tracker)           \
	(tracker->count.suspendable.active + \
			tracker->count.suspendable.suspended)

/* Tracker lock must be taken by the user. */
#define UNSUSPENDABLE_COUNT(tracker) (tracker->count.unsuspendable)

struct fd_tracker {
	pthread_mutex_t lock;
	struct {
		struct {
			unsigned int active;
			unsigned int suspended;
		} suspendable;
		unsigned int unsuspendable;
	} count;
	unsigned int capacity;
	struct {
		uint64_t uses;
		uint64_t misses;
		/* Failures to suspend or restore fs handles. */
		uint64_t errors;
	} stats;
	/*
	 * The head of the active_handles list is always the least recently
	 * used active handle. When an handle is used, it is removed from the
	 * list and added to the end. When a file has to be suspended, the
	 * first element in the list is "popped", suspended, and added to the
	 * list of suspended handles.
	 */
	struct cds_list_head active_handles;
	struct cds_list_head suspended_handles;
	struct cds_lfht *unsuspendable_fds;
	struct lttng_inode_registry *inode_registry;
};

struct open_properties {
	int flags;
	struct {
		bool is_set;
		mode_t value;
	} mode;
};

/*
 * A fs_handle_tracked is not ref-counted. Therefore, it is assumed that a
 * handle is never in-use while it is being reclaimed. It can be
 * shared by multiple threads, but external synchronization is required
 * to ensure it is not still being used when it is reclaimed (close method).
 * In this respect, it is not different from a regular file descriptor.
 *
 * The fs_handle lock always nests _within_ the tracker's lock.
 */
struct fs_handle_tracked {
	struct fs_handle parent;
	pthread_mutex_t lock;
	/*
	 * Weak reference to the tracker. All fs_handles are assumed to have
	 * been closed at the moment of the destruction of the fd_tracker.
	 */
	struct fd_tracker *tracker;
	struct open_properties properties;
	struct lttng_inode *inode;
	int fd;
	/* inode number of the file at the time of the handle's creation. */
	uint64_t ino;
	bool in_use;
	/* Offset to which the file should be restored. */
	off_t offset;
	struct cds_list_head handles_list_node;
};

struct unsuspendable_fd {
	/*
	 * Accesses are only performed through the tracker, which is protected
	 * by its own lock.
	 */
	int fd;
	char *name;
	struct cds_lfht_node tracker_node;
	struct rcu_head rcu_head;
};

static struct {
	pthread_mutex_t lock;
	bool initialized;
	unsigned long value;
} seed = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

static int match_fd(struct cds_lfht_node *node, const void *key);
static void unsuspendable_fd_destroy(struct unsuspendable_fd *entry);
static struct unsuspendable_fd *unsuspendable_fd_create(
		const char *name, int fd);
static int open_from_properties(
		const char *path, struct open_properties *properties);

static void fs_handle_tracked_log(struct fs_handle_tracked *handle);
static int fs_handle_tracked_suspend(struct fs_handle_tracked *handle);
static int fs_handle_tracked_restore(struct fs_handle_tracked *handle);
static int fs_handle_tracked_get_fd(struct fs_handle *_handle);
static void fs_handle_tracked_put_fd(struct fs_handle *_handle);
static int fs_handle_tracked_unlink(struct fs_handle *_handle);
static int fs_handle_tracked_close(struct fs_handle *_handle);

static void fd_tracker_track(
		struct fd_tracker *tracker, struct fs_handle_tracked *handle);
static void fd_tracker_untrack(
		struct fd_tracker *tracker, struct fs_handle_tracked *handle);
static int fd_tracker_suspend_handles(
		struct fd_tracker *tracker, unsigned int count);
static int fd_tracker_restore_handle(
		struct fd_tracker *tracker, struct fs_handle_tracked *handle);

static const struct fs_handle fs_handle_tracked_callbacks = {
	.get_fd = fs_handle_tracked_get_fd,
	.put_fd = fs_handle_tracked_put_fd,
	.unlink = fs_handle_tracked_unlink,
	.close = fs_handle_tracked_close,
};

/* Match function of the tracker's unsuspendable_fds hash table. */
static int match_fd(struct cds_lfht_node *node, const void *key)
{
	struct unsuspendable_fd *entry = caa_container_of(
			node, struct unsuspendable_fd, tracker_node);

	return hash_match_key_ulong(
			(void *) (unsigned long) entry->fd, (void *) key);
}

static void delete_unsuspendable_fd(struct rcu_head *head)
{
	struct unsuspendable_fd *fd = caa_container_of(
			head, struct unsuspendable_fd, rcu_head);

	free(fd->name);
	free(fd);
}

static void unsuspendable_fd_destroy(struct unsuspendable_fd *entry)
{
	if (!entry) {
		return;
	}
	call_rcu(&entry->rcu_head, delete_unsuspendable_fd);
}

static struct unsuspendable_fd *unsuspendable_fd_create(
		const char *name, int fd)
{
	struct unsuspendable_fd *entry = zmalloc(sizeof(*entry));

	if (!entry) {
		goto error;
	}
	if (name) {
		entry->name = strdup(name);
		if (!entry->name) {
			goto error;
		}
	}
	cds_lfht_node_init(&entry->tracker_node);
	entry->fd = fd;
	return entry;
error:
	unsuspendable_fd_destroy(entry);
	return NULL;
}

static void fs_handle_tracked_log(struct fs_handle_tracked *handle)
{
	const char *path;

	pthread_mutex_lock(&handle->lock);
	path = lttng_inode_get_path(handle->inode);

	if (handle->fd >= 0) {
		DBG_NO_LOC("    %s [active, fd %d%s]", path, handle->fd,
				handle->in_use ? ", in use" : "");
	} else {
		DBG_NO_LOC("    %s [suspended]", path);
	}
	pthread_mutex_unlock(&handle->lock);
}

/* Tracker lock must be held by the caller. */
static int fs_handle_tracked_suspend(struct fs_handle_tracked *handle)
{
	int ret = 0;
	struct stat fs_stat;
	const char *path;

	pthread_mutex_lock(&handle->lock);
	path = lttng_inode_get_path(handle->inode);
	assert(handle->fd >= 0);
	if (handle->in_use) {
		/* This handle can't be suspended as it is currently in use. */
		ret = -EAGAIN;
		goto end;
	}

	ret = stat(path, &fs_stat);
	if (ret) {
		PERROR("Filesystem handle to %s cannot be suspended as stat() failed",
				path);
		ret = -errno;
		goto end;
	}

	if (fs_stat.st_ino != handle->ino) {
		/* Don't suspend as the handle would not be restorable. */
		WARN("Filesystem handle to %s cannot be suspended as its inode changed",
				path);
		ret = -ENOENT;
		goto end;
	}

	handle->offset = lseek(handle->fd, 0, SEEK_CUR);
	if (handle->offset == -1) {
		WARN("Filesystem handle to %s cannot be suspended as lseek() failed to sample its current position",
				path);
		ret = -errno;
		goto end;
	}

	ret = close(handle->fd);
	if (ret) {
		PERROR("Filesystem handle to %s cannot be suspended as close() failed",
				path);
		ret = -errno;
		goto end;
	}
	DBG("Suspended filesystem handle to %s (fd %i) at position %" PRId64,
			path, handle->fd, handle->offset);
	handle->fd = -1;
end:
	if (ret) {
		handle->tracker->stats.errors++;
	}
	pthread_mutex_unlock(&handle->lock);
	return ret;
}

/* Caller must hold the tracker and handle's locks. */
static int fs_handle_tracked_restore(struct fs_handle_tracked *handle)
{
	int ret, fd = -1;
	const char *path = lttng_inode_get_path(handle->inode);

	assert(handle->fd == -1);
	assert(path);
	ret = open_from_properties(path, &handle->properties);
	if (ret < 0) {
		PERROR("Failed to restore filesystem handle to %s, open() failed",
				path);
		ret = -errno;
		goto end;
	}
	fd = ret;

	ret = lseek(fd, handle->offset, SEEK_SET);
	if (ret < 0) {
		PERROR("Failed to restore filesystem handle to %s, lseek() failed",
				path);
		ret = -errno;
		goto end;
	}
	DBG("Restored filesystem handle to %s (fd %i) at position %" PRId64,
			path, fd, handle->offset);
	ret = 0;
	handle->fd = fd;
	fd = -1;
end:
	if (fd >= 0) {
		(void) close(fd);
	}
	return ret;
}

static int open_from_properties(
		const char *path, struct open_properties *properties)
{
	int ret;

	/*
	 * open() ignores the 'flags' parameter unless the O_CREAT or O_TMPFILE
	 * flags are set. O_TMPFILE would not make sense in the context of a
	 * suspendable fs_handle as it would not be restorable (see OPEN(2)),
	 * thus it is ignored here.
	 */
	if ((properties->flags & O_CREAT) && properties->mode.is_set) {
		ret = open(path, properties->flags, properties->mode.value);
	} else {
		ret = open(path, properties->flags);
	}
	/*
	 * Some flags should not be used beyond the initial open() of a
	 * restorable file system handle. O_CREAT and O_TRUNC must
	 * be cleared since it would be unexpected to re-use them
	 * when the handle is retored:
	 *  - O_CREAT should not be needed as the file has been created
	 *    on the initial call to open(),
	 *  - O_TRUNC would destroy the file's contents by truncating it
	 *    to length 0.
	 */
	properties->flags &= ~(O_CREAT | O_TRUNC);
	if (ret < 0) {
		ret = -errno;
		goto end;
	}
end:
	return ret;
}

struct fd_tracker *fd_tracker_create(unsigned int capacity)
{
	struct fd_tracker *tracker = zmalloc(sizeof(struct fd_tracker));

	if (!tracker) {
		goto end;
	}

	pthread_mutex_lock(&seed.lock);
	if (!seed.initialized) {
		seed.value = (unsigned long) time(NULL);
		seed.initialized = true;
	}
	pthread_mutex_unlock(&seed.lock);

	CDS_INIT_LIST_HEAD(&tracker->active_handles);
	CDS_INIT_LIST_HEAD(&tracker->suspended_handles);
	tracker->capacity = capacity;
	tracker->unsuspendable_fds = cds_lfht_new(DEFAULT_HT_SIZE, 1, 0,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!tracker->unsuspendable_fds) {
		ERR("Failed to create fd-tracker's unsuspendable_fds hash table");
		goto error;
	}
	tracker->inode_registry = lttng_inode_registry_create();
	if (!tracker->inode_registry) {
		ERR("Failed to create fd-tracker's inode registry");
		goto error;
	}
	DBG("File descriptor tracker created with a limit of %u simultaneously-opened FDs",
			capacity);
end:
	return tracker;
error:
	fd_tracker_destroy(tracker);
	return NULL;
}

void fd_tracker_log(struct fd_tracker *tracker)
{
	struct fs_handle_tracked *handle;
	struct unsuspendable_fd *unsuspendable_fd;
	struct cds_lfht_iter iter;

	pthread_mutex_lock(&tracker->lock);
	DBG_NO_LOC("File descriptor tracker");
	DBG_NO_LOC("  Stats:");
	DBG_NO_LOC("    uses:            %" PRIu64, tracker->stats.uses);
	DBG_NO_LOC("    misses:          %" PRIu64, tracker->stats.misses);
	DBG_NO_LOC("    errors:          %" PRIu64, tracker->stats.errors);
	DBG_NO_LOC("  Tracked:           %u", TRACKED_COUNT(tracker));
	DBG_NO_LOC("    active:          %u", ACTIVE_COUNT(tracker));
	DBG_NO_LOC("      suspendable:   %u", SUSPENDABLE_COUNT(tracker));
	DBG_NO_LOC("      unsuspendable: %u", UNSUSPENDABLE_COUNT(tracker));
	DBG_NO_LOC("    suspended:       %u", SUSPENDED_COUNT(tracker));
	DBG_NO_LOC("    capacity:        %u", tracker->capacity);

	DBG_NO_LOC("  Tracked suspendable file descriptors");
	cds_list_for_each_entry(
			handle, &tracker->active_handles, handles_list_node) {
		fs_handle_tracked_log(handle);
	}
	cds_list_for_each_entry(handle, &tracker->suspended_handles,
			handles_list_node) {
		fs_handle_tracked_log(handle);
	}
	if (!SUSPENDABLE_COUNT(tracker)) {
		DBG_NO_LOC("    None");
	}

	DBG_NO_LOC("  Tracked unsuspendable file descriptors");
	rcu_read_lock();
	cds_lfht_for_each_entry(tracker->unsuspendable_fds, &iter,
			unsuspendable_fd, tracker_node) {
		DBG_NO_LOC("    %s [active, fd %d]",
				unsuspendable_fd->name ?: "Unnamed",
				unsuspendable_fd->fd);
	}
	rcu_read_unlock();
	if (!UNSUSPENDABLE_COUNT(tracker)) {
		DBG_NO_LOC("    None");
	}

	pthread_mutex_unlock(&tracker->lock);
}

int fd_tracker_destroy(struct fd_tracker *tracker)
{
	int ret = 0;

	/*
	 * Refuse to destroy the tracker as fs_handles may still old
	 * weak references to the tracker.
	 */
	pthread_mutex_lock(&tracker->lock);
	if (TRACKED_COUNT(tracker)) {
		ERR("A file descriptor leak has been detected: %u tracked file descriptors are still being tracked",
				TRACKED_COUNT(tracker));
		pthread_mutex_unlock(&tracker->lock);
		fd_tracker_log(tracker);
		ret = -1;
		goto end;
	}
	pthread_mutex_unlock(&tracker->lock);

	if (tracker->unsuspendable_fds) {
		ret = cds_lfht_destroy(tracker->unsuspendable_fds, NULL);
		assert(!ret);
	}

	lttng_inode_registry_destroy(tracker->inode_registry);
	pthread_mutex_destroy(&tracker->lock);
	free(tracker);
end:
	return ret;
}

struct fs_handle *fd_tracker_open_fs_handle(struct fd_tracker *tracker,
		const char *path,
		int flags,
		mode_t *mode)
{
	int ret;
	struct fs_handle_tracked *handle = NULL;
	struct stat fd_stat;
	struct open_properties properties = {
		.flags = flags,
		.mode.is_set = !!mode,
		.mode.value = mode ? *mode : 0,
	};

	pthread_mutex_lock(&tracker->lock);
	if (ACTIVE_COUNT(tracker) == tracker->capacity) {
		if (tracker->count.suspendable.active > 0) {
			ret = fd_tracker_suspend_handles(tracker, 1);
			if (ret) {
				goto end;
			}
		} else {
			/*
			 * There are not enough active suspendable file
			 * descriptors to open a new fd and still accommodate
			 * the tracker's capacity.
			 */
			WARN("Cannot open file system handle, too many unsuspendable file descriptors are opened (%u)",
					tracker->count.unsuspendable);
			goto end;
		}
	}

	handle = zmalloc(sizeof(*handle));
	if (!handle) {
		goto end;
	}
	handle->parent = fs_handle_tracked_callbacks;
	handle->tracker = tracker;

	ret = pthread_mutex_init(&handle->lock, NULL);
	if (ret) {
		PERROR("Failed to initialize handle mutex while creating fs handle");
		goto error_mutex_init;
	}

	handle->fd = open_from_properties(path, &properties);
	if (handle->fd < 0) {
		PERROR("Failed to open fs handle to %s, open() returned", path);
		goto error;
	}

	handle->properties = properties;

	handle->inode = lttng_inode_registry_get_inode(
			tracker->inode_registry, handle->fd, path);
	if (!handle->inode) {
		ERR("Failed to get lttng_inode corresponding to file %s", path);
		goto error;
	}

	if (fstat(handle->fd, &fd_stat)) {
		PERROR("Failed to retrieve file descriptor inode while creating fs handle, fstat() returned");
		goto error;
	}
	handle->ino = fd_stat.st_ino;

	fd_tracker_track(tracker, handle);
end:
	pthread_mutex_unlock(&tracker->lock);
	return handle ? &handle->parent : NULL;
error:
	if (handle->inode) {
		lttng_inode_put(handle->inode);
	}
	pthread_mutex_destroy(&handle->lock);
error_mutex_init:
	free(handle);
	handle = NULL;
	goto end;
}

/* Caller must hold the tracker's lock. */
static int fd_tracker_suspend_handles(
		struct fd_tracker *tracker, unsigned int count)
{
	unsigned int left_to_close = count;
	struct fs_handle_tracked *handle, *tmp;

	cds_list_for_each_entry_safe(handle, tmp, &tracker->active_handles,
			handles_list_node) {
		int ret;

		fd_tracker_untrack(tracker, handle);
		ret = fs_handle_tracked_suspend(handle);
		fd_tracker_track(tracker, handle);
		if (!ret) {
			left_to_close--;
		}

		if (!left_to_close) {
			break;
		}
	}
	return left_to_close ? -EMFILE : 0;
}

int fd_tracker_open_unsuspendable_fd(struct fd_tracker *tracker,
		int *out_fds,
		const char **names,
		unsigned int fd_count,
		fd_open_cb open,
		void *user_data)
{
	int ret, user_ret, i, fds_to_suspend;
	unsigned int active_fds;
	struct unsuspendable_fd **entries;

	entries = zmalloc(fd_count * sizeof(*entries));
	if (!entries) {
		ret = -1;
		goto end;
	}

	pthread_mutex_lock(&tracker->lock);

	active_fds = ACTIVE_COUNT(tracker);
	fds_to_suspend = (int) active_fds + (int) fd_count -
			(int) tracker->capacity;
	if (fds_to_suspend > 0) {
		if (fds_to_suspend <= tracker->count.suspendable.active) {
			ret = fd_tracker_suspend_handles(
					tracker, fds_to_suspend);
			if (ret) {
				goto end_unlock;
			}
		} else {
			/*
			 * There are not enough active suspendable file
			 * descriptors to open a new fd and still accomodate the
			 * tracker's capacity.
			 */
			WARN("Cannot open unsuspendable fd, too many unsuspendable file descriptors are opened (%u)",
					tracker->count.unsuspendable);
			ret = -EMFILE;
			goto end_unlock;
		}
	}

	user_ret = open(user_data, out_fds);
	if (user_ret) {
		ret = user_ret;
		goto end_unlock;
	}

	/*
	 * Add the fds returned by the user's callback to the hashtable
	 * of unsuspendable fds.
	 */
	for (i = 0; i < fd_count; i++) {
		struct unsuspendable_fd *entry = unsuspendable_fd_create(
				names ? names[i] : NULL, out_fds[i]);

		if (!entry) {
			ret = -1;
			goto end_free_entries;
		}
		entries[i] = entry;
	}

	rcu_read_lock();
	for (i = 0; i < fd_count; i++) {
		struct cds_lfht_node *node;
		struct unsuspendable_fd *entry = entries[i];

		node = cds_lfht_add_unique(tracker->unsuspendable_fds,
				hash_key_ulong((void *) (unsigned long)
								out_fds[i],
						seed.value),
				match_fd, (void *) (unsigned long) out_fds[i],
				&entry->tracker_node);

		if (node != &entry->tracker_node) {
			ret = -EEXIST;
			rcu_read_unlock();
			goto end_free_entries;
		}
		entries[i] = NULL;
	}
	tracker->count.unsuspendable += fd_count;
	rcu_read_unlock();
	ret = user_ret;
end_unlock:
	pthread_mutex_unlock(&tracker->lock);
end:
	free(entries);
	return ret;
end_free_entries:
	for (i = 0; i < fd_count; i++) {
		unsuspendable_fd_destroy(entries[i]);
	}
	goto end_unlock;
}

int fd_tracker_close_unsuspendable_fd(struct fd_tracker *tracker,
		int *fds_in,
		unsigned int fd_count,
		fd_close_cb close,
		void *user_data)
{
	int i, ret, user_ret;
	int *fds = NULL;

	/*
	 * Maintain a local copy of fds_in as the user's callback may modify its
	 * contents (e.g. setting the fd(s) to -1 after close).
	 */
	fds = malloc(sizeof(*fds) * fd_count);
	if (!fds) {
		ret = -1;
		goto end;
	}
	memcpy(fds, fds_in, sizeof(*fds) * fd_count);

	pthread_mutex_lock(&tracker->lock);
	rcu_read_lock();

	/* Let the user close the file descriptors. */
	user_ret = close(user_data, fds_in);
	if (user_ret) {
		ret = user_ret;
		goto end_unlock;
	}

	/* Untrack the fds that were just closed by the user's callback. */
	for (i = 0; i < fd_count; i++) {
		struct cds_lfht_node *node;
		struct cds_lfht_iter iter;
		struct unsuspendable_fd *entry;

		cds_lfht_lookup(tracker->unsuspendable_fds,
				hash_key_ulong((void *) (unsigned long) fds[i],
						seed.value),
				match_fd, (void *) (unsigned long) fds[i],
				&iter);
		node = cds_lfht_iter_get_node(&iter);
		if (!node) {
			/* Unknown file descriptor. */
			WARN("Untracked file descriptor %d passed to fd_tracker_close_unsuspendable_fd()",
					fds[i]);
			ret = -EINVAL;
			goto end_unlock;
		}
		entry = caa_container_of(
				node, struct unsuspendable_fd, tracker_node);

		cds_lfht_del(tracker->unsuspendable_fds, node);
		unsuspendable_fd_destroy(entry);
		fds[i] = -1;
	}

	tracker->count.unsuspendable -= fd_count;
	ret = 0;
end_unlock:
	rcu_read_unlock();
	pthread_mutex_unlock(&tracker->lock);
	free(fds);
end:
	return ret;
}

/* Caller must have taken the tracker's and handle's locks. */
static void fd_tracker_track(
		struct fd_tracker *tracker, struct fs_handle_tracked *handle)
{
	if (handle->fd >= 0) {
		tracker->count.suspendable.active++;
		cds_list_add_tail(&handle->handles_list_node,
				&tracker->active_handles);
	} else {
		tracker->count.suspendable.suspended++;
		cds_list_add_tail(&handle->handles_list_node,
				&tracker->suspended_handles);
	}
}

/* Caller must have taken the tracker's and handle's locks. */
static void fd_tracker_untrack(
		struct fd_tracker *tracker, struct fs_handle_tracked *handle)
{
	if (handle->fd >= 0) {
		tracker->count.suspendable.active--;
	} else {
		tracker->count.suspendable.suspended--;
	}
	cds_list_del(&handle->handles_list_node);
}

/* Caller must have taken the tracker's and handle's locks. */
static int fd_tracker_restore_handle(
		struct fd_tracker *tracker, struct fs_handle_tracked *handle)
{
	int ret;

	fd_tracker_untrack(tracker, handle);
	if (ACTIVE_COUNT(tracker) >= tracker->capacity) {
		ret = fd_tracker_suspend_handles(tracker, 1);
		if (ret) {
			goto end;
		}
	}
	ret = fs_handle_tracked_restore(handle);
end:
	fd_tracker_track(tracker, handle);
	return ret ? ret : handle->fd;
}

static int fs_handle_tracked_get_fd(struct fs_handle *_handle)
{
	int ret;
	struct fs_handle_tracked *handle =
			container_of(_handle, struct fs_handle_tracked, parent);

	/*
	 * TODO This should be optimized as it is a fairly hot path.
	 * The fd-tracker's lock should only be taken when a fs_handle is
	 * restored (slow path). On the fast path (fs_handle is active),
	 * the only effect on the fd_tracker is marking the handle as the
	 * most recently used. Currently, it is done by a call to the
	 * track/untrack helpers, but it should be done atomically.
	 *
	 * Note that the lock's nesting order must still be respected here.
	 * The handle's lock nests inside the tracker's lock.
	 */
	pthread_mutex_lock(&handle->tracker->lock);
	pthread_mutex_lock(&handle->lock);
	assert(!handle->in_use);

	handle->tracker->stats.uses++;
	if (handle->fd >= 0) {
		ret = handle->fd;
		/* Mark as most recently used. */
		fd_tracker_untrack(handle->tracker, handle);
		fd_tracker_track(handle->tracker, handle);
	} else {
		handle->tracker->stats.misses++;
		ret = fd_tracker_restore_handle(handle->tracker, handle);
		if (ret < 0) {
			handle->tracker->stats.errors++;
			goto end;
		}
	}
	handle->in_use = true;
end:
	pthread_mutex_unlock(&handle->lock);
	pthread_mutex_unlock(&handle->tracker->lock);
	return ret;
}

static void fs_handle_tracked_put_fd(struct fs_handle *_handle)
{
	struct fs_handle_tracked *handle =
			container_of(_handle, struct fs_handle_tracked, parent);

	pthread_mutex_lock(&handle->lock);
	handle->in_use = false;
	pthread_mutex_unlock(&handle->lock);
}

static int fs_handle_tracked_unlink(struct fs_handle *_handle)
{
	int ret;
	struct fs_handle_tracked *handle =
			container_of(_handle, struct fs_handle_tracked, parent);

	pthread_mutex_lock(&handle->tracker->lock);
	pthread_mutex_lock(&handle->lock);
	ret = lttng_inode_defer_unlink(handle->inode);
	pthread_mutex_unlock(&handle->lock);
	pthread_mutex_unlock(&handle->tracker->lock);
	return ret;
}

static int fs_handle_tracked_close(struct fs_handle *_handle)
{
	int ret = 0;
	const char *path = NULL;
	struct fs_handle_tracked *handle =
			container_of(_handle, struct fs_handle_tracked, parent);

	if (!handle) {
		ret = -EINVAL;
		goto end;
	}

	pthread_mutex_lock(&handle->tracker->lock);
	pthread_mutex_lock(&handle->lock);
	if (handle->inode) {
		path = lttng_inode_get_path(handle->inode);
	}
	fd_tracker_untrack(handle->tracker, handle);
	if (handle->fd >= 0) {
		/*
		 * The return value of close() is not propagated as there
		 * isn't much the user can do about it.
		 */
		if (close(handle->fd)) {
			PERROR("Failed to close the file descritptor (%d) of fs handle to %s, close() returned",
					handle->fd, path ? path : "Unknown");
		}
		handle->fd = -1;
	}
	if (handle->inode) {
		lttng_inode_put(handle->inode);
	}
	pthread_mutex_unlock(&handle->lock);
	pthread_mutex_destroy(&handle->lock);
	pthread_mutex_unlock(&handle->tracker->lock);
	free(handle);
end:
	return ret;
}
