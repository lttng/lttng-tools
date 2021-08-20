/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <common/defaults.h>
#include <common/error.h>
#include <common/hashtable/utils.h>
#include <common/macros.h>
#include <common/optional.h>
#include <common/string-utils/format.h>
#include <common/utils.h>
#include <inttypes.h>
#include <lttng/constant.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <urcu.h>
#include <urcu/rculfhash.h>
#include <urcu/ref.h>

#include "inode.h"

struct inode_id {
	dev_t device;
	ino_t inode;
};

struct lttng_inode_registry {
	/* Hashtable of inode_id to lttng_inode. */
	struct cds_lfht *inodes;
};

struct lttng_inode {
	struct inode_id id;
	/* Node in the lttng_inode_registry's ht. */
	struct cds_lfht_node registry_node;
	/* Weak reference to ht containing the node. */
	struct cds_lfht *registry_ht;
	struct urcu_ref ref;
	struct rcu_head rcu_head;
	/* Location from which this file can be opened. */
	struct {
		struct lttng_directory_handle *directory_handle;
		char *path;
	} location;
	/* Unlink the underlying file at the release of the inode. */
	bool unlink_pending;
	LTTNG_OPTIONAL(unsigned int) unlinked_id;
	/* Weak reference. */
	struct lttng_unlinked_file_pool *unlinked_file_pool;
};

struct lttng_unlinked_file_pool {
	struct lttng_directory_handle *unlink_directory_handle;
	char *unlink_directory_path;
	unsigned int file_count;
	unsigned int next_id;
};

static struct {
	pthread_mutex_t lock;
	bool initialized;
	unsigned long value;
} seed = {
		.lock = PTHREAD_MUTEX_INITIALIZER,
};

static unsigned long lttng_inode_id_hash(const struct inode_id *id)
{
	uint64_t device = id->device, inode_no = id->inode;

	return hash_key_u64(&device, seed.value) ^
	       hash_key_u64(&inode_no, seed.value);
}

static int lttng_inode_match(struct cds_lfht_node *node, const void *key)
{
	const struct inode_id *id = key;
	const struct lttng_inode *inode = caa_container_of(
			node, struct lttng_inode, registry_node);

	return inode->id.device == id->device && inode->id.inode == id->inode;
}

static void lttng_inode_free(struct rcu_head *head)
{
	struct lttng_inode *inode =
			caa_container_of(head, struct lttng_inode, rcu_head);

	free(inode);
}

static int lttng_unlinked_file_pool_add_inode(
		struct lttng_unlinked_file_pool *pool,
		struct lttng_inode *inode)
{
	int ret;
	const unsigned int unlinked_id = pool->next_id++;
	char *inode_unlinked_name;
	bool reference_acquired;

	DBG("Adding inode of %s to unlinked file pool as id %u",
			inode->location.path, unlinked_id);
	ret = asprintf(&inode_unlinked_name, "%u", unlinked_id);
	if (ret < 0) {
		ERR("Failed to format unlinked inode name");
		ret = -1;
		goto end;
	}

	if (pool->file_count == 0) {
		DBG("Creating unlinked files directory at %s",
				pool->unlink_directory_path);
		LTTNG_ASSERT(!pool->unlink_directory_handle);
		ret = utils_mkdir(pool->unlink_directory_path,
				S_IRWXU | S_IRWXG, -1, -1);
		if (ret) {
			if (errno == EEXIST) {
				/*
				 * Unexpected (previous crash?), but not an
				 * error.
				 */
				DBG("Unlinked file directory \"%s\" already exists",
						pool->unlink_directory_path);
			} else {
				PERROR("Failed to create unlinked files directory at %s",
						pool->unlink_directory_path);
				goto end;
			}
		}
		pool->unlink_directory_handle = lttng_directory_handle_create(
				pool->unlink_directory_path);
		if (!pool->unlink_directory_handle) {
			ERR("Failed to create directory handle to unlinked file pool at %s",
					pool->unlink_directory_path);
			ret = -1;
			goto end;
		}
	}

	ret = lttng_directory_handle_rename(inode->location.directory_handle,
			inode->location.path, pool->unlink_directory_handle,
			inode_unlinked_name);
	if (ret) {
		goto end;
	}

	lttng_directory_handle_put(inode->location.directory_handle);
	inode->location.directory_handle = NULL;
	reference_acquired = lttng_directory_handle_get(
			pool->unlink_directory_handle);
	LTTNG_ASSERT(reference_acquired);
	inode->location.directory_handle = pool->unlink_directory_handle;

	free(inode->location.path);
	inode->location.path = inode_unlinked_name;
	inode_unlinked_name = NULL;
	LTTNG_OPTIONAL_SET(&inode->unlinked_id, unlinked_id);
	pool->file_count++;
end:
	free(inode_unlinked_name);
	return ret;
}

static int lttng_unlinked_file_pool_remove_inode(
		struct lttng_unlinked_file_pool *pool,
		struct lttng_inode *inode)
{
	int ret;

	DBG("Removing inode with unlinked id %u from unlinked file pool",
			LTTNG_OPTIONAL_GET(inode->unlinked_id));

	ret = lttng_directory_handle_unlink_file(
			inode->location.directory_handle, inode->location.path);
	if (ret) {
		PERROR("Failed to unlink file %s from unlinked file directory",
				inode->location.path);
		goto end;
	}
	free(inode->location.path);
	inode->location.path = NULL;
	lttng_directory_handle_put(inode->location.directory_handle);
	inode->location.directory_handle = NULL;

	pool->file_count--;
	if (pool->file_count == 0) {
		ret = utils_recursive_rmdir(pool->unlink_directory_path);
		if (ret) {
			/*
			 * There is nothing the caller can do, don't report an
			 * error except through logging.
			 */
			PERROR("Failed to remove unlinked files directory at %s",
					pool->unlink_directory_path);
		}
		lttng_directory_handle_put(pool->unlink_directory_handle);
		pool->unlink_directory_handle = NULL;
	}
end:
	return ret;
}

static void lttng_inode_destroy(struct lttng_inode *inode)
{
	if (!inode) {
		return;
	}

	rcu_read_lock();
	cds_lfht_del(inode->registry_ht, &inode->registry_node);
	rcu_read_unlock();

	if (inode->unlink_pending) {
		int ret;

		LTTNG_ASSERT(inode->location.directory_handle);
		LTTNG_ASSERT(inode->location.path);
		DBG("Removing %s from unlinked file pool",
				inode->location.path);
		ret = lttng_unlinked_file_pool_remove_inode(inode->unlinked_file_pool, inode);
		if (ret) {
			PERROR("Failed to unlink %s", inode->location.path);
		}
	}

	lttng_directory_handle_put(
			inode->location.directory_handle);
	inode->location.directory_handle = NULL;
	free(inode->location.path);
	inode->location.path = NULL;
	call_rcu(&inode->rcu_head, lttng_inode_free);
}

static void lttng_inode_release(struct urcu_ref *ref)
{
	lttng_inode_destroy(caa_container_of(ref, struct lttng_inode, ref));
}

static void lttng_inode_get(struct lttng_inode *inode)
{
	urcu_ref_get(&inode->ref);
}

LTTNG_HIDDEN struct lttng_unlinked_file_pool *lttng_unlinked_file_pool_create(
		const char *path)
{
	struct lttng_unlinked_file_pool *pool = zmalloc(sizeof(*pool));

	if (!pool) {
		goto error;
	}

	if (!path || *path != '/') {
		ERR("Unlinked file pool must be created with an absolute path, path = \"%s\"",
				path ? path : "NULL");
		goto error;
	}

	pool->unlink_directory_path = strdup(path);
	if (!pool->unlink_directory_path) {
		PERROR("Failed to allocation unlinked file pool path");
		goto error;
	}
	DBG("Unlinked file pool created at: %s", path);
	return pool;
error:
	lttng_unlinked_file_pool_destroy(pool);
	return NULL;
}

LTTNG_HIDDEN void lttng_unlinked_file_pool_destroy(
		struct lttng_unlinked_file_pool *pool)
{
	if (!pool) {
		return;
	}

	LTTNG_ASSERT(pool->file_count == 0);
	lttng_directory_handle_put(pool->unlink_directory_handle);
	free(pool->unlink_directory_path);
	free(pool);
}

LTTNG_HIDDEN void lttng_inode_put(struct lttng_inode *inode)
{
	urcu_ref_put(&inode->ref, lttng_inode_release);
}

LTTNG_HIDDEN struct lttng_directory_handle *
lttng_inode_get_location_directory_handle(
		struct lttng_inode *inode)
{
	if (inode->location.directory_handle) {
		const bool reference_acquired = lttng_directory_handle_get(
				inode->location.directory_handle);

		LTTNG_ASSERT(reference_acquired);
	}
	return inode->location.directory_handle;
}

LTTNG_HIDDEN void lttng_inode_borrow_location(struct lttng_inode *inode,
		const struct lttng_directory_handle **out_directory_handle,
		const char **out_path)
{
	if (out_directory_handle) {
		*out_directory_handle = inode->location.directory_handle;
	}
	if (out_path) {
		*out_path = inode->location.path;
	}
}

LTTNG_HIDDEN int lttng_inode_rename(
		struct lttng_inode *inode,
		struct lttng_directory_handle *old_directory_handle,
		const char *old_path,
		struct lttng_directory_handle *new_directory_handle,
		const char *new_path,
		bool overwrite)
{
	int ret = 0;
	char *new_path_copy = strdup(new_path);
	bool reference_acquired;

	DBG("Performing rename of inode from %s to %s with %s directory handles",
			old_path, new_path,
			lttng_directory_handle_equals(old_directory_handle,
					new_directory_handle) ?
					"identical" :
					"different");

	if (!new_path_copy) {
		ret = -ENOMEM;
		goto end;
	}

	if (inode->unlink_pending) {
		WARN("An attempt to rename an unlinked file from %s to %s has been performed",
				old_path, new_path);
		ret = -ENOENT;
		goto end;
	}

	if (!overwrite) {
		/* Verify that file doesn't exist. */
		struct stat statbuf;

		ret = lttng_directory_handle_stat(
				new_directory_handle, new_path, &statbuf);
		if (ret == 0) {
			ERR("Refusing to rename %s as the destination already exists",
					old_path);
			ret = -EEXIST;
			goto end;
		} else if (ret < 0 && errno != ENOENT) {
			PERROR("Failed to stat() %s", new_path);
			ret = -errno;
			goto end;
		}
	}

	ret = lttng_directory_handle_rename(old_directory_handle, old_path,
			new_directory_handle, new_path);
	if (ret) {
		PERROR("Failed to rename file %s to %s", old_path, new_path);
		ret = -errno;
		goto end;
	}

	reference_acquired = lttng_directory_handle_get(new_directory_handle);
	LTTNG_ASSERT(reference_acquired);
	lttng_directory_handle_put(inode->location.directory_handle);
	free(inode->location.path);
	inode->location.directory_handle = new_directory_handle;
	/* Ownership transferred. */
	inode->location.path = new_path_copy;
	new_path_copy = NULL;
end:
	free(new_path_copy);
	return ret;
}

LTTNG_HIDDEN int lttng_inode_unlink(struct lttng_inode *inode)
{
	int ret = 0;

	DBG("Attempting unlink of inode %s", inode->location.path);

	if (inode->unlink_pending) {
		WARN("An attempt to re-unlink %s has been performed, ignoring.",
				inode->location.path);
		ret = -ENOENT;
		goto end;
	}

	/*
	 * Move to the temporary "deleted" directory until all
	 * references are released.
	 */
	ret = lttng_unlinked_file_pool_add_inode(
			inode->unlinked_file_pool, inode);
	if (ret) {
		PERROR("Failed to add inode \"%s\" to the unlinked file pool",
				inode->location.path);
		goto end;
	}
	inode->unlink_pending = true;
end:
	return ret;
}

static struct lttng_inode *lttng_inode_create(const struct inode_id *id,
		struct cds_lfht *ht,
		struct lttng_unlinked_file_pool *unlinked_file_pool,
		struct lttng_directory_handle *directory_handle,
		const char *path)
{
	struct lttng_inode *inode = NULL;
	char *path_copy;
	bool reference_acquired;

	path_copy = strdup(path);
	if (!path_copy) {
		goto end;
	}

	reference_acquired = lttng_directory_handle_get(directory_handle);
	LTTNG_ASSERT(reference_acquired);

	inode = zmalloc(sizeof(*inode));
	if (!inode) {
		goto end;
	}

	urcu_ref_init(&inode->ref);
	cds_lfht_node_init(&inode->registry_node);
	inode->id = *id;
	inode->registry_ht = ht;
	inode->unlinked_file_pool = unlinked_file_pool;
	/* Ownership of path copy is transferred to inode. */
	inode->location.path = path_copy;
	path_copy = NULL;
	inode->location.directory_handle = directory_handle;
end:
	free(path_copy);
	return inode;
}

LTTNG_HIDDEN struct lttng_inode_registry *lttng_inode_registry_create(void)
{
	struct lttng_inode_registry *registry = zmalloc(sizeof(*registry));

	if (!registry) {
		goto end;
	}

	pthread_mutex_lock(&seed.lock);
	if (!seed.initialized) {
		seed.value = (unsigned long) time(NULL);
		seed.initialized = true;
	}
	pthread_mutex_unlock(&seed.lock);

	registry->inodes = cds_lfht_new(DEFAULT_HT_SIZE, 1, 0,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!registry->inodes) {
		goto error;
	}
end:
	return registry;
error:
	lttng_inode_registry_destroy(registry);
	return NULL;
}

LTTNG_HIDDEN void lttng_inode_registry_destroy(
		struct lttng_inode_registry *registry)
{
	if (!registry) {
		return;
	}
	if (registry->inodes) {
		int ret = cds_lfht_destroy(registry->inodes, NULL);

		LTTNG_ASSERT(!ret);
	}
	free(registry);
}

LTTNG_HIDDEN struct lttng_inode *lttng_inode_registry_get_inode(
		struct lttng_inode_registry *registry,
		struct lttng_directory_handle *handle,
		const char *path,
		int fd,
		struct lttng_unlinked_file_pool *unlinked_file_pool)
{
	int ret;
	struct stat statbuf;
	struct inode_id id;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct lttng_inode *inode = NULL;

	ret = fstat(fd, &statbuf);
	if (ret < 0) {
		PERROR("stat() failed on fd %i", fd);
		goto end;
	}

	id.device = statbuf.st_dev;
	id.inode = statbuf.st_ino;

	rcu_read_lock();
	cds_lfht_lookup(registry->inodes, lttng_inode_id_hash(&id),
			lttng_inode_match, &id, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node) {
		inode = caa_container_of(
				node, struct lttng_inode, registry_node);
		lttng_inode_get(inode);
		goto end_unlock;
	}

	inode = lttng_inode_create(&id, registry->inodes, unlinked_file_pool,
			handle, path);
	if (!inode) {
		goto end_unlock;
	}

	node = cds_lfht_add_unique(registry->inodes,
			lttng_inode_id_hash(&inode->id), lttng_inode_match,
			&inode->id, &inode->registry_node);
	LTTNG_ASSERT(node == &inode->registry_node);
end_unlock:
	rcu_read_unlock();
end:
	return inode;
}
