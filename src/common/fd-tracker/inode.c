/*
 * Copyright (C) 2018 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>
#include <urcu.h>
#include <urcu/ref.h>
#include <urcu/rculfhash.h>
#include <common/hashtable/utils.h>
#include <common/macros.h>
#include <common/defaults.h>
#include <common/error.h>
#include <lttng/constant.h>

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
	char *path;
	bool unlink_pending;
	/* Node in the lttng_inode_registry's ht. */
	struct cds_lfht_node registry_node;
	/* Weak reference to ht containing the node. */
	struct cds_lfht *registry_ht;
	struct urcu_ref ref;
	struct rcu_head rcu_head;
};

static struct {
	pthread_mutex_t lock;
	bool initialized;
	unsigned long value;
} seed = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

static
unsigned long lttng_inode_id_hash(struct inode_id *id)
{
	uint64_t device = id->device, inode_no = id->inode;

        return hash_key_u64(&device, seed.value) ^
			hash_key_u64(&inode_no, seed.value);
}

static
int lttng_inode_match(struct cds_lfht_node *node, const void *key)
{
	const struct inode_id *id = key;
	struct lttng_inode *inode = caa_container_of(node, struct lttng_inode,
			registry_node);

	return inode->id.device == id->device && inode->id.inode == id->inode;
}

static
void lttng_inode_delete(struct rcu_head *head)
{
	struct lttng_inode *inode = caa_container_of(head,
			struct lttng_inode, rcu_head);

	free(inode->path);
	free(inode);
}

static
void lttng_inode_destroy(struct lttng_inode *inode)
{
	if (!inode) {
		return;
	}
	if (inode->unlink_pending) {
		int ret = unlink(inode->path);

		DBG("Unlinking %s during lttng_inode destruction", inode->path);
		if (ret) {
			PERROR("Failed to unlink %s", inode->path);
		}
	}
	call_rcu(&inode->rcu_head, lttng_inode_delete);
}

static
void lttng_inode_release(struct urcu_ref *ref)
{
        lttng_inode_destroy(caa_container_of(ref, struct lttng_inode, ref));
}

static
void lttng_inode_get(struct lttng_inode *inode)
{
	urcu_ref_get(&inode->ref);
}

void lttng_inode_put(struct lttng_inode *inode)
{
	urcu_ref_put(&inode->ref, lttng_inode_release);
}

const char *lttng_inode_get_path(const struct lttng_inode *inode)
{
	return inode->path;
}

int lttng_inode_rename(struct lttng_inode *inode, const char *new_path,
	bool overwrite)
{
	int ret = 0;
	char *new_path_copy = NULL;

	if (inode->unlink_pending) {
		WARN("An attempt to rename an unlinked file, %s to %s, has been performed",
				inode->path, new_path);
		ret = -ENOENT;
		goto end;
	}

	if (!overwrite) {
		struct stat statbuf;

		ret = stat(new_path, &statbuf);
		if (ret == 0) {
			ret = -EEXIST;
			goto end;
		} else if (ret < 0 && errno != ENOENT) {
			PERROR("Failed to stat() %s", new_path);
			ret = -errno;
			goto end;
		}
	}

	new_path_copy = strdup(new_path);
	if (!new_path_copy) {
		ERR("Failed to allocate storage for path %s", new_path);
		ret = -ENOMEM;
		goto end;
	}

	ret = rename(inode->path, new_path);
	if (ret) {
		PERROR("Failed to rename %s to %s", inode->path, new_path);
		ret = -errno;
		goto end;
	}

	free(inode->path);
	inode->path = new_path_copy;
	new_path_copy = NULL;
end:
	free(new_path_copy);
	return ret;
}

int lttng_inode_defer_unlink(struct lttng_inode *inode)
{
	int ret = 0;
	uint16_t i = 0;
	char suffix[sizeof("-deleted-65535")] = "-deleted";
	char new_path[LTTNG_PATH_MAX];
	size_t original_path_len = strlen(inode->path);

	if (inode->unlink_pending) {
		WARN("An attempt to re-unlink %s has been performed, ignoring.",
				inode->path);
		ret = -ENOENT;
		goto end;
	}

	ret = lttng_strncpy(new_path, inode->path, sizeof(new_path));
	if (ret < 0) {
		ret = -ENAMETOOLONG;
		goto end;
	}

	for (i = 0; i < UINT16_MAX; i++) {
		int p_ret;

		if (i != 0) {
			p_ret = snprintf(suffix, sizeof(suffix), "-deleted-%" PRIu16, i);

			if (p_ret < 0) {
				PERROR("Failed to form suffix to rename file %s",
						inode->path);
				ret = -errno;
				goto end;
			}
			assert(p_ret != sizeof(suffix));
		} else {
			/* suffix is initialy set to '-deleted'. */
			p_ret = strlen(suffix);
		}

		if (original_path_len + p_ret + 1 >= sizeof(new_path)) {
			ret = -ENAMETOOLONG;
			goto end;
		}

		strcat(&new_path[original_path_len], suffix);
		ret = lttng_inode_rename(inode, new_path, false);
		if (ret != -EEXIST) {
			break;
		}
		new_path[original_path_len] = '\0';
	}
	if (!ret) {
		inode->unlink_pending = true;
	}
end:
	return ret;
}

static
struct lttng_inode *lttng_inode_create(const struct inode_id *id,
		const char *path, struct cds_lfht *ht)
{
	struct lttng_inode *inode = zmalloc(sizeof(*inode));

	if (!inode) {
		goto end;
	}

	urcu_ref_init(&inode->ref);
	cds_lfht_node_init(&inode->registry_node);
	inode->id = *id;
	inode->path = strdup(path);
	if (!inode->path) {
		goto error;
	}
end:
	return inode;
error:
	lttng_inode_destroy(inode);
	return NULL;
}

struct lttng_inode_registry *lttng_inode_registry_create(void)
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

void lttng_inode_registry_destroy(struct lttng_inode_registry *registry)
{
	if (!registry) {
		return;
	}
	if (registry->inodes) {
		int ret = cds_lfht_destroy(registry->inodes, NULL);

		assert(!ret);
	}
	free(registry);
}

struct lttng_inode *lttng_inode_registry_get_inode(
		struct lttng_inode_registry *registry,
		int fd, const char *path)
{
	int ret;
	struct stat statbuf;
	struct inode_id id;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct lttng_inode *inode = NULL;

	ret = fstat(fd, &statbuf);
	if (ret < 0) {
		PERROR("stat() failed on file %s, fd = %i", path, fd);
		goto end;
	}

	id.device = statbuf.st_dev;
	id.inode = statbuf.st_ino;

	rcu_read_lock();
	cds_lfht_lookup(registry->inodes,
			lttng_inode_id_hash(&id),
			lttng_inode_match,
		        &id,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node) {
	        inode = caa_container_of(node, struct lttng_inode, registry_node);
		/* Renames should happen through the fs-handle interface. */
		assert(!strcmp(path, inode->path));
		lttng_inode_get(inode);
		goto end_unlock;
	}

	inode = lttng_inode_create(&id, path, registry->inodes);
	node = cds_lfht_add_unique(registry->inodes,
			lttng_inode_id_hash(&inode->id),
			lttng_inode_match,
			&inode->id,
			&inode->registry_node);
	assert(node == &inode->registry_node);
end_unlock:
	rcu_read_unlock();
end:
	return inode;
}
