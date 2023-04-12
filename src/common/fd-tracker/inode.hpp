/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef FD_TRACKER_INODE_H
#define FD_TRACKER_INODE_H

#include <common/compat/directory-handle.hpp>

#include <stdbool.h>

struct lttng_inode;
struct lttng_inode_registry;
struct lttng_unlinked_file_directory;
struct lttng_directory_handle;

/*
 * The unlinked file pool is protected by the fd-tracker's lock.
 *
 * NOTE: the unlinked file pool can use a single file desriptor when unlinked
 * files are present in the pool. This file descriptor is not accounted-for
 * by the fd-tracker. Users of the fd-tracker should account for this extra
 * file descriptor.
 */
struct lttng_unlinked_file_pool *lttng_unlinked_file_pool_create(const char *path);

void lttng_unlinked_file_pool_destroy(struct lttng_unlinked_file_pool *pool);

/* The inode registry is protected by the fd-tracker's lock. */
struct lttng_inode_registry *lttng_inode_registry_create(void);

struct lttng_inode *lttng_inode_registry_get_inode(struct lttng_inode_registry *registry,
						   struct lttng_directory_handle *handle,
						   const char *path,
						   int fd,
						   struct lttng_unlinked_file_pool *pool);

void lttng_inode_registry_destroy(struct lttng_inode_registry *registry);

void lttng_inode_borrow_location(struct lttng_inode *inode,
				 const struct lttng_directory_handle **out_directory_handle,
				 const char **out_path);

/* Returns a new reference to the inode's location directory handle. */
struct lttng_directory_handle *lttng_inode_get_location_directory_handle(struct lttng_inode *inode);

int lttng_inode_rename(struct lttng_inode *inode,
		       struct lttng_directory_handle *old_directory_handle,
		       const char *old_path,
		       struct lttng_directory_handle *new_directory_handle,
		       const char *new_path,
		       bool overwrite);

int lttng_inode_unlink(struct lttng_inode *inode);

void lttng_inode_put(struct lttng_inode *inode);

#endif /* FD_TRACKER_INODE_H */
