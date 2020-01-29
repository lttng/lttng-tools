/*
 * Copyright (C) 2020 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#ifndef FD_TRACKER_INODE_H
#define FD_TRACKER_INODE_H

#include <common/compat/directory-handle.h>
#include <stdbool.h>

struct lttng_inode;
struct lttng_inode_registry;
struct lttng_unlinked_file_directory;

/*
 * The unlinked file pool is protected by the fd-tracker's lock.
 *
 * NOTE: the unlinked file pool can use a single file desriptor when unlinked
 * files are present in the pool. This file descriptor is not accounted-for
 * by the fd-tracker. Users of the fd-tracker should account for this extra
 * file descriptor.
 */
struct lttng_unlinked_file_pool *lttng_unlinked_file_pool_create(
		const char *path);

void lttng_unlinked_file_pool_destroy(
		struct lttng_unlinked_file_pool *pool);

/* The inode registry is protected by the fd-tracker's lock. */
struct lttng_inode_registry *lttng_inode_registry_create(void);

struct lttng_inode *lttng_inode_registry_get_inode(
		struct lttng_inode_registry *registry,
		struct lttng_directory_handle *handle,
		const char *path,
		int fd,
		struct lttng_unlinked_file_pool *pool);

void lttng_inode_registry_destroy(struct lttng_inode_registry *registry);

void lttng_inode_get_location(struct lttng_inode *inode,
		const struct lttng_directory_handle **out_directory_handle,
		const char **out_path);

int lttng_inode_rename(struct lttng_inode *inode,
		struct lttng_directory_handle *old_directory_handle,
		const char *old_path,
		struct lttng_directory_handle *new_directory_handle,
		const char *new_path,
		bool overwrite);

int lttng_inode_unlink(struct lttng_inode *inode);

void lttng_inode_put(struct lttng_inode *inode);

#endif /* FD_TRACKER_INODE_H */
