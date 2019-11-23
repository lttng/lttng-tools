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

#ifndef FD_TRACKER_INODE_H
#define FD_TRACKER_INODE_H

#include <stdbool.h>

struct lttng_inode;
struct lttng_inode_registry;

/* The inode registry is protected by the fd-tracker's lock. */
struct lttng_inode_registry *lttng_inode_registry_create(void);

struct lttng_inode *lttng_inode_registry_get_inode(
		struct lttng_inode_registry *registry, int fd,
		const char *path);

void lttng_inode_registry_destroy(struct lttng_inode_registry *registry);

const char *lttng_inode_get_path(const struct lttng_inode *inode);
int lttng_inode_rename(struct lttng_inode *inode, const char *new_path,
		bool overwrite);
int lttng_inode_defer_unlink(struct lttng_inode *inode);
void lttng_inode_put(struct lttng_inode *inode);

#endif /* FD_TRACKER_INODE_H */
