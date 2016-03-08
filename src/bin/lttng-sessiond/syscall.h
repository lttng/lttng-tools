/*
 * Copyright (C) 2014 - David Goulet <dgoulet@efficios.com>
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

#ifndef SYSCALL_H
#define SYSCALL_H

#include <common/hashtable/hashtable.h>
#include <lttng/event.h>

#include "trace-kernel.h"

/*
 * Default size of the kernel system call array. With this size, we usually
 * reallocate twice considering a 32 bit compat layer also.
 */
#define SYSCALL_TABLE_INIT_SIZE    256

/* Maximum length of a syscall name. */
#define SYSCALL_NAME_LEN           255

/*
 * Represent a kernel syscall and used when we are populating the internal
 * list.
 */
struct syscall {
	uint32_t index;
	uint32_t bitness;
	char name[SYSCALL_NAME_LEN];
	/* Used by the list syscalls command. */
	struct lttng_ht_node_str node;
};

/*
 * Allocated once when listing all syscalls at boot time. This is an array
 * indexed by the syscall index provided in the listing.
 */
extern struct syscall *syscall_table;

/* Use to list kernel system calls. */
int syscall_init_table(void);
ssize_t syscall_table_list(struct lttng_event **events);

#endif /* SYSCALL_H */
