/*
 * Copyright (C) 2014 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SYSCALL_H
#define LTTNG_SYSCALL_H

#include "trace-kernel.hpp"

#include <common/hashtable/hashtable.hpp>

#include <lttng/event.h>

/*
 * Default size of the kernel system call array. With this size, we usually
 * reallocate twice considering a 32 bit compat layer also.
 */
#define SYSCALL_TABLE_INIT_SIZE 256

/* Maximum length of a syscall name. */
#define SYSCALL_NAME_LEN 255

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
int syscall_init_table(int tracer_fd);
ssize_t syscall_table_list(struct lttng_event **events);

#endif /* LTTNG_SYSCALL_H */
