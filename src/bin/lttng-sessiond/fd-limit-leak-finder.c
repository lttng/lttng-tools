/*
 * fd-limit-leak-finder.c
 *
 * File descriptor leak finder
 *
 * Copyright (c) 2013 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <stdarg.h>
#include <execinfo.h>
#include <sys/epoll.h>
#include <sys/prctl.h>	/* prctl */
#include <errno.h>
#include "hlist.h"

#include "jhash.h"
#include "fd-limit.h"

#define BACKTRACE_LEN			16
#define MAX_NUM_FD			65536
#define DEFAULT_PRINT_BACKTRACE_LEN	3
#define PROCNAME_LEN			17

#ifdef __linux__
#include <syscall.h>
#endif

#if defined(_syscall0)
_syscall0(pid_t, gettid)
#elif defined(__NR_gettid)
#include <unistd.h>
static inline pid_t gettid(void)
{
	return syscall(__NR_gettid);
}
#else
#include <sys/types.h>
#include <unistd.h>

/* Fall-back on getpid for tid if not available. */
static inline pid_t gettid(void)
{
	return getpid();
}
#endif

#define fdl_printf(fmt, args...) \
	fprintf(stderr, "[fdleak %s %ld/%ld] "  fmt, \
		proc_name, (long) getpid(), (long) gettid(), ## args)

static volatile int print_to_console,
		print_backtrace_len = DEFAULT_PRINT_BACKTRACE_LEN;
static char proc_name[PROCNAME_LEN];

static pthread_mutex_t fd_mutex = PTHREAD_MUTEX_INITIALIZER;

static volatile int initialized;
static __thread int thread_in_hook;

#define FD_HASH_BITS	20	/* 1 M entries, hardcoded for now */
#define FD_TABLE_SIZE	(1 << FD_HASH_BITS)
static struct cds_hlist_head fd_table[FD_TABLE_SIZE];

struct backtrace {
	void *ptrs[BACKTRACE_LEN];
	char **symbols;
};

struct fd_entry {
	struct cds_hlist_node hlist;
	int fd;
	const void *caller;
	char *caller_symbol;
	struct backtrace bt;
};

static struct fd_entry *
get_fd(int fd)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct fd_entry *e;
	uint32_t hash;

	hash = jhash(&fd, sizeof(fd), 0);
	head = &fd_table[hash & (FD_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (fd == e->fd)
			return e;
	}
	return NULL;
}

/*
 * Allocates a string, or NULL.
 */
static
char *get_symbol(const void *caller)
{
	Dl_info info;
	char *caller_symbol;

	if (caller && dladdr(caller, &info) && info.dli_sname) {
		caller_symbol = strdup(info.dli_sname);
	} else {
		caller_symbol = NULL;
	}
	return caller_symbol;
}

static inline __attribute__((always_inline))
void save_backtrace(struct backtrace *bt)
{
	memset(bt, 0, sizeof(*bt));
	(void) backtrace(bt->ptrs, BACKTRACE_LEN);
	bt->symbols = backtrace_symbols(bt->ptrs, BACKTRACE_LEN);
}

static
void free_backtrace(struct backtrace *bt)
{
	free(bt->symbols);
}

static
void print_bt(struct backtrace *bt)
{
	int j;
	unsigned int empty = 1;

	for (j = 0; j < BACKTRACE_LEN; j++) {
		if (bt->ptrs[j]) {
			empty = 0;
			break;
		}
	}
	if (empty)
		return;

	fdl_printf("[backtrace]\n");
	for (j = 0; j < BACKTRACE_LEN && j < print_backtrace_len; j++) {
		if (!bt->ptrs[j])
			continue;
		if (bt->symbols)
			fdl_printf(" %p <%s>\n", bt->ptrs[j], bt->symbols[j]);
		else
			fdl_printf(" %p\n", bt->ptrs[j]);
	}
}

static void
add_fd(int fd, const void *caller, struct backtrace *bt)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct fd_entry *e;
	uint32_t hash;
	char *caller_symbol;

	if (fd < 0)
		return;
	hash = jhash(&fd, sizeof(fd), 0);
	head = &fd_table[hash & (FD_TABLE_SIZE - 1)];
	caller_symbol = get_symbol(caller);
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (fd == e->fd) {
			fdl_printf("[warning] add_fd fd %d is already there, caller %p <%s>\n",
				fd, caller, caller_symbol);
			print_bt(bt);
			//assert(0);	/* already there */
		}
	}
	e = calloc(1, sizeof(*e));
	e->fd = fd;
	e->caller = caller;
	e->caller_symbol = caller_symbol;
	if (bt)
		memcpy(&e->bt, bt, sizeof(*bt));
	cds_hlist_add_head(&e->hlist, head);
}

static void
del_fd(int fd, const void *caller, struct backtrace *bt, int needclose)
{
	struct fd_entry *e;

	if (fd < 0)
		return;
	e = get_fd(fd);
	if (!e) {
		if (needclose) {
			char *caller_symbol;

			caller_symbol = get_symbol(caller);
			fdl_printf("[warning] trying to free unallocated fd %d caller %p <%s>\n",
				fd, caller, caller_symbol);
			print_bt(bt);
			free(caller_symbol);
		}
		return;
	}
	cds_hlist_del(&e->hlist);
	free(e->caller_symbol);
	free_backtrace(&e->bt);
	free(e);
}

static void
do_init(void)
{
	char *env;

	if (initialized)
		return;

	(void) prctl(PR_GET_NAME, (unsigned long) proc_name, 0, 0, 0);

	env = getenv("FD_LIMIT_LEAK_FINDER_PRINT");
	if (env && strcmp(env, "1") == 0)
		print_to_console = 1;

	env = getenv("FD_LIMIT_LEAK_BACKTRACE_LEN");
	if (env)
		print_backtrace_len = atoi(env);

	initialized = 1;
}

void fd_limit_leak_open_fd(int fd)
{
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	if (fd >= 0) {
		save_backtrace(&bt);
		add_fd(fd, caller, &bt);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("fd_limit_leak_open_fd(%d)\n", fd);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;
}

void fd_limit_leak_close_fd(int fd)
{
	const void *caller = __builtin_return_address(0);
	struct backtrace bt;

	do_init();

	thread_in_hook = 1;

	pthread_mutex_lock(&fd_mutex);

	save_backtrace(&bt);
	del_fd(fd, caller, &bt, 1);

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fdl_printf("fd_limit_leak_close_fd(%d)\n", fd);

	pthread_mutex_unlock(&fd_mutex);

	thread_in_hook = 0;
}

/*
 * Library constructor initializing fd tracking. This handles file
 * descriptors present at program startup, e.g. FDs left by an exec()
 * because they did not have the FD_CLOEXEC flag set.
 */
static __attribute((constructor))
void init_fd_tracking(void)
{
	do_init();
}

static __attribute__((destructor))
void print_leaks(void)
{
	unsigned long i;

	fdl_printf("Printing leaks...\n");

	for (i = 0; i < FD_TABLE_SIZE; i++) {
		struct cds_hlist_head *head;
		struct cds_hlist_node *node;
		struct fd_entry *e;

		head = &fd_table[i];
		cds_hlist_for_each_entry(e, node, head, hlist) {
			fdl_printf("[leak] fd: %d caller: %p <%s>\n",
				e->fd, e->caller, e->caller_symbol);
			print_bt(&e->bt);
		}
	}
}
