/*
 * lttng-memleak-finder.c
 *
 * LTTng memory leak finder
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
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include "hlist.h"

#include "jhash.h"

static volatile int print_to_console;

static pthread_mutex_t mh_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *(*callocp)(size_t, size_t);
static void *(*mallocp)(size_t);
static void *(*reallocp)(void *, size_t);
static void *(*memalignp)(size_t, size_t);
static void (*freep)(void *);

static volatile int initialized;
static __thread int thread_in_hook;

#define STATIC_CALLOC_LEN	4096
static char static_calloc_buf[STATIC_CALLOC_LEN];
static size_t static_calloc_len;

#define MH_HASH_BITS	20	/* 1 M entries, hardcoded for now */
#define MH_TABLE_SIZE	(1 << MH_HASH_BITS)
static struct cds_hlist_head mh_table[MH_TABLE_SIZE];

struct mh_entry {
	struct cds_hlist_node hlist;
	void *ptr;
	const void *alloc_caller;
	char *caller_symbol;
	size_t alloc_size;
};

static struct mh_entry *
get_mh(const void *ptr)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct mh_entry *e;
	uint32_t hash;

	hash = jhash(&ptr, sizeof(ptr), 0);
	head = &mh_table[hash & (MH_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (ptr == e->ptr)
			return e;
	}
	return NULL;
}

static void
add_mh(void *ptr, size_t alloc_size, const void *caller)
{
	struct cds_hlist_head *head;
	struct cds_hlist_node *node;
	struct mh_entry *e;
	uint32_t hash;
	Dl_info info;

	if (!ptr)
		return;
	hash = jhash(&ptr, sizeof(ptr), 0);
	head = &mh_table[hash & (MH_TABLE_SIZE - 1)];
	cds_hlist_for_each_entry(e, node, head, hlist) {
		if (ptr == e->ptr) {
			fprintf(stderr, "[warning] add_mh pointer %p is already there\n",
				ptr);
			//assert(0);	/* already there */
		}
	}
	e = malloc(sizeof(*e));
	e->ptr = ptr;
	e->alloc_caller = caller;
	e->alloc_size = alloc_size;
	if (dladdr(caller, &info) && info.dli_sname) {
		e->caller_symbol = strdup(info.dli_sname);
	} else {
		e->caller_symbol = NULL;
	}
	cds_hlist_add_head(&e->hlist, head);
}

static void
del_mh(void *ptr, const void *caller)
{
	struct mh_entry *e;

	if (!ptr)
		return;
	e = get_mh(ptr);
	if (!e) {
		fprintf(stderr,
			"[warning] trying to free unallocated ptr %p caller %p\n",
			ptr, caller);
		return;
	}
	cds_hlist_del(&e->hlist);
	free(e->caller_symbol);
	free(e);
}

static void __attribute__((constructor))
do_init(void)
{
	char *env;

	if (initialized)
		return;
	callocp = (void *(*) (size_t, size_t)) dlsym (RTLD_NEXT, "calloc");
	mallocp = (void *(*) (size_t)) dlsym (RTLD_NEXT, "malloc");
	reallocp = (void *(*) (void *, size_t)) dlsym (RTLD_NEXT, "realloc");
	memalignp = (void *(*)(size_t, size_t)) dlsym (RTLD_NEXT, "memalign");
	freep = (void (*) (void *)) dlsym (RTLD_NEXT, "free");

	env = getenv("LTTNG_MEMLEAK_PRINT");
	if (env && strcmp(env, "1") == 0)
		print_to_console = 1;

	initialized = 1;
}

static
void *static_calloc(size_t nmemb, size_t size)
{
	size_t prev_len;

	if (nmemb * size > sizeof(static_calloc_buf) - static_calloc_len)
		return NULL;
	prev_len = static_calloc_len;
	static_calloc_len += nmemb + size;
	return &static_calloc_buf[prev_len];
}

void *
calloc(size_t nmemb, size_t size)
{
	void *result;
	const void *caller = __builtin_return_address(0);

	if (callocp == NULL) {
		return static_calloc(nmemb, size);
	}

	do_init();

	if (thread_in_hook) {
		return callocp(nmemb, size);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&mh_mutex);

	/* Call resursively */
	result = callocp(nmemb, size);

	add_mh(result, nmemb * size, caller);

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "calloc(%zu,%zu) returns %p\n", nmemb, size, result);

	pthread_mutex_unlock(&mh_mutex);

	thread_in_hook = 0;

	return result;
}

void *
malloc(size_t size)
{
	void *result;
	const void *caller = __builtin_return_address(0);

	do_init();

	if (thread_in_hook) {
		return mallocp(size);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&mh_mutex);

	/* Call resursively */
	result = mallocp(size);

	add_mh(result, size, caller);

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "malloc(%zu) returns %p\n", size, result);

	pthread_mutex_unlock(&mh_mutex);

	thread_in_hook = 0;

	return result;
}

void *
realloc(void *ptr, size_t size)
{
	void *result;
	const void *caller = __builtin_return_address(0);

	do_init();

	if (thread_in_hook) {
		return reallocp(ptr, size);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&mh_mutex);

	/* Call resursively */
	result = reallocp(ptr, size);

	if (size == 0 && ptr) {
		/* equivalent to free() */
		del_mh(ptr, caller);
	} else if (result) {
		del_mh(ptr, caller);
		add_mh(result, size, caller);
	}

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "realloc(%p,%zu) returns %p\n", ptr, size, result);

	pthread_mutex_unlock(&mh_mutex);

	thread_in_hook = 0;

	return result;
}

void *
memalign(size_t alignment, size_t size)
{
	void *result;
	const void *caller = __builtin_return_address(0);

	do_init();

	if (thread_in_hook) {
		return memalignp(alignment, size);
	}

	thread_in_hook = 1;

	pthread_mutex_lock(&mh_mutex);

	/* Call resursively */
	result = memalignp(alignment, size);

	add_mh(result, size, caller);

	/* printf might call malloc, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "memalign(%zu,%zu) returns %p\n",
			alignment, size, result);

	pthread_mutex_unlock(&mh_mutex);

	thread_in_hook = 0;

	return result;
}

void
free(void *ptr)
{
	const void *caller = __builtin_return_address(0);

	do_init();

	if (thread_in_hook) {
		freep(ptr);
		return;
	}

	thread_in_hook = 1;
	pthread_mutex_lock(&mh_mutex);

	/* Call resursively */
	freep(ptr);

	del_mh(ptr, caller);

	/* printf might call free, so protect it too. */
	if (print_to_console)
		fprintf(stderr, "freed pointer %p\n", ptr);

	pthread_mutex_unlock(&mh_mutex);
	thread_in_hook = 0;
}

static __attribute__((destructor))
void print_leaks(void)
{
	unsigned long i;

	for (i = 0; i < MH_TABLE_SIZE; i++) {
		struct cds_hlist_head *head;
		struct cds_hlist_node *node;
		struct mh_entry *e;

		head = &mh_table[i];
		cds_hlist_for_each_entry(e, node, head, hlist) {
			fprintf(stderr, "[leak] ptr: %p size: %zu caller: %p <%s>\n",
				e->ptr, e->alloc_size, e->alloc_caller,
				e->caller_symbol);
		}
	}
}
