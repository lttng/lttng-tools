/*
 * Copyright (C) 2014 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-syscall.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/urcu.hpp>

#include <stdbool.h>

/* Global syscall table. */
std::vector<struct syscall> syscall_table;

/*
 * Populate the system call table using the kernel tracer.
 *
 * Return 0 on success and the syscall table is allocated. On error, a negative
 * value is returned.
 */
int syscall_init_table(int tracer_fd)
{
	int ret, fd, err;
	FILE *fp;
	/* Syscall data from the kernel. */
	size_t index = 0;
	uint32_t bitness;
	char name[SYSCALL_NAME_LEN];

#if (SYSCALL_NAME_LEN == 255)
#define SYSCALL_NAME_LEN_SCANF_IS_A_BROKEN_API "254"
#endif

	DBG3("Syscall init system call table");

	fd = kernctl_syscall_list(tracer_fd);
	if (fd < 0) {
		ret = fd;
		PERROR("kernelctl syscall list");
		goto error_ioctl;
	}

	fp = fdopen(fd, "r");
	if (!fp) {
		ret = -errno;
		PERROR("syscall list fdopen");
		goto error_fp;
	}

	while (fscanf(fp,
		      "syscall { index = %zu; \
				name = %" SYSCALL_NAME_LEN_SCANF_IS_A_BROKEN_API "[^;]; \
				bitness = %u; };\n",
		      &index,
		      name,
		      &bitness) == 3) {
		try {
			syscall_table.emplace_back(index, bitness, name);
		} catch (const std::bad_alloc&) {
			ERR_FMT("Failed to add syscall to syscall table: table_current_element_count={}, syscall_name=`{}`",
				syscall_table.size(),
				name);
			ret = ENOMEM;
			goto error;
		} catch (const lttng::invalid_argument_error& ex) {
			ERR_FMT("Failed to add syscall to syscall table: table_current_element_count={}, reason=`{}`",
				syscall_table.size(),
				name,
				ex.what());
			ret = EINVAL;
			goto error;
		}
	}

	ret = 0;

error:
	err = fclose(fp);
	if (err) {
		PERROR("syscall list fclose");
	}
	return ret;

error_fp:
	err = close(fd);
	if (err) {
		PERROR("syscall list close");
	}

error_ioctl:
	return ret;
}

/*
 * Helper function for the list syscalls command that empty the temporary
 * syscall hashtable used to track duplicate between 32 and 64 bit arch.
 *
 * This empty the hash table and destroys it after. After this, the pointer is
 * unsuable. RCU read side lock MUST NOT be acquired before calling this.
 */
static void destroy_syscall_ht(struct lttng_ht *ht)
{
	DBG3("Destroying syscall hash table.");

	if (!ht) {
		return;
	}

	for (auto *ksyscall : lttng::urcu::lfht_iteration_adapter<struct syscall,
								  decltype(syscall::node),
								  &syscall::node>(*ht->ht)) {
		const auto ret = cds_lfht_del(ht->ht, &ksyscall->node.node);
		LTTNG_ASSERT(!ret);
		delete ksyscall;
	}

	lttng_ht_destroy(ht);
}

/*
 * Allocate the given hashtable pointer.
 *
 * Return 0 on success else a negative LTTNG error value.
 */
static int init_syscall_ht(struct lttng_ht **ht)
{
	int ret;

	*ht = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!*ht) {
		ret = -LTTNG_ERR_NOMEM;
	} else {
		ret = 0;
	}

	return ret;
}

/*
 * Lookup a syscall in the given hash table by name.
 *
 * RCU read lock MUST be acquired by the callers of this function.
 *
 * Return syscall object if found or else NULL.
 */
static struct syscall *lookup_syscall(struct lttng_ht *ht, const char *name)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct syscall *ksyscall = nullptr;

	LTTNG_ASSERT(ht);
	LTTNG_ASSERT(name);

	lttng_ht_lookup(ht, (void *) name, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_str>(&iter);
	if (node) {
		ksyscall = lttng::utils::container_of(node, &syscall::node);
	}

	return ksyscall;
}

/*
 * Using the given syscall object in the events array with the bitness of the
 * syscall at index in the syscall table.
 */
static void update_event_syscall_bitness(struct lttng_event *events,
					 unsigned int index,
					 unsigned int syscall_index)
{
	LTTNG_ASSERT(events);

	if (syscall_table[index].bitness == 32) {
		events[syscall_index].flags = (lttng_event_flag) (events[syscall_index].flags |
								  LTTNG_EVENT_FLAG_SYSCALL_32);
	} else {
		events[syscall_index].flags = (lttng_event_flag) (events[syscall_index].flags |
								  LTTNG_EVENT_FLAG_SYSCALL_64);
	}
}

/*
 * Allocate and initialize syscall object and add it to the given hashtable.
 *
 * Return 0 on success else -LTTNG_ERR_NOMEM.
 */
static int add_syscall_to_ht(struct lttng_ht *ht, unsigned int index, unsigned int syscall_index)
{
	int ret;
	struct syscall *ksyscall;

	LTTNG_ASSERT(ht);

	try {
		ksyscall = new struct syscall(
			syscall_index, syscall_table[index].bitness, syscall_table[index].name);
	} catch (const std::bad_alloc& ex) {
		ERR_FMT("Failed to allocate syscall entry when adding it to the global syscall hash table: syscall name=`{}`",
			syscall_table[index].name);
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	lttng_ht_add_unique_str(ht, &ksyscall->node);
	ret = 0;

error:
	return ret;
}

/*
 * List syscalls present in the kernel syscall global array, allocate and
 * populate the events structure with them. Skip the empty syscall name.
 *
 * Return the number of entries in the array else a negative value.
 */
ssize_t syscall_table_list(struct lttng_event **_events)
{
	int i, index = 0;
	ssize_t ret;
	struct lttng_event *events;
	/* Hash table used to filter duplicate out. */
	struct lttng_ht *syscalls_ht = nullptr;

	LTTNG_ASSERT(_events);

	DBG("Syscall table listing.");

	/*
	 * Allocate at least the number of total syscall we have even if some of
	 * them might not be valid. The count below will make sure to return the
	 * right size of the events array.
	 */
	events = calloc<lttng_event>(syscall_table.size());
	if (!events) {
		PERROR("syscall table list zmalloc");
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	ret = init_syscall_ht(&syscalls_ht);
	if (ret < 0) {
		goto error;
	}

	for (i = 0; i < syscall_table.size(); i++) {
		/* Skip empty syscalls. */
		if (*syscall_table[i].name == '\0') {
			continue;
		}

		{
			const lttng::urcu::read_lock_guard read_lock;
			struct syscall *ksyscall;

			ksyscall = lookup_syscall(syscalls_ht, syscall_table[i].name);
			if (ksyscall) {
				update_event_syscall_bitness(events, i, ksyscall->index);
				continue;
			}
		}

		ret = add_syscall_to_ht(syscalls_ht, i, index);
		if (ret < 0) {
			goto error;
		}

		/* Copy the event information in the event's array. */
		strncpy(events[index].name, syscall_table[i].name, sizeof(events[index].name));
		update_event_syscall_bitness(events, i, index);
		events[index].type = LTTNG_EVENT_SYSCALL;
		/* This makes the command line not print the enabled/disabled field. */
		events[index].enabled = -1;
		index++;
	}

	destroy_syscall_ht(syscalls_ht);
	*_events = events;
	return index;

error:
	destroy_syscall_ht(syscalls_ht);
	free(events);
	return ret;
}
