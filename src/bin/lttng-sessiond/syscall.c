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

#define _GNU_SOURCE
#include <common/bitfield.h>
#include <common/common.h>
#include <common/kernel-ctl/kernel-ctl.h>

#include "lttng-sessiond.h"
#include "kernel.h"
#include "syscall.h"
#include "utils.h"

/* Global syscall table. */
struct syscall *syscall_table;

/* Number of entry in the syscall table. */
static size_t syscall_table_nb_entry;

/*
 * Populate the system call table using the kernel tracer.
 *
 * Return 0 on success and the syscall table is allocated. On error, a negative
 * value is returned and the syscall table is set to NULL.
 */
int syscall_init_table(void)
{
	int ret, fd, err;
	size_t nbmem;
	FILE *fp;
	/* Syscall data from the kernel. */
	size_t index;
	uint32_t bitness;
	char name[SYSCALL_NAME_LEN];

	DBG3("Syscall init system call table");

	fd = kernctl_syscall_list(kernel_tracer_fd);
	if (fd < 0) {
		ret = -errno;
		PERROR("kernelctl syscall list");
		goto error_ioctl;
	}

	fp = fdopen(fd, "r");
	if (!fp) {
		ret = -errno;
		PERROR("syscall list fdopen");
		goto error_fp;
	}

	nbmem = SYSCALL_TABLE_INIT_SIZE;
	syscall_table = zmalloc(sizeof(struct syscall) * nbmem);
	if (!syscall_table) {
		ret = -errno;
		PERROR("syscall list zmalloc");
		goto error;
	}

	while (fscanf(fp,
				"syscall { index = %lu; \
				name = %" XSTR(SYSCALL_NAME_LEN) "[^;]; \
				bitness = %u; };\n",
				&index, name, &bitness) == 3) {
		if (index >= nbmem ) {
			struct syscall *new_list;
			size_t new_nbmem;

			/* Double memory size. */
			new_nbmem = index << 1;

			DBG("Reallocating syscall table from %zu to %zu entries", nbmem,
					new_nbmem);
			new_list = realloc(syscall_table, new_nbmem * sizeof(*new_list));
			if (!new_list) {
				ret = -errno;
				PERROR("syscall list realloc");
				goto error;
			}

			/* Zero out the new memory. */
			memset(new_list + nbmem, 0,
					(new_nbmem - nbmem) * sizeof(*new_list));
			nbmem = new_nbmem;
			syscall_table = new_list;
		}
		syscall_table[index].index = index;
		syscall_table[index].bitness = bitness;
		strncpy(syscall_table[index].name, name,
				sizeof(syscall_table[index].name));
		/*
		DBG("Syscall name '%s' at index %" PRIu32 " of bitness %u",
				syscall_table[index].name,
				syscall_table[index].index,
				syscall_table[index].bitness);
		*/
	}

	syscall_table_nb_entry = index;

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
 * unsuable. RCU read side lock MUST be acquired before calling this.
 */
static void destroy_syscall_ht(struct lttng_ht *ht)
{
	struct lttng_ht_iter iter;
	struct syscall *ksyscall;

	DBG3("Destroying syscall hash table.");

	if (!ht) {
		return;
	}

	cds_lfht_for_each_entry(ht->ht, &iter.iter, ksyscall, node.node) {
		int ret;

		ret = lttng_ht_del(ht, &iter);
		assert(!ret);
		free(ksyscall);
	}
	ht_cleanup_push(ht);
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
 * Return syscall object if found or else NULL.
 */
static struct syscall *lookup_syscall(struct lttng_ht *ht, const char *name)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct syscall *ksyscall = NULL;

	assert(ht);
	assert(name);

	lttng_ht_lookup(ht, (void *) name, &iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node) {
		ksyscall = caa_container_of(node, struct syscall, node);
	}

	return ksyscall;
}

/*
 * Using the given syscall object in the events array with the bitness of the
 * syscall at index in the syscall table.
 */
static void update_event_syscall_bitness(struct lttng_event *events,
		unsigned int index, unsigned int syscall_index)
{
	assert(events);

	if (syscall_table[index].bitness == 32) {
		events[syscall_index].flags |= LTTNG_EVENT_FLAG_SYSCALL_32;
	} else {
		events[syscall_index].flags |= LTTNG_EVENT_FLAG_SYSCALL_64;
	}
}

/*
 * Allocate and initialize syscall object and add it to the given hashtable.
 *
 * Return 0 on success else -LTTNG_ERR_NOMEM.
 */
static int add_syscall_to_ht(struct lttng_ht *ht, unsigned int index,
		unsigned int syscall_index)
{
	int ret;
	struct syscall *ksyscall;

	assert(ht);

	ksyscall = zmalloc(sizeof(*ksyscall));
	if (!ksyscall) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	strncpy(ksyscall->name, syscall_table[index].name,
			sizeof(ksyscall->name));
	ksyscall->bitness = syscall_table[index].bitness;
	ksyscall->index = syscall_index;
	lttng_ht_node_init_str(&ksyscall->node, ksyscall->name);
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
	struct lttng_ht *syscalls_ht = NULL;

	assert(_events);

	DBG("Syscall table listing.");

	rcu_read_lock();

	/*
	 * Allocate at least the number of total syscall we have even if some of
	 * them might not be valid. The count below will make sure to return the
	 * right size of the events array.
	 */
	events = zmalloc(syscall_table_nb_entry * sizeof(*events));
	if (!events) {
		PERROR("syscall table list zmalloc");
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	ret = init_syscall_ht(&syscalls_ht);
	if (ret < 0) {
		goto error;
	}

	for (i = 0; i < syscall_table_nb_entry; i++) {
		struct syscall *ksyscall;

		/* Skip empty syscalls. */
		if (*syscall_table[i].name == '\0') {
			continue;
		}

		ksyscall = lookup_syscall(syscalls_ht, syscall_table[i].name);
		if (ksyscall) {
			update_event_syscall_bitness(events, i, ksyscall->index);
			continue;
		}

		ret = add_syscall_to_ht(syscalls_ht, i, index);
		if (ret < 0) {
			goto error;
		}

		/* Copy the event information in the event's array. */
		strncpy(events[index].name, syscall_table[i].name,
				sizeof(events[index].name));
		update_event_syscall_bitness(events, i, index);
		events[index].type = LTTNG_EVENT_SYSCALL;
		/* This makes the command line not print the enabled/disabled field. */
		events[index].enabled = -1;
		index++;
	}

	destroy_syscall_ht(syscalls_ht);
	*_events = events;
	rcu_read_unlock();
	return index;

error:
	destroy_syscall_ht(syscalls_ht);
	free(events);
	rcu_read_unlock();
	return ret;
}

/*
 * Add enabled syscall to the events list using the given kernel channel.
 *
 * Return the number of entry of the events array that is different from size
 * if the array grows. On error, return negative value and events is untouched.
 */
ssize_t syscall_list_channel(struct ltt_kernel_channel *kchan,
		struct lttng_event **_events, size_t size)
{
	int err, i;
	size_t new_size;
	ssize_t ret, count;
	char *mask = NULL;
	uint32_t len;
	struct lttng_event *events = NULL;
	/* Hash table used to filter duplicate out. */
	struct lttng_ht *syscalls_ht = NULL;

	assert(kchan);

	/* Get syscall mask from the kernel tracer. */
	err = kernel_syscall_mask(kchan->fd, &mask, &len);
	if (err < 0) {
		ret = err;
		goto error;
	}

	ret = init_syscall_ht(&syscalls_ht);
	if (ret < 0) {
		goto error;
	}

	count = new_size = size;
	events = *_events;

	for (i = 0; i < len; i++) {
		unsigned char val;
		struct syscall *ksyscall;

		bitfield_read_be(mask, unsigned char, i, 1, &val);
		if (!val) {
			/* Syscall is disabled, continue the loop. */
			continue;
		}

		/* Skip empty syscall. */
		if (*syscall_table[i].name == '\0') {
			continue;
		}

		/* Syscall is enabled thus add it to the events list. */

		if (count >= new_size) {
			struct lttng_event *new_events;

			/* Get the maximum here since count can be 0. */
			new_size = max(count << 1, 1);
			DBG3("Listing syscall realloc events array from %zu to %zu", count,
					new_size);
			new_events = realloc(events, new_size * sizeof(*new_events));
			if (!new_events) {
				PERROR("realloc kernel events list");
				ret = -ENOMEM;
				goto error;
			}
			memset(new_events + count, 0,
					(new_size - count) * sizeof(*new_events));
			events = new_events;
		}

		ksyscall = lookup_syscall(syscalls_ht, syscall_table[i].name);
		if (ksyscall) {
			update_event_syscall_bitness(events, i, ksyscall->index);
			continue;
		}

		ret = add_syscall_to_ht(syscalls_ht, i, count);
		if (ret < 0) {
			goto error;
		}

		update_event_syscall_bitness(events, i, count);
		strncpy(events[count].name, syscall_table[i].name,
				sizeof(events[count].name));
		events[count].enabled = 1;
		events[count].type = LTTNG_KERNEL_SYSCALL;
		count++;
	}

	*_events = events;

	return count;

error:
	destroy_syscall_ht(syscalls_ht);
	free(events);
	return ret;
}
