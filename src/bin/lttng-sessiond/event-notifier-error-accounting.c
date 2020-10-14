/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <urcu/compiler.h>

#include <common/error.h>
#include <common/hashtable/hashtable.h>
#include <common/index-allocator.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <lttng/trigger/trigger-internal.h>

#include "event-notifier-error-accounting.h"

#define ERROR_COUNTER_INDEX_HT_INITIAL_SIZE 16

struct index_ht_entry {
	struct lttng_ht_node_u64 node;
	uint64_t error_counter_index;
	struct rcu_head rcu_head;
};

struct kernel_error_account_entry {
	int kernel_event_notifier_error_counter_fd;
};

static struct kernel_error_account_entry kernel_error_accountant;

/* Hashtable mapping event notifier token to index_ht_entry. */
static struct lttng_ht *error_counter_indexes_ht;

static uint64_t error_counter_size;
static struct lttng_index_allocator *index_allocator;

static inline
const char *error_accounting_status_str(
		enum event_notifier_error_accounting_status status)
{
	switch (status) {
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK:
		return "OK";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR:
		return "ERROR";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND:
		return "NOT_FOUND";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM:
		return "NOMEM";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE:
		return "NO_INDEX_AVAILABLE";
	default:
		abort();
	}
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_init(uint64_t nb_bucket)
{
	enum event_notifier_error_accounting_status status;

	index_allocator = lttng_index_allocator_create(nb_bucket);
	if (!index_allocator) {
		ERR("Failed to allocate event notifier error counter index");
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto error_index_allocator;
	}

	error_counter_indexes_ht = lttng_ht_new(
			ERROR_COUNTER_INDEX_HT_INITIAL_SIZE, LTTNG_HT_TYPE_U64);
	if (!error_counter_indexes_ht) {
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto error_index_allocator;
	}

	error_counter_size = nb_bucket;

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;

error_index_allocator:
	return status;
}

static
enum event_notifier_error_accounting_status get_error_counter_index_for_token(
		uint64_t tracer_token, uint64_t *error_counter_index)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	const struct index_ht_entry *index_entry;
	enum event_notifier_error_accounting_status status;

	rcu_read_lock();
	lttng_ht_lookup(error_counter_indexes_ht, &tracer_token, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node) {
		index_entry = caa_container_of(
				node, const struct index_ht_entry, node);
		*error_counter_index = index_entry->error_counter_index;
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	} else {
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND;
	}

	rcu_read_unlock();
	return status;
}

static
enum event_notifier_error_accounting_status
event_notifier_error_accounting_kernel_clear(
		const struct lttng_trigger *trigger)
{
	int ret;
	uint64_t error_counter_index;
	enum event_notifier_error_accounting_status status;
	struct lttng_kernel_counter_clear counter_clear = {};

	status = get_error_counter_index_for_token(
			lttng_trigger_get_tracer_token(trigger),
			&error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		uid_t trigger_owner_uid;
		const char *trigger_name;
		const enum lttng_trigger_status trigger_status =
				lttng_trigger_get_owner_uid(
						trigger, &trigger_owner_uid);

		assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);
		if (lttng_trigger_get_name(trigger, &trigger_name) !=
				LTTNG_TRIGGER_STATUS_OK) {
			trigger_name = "(unnamed)";
		}

		ERR("Failed to get event notifier error counter index: trigger owner uid = %d, trigger name = '%s'",
				trigger_owner_uid, trigger_name);
		goto end;
	}

	counter_clear.index.number_dimensions = 1;
	counter_clear.index.dimension_indexes[0] = error_counter_index;

	ret = kernctl_counter_clear(
			kernel_error_accountant.kernel_event_notifier_error_counter_fd,
			&counter_clear);
	if (ret) {
		ERR("Failed to clear event notifier error counter");
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto end;
	}

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_kernel(
		int kernel_event_notifier_group_fd)
{
	int error_counter_fd = -1, ret;
	enum event_notifier_error_accounting_status status;
	const struct lttng_kernel_counter_conf error_counter_conf = {
		.arithmetic = LTTNG_KERNEL_COUNTER_ARITHMETIC_MODULAR,
		.bitness = sizeof(void *) == sizeof(uint32_t) ?
				LTTNG_KERNEL_COUNTER_BITNESS_32 :
				LTTNG_KERNEL_COUNTER_BITNESS_64,
		.global_sum_step = 0,
		.number_dimensions = 1,
		.dimensions[0].size = error_counter_size,
		.dimensions[0].has_underflow = false,
		.dimensions[0].has_overflow = false,
	};

	ret = kernctl_create_event_notifier_group_error_counter(
			kernel_event_notifier_group_fd, &error_counter_conf);
	if (ret < 0) {
		PERROR("Failed to create event notifier group error counter through kernel ioctl: kernel_event_notifier_group_fd = %d",
				kernel_event_notifier_group_fd);
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto error;
	}

	error_counter_fd = ret;

	/* Prevent fd duplication after execlp(). */
	ret = fcntl(error_counter_fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("Failed to set FD_CLOEXEC flag on event notifier error counter file descriptor: error_counter_fd = %d",
				error_counter_fd);
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto error;
	}

	DBG("Created kernel event notifier group error counter: fd = %d",
			error_counter_fd);

	kernel_error_accountant.kernel_event_notifier_error_counter_fd =
			error_counter_fd;
	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;

error:
	return status;
}

static
enum event_notifier_error_accounting_status create_error_counter_index_for_token(
		uint64_t tracer_token, uint64_t *error_counter_index)
{
	struct index_ht_entry *index_entry;
	enum lttng_index_allocator_status index_alloc_status;
	uint64_t local_error_counter_index;
	enum event_notifier_error_accounting_status status;

	/* Allocate a new index for that counter. */
	index_alloc_status = lttng_index_allocator_alloc(index_allocator,
			&local_error_counter_index);
	switch (index_alloc_status) {
	case LTTNG_INDEX_ALLOCATOR_STATUS_EMPTY:
		DBG("No indices left in the configured event notifier error counter: "
				"number-of-indices = %"PRIu64,
				lttng_index_allocator_get_index_count(
					index_allocator));
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE;
		goto end;
	case LTTNG_INDEX_ALLOCATOR_STATUS_OK:
		break;
	default:
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto end;
	}

	index_entry = zmalloc(sizeof(*index_entry));
	if (index_entry == NULL) {
		PERROR("Failed to allocate event notifier error counter hash table entry");
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto end;
	}

	index_entry->error_counter_index = local_error_counter_index;
	lttng_ht_node_init_u64(&index_entry->node, tracer_token);
	lttng_ht_add_unique_u64(error_counter_indexes_ht, &index_entry->node);

	DBG("Allocated error counter index for tracer token: tracer token = %" PRIu64 ", index = %" PRIu64,
			tracer_token, local_error_counter_index);
	*error_counter_index = local_error_counter_index;
	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_event_notifier(
		const struct lttng_trigger *trigger,
		uint64_t *error_counter_index)
{
	enum event_notifier_error_accounting_status status;
	uint64_t local_error_counter_index;

	/*
	 * Check if this event notifier already has a error counter index
	 * assigned.
	 */
	status = get_error_counter_index_for_token(
			lttng_trigger_get_tracer_token(trigger),
			&local_error_counter_index);
	switch (status) {
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND:
	{
		uid_t trigger_owner_uid;
		const char *trigger_name;
		const enum lttng_trigger_status trigger_status =
				lttng_trigger_get_owner_uid(
						trigger, &trigger_owner_uid);

		assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);
		if (lttng_trigger_get_name(trigger, &trigger_name) !=
				LTTNG_TRIGGER_STATUS_OK) {
			trigger_name = "(unnamed)";
		}

		DBG("Event notifier error counter index not found for tracer token (allocating a new one): trigger owner = %d, trigger name = '%s', tracer token = %" PRIu64,
				trigger_owner_uid, trigger_name,
				lttng_trigger_get_tracer_token(trigger));
		status = create_error_counter_index_for_token(
				lttng_trigger_get_tracer_token(trigger),
				&local_error_counter_index);
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			goto end;
		}
		/* fall-through. */
	}
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK:
		*error_counter_index = local_error_counter_index;
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
		break;
	default:
		break;
	}

end:
	return status;
}

static
enum event_notifier_error_accounting_status
event_notifier_error_accounting_kernel_get_count(
		const struct lttng_trigger *trigger, uint64_t *count)
{
	struct lttng_kernel_counter_aggregate counter_aggregate = {};
	enum event_notifier_error_accounting_status status;
	uint64_t error_counter_index;
	int ret;

	status = get_error_counter_index_for_token(
			lttng_trigger_get_tracer_token(trigger), &error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		goto end;
	}

	counter_aggregate.index.number_dimensions = 1;
	counter_aggregate.index.dimension_indexes[0] = error_counter_index;

	assert(kernel_error_accountant.kernel_event_notifier_error_counter_fd);

	ret = kernctl_counter_get_aggregate_value(
			kernel_error_accountant.kernel_event_notifier_error_counter_fd,
			&counter_aggregate);
	if (ret || counter_aggregate.value.value < 0) {
		uid_t trigger_owner_uid;
		const char *trigger_name;
		const enum lttng_trigger_status trigger_status =
				lttng_trigger_get_owner_uid(
						trigger, &trigger_owner_uid);

		assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);
		if (lttng_trigger_get_name(trigger, &trigger_name) !=
				LTTNG_TRIGGER_STATUS_OK) {
			trigger_name = "(unnamed)";
		}

		if (counter_aggregate.value.value < 0) {
			ERR("Invalid negative event notifier error counter value: trigger owner = %d, trigger name = '%s', value = %" PRId64,
					trigger_owner_uid, trigger_name,
					counter_aggregate.value.value);
		} else {
			ERR("Failed to getting event notifier error count: trigger owner = %d, trigger name = '%s', ret = %d",
					trigger_owner_uid, trigger_name, ret);
		}

		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto end;
	}

	/* Error count can't be negative. */
	assert(counter_aggregate.value.value >= 0);
	*count = (uint64_t) counter_aggregate.value.value;

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;

end:
	return status;
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_get_count(
		const struct lttng_trigger *trigger, uint64_t *count)
{
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		return event_notifier_error_accounting_kernel_get_count(
				trigger, count);
	case LTTNG_DOMAIN_UST:
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	default:
		abort();
	}
}

static
enum event_notifier_error_accounting_status
event_notifier_error_accounting_clear(const struct lttng_trigger *trigger)
{
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		return event_notifier_error_accounting_kernel_clear(trigger);
	case LTTNG_DOMAIN_UST:
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	default:
		abort();
	}
}

static void free_index_ht_entry(struct rcu_head *head)
{
	struct index_ht_entry *entry = caa_container_of(head,
			struct index_ht_entry, rcu_head);

	free(entry);
}

void event_notifier_error_accounting_unregister_event_notifier(
		const struct lttng_trigger *trigger)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct index_ht_entry *index_entry;
	enum event_notifier_error_accounting_status status;
	enum lttng_index_allocator_status index_alloc_status;
	uint64_t tracer_token = lttng_trigger_get_tracer_token(trigger);

	status = event_notifier_error_accounting_clear(trigger);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Failed to clear event notifier error counter index");
	}

	rcu_read_lock();
	lttng_ht_lookup(error_counter_indexes_ht, &tracer_token, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if(node) {
		index_entry = caa_container_of(node, struct index_ht_entry, node);
		index_alloc_status = lttng_index_allocator_release(
				index_allocator,
				index_entry->error_counter_index);
		if (index_alloc_status != LTTNG_INDEX_ALLOCATOR_STATUS_OK) {
			ERR("Failed to release event notifier error counter index: index = %" PRIu64,
					index_entry->error_counter_index);
		}

		lttng_ht_del(error_counter_indexes_ht, &iter);
		call_rcu(&index_entry->rcu_head, free_index_ht_entry);
	}

	rcu_read_unlock();
}

void event_notifier_error_accounting_fini(void)
{
	lttng_index_allocator_destroy(index_allocator);

	if (kernel_error_accountant.kernel_event_notifier_error_counter_fd) {
		const int ret = close(kernel_error_accountant.kernel_event_notifier_error_counter_fd);

		if (ret) {
			PERROR("Failed to close kernel event notifier error counter");
		}
	}

	/*
	 * Will assert if some error counters were not released (an internal
	 * error).
	 */
	lttng_ht_destroy(error_counter_indexes_ht);
}
