/*
 * SPDX-FileCopyrightText: 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-notifier-error-accounting-ust.hpp"
#include "event-notifier-error-accounting-utils.hpp"
#include "event-notifier-error-accounting.hpp"
#include "map-channel-configuration.hpp"
#include "modules-map-group.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/index-allocator.hpp>
#include <common/urcu.hpp>

#include <lttng/trigger/trigger-internal.hpp>

#include <urcu/compiler.h>

#define ERROR_COUNTER_INDEX_HT_INITIAL_SIZE 16

namespace {
struct index_ht_entry {
	struct lttng_ht_node_u64 node;
	uint64_t error_counter_index;
	struct rcu_head rcu_head;
};

nonstd::optional<lttng::sessiond::config::map_channel_configuration> default_kernel_config;
nonstd::optional<lttng::sessiond::modules::map_group> kernel_map_group;

struct error_accounting_state kernel_state;
} /* namespace */

struct error_accounting_state ust_state;

void get_trigger_info_for_log(const struct lttng_trigger *trigger,
			      const char **trigger_name,
			      uid_t *trigger_owner_uid)
{
	enum lttng_trigger_status trigger_status;

	trigger_status = lttng_trigger_get_name(trigger, trigger_name);
	switch (trigger_status) {
	case LTTNG_TRIGGER_STATUS_OK:
		break;
	case LTTNG_TRIGGER_STATUS_UNSET:
		*trigger_name = "(anonymous)";
		break;
	default:
		abort();
	}

	trigger_status = lttng_trigger_get_owner_uid(trigger, trigger_owner_uid);
	LTTNG_ASSERT(trigger_status == LTTNG_TRIGGER_STATUS_OK);
}

const char *error_accounting_status_str(enum event_notifier_error_accounting_status status)
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
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD:
		return "APP_DEAD";
	default:
		abort();
	}
}

namespace {
enum event_notifier_error_accounting_status
init_error_accounting_state(struct error_accounting_state *state, uint64_t index_count)
{
	enum event_notifier_error_accounting_status status;

	LTTNG_ASSERT(state);

	state->number_indices = index_count;

	state->index_allocator = lttng_index_allocator_create(index_count);
	if (!state->index_allocator) {
		ERR("Failed to allocate event notifier error counter index allocator");
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto end;
	}

	state->indices_ht = lttng_ht_new(ERROR_COUNTER_INDEX_HT_INITIAL_SIZE, LTTNG_HT_TYPE_U64);
	if (!state->indices_ht) {
		ERR("Failed to allocate error counter indices hash table");
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto error_indices_ht;
	}

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	goto end;

error_indices_ht:
	lttng_index_allocator_destroy(state->index_allocator);
	state->index_allocator = nullptr;
end:
	return status;
}
} /* namespace */

namespace {
void fini_error_accounting_state(struct error_accounting_state *state)
{
	LTTNG_ASSERT(state);

	/*
	 * Will assert if some error counter indices were not released (an
	 * internal error).
	 */
	lttng_ht_destroy(state->indices_ht);
	lttng_index_allocator_destroy(state->index_allocator);
}
} /* namespace */

enum event_notifier_error_accounting_status
event_notifier_error_accounting_init(uint64_t buffer_size_kernel, uint64_t buffer_size_ust)
{
	enum event_notifier_error_accounting_status status;

	status = init_error_accounting_state(&kernel_state, buffer_size_kernel);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Failed to initialize kernel event notifier accounting state: status = %s",
		    error_accounting_status_str(status));
		goto end;
	}

	default_kernel_config.emplace(
		"event-notifier-error-accounting",
		lttng::sessiond::config::map_channel_configuration::key_type_t::INDEX,
		lttng::sessiond::config::map_channel_configuration::value_type_t::SIGNED_INT_MAX,
		/* coalesce_hits */ false,
		buffer_size_kernel,
		lttng::sessiond::config::ownership_model_t::PER_UID);

	status = init_error_accounting_state(&ust_state, buffer_size_ust);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Failed to initialize UST event notifier accounting state: status = %s",
		    error_accounting_status_str(status));
		goto error_ust_state;
	}

	status = lttng::sessiond::ust::event_notifier_error_accounting::init();
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		goto error_ust_accounting_init;
	}

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	goto end;

error_ust_accounting_init:
	fini_error_accounting_state(&ust_state);
error_ust_state:
	fini_error_accounting_state(&kernel_state);
end:
	return status;
}

enum event_notifier_error_accounting_status get_error_counter_index_for_token(
	struct error_accounting_state *state, uint64_t tracer_token, uint64_t *error_counter_index)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	const struct index_ht_entry *index_entry;
	enum event_notifier_error_accounting_status status;
	const lttng::urcu::read_lock_guard read_guard;

	lttng_ht_lookup(state->indices_ht, &tracer_token, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (node) {
		index_entry = lttng::utils::container_of(node, &index_ht_entry::node);
		*error_counter_index = index_entry->error_counter_index;
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	} else {
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND;
	}

	return status;
}

namespace {
enum event_notifier_error_accounting_status
event_notifier_error_accounting_kernel_clear(const struct lttng_trigger *trigger)
{
	uint64_t error_counter_index;
	enum event_notifier_error_accounting_status status;

	status = get_error_counter_index_for_token(
		&kernel_state, lttng_trigger_get_tracer_token(trigger), &error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		ERR("Failed to get event notifier error counter index: trigger owner uid = %d, trigger name = '%s', status = '%s'",
		    trigger_owner_uid,
		    trigger_name,
		    error_accounting_status_str(status));
		return status;
	}

	try {
		kernel_map_group->clear_element(error_counter_index);
	} catch (const std::exception& ex) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		ERR("Failed to clear kernel event notifier error counter: trigger owner uid = %d, trigger name = '%s', error: %s",
		    trigger_owner_uid,
		    trigger_name,
		    ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}
} /* namespace */

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_kernel(int kernel_event_notifier_group_fd)
{
	try {
		kernel_map_group.emplace(
			lttng::sessiond::modules::map_group::create_for_event_notifier_group(
				kernel_event_notifier_group_fd, *default_kernel_config));
	} catch (const std::exception& ex) {
		ERR("Failed to create kernel event notifier group error counter: kernel_event_notifier_group_fd = %d, error: %s",
		    kernel_event_notifier_group_fd,
		    ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	DBG("Created kernel event notifier group error counter: fd = %d",
	    kernel_map_group->tracer_handle().fd());
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

namespace {
enum event_notifier_error_accounting_status create_error_counter_index_for_token(
	struct error_accounting_state *state, uint64_t tracer_token, uint64_t *error_counter_index)
{
	struct index_ht_entry *index_entry;
	enum lttng_index_allocator_status index_alloc_status;
	uint64_t local_error_counter_index;
	enum event_notifier_error_accounting_status status;

	LTTNG_ASSERT(state);

	/* Allocate a new index for that counter. */
	index_alloc_status =
		lttng_index_allocator_alloc(state->index_allocator, &local_error_counter_index);
	switch (index_alloc_status) {
	case LTTNG_INDEX_ALLOCATOR_STATUS_EMPTY:
		DBG("No indices left in the configured event notifier error counter: "
		    "number-of-indices = %" PRIu64,
		    lttng_index_allocator_get_index_count(state->index_allocator));
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE;
		goto end;
	case LTTNG_INDEX_ALLOCATOR_STATUS_OK:
		break;
	default:
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto end;
	}

	index_entry = zmalloc<index_ht_entry>();
	if (index_entry == nullptr) {
		PERROR("Failed to allocate event notifier error counter hash table entry");
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto end;
	}

	index_entry->error_counter_index = local_error_counter_index;
	lttng_ht_node_init_u64(&index_entry->node, tracer_token);
	lttng_ht_add_unique_u64(state->indices_ht, &index_entry->node);

	DBG("Allocated error counter index for tracer token: tracer token = %" PRIu64
	    ", index = %" PRIu64,
	    tracer_token,
	    local_error_counter_index);
	*error_counter_index = local_error_counter_index;
	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}
} /* namespace */

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_event_notifier(const struct lttng_trigger *trigger,
							uint64_t *error_counter_index)
{
	enum event_notifier_error_accounting_status status;
	uint64_t local_error_counter_index;
	struct error_accounting_state *state;

	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		state = &kernel_state;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		state = &ust_state;
		break;
	default:
		abort();
	}

	/*
	 * Check if this event notifier already has a error counter index
	 * assigned.
	 */
	status = get_error_counter_index_for_token(
		state, lttng_trigger_get_tracer_token(trigger), &local_error_counter_index);
	switch (status) {
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND:
	{
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		DBG("Event notifier error counter index not found for tracer token (allocating a new one): trigger name = '%s', trigger owner uid = %d, tracer token = %" PRIu64,
		    trigger_name,
		    trigger_owner_uid,
		    lttng_trigger_get_tracer_token(trigger));

		status = create_error_counter_index_for_token(
			state, lttng_trigger_get_tracer_token(trigger), &local_error_counter_index);
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			ERR("Error creating index for token: status = %s, trigger name = '%s', trigger owner uid = %d",
			    error_accounting_status_str(status),
			    trigger_name,
			    trigger_owner_uid);
			goto end;
		}
	}
	/* fall-through. */
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK:
		*error_counter_index = local_error_counter_index;
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
		break;
	default:
		break;
	}

	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		lttng::sessiond::ust::event_notifier_error_accounting::on_event_notifier_registered();
		break;
	default:
		break;
	}

end:
	return status;
}

namespace {
enum event_notifier_error_accounting_status
event_notifier_error_accounting_kernel_get_count(const struct lttng_trigger *trigger,
						 uint64_t *count)
{
	enum event_notifier_error_accounting_status status;
	uint64_t error_counter_index;

	status = get_error_counter_index_for_token(
		&kernel_state, lttng_trigger_get_tracer_token(trigger), &error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Error getting index for token: status=%s",
		    error_accounting_status_str(status));
		return status;
	}

	lttng::sessiond::map::element_value value;
	try {
		value = kernel_map_group->aggregate_element(error_counter_index);
	} catch (const std::exception& ex) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		ERR("Failed to get event notifier error count: trigger owner = %d, trigger name = '%s', error: %s",
		    trigger_owner_uid,
		    trigger_name,
		    ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	if (value.value < 0) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		ERR("Invalid negative event notifier error counter value: trigger owner = %d, trigger name = '%s', value = %" PRId64,
		    trigger_owner_uid,
		    trigger_name,
		    value.value);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	*count = (uint64_t) value.value;
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}
} /* namespace */

enum event_notifier_error_accounting_status
event_notifier_error_accounting_get_count(const struct lttng_trigger *trigger, uint64_t *count)
{
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		return event_notifier_error_accounting_kernel_get_count(trigger, count);
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		return lttng::sessiond::ust::event_notifier_error_accounting::get_trigger_count(
			trigger, count);
	default:
		abort();
	}
}

namespace {
enum event_notifier_error_accounting_status
event_notifier_error_accounting_clear(const struct lttng_trigger *trigger)
{
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		return event_notifier_error_accounting_kernel_clear(trigger);
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		return lttng::sessiond::ust::event_notifier_error_accounting::clear_trigger(
			trigger);
	default:
		abort();
	}
}
} /* namespace */

namespace {
void free_index_ht_entry(struct rcu_head *head)
{
	auto *entry = lttng::utils::container_of(head, &index_ht_entry::rcu_head);

	free(entry);
}
} /* namespace */

void event_notifier_error_accounting_unregister_event_notifier(const struct lttng_trigger *trigger)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	const uint64_t tracer_token = lttng_trigger_get_tracer_token(trigger);
	enum event_notifier_error_accounting_status status;
	struct error_accounting_state *state;

	const lttng::urcu::read_lock_guard read_lock;

	status = event_notifier_error_accounting_clear(trigger);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		/* Trigger details already logged by callee on error. */
		ERR("Failed to clear event notifier error counter during unregistration of event notifier: status = '%s'",
		    error_accounting_status_str(status));
		goto end;
	}

	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		state = &kernel_state;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		state = &ust_state;
		lttng::sessiond::ust::event_notifier_error_accounting::
			on_event_notifier_unregistered();
		break;
	default:
		abort();
	}

	lttng_ht_lookup(state->indices_ht, &tracer_token, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (node) {
		int del_ret;
		struct index_ht_entry *index_entry =
			lttng::utils::container_of(node, &index_ht_entry::node);
		enum lttng_index_allocator_status index_alloc_status;

		index_alloc_status = lttng_index_allocator_release(
			state->index_allocator, index_entry->error_counter_index);
		if (index_alloc_status != LTTNG_INDEX_ALLOCATOR_STATUS_OK) {
			uid_t trigger_owner_uid;
			const char *trigger_name;

			get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

			ERR("Failed to release event notifier error counter index: index = %" PRIu64
			    ", trigger name = '%s', trigger owner uid = %d",
			    index_entry->error_counter_index,
			    trigger_name,
			    (int) trigger_owner_uid);
			/* Don't exit, perform the rest of the clean-up. */
		}

		del_ret = lttng_ht_del(state->indices_ht, &iter);
		LTTNG_ASSERT(!del_ret);
		call_rcu(&index_entry->rcu_head, free_index_ht_entry);
	}
end:
	return;
}

void event_notifier_error_accounting_fini()
{
	kernel_map_group.reset();
	default_kernel_config.reset();

	lttng::sessiond::ust::event_notifier_error_accounting::fini();

	fini_error_accounting_state(&kernel_state);
	fini_error_accounting_state(&ust_state);
}
