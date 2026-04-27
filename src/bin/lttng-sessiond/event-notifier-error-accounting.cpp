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

#include <lttng/trigger/trigger-internal.hpp>

namespace {
nonstd::optional<lttng::sessiond::config::map_channel_configuration> default_kernel_config;
nonstd::optional<lttng::sessiond::modules::map_group> kernel_map_group;
nonstd::optional<lttng::sessiond::event_notifier_error_accounting::tracer_token_index_table>
	kernel_index_table;
} /* namespace */

nonstd::optional<lttng::sessiond::event_notifier_error_accounting::tracer_token_index_table>
	ust_index_table;

namespace lttng {
namespace sessiond {
namespace event_notifier_error_accounting {

tracer_token_index_table::tracer_token_index_table(std::uint64_t index_count) :
	_index_allocator(lttng_index_allocator_create(index_count)), _index_count(index_count)
{
	if (!_index_allocator) {
		LTTNG_THROW_ERROR(
			"Failed to create index allocator for event notifier error accounting");
	}
}

nonstd::optional<std::uint64_t> tracer_token_index_table::lookup(std::uint64_t tracer_token) const
{
	const std::lock_guard<std::mutex> guard(_lock);

	const auto it = _token_to_index.find(tracer_token);
	if (it == _token_to_index.end()) {
		return nonstd::nullopt;
	}

	return it->second;
}

nonstd::optional<std::uint64_t> tracer_token_index_table::allocate(std::uint64_t tracer_token)
{
	const std::lock_guard<std::mutex> guard(_lock);

	std::uint64_t index;
	const auto status = lttng_index_allocator_alloc(_index_allocator.get(), &index);
	switch (status) {
	case LTTNG_INDEX_ALLOCATOR_STATUS_EMPTY:
		return nonstd::nullopt;
	case LTTNG_INDEX_ALLOCATOR_STATUS_OK:
		break;
	default:
		LTTNG_THROW_ERROR(
			"Failed to allocate event notifier error counter index from pool");
	}

	_token_to_index.emplace(tracer_token, index);
	return index;
}

bool tracer_token_index_table::release(std::uint64_t tracer_token)
{
	const std::lock_guard<std::mutex> guard(_lock);

	const auto it = _token_to_index.find(tracer_token);
	if (it == _token_to_index.end()) {
		return false;
	}

	const auto index = it->second;
	_token_to_index.erase(it);

	const auto status = lttng_index_allocator_release(_index_allocator.get(), index);
	if (status != LTTNG_INDEX_ALLOCATOR_STATUS_OK) {
		ERR("Failed to release event notifier error counter index: index = %" PRIu64
		    ", tracer token = %" PRIu64,
		    index,
		    tracer_token);
	}

	return true;
}

} /* namespace event_notifier_error_accounting */
} /* namespace sessiond */
} /* namespace lttng */

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

enum event_notifier_error_accounting_status
event_notifier_error_accounting_init(uint64_t buffer_size_kernel, uint64_t buffer_size_ust)
{
	using lttng::sessiond::event_notifier_error_accounting::tracer_token_index_table;

	try {
		kernel_index_table.emplace(buffer_size_kernel);
	} catch (const std::exception& ex) {
		ERR("Failed to initialize kernel event notifier accounting state: %s", ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
	}

	default_kernel_config.emplace(
		"event-notifier-error-accounting",
		lttng::sessiond::config::map_channel_configuration::key_type_t::INDEX,
		lttng::sessiond::config::map_channel_configuration::value_type_t::SIGNED_INT_MAX,
		/* coalesce_hits */ false,
		buffer_size_kernel,
		lttng::sessiond::config::ownership_model_t::PER_UID);

	try {
		ust_index_table.emplace(buffer_size_ust);
	} catch (const std::exception& ex) {
		ERR("Failed to initialize UST event notifier accounting state: %s", ex.what());
		default_kernel_config.reset();
		kernel_index_table.reset();
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
	}

	const auto ust_status = lttng::sessiond::ust::event_notifier_error_accounting::init();
	if (ust_status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ust_index_table.reset();
		default_kernel_config.reset();
		kernel_index_table.reset();
		return ust_status;
	}

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

namespace {
enum event_notifier_error_accounting_status
event_notifier_error_accounting_kernel_clear(const struct lttng_trigger *trigger)
{
	const auto error_counter_index =
		kernel_index_table->lookup(lttng_trigger_get_tracer_token(trigger));
	if (!error_counter_index) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		ERR("Failed to get event notifier error counter index: trigger owner uid = %d, trigger name = '%s'",
		    trigger_owner_uid,
		    trigger_name);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND;
	}

	try {
		kernel_map_group->clear_element(*error_counter_index);
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

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_event_notifier(const struct lttng_trigger *trigger,
							uint64_t *error_counter_index)
{
	using lttng::sessiond::event_notifier_error_accounting::tracer_token_index_table;

	tracer_token_index_table *table;
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		table = &*kernel_index_table;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		table = &*ust_index_table;
		break;
	default:
		abort();
	}

	const auto tracer_token = lttng_trigger_get_tracer_token(trigger);
	auto index = table->lookup(tracer_token);
	if (!index) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		DBG("Event notifier error counter index not found for tracer token (allocating a new one): trigger name = '%s', trigger owner uid = %d, tracer token = %" PRIu64,
		    trigger_name,
		    trigger_owner_uid,
		    tracer_token);

		try {
			index = table->allocate(tracer_token);
		} catch (const std::exception& ex) {
			ERR("Failed to allocate event notifier error counter index: trigger name = '%s', trigger owner uid = %d, error: %s",
			    trigger_name,
			    trigger_owner_uid,
			    ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		if (!index) {
			DBG("No indices left in the configured event notifier error counter: number-of-indices = %" PRIu64,
			    table->index_count());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE;
		}

		DBG("Allocated error counter index for tracer token: tracer token = %" PRIu64
		    ", index = %" PRIu64,
		    tracer_token,
		    *index);
	}

	*error_counter_index = *index;

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

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

namespace {
enum event_notifier_error_accounting_status
event_notifier_error_accounting_kernel_get_count(const struct lttng_trigger *trigger,
						 uint64_t *count)
{
	const auto error_counter_index =
		kernel_index_table->lookup(lttng_trigger_get_tracer_token(trigger));
	if (!error_counter_index) {
		ERR("Error getting index for tracer token: status=%s",
		    error_accounting_status_str(EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND));
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND;
	}

	lttng::sessiond::map::element_value value;
	try {
		value = kernel_map_group->aggregate_element(*error_counter_index);
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
		return lttng::sessiond::ust::event_notifier_error_accounting::get_trigger_error_count(
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
		return lttng::sessiond::ust::event_notifier_error_accounting::
			clear_trigger_error_counter(trigger);
	default:
		abort();
	}
}
} /* namespace */

void event_notifier_error_accounting_unregister_event_notifier(const struct lttng_trigger *trigger)
{
	using lttng::sessiond::event_notifier_error_accounting::tracer_token_index_table;

	const auto status = event_notifier_error_accounting_clear(trigger);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		/* Trigger details already logged by callee on error. */
		ERR("Failed to clear event notifier error counter during unregistration of event notifier: status = '%s'",
		    error_accounting_status_str(status));
		return;
	}

	tracer_token_index_table *table;
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		table = &*kernel_index_table;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
	case LTTNG_DOMAIN_LOG4J2:
		table = &*ust_index_table;
		lttng::sessiond::ust::event_notifier_error_accounting::
			on_event_notifier_unregistered();
		break;
	default:
		abort();
	}

	if (!table->release(lttng_trigger_get_tracer_token(trigger))) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		DBG("No event notifier error counter index registered for trigger during unregistration: trigger name = '%s', trigger owner uid = %d",
		    trigger_name,
		    (int) trigger_owner_uid);
	}
}

void event_notifier_error_accounting_fini()
{
	kernel_map_group.reset();
	default_kernel_config.reset();

	lttng::sessiond::ust::event_notifier_error_accounting::fini();

	kernel_index_table.reset();
	ust_index_table.reset();
}
