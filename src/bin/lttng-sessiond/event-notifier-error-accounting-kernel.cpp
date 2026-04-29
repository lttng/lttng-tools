/*
 * SPDX-FileCopyrightText: 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-notifier-error-accounting-kernel.hpp"
#include "event-notifier-error-accounting-utils.hpp"
#include "map-channel-configuration.hpp"
#include "modules-map-group.hpp"

#include <common/error.hpp>

#include <lttng/trigger/trigger-internal.hpp>

#include <vendor/optional.hpp>

namespace {
nonstd::optional<lttng::sessiond::event_notifier_error_accounting::tracer_token_index_table>
	index_table;
nonstd::optional<lttng::sessiond::config::map_channel_configuration> default_kernel_config;
nonstd::optional<lttng::sessiond::modules::map_group> kernel_map_group;
} /* namespace */

namespace lttng {
namespace sessiond {
namespace modules {
namespace event_notifier_error_accounting {

enum event_notifier_error_accounting_status init(uint64_t index_count)
{
	index_table.emplace(index_count);

	default_kernel_config.emplace(
		"event-notifier-error-accounting",
		lttng::sessiond::config::map_channel_configuration::key_type_t::INDEX,
		lttng::sessiond::config::map_channel_configuration::value_type_t::SIGNED_INT_MAX,
		lttng::sessiond::config::map_channel_configuration::update_policy_t::PER_RULE_MATCH,
		index_count,
		lttng::sessiond::config::ownership_model_t::PER_UID,
		lttng::sessiond::config::map_channel_configuration::dead_group_policy_t::DROP);

	DBG_FMT("Initialized kernel event notifier error accounting: configuration={}",
		*default_kernel_config);
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

void fini()
{
	DBG_FMT("Tearing down kernel event notifier error accounting");
	kernel_map_group.reset();
	default_kernel_config.reset();
	index_table.reset();
}

enum event_notifier_error_accounting_status
register_kernel_event_notifier_group(int kernel_event_notifier_group_fd)
{
	DBG_FMT("Creating kernel event notifier group error counter: event_notifier_group_fd={}",
		kernel_event_notifier_group_fd);

	try {
		kernel_map_group.emplace(
			lttng::sessiond::modules::map_group::create_for_event_notifier_group(
				kernel_event_notifier_group_fd, *default_kernel_config));
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to create kernel event notifier group error counter: event_notifier_group_fd={}, error=`{}`",
			kernel_event_notifier_group_fd,
			ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	DBG_FMT("Created kernel event notifier group error counter: counter_fd={}",
		kernel_map_group->tracer_handle().fd());
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

enum event_notifier_error_accounting_status
register_event_notifier(const struct lttng_trigger *trigger, uint64_t *error_counter_index)
{
	const auto tracer_token = lttng_trigger_get_tracer_token(trigger);

	DBG_FMT("Registering kernel event notifier: trigger={}", *trigger);

	auto index = index_table->lookup(tracer_token);
	if (!index) {
		DBG_FMT("Event notifier error counter index not found for tracer token, allocating a new one: trigger={}",
			*trigger);

		try {
			index = index_table->allocate(tracer_token);
		} catch (const std::exception& ex) {
			ERR_FMT("Failed to allocate event notifier error counter index: trigger={}, error=`{}`",
				*trigger,
				ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		if (!index) {
			DBG_FMT("No indices left in the configured event notifier error counter: trigger={}, index_count={}",
				*trigger,
				index_table->index_count());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE;
		}

		DBG_FMT("Allocated kernel error counter index for tracer token: trigger={}, index={}",
			*trigger,
			*index);
	} else {
		DBG_FMT("Reusing existing kernel error counter index for tracer token: trigger={}, index={}",
			*trigger,
			*index);
	}

	*error_counter_index = *index;
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

namespace {
enum event_notifier_error_accounting_status
clear_event_notifier_error_count(const struct lttng_trigger *trigger)
{
	const auto tracer_token = lttng_trigger_get_tracer_token(trigger);
	const auto error_counter_index = index_table->lookup(tracer_token);
	if (!error_counter_index) {
		ERR_FMT("Failed to get event notifier error counter index: trigger={}", *trigger);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND;
	}

	DBG_FMT("Clearing kernel event notifier error counter: trigger={}, index={}",
		*trigger,
		*error_counter_index);

	try {
		kernel_map_group->clear_element(*error_counter_index);
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to clear kernel event notifier error counter: trigger={}, index={}, error=`{}`",
			*trigger,
			*error_counter_index,
			ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}
} /* namespace */

void unregister_event_notifier(const struct lttng_trigger *trigger)
{
	DBG_FMT("Unregistering kernel event notifier: trigger={}", *trigger);

	const auto status = clear_event_notifier_error_count(trigger);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		/* Trigger details already logged by callee on error. */
		ERR_FMT("Failed to clear event notifier error counter during unregistration of event notifier: status=`{}`",
			status);
		return;
	}

	if (!index_table->release(lttng_trigger_get_tracer_token(trigger))) {
		DBG_FMT("No event notifier error counter index registered for trigger during unregistration: trigger={}",
			*trigger);
	}
}

enum event_notifier_error_accounting_status
get_event_notifier_error_count(const struct lttng_trigger *trigger, uint64_t *count)
{
	const auto tracer_token = lttng_trigger_get_tracer_token(trigger);
	const auto error_counter_index = index_table->lookup(tracer_token);
	if (!error_counter_index) {
		ERR_FMT("Failed to retrieve index for tracer token: trigger={}", *trigger);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND;
	}

	lttng::sessiond::map::element_value value;
	try {
		value = kernel_map_group->aggregate_element(*error_counter_index);
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to get event notifier error count: trigger={}, index={}, error=`{}`",
			*trigger,
			*error_counter_index,
			ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	if (value.value < 0) {
		ERR_FMT("Invalid negative event notifier error counter value: trigger={}, index={}, value={}",
			*trigger,
			*error_counter_index,
			value.value);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	DBG_FMT("Read kernel event notifier error count: trigger={}, index={}, count={}",
		*trigger,
		*error_counter_index,
		value.value);

	*count = (uint64_t) value.value;
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

} /* namespace event_notifier_error_accounting */
} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */
