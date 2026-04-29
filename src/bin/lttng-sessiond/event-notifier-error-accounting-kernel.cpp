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

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

void fini()
{
	kernel_map_group.reset();
	default_kernel_config.reset();
	index_table.reset();
}

enum event_notifier_error_accounting_status
register_kernel_event_notifier_group(int kernel_event_notifier_group_fd)
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
register_event_notifier(const struct lttng_trigger *trigger, uint64_t *error_counter_index)
{
	const auto tracer_token = lttng_trigger_get_tracer_token(trigger);
	auto index = index_table->lookup(tracer_token);
	if (!index) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		DBG("Event notifier error counter index not found for tracer token (allocating a new one): trigger name = '%s', trigger owner uid = %d, tracer token = %" PRIu64,
		    trigger_name,
		    trigger_owner_uid,
		    tracer_token);

		try {
			index = index_table->allocate(tracer_token);
		} catch (const std::exception& ex) {
			ERR("Failed to allocate event notifier error counter index: trigger name = '%s', trigger owner uid = %d, error: %s",
			    trigger_name,
			    trigger_owner_uid,
			    ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		if (!index) {
			DBG("No indices left in the configured event notifier error counter: number-of-indices = %" PRIu64,
			    index_table->index_count());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE;
		}

		DBG("Allocated error counter index for tracer token: tracer token = %" PRIu64
		    ", index = %" PRIu64,
		    tracer_token,
		    *index);
	}

	*error_counter_index = *index;
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

namespace {
enum event_notifier_error_accounting_status
clear_event_notifier_error_count(const struct lttng_trigger *trigger)
{
	const auto error_counter_index =
		index_table->lookup(lttng_trigger_get_tracer_token(trigger));
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

void unregister_event_notifier(const struct lttng_trigger *trigger)
{
	const auto status = clear_event_notifier_error_count(trigger);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		/* Trigger details already logged by callee on error. */
		ERR("Failed to clear event notifier error counter during unregistration of event notifier: status = '%s'",
		    error_accounting_status_str(status));
		return;
	}

	if (!index_table->release(lttng_trigger_get_tracer_token(trigger))) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		DBG("No event notifier error counter index registered for trigger during unregistration: trigger name = '%s', trigger owner uid = %d",
		    trigger_name,
		    (int) trigger_owner_uid);
	}
}

enum event_notifier_error_accounting_status
get_event_notifier_error_count(const struct lttng_trigger *trigger, uint64_t *count)
{
	const auto error_counter_index =
		index_table->lookup(lttng_trigger_get_tracer_token(trigger));
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

} /* namespace event_notifier_error_accounting */
} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */
