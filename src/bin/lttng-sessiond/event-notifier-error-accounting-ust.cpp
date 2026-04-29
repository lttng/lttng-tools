/*
 * SPDX-FileCopyrightText: 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-notifier-error-accounting-ust.hpp"
#include "event-notifier-error-accounting-utils.hpp"
#include "map-channel-configuration.hpp"
#include "ust-app.hpp"
#include "ust-map-group.hpp"

#include <common/error.hpp>
#include <common/scope-exit.hpp>

#include <lttng/trigger/trigger-internal.hpp>

#include <mutex>
#include <sys/types.h>
#include <unordered_map>
#include <utility>
#include <vector>

namespace lttng {
namespace sessiond {
namespace ust {
namespace event_notifier_error_accounting {
namespace details {

struct ust_uid_map_group_entry {
	ust_uid_map_group_entry(uid_t uid_, lttng::sessiond::ust::map_group group_) :
		uid(uid_), group(std::move(group_))
	{
	}

	uid_t uid;
	lttng::sessiond::ust::map_group group;
	unsigned int attached_app_count = 0;
};

} /* namespace details */
} /* namespace event_notifier_error_accounting */
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

namespace {
namespace eea_details = lttng::sessiond::ust::event_notifier_error_accounting::details;

/*
 * Single mutex protecting the UID-keyed entry table and the
 * event-notifier registration count. Both pieces of state need to
 * be consulted together when deciding whether a UID entry can be
 * retired, so a unified mutex keeps the locking discipline simple.
 */
std::mutex accounting_lock;

std::unordered_map<uid_t, std::unique_ptr<eea_details::ust_uid_map_group_entry>> uid_map_groups;

/*
 * Number of currently-registered UST event notifiers. While this
 * is non-zero, every UID entry is retained even if no application
 * references it: a count query can arrive at any time and must
 * still aggregate values across known UIDs.
 */
unsigned int registered_event_notifier_count;

nonstd::optional<lttng::sessiond::event_notifier_error_accounting::tracer_token_index_table>
	ust_index_table;

nonstd::optional<lttng::sessiond::config::map_channel_configuration> default_ust_config;
} /* namespace */

namespace {
/*
 * Drop the entry if no application and no event notifier is keeping
 * it alive. Must be called with `accounting_lock` held.
 */
void drop_uid_map_group_entry_if_unused(uid_t uid)
{
	const auto it = uid_map_groups.find(uid);
	if (it == uid_map_groups.end()) {
		return;
	}

	if (it->second->attached_app_count == 0 && registered_event_notifier_count == 0) {
		DBG_FMT("Dropping unused UST UID map group entry: uid={}", uid);
		uid_map_groups.erase(it);
	}
}

/*
 * Find or create the entry for `uid` and bump its attached_app_count.
 * Paired with the destructor of `uid_entry_reference`, which
 * decrements the count and drops the entry if it becomes unused.
 */
eea_details::ust_uid_map_group_entry& acquire_uid_entry(uid_t uid)
{
	const std::lock_guard<std::mutex> guard(accounting_lock);

	eea_details::ust_uid_map_group_entry *entry;
	const auto it = uid_map_groups.find(uid);
	if (it != uid_map_groups.end()) {
		entry = it->second.get();
		DBG_FMT("Reusing existing UST UID map group entry: uid={}, attached_app_count={}",
			uid,
			entry->attached_app_count);
	} else {
		DBG_FMT("Creating new UST UID map group entry: uid={}, configuration={}",
			uid,
			*default_ust_config);
		auto new_entry = lttng::make_unique<eea_details::ust_uid_map_group_entry>(
			uid,
			lttng::sessiond::ust::map_group::create_from_config(*default_ust_config));
		entry = new_entry.get();
		uid_map_groups.emplace(uid, std::move(new_entry));
	}

	entry->attached_app_count++;
	return *entry;
}
} /* namespace */

namespace lttng {
namespace sessiond {
namespace ust {
namespace event_notifier_error_accounting {
namespace details {

uid_entry_reference::uid_entry_reference(uid_t uid) : _uid(uid), _entry(acquire_uid_entry(uid))
{
}

uid_entry_reference::~uid_entry_reference()
{
	const std::lock_guard<std::mutex> guard(accounting_lock);
	_entry.attached_app_count--;
	DBG_FMT("Releasing UST UID map group entry reference: uid={}, attached_app_count={}, registered_event_notifier_count={}",
		_uid,
		_entry.attached_app_count,
		registered_event_notifier_count);
	drop_uid_map_group_entry_if_unused(_uid);
}

ust_uid_map_group_entry& uid_entry_reference::entry() const noexcept
{
	return _entry;
}

} /* namespace details */
} /* namespace event_notifier_error_accounting */
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

namespace {
enum event_notifier_error_accounting_status
send_counter_data_to_ust(lttng::sessiond::ust::app *app,
			 struct lttng_ust_abi_object_data *new_counter)
{
	/* Attach counter to trigger group. */
	try {
		app->command_socket.lock().send_counter_data_to_ust(
			app->event_notifier_group.object->header.handle, new_counter);
	} catch (const lttng::sessiond::ust::app_communication_error&) {
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD;
	} catch (const lttng::runtime_error&) {
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}
} /* namespace */

namespace {
enum event_notifier_error_accounting_status
send_counter_cpu_data_to_ust(lttng::sessiond::ust::app *app,
			     struct lttng_ust_abi_object_data *counter,
			     struct lttng_ust_abi_object_data *counter_cpu)
{
	try {
		app->command_socket.lock().send_counter_cpu_data_to_ust(counter, counter_cpu);
	} catch (const lttng::sessiond::ust::app_communication_error&) {
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD;
	} catch (const lttng::runtime_error&) {
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}
} /* namespace */

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_app(lttng::sessiond::ust::app *app)
{
	if (!ust_app_supports_counters(app)) {
		DBG_FMT("Skipping event notifier error accounting registration: app does not support counters: app={}",
			*app);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_UNSUPPORTED;
	}

	DBG_FMT("Registering app for event notifier error accounting: app={}", *app);

	/*
	 * Take the reference directly into the app's storage so the
	 * unregister path is just a `.reset()`. A scope_exit drops the
	 * reference on every early return below; disarming it at the
	 * bottom keeps it once the tracer handles have been transferred.
	 */
	try {
		app->event_notifier_group.accounting_reference.emplace(app->uid);
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to create UID map group entry: app={}, error=`{}`",
			*app,
			ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	auto rollback_reference = lttng::make_scope_exit(
		[app]() noexcept { app->event_notifier_group.accounting_reference.reset(); });

	auto& entry = app->event_notifier_group.accounting_reference->entry();

	lttng::sessiond::ust::ust_object_data new_counter(nullptr);
	try {
		new_counter = entry.group.duplicate_app_counter_handle();
	} catch (const std::exception& ex) {
		ERR_FMT("Failed to duplicate UST counter object: app={}, error=`{}`",
			*app,
			ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	auto status = send_counter_data_to_ust(app, new_counter.get());
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD) {
			ERR_FMT("Failed to send counter data to application tracer: status=`{}`, app={}",
				status,
				*app);
		}
		return status;
	}

	const auto nr_counter_cpu = entry.group.map_count();
	std::vector<lttng::sessiond::ust::ust_object_data> new_cpu_counters;
	new_cpu_counters.reserve(nr_counter_cpu);

	for (const auto& m : entry.group.maps()) {
		lttng::sessiond::ust::ust_object_data new_counter_cpu(nullptr);
		try {
			new_counter_cpu = entry.group.duplicate_map_handle(*m->cpu_id);
		} catch (const std::exception& ex) {
			ERR_FMT("Failed to duplicate UST counter cpu handle: app={}, cpu={}, error=`{}`",
				*app,
				*m->cpu_id,
				ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		status =
			send_counter_cpu_data_to_ust(app, new_counter.get(), new_counter_cpu.get());
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD) {
				ERR_FMT("Failed to send counter cpu data to application tracer: status=`{}`, app={}, cpu={}",
					status,
					*app,
					*m->cpu_id);
			}
			return status;
		}

		new_cpu_counters.emplace_back(std::move(new_counter_cpu));
	}

	/*
	 * Transfer ownership of the wire-format handles to the app.
	 * The unregister path releases them through the app socket.
	 */
	auto **cpu_counters_raw = calloc<lttng_ust_abi_object_data *>(nr_counter_cpu);
	if (!cpu_counters_raw) {
		PERROR_FMT(
			"Failed to allocate event notifier error counter lttng_ust_abi_object_data array: app={}",
			*app);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
	}

	for (unsigned int i = 0; i < nr_counter_cpu; i++) {
		cpu_counters_raw[i] = new_cpu_counters[i].release();
	}

	app->event_notifier_group.counter = new_counter.release();
	app->event_notifier_group.nr_counter_cpu = nr_counter_cpu;
	app->event_notifier_group.counter_cpu = cpu_counters_raw;

	DBG_FMT("Registered app for event notifier error accounting: app={}, nr_counter_cpu={}",
		*app,
		nr_counter_cpu);

	rollback_reference.disarm();
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_unregister_app(lttng::sessiond::ust::app *app)
{
	/* If an error occurred during app registration no entry was created. */
	if (!app->event_notifier_group.counter) {
		DBG_FMT("Skipping event notifier error accounting unregistration: no counter attached to app: app={}",
			*app);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	}

	DBG_FMT("Unregistering app from event notifier error accounting: app={}, nr_counter_cpu={}",
		*app,
		app->event_notifier_group.nr_counter_cpu);

	{
		auto protocol = app->command_socket.lock();
		for (int i = 0; i < app->event_notifier_group.nr_counter_cpu; i++) {
			try {
				protocol.release_object(app->event_notifier_group.counter_cpu[i]);
			} catch (const lttng::sessiond::ust::app_communication_error&) {
			} catch (const lttng::runtime_error&) {
			}

			free(app->event_notifier_group.counter_cpu[i]);
		}

		free(app->event_notifier_group.counter_cpu);

		try {
			protocol.release_object(app->event_notifier_group.counter);
		} catch (const lttng::sessiond::ust::app_communication_error&) {
		} catch (const lttng::runtime_error&) {
		}

		free(app->event_notifier_group.counter);
	}

	app->event_notifier_group.accounting_reference.reset();

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

namespace {
/*
 * Bump the registered-event-notifier count. While this count is
 * non-zero, every UID entry is retained even if no application
 * references it.
 */
void on_event_notifier_registered()
{
	const std::lock_guard<std::mutex> guard(accounting_lock);

	registered_event_notifier_count++;
	DBG_FMT("Bumped registered UST event notifier count: registered_event_notifier_count={}",
		registered_event_notifier_count);
}

/*
 * Drop the count and, on hitting zero, sweep UID entries that are no
 * longer referenced by any app -- the same predicate the per-app
 * `uid_entry_reference` destructor would apply, but for every UID at
 * once.
 */
void on_event_notifier_unregistered()
{
	const std::lock_guard<std::mutex> guard(accounting_lock);

	LTTNG_ASSERT(registered_event_notifier_count > 0);
	registered_event_notifier_count--;
	DBG_FMT("Decremented registered UST event notifier count: registered_event_notifier_count={}",
		registered_event_notifier_count);

	if (registered_event_notifier_count == 0) {
		for (auto it = uid_map_groups.begin(); it != uid_map_groups.end();) {
			if (it->second->attached_app_count == 0) {
				DBG_FMT("Sweeping unused UST UID map group entry: uid={}",
					it->second->uid);
				it = uid_map_groups.erase(it);
			} else {
				++it;
			}
		}
	}
}

enum event_notifier_error_accounting_status
clear_event_notifier_error_count(const struct lttng_trigger *trigger)
{
	const auto tracer_token = lttng_trigger_get_tracer_token(trigger);

	const auto error_counter_index = ust_index_table->lookup(tracer_token);
	if (!error_counter_index) {
		ERR_FMT("Failed to retrieve index for tracer token: trigger={}", *trigger);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND;
	}

	const std::lock_guard<std::mutex> guard(accounting_lock);

	DBG_FMT("Clearing UST event notifier error counter across all UID entries: trigger={}, index={}, uid_entry_count={}",
		*trigger,
		*error_counter_index,
		uid_map_groups.size());

	for (const auto& kv : uid_map_groups) {
		try {
			kv.second->group.clear_element(*error_counter_index);
		} catch (const std::exception& ex) {
			ERR_FMT("Failed to clear event notifier counter value for trigger: trigger={}, counter_uid={}, index={}, error=`{}`",
				*trigger,
				kv.second->uid,
				*error_counter_index,
				ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}
	}

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}
} /* namespace */

namespace lttng {
namespace sessiond {
namespace ust {
namespace event_notifier_error_accounting {

enum event_notifier_error_accounting_status init(std::uint64_t index_count)
{
	ust_index_table.emplace(index_count);

	default_ust_config.emplace(
		"event-notifier-error-accounting",
		lttng::sessiond::config::map_channel_configuration::key_type_t::INDEX,
		lttng::sessiond::config::map_channel_configuration::value_type_t::SIGNED_INT_32,
		lttng::sessiond::config::map_channel_configuration::update_policy_t::PER_RULE_MATCH,
		index_count,
		lttng::sessiond::config::ownership_model_t::PER_UID,
		lttng::sessiond::config::map_channel_configuration::dead_group_policy_t::DROP);

	DBG_FMT("Initialized UST event notifier error accounting: configuration={}",
		*default_ust_config);
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

void fini()
{
	DBG_FMT("Tearing down UST event notifier error accounting");
	{
		const std::lock_guard<std::mutex> guard(accounting_lock);

		uid_map_groups.clear();
		registered_event_notifier_count = 0;
	}
	default_ust_config.reset();
	ust_index_table.reset();
}

enum event_notifier_error_accounting_status
register_event_notifier(const struct lttng_trigger *trigger, std::uint64_t *error_counter_index)
{
	const auto tracer_token = lttng_trigger_get_tracer_token(trigger);

	DBG_FMT("Registering UST event notifier: trigger={}", *trigger);

	auto index = ust_index_table->lookup(tracer_token);
	if (!index) {
		DBG_FMT("Event notifier error counter index not found for tracer token, allocating a new one: trigger={}",
			*trigger);

		try {
			index = ust_index_table->allocate(tracer_token);
		} catch (const std::exception& ex) {
			ERR_FMT("Failed to allocate event notifier error counter index: trigger={}, error=`{}`",
				*trigger,
				ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		if (!index) {
			DBG_FMT("No indices left in the configured event notifier error counter: trigger={}, index_count={}",
				*trigger,
				ust_index_table->index_count());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE;
		}

		DBG_FMT("Allocated UST error counter index for tracer token: trigger={}, index={}",
			*trigger,
			*index);
	} else {
		DBG_FMT("Reusing existing UST error counter index for tracer token: trigger={}, index={}",
			*trigger,
			*index);
	}

	*error_counter_index = *index;
	on_event_notifier_registered();
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

void unregister_event_notifier(const struct lttng_trigger *trigger)
{
	DBG_FMT("Unregistering UST event notifier: trigger={}", *trigger);

	const auto status = clear_event_notifier_error_count(trigger);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		/* Trigger details already logged by callee on error. */
		ERR_FMT("Failed to clear event notifier error counter during unregistration of event notifier: status=`{}`",
			status);
		return;
	}

	on_event_notifier_unregistered();

	if (!ust_index_table->release(lttng_trigger_get_tracer_token(trigger))) {
		DBG_FMT("No event notifier error counter index registered for trigger during unregistration: trigger={}",
			*trigger);
	}
}

enum event_notifier_error_accounting_status
get_event_notifier_error_count(const struct lttng_trigger *trigger, std::uint64_t *count)
{
	const auto tracer_token = lttng_trigger_get_tracer_token(trigger);

	const auto error_counter_index = ust_index_table->lookup(tracer_token);
	if (!error_counter_index) {
		ERR_FMT("Failed to retrieve index for tracer token: trigger={}", *trigger);
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND;
	}

	uint64_t global_sum = 0;
	const std::lock_guard<std::mutex> guard(accounting_lock);

	DBG_FMT("Aggregating UST event notifier error count across all UID entries: trigger={}, index={}, uid_entry_count={}",
		*trigger,
		*error_counter_index,
		uid_map_groups.size());

	/*
	 * Aggregate across all UID entries regardless of the trigger's
	 * uid: any user that is allowed to register a trigger with this
	 * sessiond is also allowed to observe errors generated by any of
	 * the applications the sessiond manages.
	 */
	for (const auto& kv : uid_map_groups) {
		lttng::sessiond::map::element_value value;

		try {
			value = kv.second->group.aggregate_element(*error_counter_index);
		} catch (const std::exception& ex) {
			ERR_FMT("Failed to aggregate event notifier error counter value: trigger={}, counter_uid={}, index={}, error=`{}`",
				*trigger,
				kv.second->uid,
				*error_counter_index,
				ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		if (value.value < 0) {
			ERR_FMT("Negative event notifier error counter value encountered during aggregation: trigger={}, counter_uid={}, index={}, value={}",
				*trigger,
				kv.second->uid,
				*error_counter_index,
				value.value);
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		global_sum += (uint64_t) value.value;
	}

	DBG_FMT("Aggregated UST event notifier error count: trigger={}, index={}, count={}",
		*trigger,
		*error_counter_index,
		global_sum);

	*count = global_sum;
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

} /* namespace event_notifier_error_accounting */
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */
