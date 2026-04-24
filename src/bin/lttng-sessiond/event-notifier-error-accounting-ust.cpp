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
#include <common/hashtable/hashtable.hpp>
#include <common/urcu.hpp>

#include <lttng/trigger/trigger-internal.hpp>

#include <pthread.h>
#include <sys/types.h>

#include <utility>
#include <vector>

namespace {
struct event_notifier_counter {
	pthread_mutex_t lock;
	long count;
};

struct ust_uid_map_group_entry {
	ust_uid_map_group_entry(uid_t uid_, lttng::sessiond::ust::map_group group_) :
		uid(uid_), group(std::move(group_))
	{
	}

	uid_t uid;
	struct lttng_ht_node_u64 node = {};
	struct rcu_head rcu_head = {};
	lttng::sessiond::ust::map_group group;
	unsigned int attached_app_count = 0;
	bool event_notifier_present = false;
};

struct event_notifier_counter the_event_notifier_counter;
nonstd::optional<lttng::sessiond::config::map_channel_configuration> default_ust_config;
struct lttng_ht *uid_map_group_ht;
} /* namespace */

namespace {
void free_uid_map_group_entry(struct rcu_head *head)
{
	auto *entry = lttng::utils::container_of(head, &ust_uid_map_group_entry::rcu_head);

	delete entry;
}
} /* namespace */

/*
 * Remove the entry from the hash table and schedule its destruction
 * via RCU.
 */
namespace {
void retire_uid_map_group_entry(ust_uid_map_group_entry *entry)
{
	const lttng::urcu::read_lock_guard read_lock;

	cds_lfht_del(uid_map_group_ht->ht, &entry->node.node);
	call_rcu(&entry->rcu_head, free_uid_map_group_entry);
}
} /* namespace */

/*
 * Drop the entry if no application and no event notifier is keeping
 * it alive.
 */
namespace {
void drop_uid_map_group_entry_if_unused(ust_uid_map_group_entry *entry)
{
	if (entry->attached_app_count == 0 && !entry->event_notifier_present) {
		retire_uid_map_group_entry(entry);
	}
}
} /* namespace */

/*
 * Find the entry for this app's UID. The caller must hold the RCU
 * read-lock for the duration of its use of the returned pointer.
 */
namespace {
ust_uid_map_group_entry *uid_map_group_entry_find(struct lttng_ht *uid_ht,
						  const lttng::sessiond::ust::app *app)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	uint64_t key = app->uid;

	lttng_ht_lookup(uid_ht, &key, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (!node) {
		return nullptr;
	}

	return lttng::utils::container_of(node, &ust_uid_map_group_entry::node);
}
} /* namespace */

/*
 * Create a new UID entry by constructing a UST map group from the
 * default configuration. The hash table becomes the sole owner of the
 * returned entry; teardown goes through retire_uid_map_group_entry().
 */
namespace {
ust_uid_map_group_entry *uid_map_group_entry_create(const lttng::sessiond::ust::app *app)
{
	if (!ust_app_supports_counters(app)) {
		DBG("Refusing to create UID map group entry for application (unsupported feature): app name = '%s', app ppid = %d",
		    app->name.c_str(),
		    (int) app->ppid);
		return nullptr;
	}

	std::unique_ptr<ust_uid_map_group_entry> entry;
	try {
		entry.reset(new ust_uid_map_group_entry(
			app->uid,
			lttng::sessiond::ust::map_group::create_from_config(
				*default_ust_config)));
	} catch (const std::exception& ex) {
		ERR("Failed to create UID map group entry: uid=%d, pid=%d, app='%s', error: %s",
		    (int) app->uid,
		    (int) app->pid,
		    app->name.c_str(),
		    ex.what());
		return nullptr;
	}

	lttng_ht_node_init_u64(&entry->node, entry->uid);
	lttng_ht_add_unique_u64(uid_map_group_ht, &entry->node);

	return entry.release();
}
} /* namespace */

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
	enum event_notifier_error_accounting_status status;
	const lttng::urcu::read_lock_guard read_lock;

	if (!ust_app_supports_counters(app)) {
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_UNSUPPORTED;
	}

	ust_uid_map_group_entry *entry = uid_map_group_entry_find(uid_map_group_ht, app);
	if (!entry) {
		/*
		 * Take the event notifier counter lock before creating
		 * the new entry so that `event_notifier_present` reflects
		 * the state at creation time atomically with respect to
		 * any concurrent (un)registration.
		 */
		pthread_mutex_lock(&the_event_notifier_counter.lock);

		entry = uid_map_group_entry_create(app);
		if (!entry) {
			pthread_mutex_unlock(&the_event_notifier_counter.lock);
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		if (the_event_notifier_counter.count > 0) {
			entry->event_notifier_present = true;
		}

		pthread_mutex_unlock(&the_event_notifier_counter.lock);
	}

	lttng::sessiond::ust::ust_object_data new_counter(nullptr);
	try {
		new_counter = entry->group.duplicate_counter_object();
	} catch (const std::exception& ex) {
		ERR("Failed to duplicate UST counter object: uid=%d, pid=%d, app='%s', error: %s",
		    (int) app->uid,
		    (int) app->pid,
		    app->name.c_str(),
		    ex.what());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	status = send_counter_data_to_ust(app, new_counter.get());
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD) {
			ERR("Failed to send counter data to application tracer: status = %s, uid=%d, pid=%d, app='%s'",
			    error_accounting_status_str(status),
			    (int) app->uid,
			    (int) app->pid,
			    app->name.c_str());
		}
		return status;
	}

	const auto nr_counter_cpu = entry->group.map_count();
	std::vector<lttng::sessiond::ust::ust_object_data> new_cpu_counters;
	new_cpu_counters.reserve(nr_counter_cpu);

	for (const auto& m : entry->group.maps()) {
		lttng::sessiond::ust::ust_object_data new_counter_cpu(nullptr);
		try {
			new_counter_cpu = entry->group.duplicate_map_handle(*m->cpu_id);
		} catch (const std::exception& ex) {
			ERR("Failed to duplicate UST counter cpu handle: uid=%d, pid=%d, app='%s', cpu=%u, error: %s",
			    (int) app->uid,
			    (int) app->pid,
			    app->name.c_str(),
			    *m->cpu_id,
			    ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		status = send_counter_cpu_data_to_ust(app, new_counter.get(), new_counter_cpu.get());
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD) {
				ERR("Failed to send counter cpu data to application tracer: status = %s, uid=%d, pid=%d, app='%s'",
				    error_accounting_status_str(status),
				    (int) app->uid,
				    (int) app->pid,
				    app->name.c_str());
			}
			return status;
		}

		new_cpu_counters.emplace_back(std::move(new_counter_cpu));
	}

	/*
	 * Transfer ownership of the wire-format handles to the app. The
	 * unregister path releases them through the app socket.
	 */
	auto **cpu_counters_raw = calloc<lttng_ust_abi_object_data *>(nr_counter_cpu);
	if (!cpu_counters_raw) {
		PERROR("Failed to allocate event notifier error counter lttng_ust_abi_object_data array: uid=%d, pid=%d, app='%s'",
		       (int) app->uid,
		       (int) app->pid,
		       app->name.c_str());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
	}

	for (unsigned int i = 0; i < nr_counter_cpu; i++) {
		cpu_counters_raw[i] = new_cpu_counters[i].release();
	}

	app->event_notifier_group.counter = new_counter.release();
	app->event_notifier_group.nr_counter_cpu = nr_counter_cpu;
	app->event_notifier_group.counter_cpu = cpu_counters_raw;

	entry->attached_app_count++;
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_unregister_app(lttng::sessiond::ust::app *app)
{
	ust_uid_map_group_entry *entry;
	int i;

	const lttng::urcu::read_lock_guard read_lock;

	/* If an error occurred during app registration no entry was created. */
	if (!app->event_notifier_group.counter) {
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	}

	entry = uid_map_group_entry_find(uid_map_group_ht, app);
	if (!entry) {
		ERR("Failed to find event notifier error accounting entry on application teardown: pid = %d, app = '%s'",
		    app->pid,
		    app->name.c_str());
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
	}

	{
		auto protocol = app->command_socket.lock();
		for (i = 0; i < app->event_notifier_group.nr_counter_cpu; i++) {
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

	entry->attached_app_count--;
	drop_uid_map_group_entry_if_unused(entry);

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

namespace lttng {
namespace sessiond {
namespace ust {
namespace event_notifier_error_accounting {

enum event_notifier_error_accounting_status init()
{
	uid_map_group_ht =
		lttng_ht_new(16 /* ERROR_COUNTER_INDEX_HT_INITIAL_SIZE */, LTTNG_HT_TYPE_U64);
	if (!uid_map_group_ht) {
		ERR("Failed to allocate UID to UST map group hash table");
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
	}

	default_ust_config.emplace(
		"event-notifier-error-accounting",
		lttng::sessiond::config::map_channel_configuration::key_type_t::INDEX,
		lttng::sessiond::config::map_channel_configuration::value_type_t::SIGNED_INT_32,
		/* coalesce_hits */ false,
		ust_state.number_indices,
		lttng::sessiond::config::ownership_model_t::PER_UID);

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

void fini()
{
	lttng_ht_destroy(uid_map_group_ht);
	uid_map_group_ht = nullptr;
	default_ust_config.reset();
}

void on_event_notifier_registered()
{
	pthread_mutex_lock(&the_event_notifier_counter.lock);
	the_event_notifier_counter.count++;
	if (the_event_notifier_counter.count == 1) {
		/*
		 * On the first event notifier, mark every known UID
		 * entry as having an event-notifier present so the
		 * entries are retained even if the last app of a UID
		 * leaves.
		 */
		for (auto *uid_entry :
		     lttng::urcu::lfht_iteration_adapter<ust_uid_map_group_entry,
							 decltype(ust_uid_map_group_entry::node),
							 &ust_uid_map_group_entry::node>(
			     *uid_map_group_ht->ht)) {
			uid_entry->event_notifier_present = true;
		}
	}
	pthread_mutex_unlock(&the_event_notifier_counter.lock);
}

void on_event_notifier_unregistered()
{
	pthread_mutex_lock(&the_event_notifier_counter.lock);
	the_event_notifier_counter.count--;
	if (the_event_notifier_counter.count == 0) {
		/*
		 * Clear the event-notifier-present flag on every entry
		 * and drop those that no application references. The
		 * "drop" step is deferred until after the iteration to
		 * avoid mutating the hash table mid-walk.
		 */
		std::vector<ust_uid_map_group_entry *> to_drop;
		for (auto *uid_entry :
		     lttng::urcu::lfht_iteration_adapter<ust_uid_map_group_entry,
							 decltype(ust_uid_map_group_entry::node),
							 &ust_uid_map_group_entry::node>(
			     *uid_map_group_ht->ht)) {
			uid_entry->event_notifier_present = false;
			if (uid_entry->attached_app_count == 0) {
				to_drop.push_back(uid_entry);
			}
		}

		for (auto *uid_entry : to_drop) {
			retire_uid_map_group_entry(uid_entry);
		}
	}
	pthread_mutex_unlock(&the_event_notifier_counter.lock);
}

enum event_notifier_error_accounting_status get_trigger_count(const struct lttng_trigger *trigger,
							      uint64_t *count)
{
	uint64_t error_counter_index, global_sum = 0;
	enum event_notifier_error_accounting_status status;
	const uint64_t tracer_token = lttng_trigger_get_tracer_token(trigger);
	uid_t trigger_owner_uid;
	const char *trigger_name;

	const lttng::urcu::read_lock_guard read_lock;

	get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

	status = get_error_counter_index_for_token(&ust_state, tracer_token, &error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Failed to retrieve index for tracer token: token = %" PRIu64
		    ", trigger name = '%s', trigger owner uid = %d, status = %s",
		    tracer_token,
		    trigger_name,
		    (int) trigger_owner_uid,
		    error_accounting_status_str(status));
		return status;
	}

	/*
	 * Aggregate across all UID entries regardless of the trigger's
	 * uid: any user that is allowed to register a trigger with this
	 * sessiond is also allowed to observe errors generated by any of
	 * the applications the sessiond manages.
	 */
	for (auto *uid_entry :
	     lttng::urcu::lfht_iteration_adapter<ust_uid_map_group_entry,
						 decltype(ust_uid_map_group_entry::node),
						 &ust_uid_map_group_entry::node>(
		     *uid_map_group_ht->ht)) {
		lttng::sessiond::map::element_value value;
		try {
			value = uid_entry->group.aggregate_element(error_counter_index);
		} catch (const std::exception& ex) {
			ERR("Failed to aggregate event notifier error counter value: trigger name = '%s', trigger owner uid = %d, counter uid = %d, error: %s",
			    trigger_name,
			    (int) trigger_owner_uid,
			    (int) uid_entry->uid,
			    ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		if (value.value < 0) {
			ERR("Negative event notifier error counter value encountered during aggregation: trigger name = '%s', trigger owner uid = %d, counter uid = %d, value = %" PRId64,
			    trigger_name,
			    (int) trigger_owner_uid,
			    (int) uid_entry->uid,
			    value.value);
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}

		global_sum += (uint64_t) value.value;
	}

	*count = global_sum;
	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

enum event_notifier_error_accounting_status clear_trigger(const struct lttng_trigger *trigger)
{
	uint64_t error_counter_index;
	enum event_notifier_error_accounting_status status;
	const uint64_t tracer_token = lttng_trigger_get_tracer_token(trigger);

	const lttng::urcu::read_lock_guard read_lock;

	status = get_error_counter_index_for_token(&ust_state, tracer_token, &error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

		ERR("Failed to retrieve index for tracer token: token = %" PRIu64
		    ", trigger name = '%s', trigger owner uid = %d, status = %s",
		    tracer_token,
		    trigger_name,
		    (int) trigger_owner_uid,
		    error_accounting_status_str(status));
		return status;
	}

	for (auto *uid_entry :
	     lttng::urcu::lfht_iteration_adapter<ust_uid_map_group_entry,
						 decltype(ust_uid_map_group_entry::node),
						 &ust_uid_map_group_entry::node>(
		     *uid_map_group_ht->ht)) {
		try {
			uid_entry->group.clear_element(error_counter_index);
		} catch (const std::exception& ex) {
			uid_t trigger_owner_uid;
			const char *trigger_name;

			get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);
			ERR("Failed to clear event notifier counter value for trigger: counter uid = %d, trigger name = '%s', trigger owner uid = %d, error: %s",
			    (int) uid_entry->uid,
			    trigger_name,
			    (int) trigger_owner_uid,
			    ex.what());
			return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		}
	}

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

} /* namespace event_notifier_error_accounting */
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */
