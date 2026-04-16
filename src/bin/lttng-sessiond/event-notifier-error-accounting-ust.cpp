/*
 * SPDX-FileCopyrightText: 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-notifier-error-accounting-ust.hpp"
#include "event-notifier-error-accounting-utils.hpp"
#include "ust-app.hpp"

#include <common/error.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/shm.hpp>
#include <common/urcu.hpp>

#include <lttng/trigger/trigger-internal.hpp>
#include <lttng/ust-ctl.h>

#include <pthread.h>
#include <sys/types.h>
#include <unistd.h>
#include <urcu/compiler.h>

namespace {
struct event_notifier_counter {
	pthread_mutex_t lock;
	long count;
};

struct ust_error_accounting_entry {
	uid_t uid;
	struct urcu_ref ref;
	struct lttng_ht_node_u64 node;
	struct rcu_head rcu_head;
	struct lttng_ust_ctl_daemon_counter *daemon_counter;
	/*
	 * Those `lttng_ust_abi_object_data` are anonymous handles to the
	 * counters objects.
	 * They are only used to be duplicated for each new applications of the
	 * user. To destroy them, call with the `sock` parameter set to -1.
	 * e.g. `lttng_ust_ctl_release_object(-1, data)`;
	 */
	struct lttng_ust_abi_object_data *counter;
	struct lttng_ust_abi_object_data **cpu_counters;
	int nr_counter_cpu_fds;
};

struct event_notifier_counter the_event_notifier_counter;
struct lttng_ht *error_counter_uid_ht;
} /* namespace */

static void free_ust_error_accounting_entry(struct rcu_head *head)
{
	int i;
	struct ust_error_accounting_entry *entry =
		lttng::utils::container_of(head, &ust_error_accounting_entry::rcu_head);

	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		lttng_ust_ctl_release_object(-1, entry->cpu_counters[i]);
		free(entry->cpu_counters[i]);
	}

	free(entry->cpu_counters);

	lttng_ust_ctl_release_object(-1, entry->counter);
	free(entry->counter);

	lttng_ust_ctl_destroy_counter(entry->daemon_counter);

	free(entry);
}

static bool ust_error_accounting_entry_get(struct ust_error_accounting_entry *entry)
{
	return urcu_ref_get_unless_zero(&entry->ref);
}

static void ust_error_accounting_entry_release(struct urcu_ref *entry_ref)
{
	struct ust_error_accounting_entry *entry =
		lttng::utils::container_of(entry_ref, &ust_error_accounting_entry::ref);

	const lttng::urcu::read_lock_guard read_lock;
	cds_lfht_del(error_counter_uid_ht->ht, &entry->node.node);
	call_rcu(&entry->rcu_head, free_ust_error_accounting_entry);
}

static void ust_error_accounting_entry_put(struct ust_error_accounting_entry *entry)
{
	if (!entry) {
		return;
	}

	urcu_ref_put(&entry->ref, ust_error_accounting_entry_release);
}

/*
 * Put one reference to every UID entries.
 */
static void put_ref_all_ust_error_accounting_entry()
{
	ASSERT_LOCKED(the_event_notifier_counter.lock);

	for (auto *uid_entry :
	     lttng::urcu::lfht_iteration_adapter<ust_error_accounting_entry,
						 decltype(ust_error_accounting_entry::node),
						 &ust_error_accounting_entry::node>(
		     *error_counter_uid_ht->ht)) {
		ust_error_accounting_entry_put(uid_entry);
	}
}

/*
 * Get one reference to every UID entries.
 */
static void get_ref_all_ust_error_accounting_entry()
{
	ASSERT_LOCKED(the_event_notifier_counter.lock);

	for (auto *uid_entry :
	     lttng::urcu::lfht_iteration_adapter<ust_error_accounting_entry,
						 decltype(ust_error_accounting_entry::node),
						 &ust_error_accounting_entry::node>(
		     *error_counter_uid_ht->ht)) {
		ust_error_accounting_entry_get(uid_entry);
	}
}

/*
 * Find the entry for this app's UID, the caller acquires a reference if the
 * entry is found.
 */
static struct ust_error_accounting_entry *
ust_error_accounting_entry_find(struct lttng_ht *uid_ht, const lttng::sessiond::ust::app *app)
{
	struct ust_error_accounting_entry *entry;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	uint64_t key = app->uid;

	lttng_ht_lookup(uid_ht, &key, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (node == nullptr) {
		entry = nullptr;
	} else {
		bool got_ref;

		entry = lttng::utils::container_of(node, &ust_error_accounting_entry::node);

		got_ref = ust_error_accounting_entry_get(entry);
		if (!got_ref) {
			entry = nullptr;
		}
	}

	return entry;
}

/*
 * Create the entry for this app's UID, the caller acquires a reference to the
 * entry,
 */
static struct ust_error_accounting_entry *
ust_error_accounting_entry_create(const lttng::sessiond::ust::app *app)
{
	int i, ret, *cpu_counter_fds = nullptr;
	struct lttng_ust_ctl_daemon_counter *daemon_counter;
	struct lttng_ust_abi_object_data *counter, **cpu_counters;
	struct ust_error_accounting_entry *entry = nullptr;
	lttng_ust_ctl_counter_dimension dimension = {};

	dimension.size = ust_state.number_indices;
	dimension.has_underflow = false;
	dimension.has_overflow = false;

	if (!ust_app_supports_counters(app)) {
		DBG("Refusing to create accounting entry for application (unsupported feature): app name = '%s', app ppid = %d",
		    app->name.c_str(),
		    (int) app->ppid);
		goto error;
	}

	entry = zmalloc<ust_error_accounting_entry>();
	if (!entry) {
		PERROR("Failed to allocate event notifier error acounting entry")
		goto error;
	}

	urcu_ref_init(&entry->ref);
	entry->uid = app->uid;
	entry->nr_counter_cpu_fds = lttng_ust_ctl_get_nr_cpu_per_counter();

	cpu_counter_fds = calloc<int>(entry->nr_counter_cpu_fds);
	if (!cpu_counter_fds) {
		PERROR("Failed to allocate event notifier error counter file descriptors array: application uid = %d, application name = '%s', pid = %d, allocation size = %zu",
		       (int) app->uid,
		       app->name.c_str(),
		       (int) app->pid,
		       entry->nr_counter_cpu_fds * sizeof(*cpu_counter_fds));
		goto error_counter_cpu_fds_alloc;
	}

	/* Initialize to an invalid fd value to closes fds in case of error. */
	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		cpu_counter_fds[i] = -1;
	}

	cpu_counters = calloc<lttng_ust_abi_object_data *>(entry->nr_counter_cpu_fds);
	if (!cpu_counters) {
		PERROR("Failed to allocate event notifier error counter lttng_ust_abi_object_data array: application uid = %d, application name = '%s', pid = %d, allocation size = %zu",
		       (int) app->uid,
		       app->name.c_str(),
		       (int) app->pid,
		       entry->nr_counter_cpu_fds * sizeof(struct lttng_ust_abi_object_data *));
		goto error_counter_cpus_alloc;
	}

	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		cpu_counter_fds[i] = shm_create_anonymous("event-notifier-error-accounting");
		if (cpu_counter_fds[i] == -1) {
			ERR("Failed to create event notifier error accounting shared memory for application user: application uid = %d, pid = %d, application name = '%s'",
			    (int) app->uid,
			    (int) app->pid,
			    app->name.c_str());
			goto error_shm_alloc;
		}
	}

	/*
	 * Ownership of the file descriptors transferred to the ustctl object.
	 */
	daemon_counter = lttng_ust_ctl_create_counter(1,
						      &dimension,
						      0,
						      -1,
						      entry->nr_counter_cpu_fds,
						      cpu_counter_fds,
						      LTTNG_UST_CTL_COUNTER_BITNESS_32,
						      LTTNG_UST_CTL_COUNTER_ARITHMETIC_MODULAR,
						      LTTNG_UST_CTL_COUNTER_ALLOC_PER_CPU,
						      false);
	if (!daemon_counter) {
		goto error_create_daemon_counter;
	}

	ret = lttng_ust_ctl_create_counter_data(daemon_counter, &counter);
	if (ret) {
		ERR("Failed to create userspace tracer counter data for application user: uid = %d, pid = %d, application name = '%s'",
		    (int) app->uid,
		    (int) app->pid,
		    app->name.c_str());
		goto error_create_counter_data;
	}

	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		ret = lttng_ust_ctl_create_counter_cpu_data(daemon_counter, i, &cpu_counters[i]);
		if (ret) {
			ERR("Failed to create userspace tracer counter cpu data for application user: uid = %d, pid = %d, application name = '%s'",
			    (int) app->uid,
			    (int) app->pid,
			    app->name.c_str());
			goto error_create_counter_cpu_data;
		}
	}

	entry->daemon_counter = daemon_counter;
	entry->counter = counter;
	entry->cpu_counters = cpu_counters;

	lttng_ht_node_init_u64(&entry->node, entry->uid);
	lttng_ht_add_unique_u64(error_counter_uid_ht, &entry->node);

	goto end;

error_create_counter_cpu_data:
	/* Teardown any allocated cpu counters. */
	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		if (!cpu_counters[i]) {
			/*
			 * Early-exit when error occurred before all cpu
			 * counters could be initialized.
			 */
			break;
		}

		lttng_ust_ctl_release_object(-1, cpu_counters[i]);
		free(cpu_counters[i]);
	}

	lttng_ust_ctl_release_object(-1, entry->counter);
	free(entry->counter);
error_create_counter_data:
	lttng_ust_ctl_destroy_counter(daemon_counter);
error_create_daemon_counter:
error_shm_alloc:
	/* Error occurred before per-cpu SHMs were handed-off to ustctl. */
	if (cpu_counter_fds) {
		for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
			if (cpu_counter_fds[i] < 0) {
				/*
				 * Early-exit when error occurred before all cpu
				 * counter shm fds could be initialized.
				 */
				break;
			}

			ret = close(cpu_counter_fds[i]);
			if (ret) {
				PERROR("Failed to close error counter per-CPU shm file descriptor: fd = %d",
				       cpu_counter_fds[i]);
			}
		}
	}

	free(cpu_counters);
error_counter_cpus_alloc:
error_counter_cpu_fds_alloc:
	free(entry);
error:
	entry = nullptr;
end:
	free(cpu_counter_fds);
	return entry;
}

static enum event_notifier_error_accounting_status
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

static enum event_notifier_error_accounting_status
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

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_app(lttng::sessiond::ust::app *app)
{
	int ret;
	uint64_t i;
	struct lttng_ust_abi_object_data *new_counter;
	struct ust_error_accounting_entry *entry;
	enum event_notifier_error_accounting_status status;
	struct lttng_ust_abi_object_data **cpu_counters;
	const lttng::urcu::read_lock_guard read_lock;

	if (!ust_app_supports_counters(app)) {
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_UNSUPPORTED;
		goto end;
	}

	/*
	 * Check if we already have a error counter for the user id of this
	 * app. If not, create one.
	 */
	entry = ust_error_accounting_entry_find(error_counter_uid_ht, app);
	if (entry == nullptr) {
		/*
		 * Take the event notifier counter lock before creating the new
		 * entry to ensure that no event notifier is registered between
		 * the the entry creation and event notifier count check.
		 */
		pthread_mutex_lock(&the_event_notifier_counter.lock);

		entry = ust_error_accounting_entry_create(app);
		if (!entry) {
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
			pthread_mutex_unlock(&the_event_notifier_counter.lock);
			goto error_creating_entry;
		}

		/*
		 * We just created a new UID entry, If there are event
		 * notifiers already registered, take one reference on their
		 * behalf.
		 */
		if (the_event_notifier_counter.count > 0) {
			ust_error_accounting_entry_get(entry);
		}

		pthread_mutex_unlock(&the_event_notifier_counter.lock);
	}

	/* Duplicate counter object data. */
	ret = lttng_ust_ctl_duplicate_ust_object_data(&new_counter, entry->counter);
	if (ret) {
		ERR("Failed to duplicate event notifier error accounting counter for application user: application uid = %d, pid = %d, application name = '%s'",
		    (int) app->uid,
		    (int) app->pid,
		    app->name.c_str());
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto error_duplicate_counter;
	}

	status = send_counter_data_to_ust(app, new_counter);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		if (status == EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD) {
			goto error_send_counter_data;
		}

		ERR("Failed to send counter data to application tracer: status = %s, application uid = %d, pid = %d, application name = '%s'",
		    error_accounting_status_str(status),
		    (int) app->uid,
		    (int) app->pid,
		    app->name.c_str());
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto error_send_counter_data;
	}

	cpu_counters = calloc<lttng_ust_abi_object_data *>(entry->nr_counter_cpu_fds);
	if (!cpu_counters) {
		PERROR("Failed to allocate event notifier error counter lttng_ust_abi_object_data array: application uid = %d, application name = '%s', pid = %d, allocation size = %zu",
		       (int) app->uid,
		       app->name.c_str(),
		       (int) app->pid,
		       entry->nr_counter_cpu_fds * sizeof(**cpu_counters));
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto error_allocate_cpu_counters;
	}

	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		struct lttng_ust_abi_object_data *new_counter_cpu = nullptr;

		ret = lttng_ust_ctl_duplicate_ust_object_data(&new_counter_cpu,
							      entry->cpu_counters[i]);
		if (ret) {
			ERR("Failed to duplicate userspace tracer counter cpu data for application user: uid = %d, pid = %d, application name = '%s'",
			    (int) app->uid,
			    (int) app->pid,
			    app->name.c_str());
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
			goto error_duplicate_cpu_counter;
		}

		cpu_counters[i] = new_counter_cpu;

		status = send_counter_cpu_data_to_ust(app, new_counter, new_counter_cpu);
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			if (status == EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD) {
				goto error_send_cpu_counter_data;
			}

			ERR("Failed to send counter cpu data to application tracer: status = %s, application uid = %d, pid = %d, application name = '%s'",
			    error_accounting_status_str(status),
			    (int) app->uid,
			    (int) app->pid,
			    app->name.c_str());
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
			lttng_ust_ctl_release_object(-1, new_counter_cpu);
			goto error_send_cpu_counter_data;
		}
		lttng_ust_ctl_release_object(-1, new_counter_cpu);
	}
	lttng_ust_ctl_release_object(-1, new_counter);

	app->event_notifier_group.counter = new_counter;
	new_counter = nullptr;
	app->event_notifier_group.nr_counter_cpu = entry->nr_counter_cpu_fds;
	app->event_notifier_group.counter_cpu = cpu_counters;
	cpu_counters = nullptr;
	goto end;

error_send_cpu_counter_data:
error_duplicate_cpu_counter:
	/* Teardown any duplicated cpu counters. */
	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		if (!cpu_counters[i]) {
			/*
			 * Early-exit when error occurred before all cpu
			 * counters could be initialized.
			 */
			break;
		}
		free(cpu_counters[i]);
	}

	free(cpu_counters);

error_allocate_cpu_counters:
error_send_counter_data:
	lttng_ust_ctl_release_object(-1, new_counter);
	free(new_counter);
error_duplicate_counter:
	ust_error_accounting_entry_put(entry);
error_creating_entry:
	app->event_notifier_group.counter = nullptr;
end:
	return status;
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_unregister_app(lttng::sessiond::ust::app *app)
{
	enum event_notifier_error_accounting_status status;
	struct ust_error_accounting_entry *entry;
	int i;

	const lttng::urcu::read_lock_guard read_lock;

	/* If an error occurred during app registration no entry was created. */
	if (!app->event_notifier_group.counter) {
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
		goto end;
	}

	entry = ust_error_accounting_entry_find(error_counter_uid_ht, app);
	if (entry == nullptr) {
		ERR("Failed to find event notitifier error accounting entry on application teardown: pid = %d, application name = '%s'",
		    app->pid,
		    app->name.c_str());
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto end;
	} else {
		/*
		 * Put the entry twice as we acquired a reference from the
		 * `ust_error_accounting_entry_find()` above.
		 */
		ust_error_accounting_entry_put(entry);
		ust_error_accounting_entry_put(entry);
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

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

namespace lttng {
namespace sessiond {
namespace ust {
namespace event_notifier_error_accounting {

enum event_notifier_error_accounting_status init()
{
	error_counter_uid_ht =
		lttng_ht_new(16 /* ERROR_COUNTER_INDEX_HT_INITIAL_SIZE */, LTTNG_HT_TYPE_U64);
	if (!error_counter_uid_ht) {
		ERR("Failed to allocate UID to error counter accountant hash table");
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
	}

	return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
}

void fini()
{
	lttng_ht_destroy(error_counter_uid_ht);
	error_counter_uid_ht = nullptr;
}

void on_event_notifier_registered()
{
	pthread_mutex_lock(&the_event_notifier_counter.lock);
	the_event_notifier_counter.count++;
	if (the_event_notifier_counter.count == 1) {
		/*
		 * On the first event notifier, we get a reference to
		 * every existing UID entries. This ensures that the
		 * entries are kept around if there are still
		 * registered event notifiers but no apps.
		 */
		get_ref_all_ust_error_accounting_entry();
	}
	pthread_mutex_unlock(&the_event_notifier_counter.lock);
}

void on_event_notifier_unregistered()
{
	pthread_mutex_lock(&the_event_notifier_counter.lock);
	the_event_notifier_counter.count--;
	if (the_event_notifier_counter.count == 0) {
		/*
		 * When unregistering the last event notifier, put one
		 * reference to every uid entries on the behalf of all
		 * event notifiers.
		 */
		put_ref_all_ust_error_accounting_entry();
	}
	pthread_mutex_unlock(&the_event_notifier_counter.lock);
}

enum event_notifier_error_accounting_status get_trigger_count(const struct lttng_trigger *trigger,
							      uint64_t *count)
{
	uint64_t error_counter_index, global_sum = 0;
	enum event_notifier_error_accounting_status status;
	size_t dimension_indexes[1];
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
		goto end;
	}

	dimension_indexes[0] = error_counter_index;

	/*
	 * Iterate over all the UID entries.
	 * We aggregate the value of all uid entries regardless of if the uid
	 * matches the trigger's uid because a user that is allowed to register
	 * a trigger to a given sessiond is also allowed to create an event
	 * notifier on all apps that this sessiond is aware of.
	 */
	for (auto *uid_entry :
	     lttng::urcu::lfht_iteration_adapter<ust_error_accounting_entry,
						 decltype(ust_error_accounting_entry::node),
						 &ust_error_accounting_entry::node>(
		     *error_counter_uid_ht->ht)) {
		int ret;
		int64_t local_value = 0;
		bool overflow = false, underflow = false;

		ret = lttng_ust_ctl_counter_aggregate(uid_entry->daemon_counter,
						      dimension_indexes,
						      &local_value,
						      &overflow,
						      &underflow);
		if (ret || local_value < 0) {
			if (ret) {
				ERR("Failed to aggregate event notifier error counter values of trigger: trigger name = '%s', trigger owner uid = %d",
				    trigger_name,
				    (int) trigger_owner_uid);
			} else if (local_value < 0) {
				ERR("Negative event notifier error counter value encountered during aggregation: trigger name = '%s', trigger owner uid = %d, value = %" PRId64,
				    trigger_name,
				    (int) trigger_owner_uid,
				    local_value);
			} else {
				abort();
			}

			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
			goto end;
		}

		/* Cast is safe as negative values are checked-for above. */
		global_sum += (uint64_t) local_value;
	}

	*count = global_sum;
	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;

end:
	return status;
}

enum event_notifier_error_accounting_status clear_trigger(const struct lttng_trigger *trigger)
{
	uint64_t error_counter_index;
	enum event_notifier_error_accounting_status status;
	size_t dimension_index;
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
		goto end;
	}

	dimension_index = error_counter_index;

	/*
	 * Go over all error counters (ignoring uid) as a trigger (and trigger
	 * errors) can be generated from any applications that this session
	 * daemon is managing.
	 */
	for (auto *uid_entry :
	     lttng::urcu::lfht_iteration_adapter<ust_error_accounting_entry,
						 decltype(ust_error_accounting_entry::node),
						 &ust_error_accounting_entry::node>(
		     *error_counter_uid_ht->ht)) {
		const int ret =
			lttng_ust_ctl_counter_clear(uid_entry->daemon_counter, &dimension_index);

		if (ret) {
			uid_t trigger_owner_uid;
			const char *trigger_name;

			get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);
			ERR("Failed to clear event notifier counter value for trigger: counter uid = %d, trigger name = '%s', trigger owner uid = %d",
			    (int) uid_entry->node.key,
			    trigger_name,
			    (int) trigger_owner_uid);
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
			goto end;
		}
	}

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

} /* namespace event_notifier_error_accounting */
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */
