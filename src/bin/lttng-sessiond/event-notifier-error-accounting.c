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
#include <pthread.h>

#include <common/error.h>
#include <common/hashtable/hashtable.h>
#include <common/index-allocator.h>
#include <common/kernel-ctl/kernel-ctl.h>
#include <common/shm.h>
#include <lttng/trigger/trigger-internal.h>

#include "event-notifier-error-accounting.h"
#include "lttng-ust-error.h"
#include "ust-app.h"

#define ERROR_COUNTER_INDEX_HT_INITIAL_SIZE 16

struct index_ht_entry {
	struct lttng_ht_node_u64 node;
	uint64_t error_counter_index;
	struct rcu_head rcu_head;
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

struct kernel_error_accounting_entry {
	int error_counter_fd;
};

static struct kernel_error_accounting_entry kernel_error_accounting_entry;

/* Hashtable mapping uid to error_account_entry. */
static struct lttng_ht *error_counter_uid_ht;

struct error_accounting_state {
	struct lttng_index_allocator *index_allocator;
	/* Hashtable mapping event notifier token to index_ht_entry. */
	struct lttng_ht *indices_ht;
	uint64_t number_indices;
};

static struct error_accounting_state ust_state;
static struct error_accounting_state kernel_state;

static inline void get_trigger_info_for_log(const struct lttng_trigger *trigger,
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

	trigger_status = lttng_trigger_get_owner_uid(trigger,
			trigger_owner_uid);
	assert(trigger_status == LTTNG_TRIGGER_STATUS_OK);
}

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
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD:
		return "APP_DEAD";
	default:
		abort();
	}
}

#ifdef HAVE_LIBLTTNG_UST_CTL
struct event_notifier_counter {
	pthread_mutex_t lock;
	long count;
};

static struct event_notifier_counter the_event_notifier_counter;

static void free_ust_error_accounting_entry(struct rcu_head *head)
{
	int i;
	struct ust_error_accounting_entry *entry =
			caa_container_of(head, typeof(*entry), rcu_head);

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

static
bool ust_error_accounting_entry_get(struct ust_error_accounting_entry *entry)
{
	return urcu_ref_get_unless_zero(&entry->ref);
}

static
void ust_error_accounting_entry_release(struct urcu_ref *entry_ref)
{
	struct ust_error_accounting_entry *entry =
			container_of(entry_ref, typeof(*entry), ref);

	rcu_read_lock();
	cds_lfht_del(error_counter_uid_ht->ht, &entry->node.node);
	call_rcu(&entry->rcu_head, free_ust_error_accounting_entry);
	rcu_read_unlock();
}


static
void ust_error_accounting_entry_put(struct ust_error_accounting_entry *entry)
{
	if (!entry) {
		return;
	}

	urcu_ref_put(&entry->ref, ust_error_accounting_entry_release);
}

/*
 * Put one reference to every UID entries.
 */
static
void put_ref_all_ust_error_accounting_entry(void)
{
	struct lttng_ht_iter iter;
	struct ust_error_accounting_entry *uid_entry;

	ASSERT_LOCKED(the_event_notifier_counter.lock);

	rcu_read_lock();
	cds_lfht_for_each_entry(error_counter_uid_ht->ht, &iter.iter,
        		uid_entry, node.node) {
        	ust_error_accounting_entry_put(uid_entry);
	}

	rcu_read_unlock();
}

/*
 * Get one reference to every UID entries.
 */
static
void get_ref_all_ust_error_accounting_entry(void)
{
	struct lttng_ht_iter iter;
	struct ust_error_accounting_entry *uid_entry;

	ASSERT_LOCKED(the_event_notifier_counter.lock);

	rcu_read_lock();
	cds_lfht_for_each_entry(error_counter_uid_ht->ht, &iter.iter,
        		uid_entry, node.node) {
        	ust_error_accounting_entry_get(uid_entry);
	}

	rcu_read_unlock();
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

static
enum event_notifier_error_accounting_status
init_error_accounting_state(struct error_accounting_state *state,
		uint64_t index_count)
{
	enum event_notifier_error_accounting_status status;

	assert(state);

	state->number_indices = index_count;

	state->index_allocator = lttng_index_allocator_create(index_count);
	if (!state->index_allocator) {
		ERR("Failed to allocate event notifier error counter index allocator");
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto end;
	}

	state->indices_ht = lttng_ht_new(ERROR_COUNTER_INDEX_HT_INITIAL_SIZE,
			LTTNG_HT_TYPE_U64);
	if (!state->indices_ht) {
		ERR("Failed to allocate error counter indices hash table");
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto error_indices_ht;
	}

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	goto end;

error_indices_ht:
	lttng_index_allocator_destroy(state->index_allocator);
	state->index_allocator = NULL;
end:
	return status;
}

static
void fini_error_accounting_state(struct error_accounting_state *state)
{
	assert(state);

	/*
	 * Will assert if some error counter indices were not released (an
	 * internal error).
	 */
	lttng_ht_destroy(state->indices_ht);
	lttng_index_allocator_destroy(state->index_allocator);
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_init(uint64_t buffer_size_kernel,
		uint64_t buffer_size_ust)
{
	enum event_notifier_error_accounting_status status;

	status = init_error_accounting_state(&kernel_state, buffer_size_kernel);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Failed to initialize kernel event notifier accounting state: status = %s",
				error_accounting_status_str(status));
		goto end;
	}

	status = init_error_accounting_state(&ust_state, buffer_size_ust);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Failed to initialize UST event notifier accounting state: status = %s",
				error_accounting_status_str(status));
		goto error_ust_state;
	}

	error_counter_uid_ht = lttng_ht_new(
			ERROR_COUNTER_INDEX_HT_INITIAL_SIZE, LTTNG_HT_TYPE_U64);
	if (!error_counter_uid_ht) {
		ERR("Failed to allocate UID to error counter accountant hash table");
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto error_uid_ht;
	}

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
	goto end;

error_uid_ht:
	fini_error_accounting_state(&ust_state);
error_ust_state:
	fini_error_accounting_state(&kernel_state);
end:
	return status;
}

/*
 * Return the error counteur index associated to this event notifier tracer
 * token. Returns _STATUS_OK if found and _STATUS_NOT_FOUND otherwise.
 */
static
enum event_notifier_error_accounting_status get_error_counter_index_for_token(
		struct error_accounting_state *state, uint64_t tracer_token,
		uint64_t *error_counter_index)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	const struct index_ht_entry *index_entry;
	enum event_notifier_error_accounting_status status;

	rcu_read_lock();
	lttng_ht_lookup(state->indices_ht, &tracer_token, &iter);
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

#ifdef HAVE_LIBLTTNG_UST_CTL
/*
 * Find the entry for this app's UID, the caller acquires a reference if the
 * entry is found.
 */
static
struct ust_error_accounting_entry *ust_error_accounting_entry_find(
		struct lttng_ht *uid_ht, const struct ust_app *app)
{
	struct ust_error_accounting_entry *entry;
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	uint64_t key = app->uid;

	lttng_ht_lookup(uid_ht, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if(node == NULL) {
		entry = NULL;
	} else {
		bool got_ref;

		entry = caa_container_of(node,
				struct ust_error_accounting_entry, node);

		got_ref = ust_error_accounting_entry_get(entry);
		if (!got_ref) {
			entry = NULL;
		}
	}

	return entry;
}

/*
 * Create the entry for this app's UID, the caller acquires a reference to the
 * entry,
 */
static
struct ust_error_accounting_entry *ust_error_accounting_entry_create(
		struct lttng_ht *uid_ht, const struct ust_app *app)
{
	int i, ret, *cpu_counter_fds = NULL;
	struct lttng_ust_ctl_daemon_counter *daemon_counter;
	struct lttng_ust_abi_object_data *counter, **cpu_counters;
	struct ust_error_accounting_entry *entry = NULL;
	const struct lttng_ust_ctl_counter_dimension dimension = {
		.size = ust_state.number_indices,
		.has_underflow = false,
		.has_overflow = false,
	};

	if (!ust_app_supports_counters(app)) {
		DBG("Refusing to create accounting entry for application (unsupported feature): app name = '%s', app ppid = %d",
				app->name, (int) app->ppid);
		goto error;
	}

	entry = zmalloc(sizeof(struct ust_error_accounting_entry));
	if (!entry) {
		PERROR("Failed to allocate event notifier error acounting entry")
		goto error;
	}

	urcu_ref_init(&entry->ref);
	entry->uid = app->uid;
	entry->nr_counter_cpu_fds = lttng_ust_ctl_get_nr_cpu_per_counter();

	cpu_counter_fds = zmalloc(entry->nr_counter_cpu_fds * sizeof(*cpu_counter_fds));
	if (!cpu_counter_fds) {
		PERROR("Failed to allocate event notifier error counter file descriptors array: application uid = %d, application name = '%s', pid = %d, allocation size = %zu",
				(int) app->uid, app->name, (int) app->pid,
				entry->nr_counter_cpu_fds * sizeof(*cpu_counter_fds));
		goto error_counter_cpu_fds_alloc;
	}

	/* Initialize to an invalid fd value to closes fds in case of error. */
	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		cpu_counter_fds[i] = -1;
	}

	cpu_counters = zmalloc(entry->nr_counter_cpu_fds * sizeof(struct lttng_ust_abi_object_data *));
	if (!cpu_counters) {
		PERROR("Failed to allocate event notifier error counter lttng_ust_abi_object_data array: application uid = %d, application name = '%s', pid = %d, allocation size = %zu",
				(int) app->uid, app->name, (int) app->pid,
				entry->nr_counter_cpu_fds * sizeof(struct lttng_ust_abi_object_data *));
		goto error_counter_cpus_alloc;
	}

	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		cpu_counter_fds[i] = shm_create_anonymous("event-notifier-error-accounting");
		if (cpu_counter_fds[i] == -1) {
			ERR("Failed to create event notifier error accounting shared memory for application user: application uid = %d, pid = %d, application name = '%s'",
					(int) app->uid, (int) app->pid, app->name);
			goto error_shm_alloc;
		}
	}

	/*
	 * Ownership of the file descriptors transferred to the ustctl object.
	 */
	daemon_counter = lttng_ust_ctl_create_counter(1, &dimension, 0, -1,
			entry->nr_counter_cpu_fds, cpu_counter_fds,
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
				(int) app->uid, (int) app->pid, app->name);
		goto error_create_counter_data;
	}

	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		ret = lttng_ust_ctl_create_counter_cpu_data(daemon_counter, i,
				&cpu_counters[i]);
		if (ret) {
			ERR("Failed to create userspace tracer counter cpu data for application user: uid = %d, pid = %d, application name = '%s'",
					(int) app->uid, (int) app->pid,
					app->name);
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
	entry = NULL;
end:
	free(cpu_counter_fds);
	return entry;
}

static
enum event_notifier_error_accounting_status send_counter_data_to_ust(
		struct ust_app *app,
		struct lttng_ust_abi_object_data *new_counter)
{
	int ret;
	enum event_notifier_error_accounting_status status;

	/* Attach counter to trigger group. */
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_send_counter_data_to_ust(app->sock,
			app->event_notifier_group.object->handle, new_counter);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
			ERR("Failed to send counter data to application: application name = '%s', pid = %d, ret = %d",
					app->name, app->pid, ret);
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		} else {
			DBG3("Failed to send counter data to application (application is dead): application name = '%s', pid = %d, ret = %d",
					app->name, app->pid, ret);
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD;
		}

		goto end;
	}

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

static
enum event_notifier_error_accounting_status send_counter_cpu_data_to_ust(
		struct ust_app *app,
		struct lttng_ust_abi_object_data *counter,
		struct lttng_ust_abi_object_data *counter_cpu)
{
	int ret;
	enum event_notifier_error_accounting_status status;

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_send_counter_cpu_data_to_ust(app->sock,
			counter, counter_cpu);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
			ERR("Failed to send counter CPU data to application: application name = '%s', pid = %d, ret = %d",
					app->name, app->pid, ret);
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		} else {
			DBG3("Failed to send counter CPU data to application: application name = '%s', pid = %d, ret = %d",
					app->name, app->pid, ret);
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD;
		}

		goto end;
	}

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
end:
	return status;
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_register_app(struct ust_app *app)
{
	int ret;
	uint64_t i;
	struct lttng_ust_abi_object_data *new_counter;
	struct ust_error_accounting_entry *entry;
	enum event_notifier_error_accounting_status status;
	struct lttng_ust_abi_object_data **cpu_counters;

	if (!ust_app_supports_counters(app)) {
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_UNSUPPORTED;
		goto end;
	}

	/*
	 * Check if we already have a error counter for the user id of this
	 * app. If not, create one.
	 */
	rcu_read_lock();
	entry = ust_error_accounting_entry_find(error_counter_uid_ht, app);
	if (entry == NULL) {
		/*
		 * Take the event notifier counter lock before creating the new
		 * entry to ensure that no event notifier is registered between
		 * the the entry creation and event notifier count check.
		 */
		pthread_mutex_lock(&the_event_notifier_counter.lock);

		entry = ust_error_accounting_entry_create(error_counter_uid_ht,
				app);
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
	ret = lttng_ust_ctl_duplicate_ust_object_data(&new_counter,
			entry->counter);
	if (ret) {
		ERR("Failed to duplicate event notifier error accounting counter for application user: application uid = %d, pid = %d, application name = '%s'",
				(int) app->uid, (int) app->pid, app->name);
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
				(int) app->uid, (int) app->pid, app->name);
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
		goto error_send_counter_data;
	}

	cpu_counters = zmalloc(entry->nr_counter_cpu_fds * sizeof(struct lttng_ust_abi_object_data *));
	if (!cpu_counters) {
		PERROR("Failed to allocate event notifier error counter lttng_ust_abi_object_data array: application uid = %d, application name = '%s', pid = %d, allocation size = %zu",
				(int) app->uid, app->name, (int) app->pid,
				entry->nr_counter_cpu_fds * sizeof(**cpu_counters));
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
		goto error_allocate_cpu_counters;
	}

	for (i = 0; i < entry->nr_counter_cpu_fds; i++) {
		struct lttng_ust_abi_object_data *new_counter_cpu = NULL;

		ret = lttng_ust_ctl_duplicate_ust_object_data(&new_counter_cpu,
				entry->cpu_counters[i]);
		if (ret) {
			ERR("Failed to duplicate userspace tracer counter cpu data for application user: uid = %d, pid = %d, application name = '%s'",
					(int) app->uid, (int) app->pid,
					app->name);
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM;
			goto error_duplicate_cpu_counter;
		}

		cpu_counters[i] = new_counter_cpu;

		status = send_counter_cpu_data_to_ust(app, new_counter,
				new_counter_cpu);
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			if (status == EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD) {
				goto error_send_cpu_counter_data;
			}

			ERR("Failed to send counter cpu data to application tracer: status = %s, application uid = %d, pid = %d, application name = '%s'",
					error_accounting_status_str(status),
					(int) app->uid, (int) app->pid,
					app->name);
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
			lttng_ust_ctl_release_object(-1, new_counter_cpu);
			goto error_send_cpu_counter_data;
		}
		lttng_ust_ctl_release_object(-1, new_counter_cpu);
	}
	lttng_ust_ctl_release_object(-1, new_counter);

	app->event_notifier_group.counter = new_counter;
	new_counter = NULL;
	app->event_notifier_group.nr_counter_cpu = entry->nr_counter_cpu_fds;
	app->event_notifier_group.counter_cpu = cpu_counters;
	cpu_counters = NULL;
	goto end_unlock;

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
	app->event_notifier_group.counter = NULL;
end_unlock:
	rcu_read_unlock();
end:
	return status;
}

enum event_notifier_error_accounting_status
event_notifier_error_accounting_unregister_app(struct ust_app *app)
{
	enum event_notifier_error_accounting_status status;
	struct ust_error_accounting_entry *entry;
	int i;

	rcu_read_lock();

	/* If an error occurred during app registration no entry was created. */
	if (!app->event_notifier_group.counter) {
		status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
		goto end;
	}

	entry = ust_error_accounting_entry_find(error_counter_uid_ht, app);
	if (entry == NULL) {
		ERR("Failed to find event notitifier error accounting entry on application teardown: pid = %d, application name = '%s'",
				app->pid, app->name);
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

	for (i = 0; i < app->event_notifier_group.nr_counter_cpu; i++) {
		lttng_ust_ctl_release_object(app->sock,
				app->event_notifier_group.counter_cpu[i]);
		free(app->event_notifier_group.counter_cpu[i]);
	}

	free(app->event_notifier_group.counter_cpu);

	lttng_ust_ctl_release_object(app->sock, app->event_notifier_group.counter);
	free(app->event_notifier_group.counter);

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
end:
	rcu_read_unlock();
	return status;
}

static
enum event_notifier_error_accounting_status
event_notifier_error_accounting_ust_get_count(
		const struct lttng_trigger *trigger, uint64_t *count)
{
	struct lttng_ht_iter iter;
	struct ust_error_accounting_entry *uid_entry;
	uint64_t error_counter_index, global_sum = 0;
	enum event_notifier_error_accounting_status status;
	size_t dimension_indexes[1];
	const uint64_t tracer_token = lttng_trigger_get_tracer_token(trigger);
	uid_t trigger_owner_uid;
	const char *trigger_name;


	rcu_read_lock();

	get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);

	status = get_error_counter_index_for_token(&ust_state, tracer_token,
			&error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {

		ERR("Failed to retrieve index for tracer token: token = %" PRIu64 ", trigger name = '%s', trigger owner uid = %d, status = %s",
				tracer_token, trigger_name,
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
	cds_lfht_for_each_entry(error_counter_uid_ht->ht, &iter.iter,
			uid_entry, node.node) {
		int ret;
		int64_t local_value = 0;
		bool overflow = false, underflow = false;

		ret = lttng_ust_ctl_counter_aggregate(uid_entry->daemon_counter,
				dimension_indexes, &local_value, &overflow,
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
	rcu_read_unlock();
	return status;
}

static
enum event_notifier_error_accounting_status event_notifier_error_accounting_ust_clear(
		const struct lttng_trigger *trigger)
{
	struct lttng_ht_iter iter;
	struct ust_error_accounting_entry *uid_entry;
	uint64_t error_counter_index;
	enum event_notifier_error_accounting_status status;
	size_t dimension_index;
	const uint64_t tracer_token = lttng_trigger_get_tracer_token(trigger);

	rcu_read_lock();
	status = get_error_counter_index_for_token(&ust_state, tracer_token,
			&error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name,
					 &trigger_owner_uid);

		ERR("Failed to retrieve index for tracer token: token = %" PRIu64 ", trigger name = '%s', trigger owner uid = %d, status = %s",
				tracer_token, trigger_name,
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
	cds_lfht_for_each_entry(error_counter_uid_ht->ht, &iter.iter,
			uid_entry, node.node) {
		const int ret = lttng_ust_ctl_counter_clear(uid_entry->daemon_counter,
				&dimension_index);

		if (ret) {
			uid_t trigger_owner_uid;
			const char *trigger_name;

			get_trigger_info_for_log(trigger, &trigger_name,
						 &trigger_owner_uid);
			ERR("Failed to clear event notifier counter value for trigger: counter uid = %d, trigger name = '%s', trigger owner uid = %d",
					(int) uid_entry->node.key, trigger_name,
					(int) trigger_owner_uid);
			status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR;
			goto end;
		}
	}

	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
end:
	rcu_read_unlock();
	return status;
}
#endif /* HAVE_LIBLTTNG_UST_CTL */

static
enum event_notifier_error_accounting_status
event_notifier_error_accounting_kernel_clear(
		const struct lttng_trigger *trigger)
{
	int ret;
	uint64_t error_counter_index;
	enum event_notifier_error_accounting_status status;
	struct lttng_kernel_abi_counter_clear counter_clear = {};

	status = get_error_counter_index_for_token(&kernel_state,
			lttng_trigger_get_tracer_token(trigger),
			&error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(
				trigger, &trigger_name, &trigger_owner_uid);

		ERR("Failed to get event notifier error counter index: trigger owner uid = %d, trigger name = '%s', status = '%s'",
				trigger_owner_uid, trigger_name,
				error_accounting_status_str(status));
		goto end;
	}

	counter_clear.index.number_dimensions = 1;
	counter_clear.index.dimension_indexes[0] = error_counter_index;

	ret = kernctl_counter_clear(
			kernel_error_accounting_entry.error_counter_fd,
			&counter_clear);
	if (ret) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(
				trigger, &trigger_name, &trigger_owner_uid);

		ERR("Failed to clear kernel event notifier error counter: trigger owner uid = %d, trigger name = '%s'",
				trigger_owner_uid, trigger_name);
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
	const struct lttng_kernel_abi_counter_conf error_counter_conf = {
		.arithmetic = LTTNG_KERNEL_ABI_COUNTER_ARITHMETIC_MODULAR,
		.bitness = sizeof(void *) == sizeof(uint32_t) ?
				LTTNG_KERNEL_ABI_COUNTER_BITNESS_32 :
				LTTNG_KERNEL_ABI_COUNTER_BITNESS_64,
		.global_sum_step = 0,
		.number_dimensions = 1,
		.dimensions[0].size = kernel_state.number_indices,
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

	kernel_error_accounting_entry.error_counter_fd =
			error_counter_fd;
	status = EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;

error:
	return status;
}

static
enum event_notifier_error_accounting_status create_error_counter_index_for_token(
		struct error_accounting_state *state, uint64_t tracer_token,
		uint64_t *error_counter_index)
{
	struct index_ht_entry *index_entry;
	enum lttng_index_allocator_status index_alloc_status;
	uint64_t local_error_counter_index;
	enum event_notifier_error_accounting_status status;

	assert(state);

	/* Allocate a new index for that counter. */
	index_alloc_status = lttng_index_allocator_alloc(state->index_allocator,
			&local_error_counter_index);
	switch (index_alloc_status) {
	case LTTNG_INDEX_ALLOCATOR_STATUS_EMPTY:
		DBG("No indices left in the configured event notifier error counter: "
				"number-of-indices = %"PRIu64,
				lttng_index_allocator_get_index_count(
					state->index_allocator));
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
	lttng_ht_add_unique_u64(state->indices_ht, &index_entry->node);

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
	struct error_accounting_state *state;

	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		state = &kernel_state;
		break;
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
		state = &ust_state;
		break;
	default:
		abort();
	}

	/*
	 * Check if this event notifier already has a error counter index
	 * assigned.
	 */
	status = get_error_counter_index_for_token(state,
			lttng_trigger_get_tracer_token(trigger),
			&local_error_counter_index);
	switch (status) {
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND:
	{
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(
				trigger, &trigger_name, &trigger_owner_uid);

		DBG("Event notifier error counter index not found for tracer token (allocating a new one): trigger name = '%s', trigger owner uid = %d, tracer token = %" PRIu64,
				trigger_name, trigger_owner_uid,
				lttng_trigger_get_tracer_token(trigger));

		status = create_error_counter_index_for_token(state,
				lttng_trigger_get_tracer_token(trigger),
				&local_error_counter_index);
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			ERR("Error creating index for token: status = %s, trigger name = '%s', trigger owner uid = %d",
					error_accounting_status_str(status),
					trigger_name, trigger_owner_uid);
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

#ifdef HAVE_LIBLTTNG_UST_CTL
	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
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
		break;
	default:
		break;
	}
#endif /* HAVE_LIBLTTNG_UST_CTL */


end:
	return status;
}

static
enum event_notifier_error_accounting_status
event_notifier_error_accounting_kernel_get_count(
		const struct lttng_trigger *trigger, uint64_t *count)
{
	struct lttng_kernel_abi_counter_aggregate counter_aggregate = {};
	enum event_notifier_error_accounting_status status;
	uint64_t error_counter_index;
	int ret;

	status = get_error_counter_index_for_token(&kernel_state,
			lttng_trigger_get_tracer_token(trigger),
			&error_counter_index);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		ERR("Error getting index for token: status=%s",
				error_accounting_status_str(status));
		goto end;
	}

	counter_aggregate.index.number_dimensions = 1;
	counter_aggregate.index.dimension_indexes[0] = error_counter_index;

	assert(kernel_error_accounting_entry.error_counter_fd);

	ret = kernctl_counter_get_aggregate_value(
			kernel_error_accounting_entry.error_counter_fd,
			&counter_aggregate);
	if (ret || counter_aggregate.value.value < 0) {
		uid_t trigger_owner_uid;
		const char *trigger_name;

		get_trigger_info_for_log(trigger, &trigger_name,
				&trigger_owner_uid);

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
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
#ifdef HAVE_LIBLTTNG_UST_CTL
		return event_notifier_error_accounting_ust_get_count(trigger,
				count);
#else
		*count = 0;
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
#endif /* HAVE_LIBLTTNG_UST_CTL */
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
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
#ifdef HAVE_LIBLTTNG_UST_CTL
		return event_notifier_error_accounting_ust_clear(trigger);
#else
		return EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK;
#endif /* HAVE_LIBLTTNG_UST_CTL */
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
	const uint64_t tracer_token = lttng_trigger_get_tracer_token(trigger);
	enum event_notifier_error_accounting_status status;
	struct error_accounting_state *state;

	status = event_notifier_error_accounting_clear(trigger);
	if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		/* Trigger details already logged by callee on error. */
		ERR("Failed to clear event notifier error counter during unregistration of event notifier: status = '%s'",
				error_accounting_status_str(status));
		goto end;
	}

	rcu_read_lock();

	switch (lttng_trigger_get_underlying_domain_type_restriction(trigger)) {
	case LTTNG_DOMAIN_KERNEL:
		state = &kernel_state;
		break;
#ifdef HAVE_LIBLTTNG_UST_CTL
	case LTTNG_DOMAIN_UST:
	case LTTNG_DOMAIN_PYTHON:
	case LTTNG_DOMAIN_JUL:
	case LTTNG_DOMAIN_LOG4J:
		state = &ust_state;

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

		break;
#endif /* HAVE_LIBLTTNG_UST_CTL */
	default:
		abort();
	}

	lttng_ht_lookup(state->indices_ht, &tracer_token, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node) {
		int del_ret;
		struct index_ht_entry *index_entry = caa_container_of(
				node, typeof(*index_entry), node);
		enum lttng_index_allocator_status index_alloc_status;

		index_alloc_status = lttng_index_allocator_release(
				state->index_allocator,
				index_entry->error_counter_index);
		if (index_alloc_status != LTTNG_INDEX_ALLOCATOR_STATUS_OK) {
			uid_t trigger_owner_uid;
			const char *trigger_name;

			get_trigger_info_for_log(trigger, &trigger_name,
					&trigger_owner_uid);

			ERR("Failed to release event notifier error counter index: index = %" PRIu64 ", trigger name = '%s', trigger owner uid = %d",
					index_entry->error_counter_index,
					trigger_name, (int) trigger_owner_uid);
			/* Don't exit, perform the rest of the clean-up. */
		}

		del_ret = lttng_ht_del(state->indices_ht, &iter);
		assert(!del_ret);
		call_rcu(&index_entry->rcu_head, free_index_ht_entry);
	}

end:
	rcu_read_unlock();
}

void event_notifier_error_accounting_fini(void)
{
	if (kernel_error_accounting_entry.error_counter_fd) {
		const int ret = close(kernel_error_accounting_entry.error_counter_fd);

		if (ret) {
			PERROR("Failed to close kernel event notifier error counter");
		}
	}

	lttng_ht_destroy(error_counter_uid_ht);

	fini_error_accounting_state(&kernel_state);
	fini_error_accounting_state(&ust_state);
}
