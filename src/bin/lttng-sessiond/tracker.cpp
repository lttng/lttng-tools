/*
 * Copyright (C) 2018 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "common/dynamic-array.hpp"
#include "common/macros.hpp"
#include "lttng/tracker.h"
#define _LGPL_SOURCE
#include "tracker.hpp"

#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/hashtable/utils.hpp>
#include <common/tracker.hpp>
#include <common/urcu.hpp>

#include <lttng/lttng-error.h>

#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <urcu.h>
#include <urcu/list.h>
#include <urcu/rculfhash.h>

struct process_attr_tracker {
	enum lttng_tracking_policy policy;
	struct cds_lfht *inclusion_set_ht;
};

namespace {
struct process_attr_tracker_value_node {
	struct process_attr_value *value;
	struct cds_lfht_node inclusion_set_ht_node;
	struct rcu_head rcu_head;
};
} /* namespace */

static void process_attr_tracker_value_node_rcu_free(struct rcu_head *rcu_head)
{
	struct process_attr_tracker_value_node *node =
		lttng::utils::container_of(rcu_head, &process_attr_tracker_value_node::rcu_head);

	free(node);
}

struct process_attr_tracker *process_attr_tracker_create()
{
	struct process_attr_tracker *tracker;

	tracker = zmalloc<process_attr_tracker>();
	if (!tracker) {
		return nullptr;
	}

	(void) process_attr_tracker_set_tracking_policy(tracker, LTTNG_TRACKING_POLICY_INCLUDE_ALL);

	tracker->inclusion_set_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!tracker->inclusion_set_ht) {
		goto error;
	}

	return tracker;
error:
	process_attr_tracker_destroy(tracker);
	return nullptr;
}

static void
process_attr_tracker_remove_value_node(struct process_attr_tracker *tracker,
				       struct process_attr_tracker_value_node *value_node)
{
	cds_lfht_del(tracker->inclusion_set_ht, &value_node->inclusion_set_ht_node);
	process_attr_value_destroy(value_node->value);
	call_rcu(&value_node->rcu_head, process_attr_tracker_value_node_rcu_free);
}

static void process_attr_tracker_clear_inclusion_set(struct process_attr_tracker *tracker)
{
	if (!tracker->inclusion_set_ht) {
		return;
	}

	for (auto *value_node : lttng::urcu::lfht_iteration_adapter<
		     process_attr_tracker_value_node,
		     decltype(process_attr_tracker_value_node::inclusion_set_ht_node),
		     &process_attr_tracker_value_node::inclusion_set_ht_node>(
		     *tracker->inclusion_set_ht)) {
		process_attr_tracker_remove_value_node(tracker, value_node);
	}

	const auto ret = cds_lfht_destroy(tracker->inclusion_set_ht, nullptr);
	LTTNG_ASSERT(ret == 0);
	tracker->inclusion_set_ht = nullptr;
}

static int process_attr_tracker_create_inclusion_set(struct process_attr_tracker *tracker)
{
	LTTNG_ASSERT(!tracker->inclusion_set_ht);
	tracker->inclusion_set_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	return tracker->inclusion_set_ht ? 0 : -1;
}

void process_attr_tracker_destroy(struct process_attr_tracker *tracker)
{
	if (!tracker) {
		return;
	}

	process_attr_tracker_clear_inclusion_set(tracker);
	free(tracker);
}

enum lttng_tracking_policy
process_attr_tracker_get_tracking_policy(const struct process_attr_tracker *tracker)
{
	return tracker->policy;
}

int process_attr_tracker_set_tracking_policy(struct process_attr_tracker *tracker,
					     enum lttng_tracking_policy tracking_policy)
{
	int ret = 0;

	if (tracker->policy == tracking_policy) {
		goto end;
	}

	process_attr_tracker_clear_inclusion_set(tracker);
	ret = process_attr_tracker_create_inclusion_set(tracker);
	if (ret) {
		goto end;
	}
	tracker->policy = tracking_policy;
end:
	return ret;
}

static int match_inclusion_set_value(struct cds_lfht_node *node, const void *key)
{
	const struct process_attr_value *value_key = (process_attr_value *) key;
	const struct process_attr_tracker_value_node *value_node = caa_container_of(
		node, struct process_attr_tracker_value_node, inclusion_set_ht_node);

	return process_attr_tracker_value_equal(value_node->value, value_key);
}

static struct process_attr_tracker_value_node *
process_attr_tracker_lookup(const struct process_attr_tracker *tracker,
			    const struct process_attr_value *value)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	LTTNG_ASSERT(tracker->policy == LTTNG_TRACKING_POLICY_INCLUDE_SET);

	const lttng::urcu::read_lock_guard read_lock;
	cds_lfht_lookup(tracker->inclusion_set_ht,
			process_attr_value_hash(value),
			match_inclusion_set_value,
			value,
			&iter);
	node = cds_lfht_iter_get_node(&iter);

	return node ? lttng::utils::container_of(
			      node, &process_attr_tracker_value_node::inclusion_set_ht_node) :
		      nullptr;
}

/* Protected by session mutex held by caller. */
enum process_attr_tracker_status
process_attr_tracker_inclusion_set_add_value(struct process_attr_tracker *tracker,
					     const struct process_attr_value *value)
{
	enum process_attr_tracker_status status = PROCESS_ATTR_TRACKER_STATUS_OK;
	struct process_attr_value *value_copy = nullptr;
	struct process_attr_tracker_value_node *value_node = nullptr;

	const lttng::urcu::read_lock_guard read_lock;
	if (tracker->policy != LTTNG_TRACKING_POLICY_INCLUDE_SET) {
		status = PROCESS_ATTR_TRACKER_STATUS_INVALID_TRACKING_POLICY;
		goto end;
	}

	if (process_attr_tracker_lookup(tracker, value)) {
		status = PROCESS_ATTR_TRACKER_STATUS_EXISTS;
		goto end;
	}

	value_node = zmalloc<process_attr_tracker_value_node>();
	if (!value_node) {
		status = PROCESS_ATTR_TRACKER_STATUS_ERROR;
		goto end;
	}

	value_copy = process_attr_value_copy(value);
	if (!value_copy) {
		status = PROCESS_ATTR_TRACKER_STATUS_ERROR;
		goto end;
	}

	value_node->value = value_copy;
	cds_lfht_add(tracker->inclusion_set_ht,
		     process_attr_value_hash(value_copy),
		     &value_node->inclusion_set_ht_node);
	value_copy = nullptr;
	value_node = nullptr;
end:
	if (value_copy) {
		process_attr_value_destroy(value_copy);
	}
	if (value_node) {
		free(value_node);
	}
	return status;
}

/* Protected by session mutex held by caller. */
enum process_attr_tracker_status
process_attr_tracker_inclusion_set_remove_value(struct process_attr_tracker *tracker,
						const struct process_attr_value *value)
{
	struct process_attr_tracker_value_node *value_node;
	enum process_attr_tracker_status status = PROCESS_ATTR_TRACKER_STATUS_OK;

	const lttng::urcu::read_lock_guard read_lock;
	if (tracker->policy != LTTNG_TRACKING_POLICY_INCLUDE_SET) {
		status = PROCESS_ATTR_TRACKER_STATUS_INVALID_TRACKING_POLICY;
		goto end;
	}

	value_node = process_attr_tracker_lookup(tracker, value);
	if (!value_node) {
		status = PROCESS_ATTR_TRACKER_STATUS_MISSING;
		goto end;
	}

	process_attr_tracker_remove_value_node(tracker, value_node);
end:
	return status;
}

enum process_attr_tracker_status
process_attr_tracker_get_inclusion_set(const struct process_attr_tracker *tracker,
				       struct lttng_process_attr_values **_values)
{
	enum process_attr_tracker_status status = PROCESS_ATTR_TRACKER_STATUS_OK;
	struct lttng_process_attr_values *values;
	struct process_attr_value *new_value = nullptr;

	values = lttng_process_attr_values_create();
	if (!values) {
		status = PROCESS_ATTR_TRACKER_STATUS_ERROR;
		goto error;
	}

	if (tracker->policy != LTTNG_TRACKING_POLICY_INCLUDE_SET) {
		status = PROCESS_ATTR_TRACKER_STATUS_INVALID_TRACKING_POLICY;
		goto error;
	}

	for (auto *value_node : lttng::urcu::lfht_iteration_adapter<
		     process_attr_tracker_value_node,
		     decltype(process_attr_tracker_value_node::inclusion_set_ht_node),
		     &process_attr_tracker_value_node::inclusion_set_ht_node>(
		     *tracker->inclusion_set_ht)) {
		int ret;

		new_value = process_attr_value_copy(value_node->value);
		if (!new_value) {
			status = PROCESS_ATTR_TRACKER_STATUS_ERROR;
			goto error_unlock;
		}

		ret = lttng_dynamic_pointer_array_add_pointer(&values->array, new_value);
		if (ret) {
			status = PROCESS_ATTR_TRACKER_STATUS_ERROR;
			goto error_unlock;
		}

		new_value = nullptr;
	}

	*_values = values;
	return status;
error_unlock:
error:
	lttng_process_attr_values_destroy(values);
	process_attr_value_destroy(new_value);
	return status;
}
