/*
 * Copyright (C) 2018 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_TRACKER_H
#define _LTT_TRACKER_H

#include <common/tracker.h>
#include <lttng/tracker.h>

struct process_attr_tracker;

enum process_attr_tracker_status {
	PROCESS_ATTR_TRACKER_STATUS_OK,
	PROCESS_ATTR_TRACKER_STATUS_ERROR,
	PROCESS_ATTR_TRACKER_STATUS_EXISTS,
	PROCESS_ATTR_TRACKER_STATUS_MISSING,
	PROCESS_ATTR_TRACKER_STATUS_INVALID_TRACKING_POLICY,
};

struct process_attr_tracker *process_attr_tracker_create(void);
void process_attr_tracker_destroy(struct process_attr_tracker *tracker);

enum lttng_tracking_policy process_attr_tracker_get_tracking_policy(
		const struct process_attr_tracker *tracker);
int process_attr_tracker_set_tracking_policy(
		struct process_attr_tracker *tracker,
		enum lttng_tracking_policy tracking_policy);

enum process_attr_tracker_status process_attr_tracker_inclusion_set_add_value(
		struct process_attr_tracker *tracker,
		const struct process_attr_value *value);
enum process_attr_tracker_status
process_attr_tracker_inclusion_set_remove_value(
		struct process_attr_tracker *tracker,
		const struct process_attr_value *value);

enum process_attr_tracker_status process_attr_tracker_get_inclusion_set(
		const struct process_attr_tracker *tracker,
		struct lttng_process_attr_values **values);

#endif /* _LTT_TRACKER_H */
