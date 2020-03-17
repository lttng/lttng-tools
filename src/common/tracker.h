/*
 * Copyright (C) 2019 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_TRACKER_H
#define LTTNG_COMMON_TRACKER_H

#include <lttng/lttng-error.h>
#include <lttng/tracker.h>

#include <common/buffer-view.h>
#include <common/dynamic-array.h>
#include <common/macros.h>
#include <common/sessiond-comm/sessiond-comm.h>

struct process_attr_value {
	enum lttng_process_attr_value_type type;
	union value {
		pid_t pid;
		uid_t uid;
		char *user_name;
		gid_t gid;
		char *group_name;
	} value;
};

struct lttng_process_attr_values {
	/* Array of struct process_attr_tracker_value. */
	struct lttng_dynamic_pointer_array array;
};

LTTNG_HIDDEN
const char *lttng_process_attr_to_string(enum lttng_process_attr process_attr);

LTTNG_HIDDEN
struct lttng_process_attr_values *lttng_process_attr_values_create(void);

/* Prefixed with '_' since the name conflicts with a public API. */
LTTNG_HIDDEN
unsigned int _lttng_process_attr_values_get_count(
		const struct lttng_process_attr_values *values);

LTTNG_HIDDEN
const struct process_attr_value *lttng_process_attr_tracker_values_get_at_index(
		const struct lttng_process_attr_values *values,
		unsigned int index);

LTTNG_HIDDEN
int lttng_process_attr_values_serialize(
		const struct lttng_process_attr_values *values,
		struct lttng_dynamic_buffer *buffer);

LTTNG_HIDDEN
ssize_t lttng_process_attr_values_create_from_buffer(
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		const struct lttng_buffer_view *buffer_view,
		struct lttng_process_attr_values **_values);

LTTNG_HIDDEN
void lttng_process_attr_values_destroy(
		struct lttng_process_attr_values *values);

LTTNG_HIDDEN
struct process_attr_value *process_attr_value_copy(
		const struct process_attr_value *value);

LTTNG_HIDDEN
unsigned long process_attr_value_hash(const struct process_attr_value *a);

LTTNG_HIDDEN
bool process_attr_tracker_value_equal(const struct process_attr_value *a,
		const struct process_attr_value *b);

LTTNG_HIDDEN
void process_attr_value_destroy(struct process_attr_value *value);

LTTNG_HIDDEN
enum lttng_error_code process_attr_value_from_comm(
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		enum lttng_process_attr_value_type value_type,
		const struct process_attr_integral_value_comm *integral_value,
		const struct lttng_buffer_view *value_view,
		struct process_attr_value **value);

#endif /* LTTNG_COMMON_TRACKER_H */
