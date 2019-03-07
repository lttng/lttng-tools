/*
 * Copyright (C) 2018 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_TRACKER_H
#define _LTT_TRACKER_H

#include <lttng/tracker.h>
#include <urcu.h>
#include <urcu/list.h>
#include <urcu/rculfhash.h>

enum lttng_tracker_list_state {
	LTTNG_TRACK_ALL,
	LTTNG_TRACK_NONE,
	LTTNG_TRACK_LIST,
};

/* Tracker ID */
struct lttng_tracker_list_node {
	struct lttng_tracker_id *id;

	struct cds_list_head list_node;
	struct cds_lfht_node ht_node;
	struct rcu_head rcu_head;
};

struct lttng_tracker_list {
	struct cds_list_head list_head;
	/* Hash table for O(1) removal lookup. */
	struct cds_lfht *ht;
	enum lttng_tracker_list_state state;
};

struct lttng_tracker_list *lttng_tracker_list_create(void);
void lttng_tracker_list_destroy(struct lttng_tracker_list *tracker_list);

int lttng_tracker_list_add(struct lttng_tracker_list *tracker_list,
		const struct lttng_tracker_id *id);
int lttng_tracker_list_remove(struct lttng_tracker_list *tracker_list,
		const struct lttng_tracker_id *id);

int lttng_tracker_id_lookup_string(enum lttng_tracker_type tracker_type,
		const struct lttng_tracker_id *id,
		int *result);
int lttng_tracker_id_get_list(const struct lttng_tracker_list *tracker_list,
		struct lttng_tracker_ids **_ids);
int lttng_tracker_id_set_list(struct lttng_tracker_list *tracker_list,
		const struct lttng_tracker_ids *_ids);

#endif /* _LTT_TRACKER_H */
