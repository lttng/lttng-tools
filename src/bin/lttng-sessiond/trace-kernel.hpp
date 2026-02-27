/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_TRACE_KERNEL_H
#define _LTT_TRACE_KERNEL_H

#include "consumer.hpp"
#include "tracker.hpp"

#include <common/defaults.hpp>
#include <common/lttng-kernel-old.hpp>
#include <common/lttng-kernel.hpp>

#include <lttng/lttng.h>

#include <urcu/list.h>

/* Kernel event */
struct ltt_kernel_event_notifier_rule {
	int fd;
	uint64_t error_counter_index;
	bool enabled;
	enum lttng_event_type type;
	struct lttng_trigger *trigger;
	uint64_t token;
	const struct lttng_bytecode *filter;
	struct lttng_userspace_probe_location *userspace_probe_location;
	struct cds_lfht_node ht_node;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

/* Kernel session */
struct ltt_kernel_session {
	int fd;
	int consumer_fds_sent;
	unsigned int channel_count;
	struct consumer_output *consumer;
	/* Tracing session id */
	uint64_t id;
	/* Session is active or not meaning it has been started or stopped. */
	bool active;
	/* Tell or not if the session has to output the traces. */
	unsigned int output_traces;
	unsigned int snapshot_mode;
	unsigned int has_non_default_channel;
};

/*
 * Create functions malloc() the data structure.
 */
struct ltt_kernel_session *trace_kernel_create_session();
/* Trigger is only non-const to acquire a reference. */
enum lttng_error_code trace_kernel_create_event_notifier_rule(
	struct lttng_trigger *trigger,
	uint64_t token,
	uint64_t error_counter_index,
	struct ltt_kernel_event_notifier_rule **event_notifier_rule);

/*
 * Destroy functions free() the data structure and remove from linked list if
 * it's applies.
 */
void trace_kernel_destroy_session(struct ltt_kernel_session *session);
void trace_kernel_destroy_event_notifier_rule(struct ltt_kernel_event_notifier_rule *rule);
void trace_kernel_free_session(struct ltt_kernel_session *session);

#endif /* _LTT_TRACE_KERNEL_H */
