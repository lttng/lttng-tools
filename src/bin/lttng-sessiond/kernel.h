/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_KERNEL_CTL_H
#define _LTT_KERNEL_CTL_H

#include "lttng/lttng-error.h"
#include "lttng/tracker.h"
#include "session.h"
#include "snapshot.h"
#include "trace-kernel.h"

/*
 * Default size for the event list when kernel_list_events is called. This size
 * value is based on the initial LTTng 2.0 version set of tracepoints.
 *
 * This is NOT an upper bound because if the real event list size is bigger,
 * dynamic reallocation is performed.
 */
#define KERNEL_EVENT_INIT_LIST_SIZE 64

int kernel_add_channel_context(struct ltt_kernel_channel *chan,
		struct ltt_kernel_context *ctx);
int kernel_create_session(struct ltt_session *session);
int kernel_create_channel(struct ltt_kernel_session *session,
		struct lttng_channel *chan);
int kernel_create_event(struct lttng_event *ev, struct ltt_kernel_channel *channel,
		char *filter_expression, struct lttng_filter_bytecode *filter);
int kernel_disable_channel(struct ltt_kernel_channel *chan);
int kernel_disable_event(struct ltt_kernel_event *event);
int kernel_enable_event(struct ltt_kernel_event *event);
int kernel_enable_channel(struct ltt_kernel_channel *chan);
enum lttng_error_code kernel_process_attr_tracker_set_tracking_policy(
		struct ltt_kernel_session *session,
		enum lttng_process_attr process_attr,
		enum lttng_tracking_policy policy);
enum lttng_error_code kernel_process_attr_tracker_inclusion_set_add_value(
		struct ltt_kernel_session *session,
		enum lttng_process_attr process_attr,
		const struct process_attr_value *value);
enum lttng_error_code kernel_process_attr_tracker_inclusion_set_remove_value(
		struct ltt_kernel_session *session,
		enum lttng_process_attr process_attr,
		const struct process_attr_value *value);
const struct process_attr_tracker *kernel_get_process_attr_tracker(
		struct ltt_kernel_session *session,
		enum lttng_process_attr process_attr);
int kernel_open_metadata(struct ltt_kernel_session *session);
int kernel_open_metadata_stream(struct ltt_kernel_session *session);
int kernel_open_channel_stream(struct ltt_kernel_channel *channel);
int kernel_flush_buffer(struct ltt_kernel_channel *channel);
int kernel_metadata_flush_buffer(int fd);
int kernel_start_session(struct ltt_kernel_session *session);
int kernel_stop_session(struct ltt_kernel_session *session);
ssize_t kernel_list_events(struct lttng_event **event_list);
void kernel_wait_quiescent(void);
int kernel_validate_version(struct lttng_kernel_tracer_version *kernel_tracer_version,
		struct lttng_kernel_tracer_abi_version *kernel_tracer_abi_version);
void kernel_destroy_session(struct ltt_kernel_session *ksess);
void kernel_free_session(struct ltt_kernel_session *ksess);
void kernel_destroy_channel(struct ltt_kernel_channel *kchan);
enum lttng_error_code kernel_snapshot_record(
		struct ltt_kernel_session *ksess,
		const struct consumer_output *output, int wait,
		uint64_t nb_packets_per_stream);
int kernel_syscall_mask(int chan_fd, char **syscall_mask, uint32_t *nr_bits);
enum lttng_error_code kernel_rotate_session(struct ltt_session *session);
enum lttng_error_code kernel_clear_session(struct ltt_session *session);

int init_kernel_workarounds(void);
int kernel_supports_ring_buffer_snapshot_sample_positions(void);
int kernel_supports_ring_buffer_packet_sequence_number(void);
int init_kernel_tracer(void);
void cleanup_kernel_tracer(void);
bool kernel_tracer_is_initialized(void);

enum lttng_error_code kernel_create_channel_subdirectories(
		const struct ltt_kernel_session *ksess);

#endif /* _LTT_KERNEL_CTL_H */
