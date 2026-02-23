/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_KERNEL_CTL_H
#define _LTT_KERNEL_CTL_H

#include "channel-configuration.hpp"
#include "lttng/lttng-error.h"
#include "lttng/tracker.h"
#include "session.hpp"
#include "snapshot.hpp"
#include "trace-kernel.hpp"

/*
 * Default size for the event list when kernel_list_events is called. This size
 * value is based on the initial LTTng 2.0 version set of tracepoints.
 *
 * This is NOT an upper bound because if the real event list size is bigger,
 * dynamic reallocation is performed.
 */
#define KERNEL_EVENT_INIT_LIST_SIZE 64

/*
 * Convert a channel_configuration to the lttng_kernel_abi_channel struct
 * expected by the kernel tracer ioctls.
 */
lttng_kernel_abi_channel
make_kernel_abi_channel(const lttng::sessiond::config::channel_configuration& channel_config);

/*
 * Allocate a unique consumer key for a kernel channel or metadata channel.
 *
 * The key uniquely identifies a channel to the consumer daemon and is
 * monotonically increasing. Must be called with the session list lock held.
 */
uint64_t allocate_next_kernel_stream_group_key();

int kernel_create_session(const ltt_session::locked_ref& session);
int kernel_open_metadata(
	struct ltt_kernel_session *session,
	const lttng::sessiond::config::metadata_channel_configuration& metadata_config);
int kernel_open_metadata_stream(struct ltt_kernel_session *session);
int kernel_open_channel_stream(struct ltt_kernel_channel *channel);
int kernel_flush_buffer(struct ltt_kernel_channel *channel);
int kernel_metadata_flush_buffer(int fd);
int kernel_start_session(struct ltt_kernel_session *session);
int kernel_stop_session(struct ltt_kernel_session *session);
ssize_t kernel_list_events(struct lttng_event **event_list);
void kernel_wait_quiescent();
int kernel_validate_version(struct lttng_kernel_abi_tracer_version *kernel_tracer_version,
			    struct lttng_kernel_abi_tracer_abi_version *kernel_tracer_abi_version);
void kernel_destroy_session(struct ltt_kernel_session *ksess);
void kernel_free_session(struct ltt_kernel_session *ksess);
void kernel_destroy_channel(struct ltt_kernel_channel *kchan);

int kernel_syscall_mask(int chan_fd, char **syscall_mask, uint32_t *nr_bits);
enum lttng_error_code kernel_rotate_session(struct ltt_kernel_session *ksess);
enum lttng_error_code kernel_clear_session(struct ltt_kernel_session *ksess);
enum lttng_error_code kernel_open_packets(struct ltt_kernel_session *ksess);

/*
 * Add callsites for a userspace probe event rule.
 *
 * Extracts the probe location from the event rule, resolves symbol offsets,
 * and registers them with the kernel tracer via the event file descriptor.
 *
 * Returns 0 on success, or an LTTNG_ERR_* code on failure.
 */
int userspace_probe_event_rule_add_callsites(const struct lttng_event_rule *rule,
					     const struct lttng_credentials *creds,
					     int fd);

int init_kernel_workarounds();
int kernel_supports_ring_buffer_snapshot_sample_positions();
int kernel_supports_ring_buffer_packet_sequence_number();
int kernel_supports_event_notifiers();
enum lttng_kernel_tracer_status get_kernel_tracer_status();
void set_kernel_tracer_status_from_modules_ret(int);
int init_kernel_tracer();
void cleanup_kernel_tracer();
bool kernel_tracer_is_initialized();

enum lttng_error_code kernel_create_channel_subdirectories(const struct ltt_kernel_session *ksess);

enum lttng_error_code
kernel_create_event_notifier_group_notification_fd(int *event_notifier_group_notification_fd);
enum lttng_error_code
kernel_destroy_event_notifier_group_notification_fd(int event_notifier_group_notification_fd);

enum lttng_error_code kernel_register_event_notifier(struct lttng_trigger *trigger,
						     const struct lttng_credentials *cmd_creds);
enum lttng_error_code kernel_unregister_event_notifier(const struct lttng_trigger *trigger);

int kernel_get_notification_fd();
void kernel_set_notification_fd_registered();

#endif /* _LTT_KERNEL_CTL_H */
