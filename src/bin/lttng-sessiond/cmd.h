/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef CMD_H
#define CMD_H

#include "context.h"
#include "lttng-sessiond.h"
#include "lttng/tracker.h"
#include "session.h"
#include <common/tracker.h>

struct notification_thread_handle;

/*
 * A callback (and associated user data) that should be run after a command
 * has been executed. No locks should be taken while executing this handler.
 *
 * The command's reply should not be sent until the handler has run and
 * completed successfully. On failure, the handler's return code should
 * be the only reply sent to the client.
 */
typedef enum lttng_error_code (*completion_handler_function)(void *);
struct cmd_completion_handler {
	completion_handler_function run;
	void *data;
};

/*
 * Init the command subsystem. Must be called before using any of the functions
 * above. This is called in the main() of the session daemon.
 */
void cmd_init(void);

/* Session commands */
enum lttng_error_code cmd_create_session(struct command_ctx *cmd_ctx, int sock,
		struct lttng_session_descriptor **return_descriptor);
int cmd_destroy_session(struct ltt_session *session,
		struct notification_thread_handle *notification_thread_handle,
		int *sock_fd);

/* Channel commands */
int cmd_disable_channel(struct ltt_session *session,
		enum lttng_domain_type domain, char *channel_name);
int cmd_enable_channel(struct ltt_session *session,
		const struct lttng_domain *domain, const struct lttng_channel *attr,
		int wpipe);

/* Process attribute tracker commands */
enum lttng_error_code cmd_process_attr_tracker_get_tracking_policy(
		struct ltt_session *session,
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		enum lttng_tracking_policy *policy);
enum lttng_error_code cmd_process_attr_tracker_set_tracking_policy(
		struct ltt_session *session,
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		enum lttng_tracking_policy policy);
enum lttng_error_code cmd_process_attr_tracker_inclusion_set_add_value(
		struct ltt_session *session,
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		const struct process_attr_value *value);
enum lttng_error_code cmd_process_attr_tracker_inclusion_set_remove_value(
		struct ltt_session *session,
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		const struct process_attr_value *value);
enum lttng_error_code cmd_process_attr_tracker_get_inclusion_set(
		struct ltt_session *session,
		enum lttng_domain_type domain,
		enum lttng_process_attr process_attr,
		struct lttng_process_attr_values **values);

/* Event commands */
int cmd_disable_event(struct ltt_session *session,
		enum lttng_domain_type domain,
		const char *channel_name,
		const struct lttng_event *event);
int cmd_add_context(struct ltt_session *session, enum lttng_domain_type domain,
		char *channel_name, const struct lttng_event_context *ctx, int kwpipe);
int cmd_set_filter(struct ltt_session *session, enum lttng_domain_type domain,
		char *channel_name, struct lttng_event *event,
		struct lttng_filter_bytecode *bytecode);
int cmd_enable_event(struct ltt_session *session, const struct lttng_domain *domain,
		char *channel_name, struct lttng_event *event,
		char *filter_expression,
		struct lttng_filter_bytecode *filter,
		struct lttng_event_exclusion *exclusion,
		int wpipe);

/* Trace session action commands */
int cmd_start_trace(struct ltt_session *session);
int cmd_stop_trace(struct ltt_session *session);

/* Consumer commands */
int cmd_register_consumer(struct ltt_session *session,
		enum lttng_domain_type domain,
		const char *sock_path, struct consumer_data *cdata);
int cmd_set_consumer_uri(struct ltt_session *session, size_t nb_uri,
		struct lttng_uri *uris);
int cmd_setup_relayd(struct ltt_session *session);

/* Listing commands */
ssize_t cmd_list_domains(struct ltt_session *session,
		struct lttng_domain **domains);
ssize_t cmd_list_events(enum lttng_domain_type domain,
		struct ltt_session *session, char *channel_name,
		struct lttng_event **events, size_t *total_size);
ssize_t cmd_list_channels(enum lttng_domain_type domain,
		struct ltt_session *session, struct lttng_channel **channels);
ssize_t cmd_list_domains(struct ltt_session *session,
		struct lttng_domain **domains);
void cmd_list_lttng_sessions(struct lttng_session *sessions,
		size_t session_count, uid_t uid, gid_t gid);
ssize_t cmd_list_tracepoint_fields(enum lttng_domain_type domain,
		struct lttng_event_field **fields);
ssize_t cmd_list_tracepoints(enum lttng_domain_type domain,
		struct lttng_event **events);
ssize_t cmd_snapshot_list_outputs(struct ltt_session *session,
		struct lttng_snapshot_output **outputs);
ssize_t cmd_list_syscalls(struct lttng_event **events);

int cmd_data_pending(struct ltt_session *session);

/* Snapshot */
int cmd_snapshot_add_output(struct ltt_session *session,
		const struct lttng_snapshot_output *output, uint32_t *id);
int cmd_snapshot_del_output(struct ltt_session *session,
		const struct lttng_snapshot_output *output);
int cmd_snapshot_record(struct ltt_session *session,
		const struct lttng_snapshot_output *output, int wait);

int cmd_set_session_shm_path(struct ltt_session *session,
		const char *shm_path);
int cmd_regenerate_metadata(struct ltt_session *session);
int cmd_regenerate_statedump(struct ltt_session *session);

int cmd_register_trigger(struct command_ctx *cmd_ctx, int sock,
		struct notification_thread_handle *notification_thread_handle);
int cmd_unregister_trigger(struct command_ctx *cmd_ctx, int sock,
		struct notification_thread_handle *notification_thread_handle);

int cmd_rotate_session(struct ltt_session *session,
		struct lttng_rotate_session_return *rotate_return,
		bool quiet_rotation,
		enum lttng_trace_chunk_command_type command);
int cmd_rotate_get_info(struct ltt_session *session,
		struct lttng_rotation_get_info_return *info_return,
		uint64_t rotate_id);
int cmd_rotation_set_schedule(struct ltt_session *session,
		bool activate, enum lttng_rotation_schedule_type schedule_type,
		uint64_t value,
		struct notification_thread_handle *notification_thread_handle);

const struct cmd_completion_handler *cmd_pop_completion_handler(void);
int start_kernel_session(struct ltt_kernel_session *ksess);
int stop_kernel_session(struct ltt_kernel_session *ksess);

#endif /* CMD_H */
