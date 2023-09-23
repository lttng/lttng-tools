/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef NOTIFICATION_THREAD_COMMANDS_H
#define NOTIFICATION_THREAD_COMMANDS_H

#include "notification-thread-events.hpp"
#include "notification-thread-internal.hpp"
#include "notification-thread.hpp"

#include <common/waiter.hpp>

#include <lttng/domain.h>
#include <lttng/lttng-error.h>

#include <vendor/optional.hpp>

#include <stdbool.h>
#include <urcu/rculfhash.h>

struct notification_thread_data;
struct lttng_trigger;

enum notification_thread_command_type {
	NOTIFICATION_COMMAND_TYPE_REGISTER_TRIGGER,
	NOTIFICATION_COMMAND_TYPE_UNREGISTER_TRIGGER,
	NOTIFICATION_COMMAND_TYPE_ADD_CHANNEL,
	NOTIFICATION_COMMAND_TYPE_REMOVE_CHANNEL,
	NOTIFICATION_COMMAND_TYPE_ADD_SESSION,
	NOTIFICATION_COMMAND_TYPE_REMOVE_SESSION,
	NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_ONGOING,
	NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_COMPLETED,
	NOTIFICATION_COMMAND_TYPE_ADD_TRACER_EVENT_SOURCE,
	NOTIFICATION_COMMAND_TYPE_REMOVE_TRACER_EVENT_SOURCE,
	NOTIFICATION_COMMAND_TYPE_LIST_TRIGGERS,
	NOTIFICATION_COMMAND_TYPE_QUIT,
	NOTIFICATION_COMMAND_TYPE_CLIENT_COMMUNICATION_UPDATE,
	NOTIFICATION_COMMAND_TYPE_GET_TRIGGER,
};

struct notification_thread_command {
	struct cds_list_head cmd_list_node = {};

	notification_thread_command_type type = NOTIFICATION_COMMAND_TYPE_QUIT;
	union {
		/* Register trigger. */
		struct {
			struct lttng_trigger *trigger;
			bool is_trigger_anonymous;
		} register_trigger;
		/* Unregister trigger. */
		struct {
			const struct lttng_trigger *trigger;
		} unregister_trigger;
		/* Add session. */
		struct {
			uint64_t session_id;
			const char *session_name;
			uid_t session_uid;
			gid_t session_gid;
		} add_session;
		/* Remove session. */
		struct {
			uint64_t session_id;
		} remove_session;
		/* Add channel. */
		struct {
			struct {
				uint64_t id;
			} session;
			struct {
				const char *name;
				enum lttng_domain_type domain;
				uint64_t key;
				uint64_t capacity;
			} channel;
		} add_channel;
		/* Remove channel. */
		struct {
			uint64_t key;
			enum lttng_domain_type domain;
		} remove_channel;
		struct {
			uint64_t session_id;
			uint64_t trace_archive_chunk_id;
			/* Weak reference. */
			struct lttng_trace_archive_location *location;
		} session_rotation;
		/* Add/Remove tracer event source fd. */
		struct {
			int tracer_event_source_fd;
			enum lttng_domain_type domain;
		} tracer_event_source;
		/* List triggers. */
		struct {
			/* Credentials of the requesting user. */
			uid_t uid;
		} list_triggers;
		/* Client communication update. */
		struct {
			notification_client_id id;
			enum client_transmission_status status;
		} client_communication_update;

		struct {
			const struct lttng_trigger *trigger;
		} get_trigger;

	} parameters = {};

	union {
		struct {
			struct lttng_triggers *triggers;
		} list_triggers;
		struct {
			struct lttng_trigger *trigger;
		} get_trigger;
	} reply = {};

	/* Used to wake origin thread for synchroneous commands. */
	nonstd::optional<lttng::synchro::waker> command_completed_waker = nonstd::nullopt;
	lttng_error_code reply_code = LTTNG_ERR_UNK;
	bool is_async = false;
};

enum lttng_error_code
notification_thread_command_register_trigger(struct notification_thread_handle *handle,
					     struct lttng_trigger *trigger,
					     bool is_anonymous_trigger);

enum lttng_error_code
notification_thread_command_unregister_trigger(struct notification_thread_handle *handle,
					       const struct lttng_trigger *trigger);

enum lttng_error_code
notification_thread_command_add_session(struct notification_thread_handle *handle,
					uint64_t session_id,
					const char *session_name,
					uid_t session_uid,
					gid_t session_gid);

enum lttng_error_code
notification_thread_command_remove_session(struct notification_thread_handle *handle,
					   uint64_t session_id);

enum lttng_error_code
notification_thread_command_add_channel(struct notification_thread_handle *handle,
					uint64_t session_id,
					char *channel_name,
					uint64_t key,
					enum lttng_domain_type domain,
					uint64_t capacity);

enum lttng_error_code notification_thread_command_remove_channel(
	struct notification_thread_handle *handle, uint64_t key, enum lttng_domain_type domain);

enum lttng_error_code
notification_thread_command_session_rotation_ongoing(struct notification_thread_handle *handle,
						     uint64_t session_id,
						     uint64_t trace_archive_chunk_id);

/* Ownership of location is transferred. */
enum lttng_error_code notification_thread_command_session_rotation_completed(
	struct notification_thread_handle *handle,
	uint64_t session_id,
	uint64_t trace_archive_chunk_id,
	struct lttng_trace_archive_location *location);

/*
 * Return the set of triggers visible to a given client.
 *
 * The trigger objects contained in the set are the actual trigger instances
 * used by the notification subsystem (i.e. not a copy). Given that the command
 * is only used to serialize the triggers, this is fine: the properties that
 * are serialized are immutable over the lifetime of the triggers.
 *
 * Moreover, the lifetime of the trigger instances is protected through
 * reference counting (references are held by the trigger set).
 *
 * The caller has the exclusive ownership of the returned trigger set.
 */
enum lttng_error_code
notification_thread_command_list_triggers(struct notification_thread_handle *handle,
					  uid_t client_uid,
					  struct lttng_triggers **triggers);

/*
 * The ownership of trigger_event_application_pipe is _not_ transferred to
 * the notification thread.
 */
enum lttng_error_code
notification_thread_command_add_tracer_event_source(struct notification_thread_handle *handle,
						    int tracer_event_source_fd,
						    enum lttng_domain_type domain);

enum lttng_error_code
notification_thread_command_remove_tracer_event_source(struct notification_thread_handle *handle,
						       int tracer_event_source_fd);

void notification_thread_command_quit(struct notification_thread_handle *handle);

enum lttng_error_code
notification_thread_command_get_trigger(struct notification_thread_handle *handle,
					const struct lttng_trigger *trigger,
					struct lttng_trigger **real_trigger);

#endif /* NOTIFICATION_THREAD_COMMANDS_H */
