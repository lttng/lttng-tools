/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef NOTIFICATION_THREAD_INTERNAL_H
#define NOTIFICATION_THREAD_INTERNAL_H

#include <common/compat/socket.h>
#include <common/credentials.h>
#include <common/payload.h>
#include <lttng/notification/channel-internal.h>
#include <lttng/ref-internal.h>
#include <stdbool.h>
#include <unistd.h>
#include <urcu/rculfhash.h>
#include <urcu/ref.h>
#include <urcu/call-rcu.h>
#include "notification-thread.h"

struct lttng_evaluation;
struct notification_thread_handle;

struct channel_key {
	uint64_t key;
	enum lttng_domain_type domain;
};

struct session_info {
	struct lttng_ref ref;
	char *name;
	uid_t uid;
	gid_t gid;
	/*
	 * Hashtable containing back-refs (weak) to all channels in this session.
	 * The hashtable's key is a hash of (struct channel_key) and
	 * the value is of type (struct channel_info *).
	 */
	struct cds_lfht *channel_infos_ht;
	struct lttng_session_trigger_list *trigger_list;
	/* Node in the notification thread state's sessions_ht. */
	struct cds_lfht_node sessions_ht_node;
	/*
	 * Weak reference to the thread state's sessions_ht. Used for removal on
	 * destruction.
	 */
	struct cds_lfht *sessions_ht;
	uint64_t consumed_data_size;
	struct {
		/* Whether a rotation is ongoing for this session. */
		bool ongoing;
		/* Identifier of the currently ongoing rotation. */
		uint64_t id;
	} rotation;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

struct channel_info {
	struct channel_key key;
	char *name;
	uint64_t capacity;
	/*
	 * A channel info holds a reference (lttng_ref) on session_info.
	 * session_info, in return, holds a weak reference to the channel.
	 */
	struct session_info *session_info;
	/* Node in the notification thread state's channels_ht. */
	struct cds_lfht_node channels_ht_node;
	/* Node in the session_info's channels_ht. */
	struct cds_lfht_node session_info_channels_ht_node;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

/*
 * Facilities to carry the different notifications type in the action
 * processing code path.
 */
struct lttng_event_notifier_notification {
	uint64_t tracer_token;
	enum lttng_domain_type type;
};

struct notification_client_list_element {
	struct notification_client *client;
	struct cds_list_head node;
};

/*
 * Thread safety of notification_client and notification_client_list.
 *
 * The notification thread (main thread) and the action executor
 * interact through client lists. Hence, when the action executor
 * thread looks-up the list of clients subscribed to a given
 * condition, it will acquire a reference to the list and lock it
 * while attempting to communicate with the various clients.
 *
 * It is not necessary to reference-count clients as they are guaranteed
 * to be 'alive' if they are present in a list and that list is locked. Indeed,
 * removing references to the client from those subscription lists is part of
 * the work performed on destruction of a client.
 *
 * No provision for other access scenarios are taken into account;
 * this is the bare minimum to make these accesses safe and the
 * notification thread's state is _not_ "thread-safe" in any general
 * sense.
 */
struct notification_client_list {
	pthread_mutex_t lock;
	struct urcu_ref ref;
	const struct lttng_trigger *trigger;
	struct cds_list_head list;
	/* Weak reference to container. */
	struct cds_lfht *notification_trigger_clients_ht;
	struct cds_lfht_node notification_trigger_clients_ht_node;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

struct notification_client {
	/*
	 * Nests within the notification_client_list lock.
	 *
	 * Protects the outbound communication and the active flag which
	 * is used by both the notification and action executor threads.
	 *
	 * The remaining fields of the object can be used without any
	 * synchronization as they are either immutable (id, creds, version) or
	 * only accessed by the notification thread.
	 */
	pthread_mutex_t lock;
	notification_client_id id;
	int socket;
	/* Client protocol version. */
	uint8_t major, minor;
	uid_t uid;
	gid_t gid;
	/*
	 * Indicates if the credentials and versions of the client have been
	 * checked.
	 */
	bool validated;
	/*
	 * Conditions to which the client's notification channel is subscribed.
	 * List of struct lttng_condition_list_node. The condition member is
	 * owned by the client.
	 */
	struct cds_list_head condition_list;
	struct cds_lfht_node client_socket_ht_node;
	struct cds_lfht_node client_id_ht_node;
	struct {
		/*
		 * If a client's communication is inactive, it means that a
		 * fatal error has occurred (could be either a protocol error or
		 * the socket API returned a fatal error). No further
		 * communication should be attempted; the client is queued for
		 * clean-up.
		 */
		bool active;
		struct {
			/*
			 * During the reception of a message, the reception
			 * buffers' "size" is set to contain the current
			 * message's complete payload.
			 */
			struct lttng_payload payload;
			/* Bytes left to receive for the current message. */
			size_t bytes_to_receive;
			/* FDs left to receive for the current message. */
			int fds_to_receive;
			/* Type of the message being received. */
			enum lttng_notification_channel_message_type msg_type;
			/*
			 * Indicates whether or not credentials are expected
			 * from the client.
			 */
			bool expect_creds;
			/*
			 * Indicates whether or not credentials were received
			 * from the client.
			 */
			bool creds_received;
			/* Only used during credentials reception. */
			lttng_sock_cred creds;
		} inbound;
		struct {
			/*
			 * Indicates whether or not a notification addressed to
			 * this client was dropped because a command reply was
			 * already buffered.
			 *
			 * A notification is dropped whenever the buffer is not
			 * empty.
			 */
			bool dropped_notification;
			/*
			 * Indicates whether or not a command reply is already
			 * buffered. In this case, it means that the client is
			 * not consuming command replies before emitting a new
			 * one. This could be caused by a protocol error or a
			 * misbehaving/malicious client.
			 */
			bool queued_command_reply;
			struct lttng_payload payload;
		} outbound;
	} communication;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

enum client_transmission_status {
	CLIENT_TRANSMISSION_STATUS_COMPLETE,
	CLIENT_TRANSMISSION_STATUS_QUEUED,
	/* Communication failure. */
	CLIENT_TRANSMISSION_STATUS_FAIL,
	/* Fatal error. */
	CLIENT_TRANSMISSION_STATUS_ERROR,
};

LTTNG_HIDDEN
bool notification_client_list_get(struct notification_client_list *list);

LTTNG_HIDDEN
void notification_client_list_put(struct notification_client_list *list);

/* Only returns a non-zero value if a fatal error occurred. */
typedef int (*report_client_transmission_result_cb)(
		struct notification_client *client,
		enum client_transmission_status status,
		void *user_data);

LTTNG_HIDDEN
int notification_client_list_send_evaluation(
		struct notification_client_list *list,
		const struct lttng_condition *condition,
		const struct lttng_evaluation *evaluation,
		const struct lttng_credentials *trigger_creds,
		const struct lttng_credentials *source_object_creds,
		report_client_transmission_result_cb client_report,
		void *user_data);

LTTNG_HIDDEN
int notification_thread_client_communication_update(
		struct notification_thread_handle *handle,
		notification_client_id id,
		enum client_transmission_status transmission_status);

LTTNG_HIDDEN
struct lttng_event_notifier_notification *lttng_event_notifier_notification_create(
		uint64_t tracer_token,
		enum lttng_domain_type domain);

LTTNG_HIDDEN
void lttng_event_notifier_notification_destroy(
		struct lttng_event_notifier_notification *event_notifier_notification);

#endif /* NOTIFICATION_THREAD_INTERNAL_H */
