/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng/action/action.h"
#include "lttng/trigger/trigger-internal.hpp"
#define _LGPL_SOURCE
#include "condition-internal.hpp"
#include "event-notifier-error-accounting.hpp"
#include "kernel.hpp"
#include "lttng-sessiond.hpp"
#include "notification-thread-commands.hpp"
#include "notification-thread-events.hpp"
#include "notification-thread.hpp"

#include <common/defaults.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/error.hpp>
#include <common/futex.hpp>
#include <common/hashtable/utils.hpp>
#include <common/macros.hpp>
#include <common/pthread-lock.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/unix.hpp>
#include <common/urcu.hpp>

#include <lttng/action/action-internal.hpp>
#include <lttng/action/list-internal.hpp>
#include <lttng/condition/buffer-usage-internal.hpp>
#include <lttng/condition/condition-internal.hpp>
#include <lttng/condition/condition.h>
#include <lttng/condition/event-rule-matches-internal.hpp>
#include <lttng/condition/session-consumed-size-internal.hpp>
#include <lttng/condition/session-rotation-internal.hpp>
#include <lttng/domain-internal.hpp>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/location-internal.hpp>
#include <lttng/notification/channel-internal.hpp>
#include <lttng/notification/notification-internal.hpp>
#include <lttng/trigger/trigger-internal.hpp>

#include <fcntl.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <urcu.h>
#include <urcu/rculfhash.h>

#define CLIENT_POLL_EVENTS_IN	  (LPOLLIN | LPOLLRDHUP)
#define CLIENT_POLL_EVENTS_IN_OUT (CLIENT_POLL_EVENTS_IN | LPOLLOUT)

/* The tracers currently limit the capture size to PIPE_BUF (4kb on linux). */
#define MAX_CAPTURE_SIZE (PIPE_BUF)

enum lttng_object_type {
	LTTNG_OBJECT_TYPE_UNKNOWN,
	LTTNG_OBJECT_TYPE_NONE,
	LTTNG_OBJECT_TYPE_CHANNEL,
	LTTNG_OBJECT_TYPE_SESSION,
};

struct lttng_channel_trigger_list {
	struct channel_key channel_key;
	/* List of struct lttng_trigger_list_element. */
	struct cds_list_head list;
	/* Node in the channel_triggers_ht */
	struct cds_lfht_node channel_triggers_ht_node;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

/*
 * List of triggers applying to a given session.
 *
 * See:
 *   - lttng_session_trigger_list_create()
 *   - lttng_session_trigger_list_build()
 *   - lttng_session_trigger_list_destroy()
 *   - lttng_session_trigger_list_add()
 */
struct lttng_session_trigger_list {
	char *session_name;
	/* List of struct lttng_trigger_list_element. */
	struct cds_list_head list;
	/* Node in the session_triggers_ht */
	struct cds_lfht_node session_triggers_ht_node;
	/*
	 * Weak reference to the notification system's session triggers
	 * hashtable.
	 *
	 * The session trigger list structure structure is owned by
	 * the session's session_info.
	 *
	 * The session_info is kept alive the the channel_infos holding a
	 * reference to it (reference counting). When those channels are
	 * destroyed (at runtime or on teardown), the reference they hold
	 * to the session_info are released. On destruction of session_info,
	 * session_info_destroy() will remove the list of triggers applying
	 * to this session from the notification system's state.
	 *
	 * This implies that the session_triggers_ht must be destroyed
	 * after the channels.
	 */
	struct cds_lfht *session_triggers_ht;
	/* Used for delayed RCU reclaim. */
	struct rcu_head rcu_node;
};

namespace {
struct lttng_trigger_list_element {
	/* No ownership of the trigger object is assumed. */
	struct lttng_trigger *trigger;
	struct cds_list_head node;
};

struct lttng_trigger_ht_element {
	struct lttng_trigger *trigger;
	struct cds_lfht_node node;
	struct cds_lfht_node node_by_name_uid;
	struct cds_list_head client_list_trigger_node;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

struct lttng_condition_list_element {
	struct lttng_condition *condition;
	struct cds_list_head node;
};

struct channel_state_sample {
	struct channel_key key;
	struct cds_lfht_node channel_state_ht_node;
	uint64_t highest_usage;
	uint64_t lowest_usage;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};
} /* namespace */

static unsigned long hash_channel_key(struct channel_key *key);
static int evaluate_buffer_condition(const struct lttng_condition *condition,
				     struct lttng_evaluation **evaluation,
				     const struct notification_thread_state *state,
				     const struct channel_state_sample *previous_sample,
				     const struct channel_state_sample *latest_sample,
				     struct channel_info *channel_info);
static int send_evaluation_to_clients(const struct lttng_trigger *trigger,
				      const struct lttng_evaluation *evaluation,
				      struct notification_client_list *client_list,
				      struct notification_thread_state *state,
				      uid_t channel_uid,
				      gid_t channel_gid);

/* session_info API */
static void session_info_destroy(void *_data);
static void session_info_get(struct session_info *session_info);
static void session_info_put(struct session_info *session_info);
static struct session_info *session_info_create(uint64_t id,
						const char *name,
						uid_t uid,
						gid_t gid,
						struct lttng_session_trigger_list *trigger_list,
						struct cds_lfht *sessions_ht);
static void session_info_add_channel(struct session_info *session_info,
				     struct channel_info *channel_info);
static void session_info_remove_channel(struct session_info *session_info,
					struct channel_info *channel_info);

/* lttng_session_trigger_list API */
static struct lttng_session_trigger_list *
lttng_session_trigger_list_create(const char *session_name, struct cds_lfht *session_triggers_ht);
static struct lttng_session_trigger_list *
lttng_session_trigger_list_build(const struct notification_thread_state *state,
				 const char *session_name);
static void lttng_session_trigger_list_destroy(struct lttng_session_trigger_list *list);
static int lttng_session_trigger_list_add(struct lttng_session_trigger_list *list,
					  struct lttng_trigger *trigger);

static int client_handle_transmission_status(struct notification_client *client,
					     enum client_transmission_status transmission_status,
					     struct notification_thread_state *state);

static int handle_one_event_notifier_notification(struct notification_thread_state *state,
						  int pipe,
						  enum lttng_domain_type domain);

static void free_lttng_trigger_ht_element_rcu(struct rcu_head *node);

static int match_client_socket(struct cds_lfht_node *node, const void *key)
{
	/* This double-cast is intended to supress pointer-to-cast warning. */
	const int socket = (int) (intptr_t) key;
	const struct notification_client *client =
		caa_container_of(node, struct notification_client, client_socket_ht_node);

	return client->socket == socket;
}

static int match_client_id(struct cds_lfht_node *node, const void *key)
{
	/* This double-cast is intended to supress pointer-to-cast warning. */
	const notification_client_id id = *((notification_client_id *) key);
	const struct notification_client *client =
		lttng::utils::container_of(node, &notification_client::client_id_ht_node);

	return client->id == id;
}

static int match_channel_trigger_list(struct cds_lfht_node *node, const void *key)
{
	struct channel_key *channel_key = (struct channel_key *) key;
	struct lttng_channel_trigger_list *trigger_list;

	trigger_list =
		caa_container_of(node, struct lttng_channel_trigger_list, channel_triggers_ht_node);

	return !!((channel_key->key == trigger_list->channel_key.key) &&
		  (channel_key->domain == trigger_list->channel_key.domain));
}

static int match_session_trigger_list(struct cds_lfht_node *node, const void *key)
{
	const char *session_name = (const char *) key;
	struct lttng_session_trigger_list *trigger_list;

	trigger_list =
		caa_container_of(node, struct lttng_session_trigger_list, session_triggers_ht_node);

	return !!(strcmp(trigger_list->session_name, session_name) == 0);
}

static int match_channel_state_sample(struct cds_lfht_node *node, const void *key)
{
	struct channel_key *channel_key = (struct channel_key *) key;
	struct channel_state_sample *sample;

	sample = caa_container_of(node, struct channel_state_sample, channel_state_ht_node);

	return !!((channel_key->key == sample->key.key) &&
		  (channel_key->domain == sample->key.domain));
}

static int match_channel_info(struct cds_lfht_node *node, const void *key)
{
	struct channel_key *channel_key = (struct channel_key *) key;
	struct channel_info *channel_info;

	channel_info = caa_container_of(node, struct channel_info, channels_ht_node);

	return !!((channel_key->key == channel_info->key.key) &&
		  (channel_key->domain == channel_info->key.domain));
}

static int match_trigger(struct cds_lfht_node *node, const void *key)
{
	struct lttng_trigger *trigger_key = (struct lttng_trigger *) key;
	struct lttng_trigger_ht_element *trigger_ht_element;

	trigger_ht_element = caa_container_of(node, struct lttng_trigger_ht_element, node);

	return !!lttng_trigger_is_equal(trigger_key, trigger_ht_element->trigger);
}

static int match_trigger_token(struct cds_lfht_node *node, const void *key)
{
	const uint64_t *_key = (uint64_t *) key;
	struct notification_trigger_tokens_ht_element *element;

	element = caa_container_of(node, struct notification_trigger_tokens_ht_element, node);
	return *_key == element->token;
}

static int match_client_list_condition(struct cds_lfht_node *node, const void *key)
{
	struct lttng_condition *condition_key = (struct lttng_condition *) key;
	struct notification_client_list *client_list;
	const struct lttng_condition *condition;

	LTTNG_ASSERT(condition_key);

	client_list = caa_container_of(
		node, struct notification_client_list, notification_trigger_clients_ht_node);
	condition = client_list->condition;

	return !!lttng_condition_is_equal(condition_key, condition);
}

static int match_session_info(struct cds_lfht_node *node, const void *key)
{
	const auto session_id = *((uint64_t *) key);
	const auto *session_info =
		lttng::utils::container_of(node, &session_info::sessions_ht_node);

	return session_id == session_info->id;
}

static unsigned long hash_session_info_id(uint64_t id)
{
	return hash_key_u64(&id, lttng_ht_seed);
}

static unsigned long hash_session_info(const struct session_info *session_info)
{
	return hash_session_info_id(session_info->id);
}

static struct session_info *get_session_info_by_id(const struct notification_thread_state *state,
						   uint64_t id)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	lttng::urcu::read_lock_guard read_lock_guard;

	cds_lfht_lookup(
		state->sessions_ht, hash_session_info_id(id), match_session_info, &id, &iter);
	node = cds_lfht_iter_get_node(&iter);

	if (node) {
		auto session_info =
			lttng::utils::container_of(node, &session_info::sessions_ht_node);

		session_info_get(session_info);
		return session_info;
	}

	return nullptr;
}

static struct session_info *get_session_info_by_name(const struct notification_thread_state *state,
						     const char *name)
{
	uint64_t session_id;
	const auto found = sample_session_id_by_name(name, &session_id);

	return found ? get_session_info_by_id(state, session_id) : nullptr;
}

static const char *notification_command_type_str(enum notification_thread_command_type type)
{
	switch (type) {
	case NOTIFICATION_COMMAND_TYPE_REGISTER_TRIGGER:
		return "REGISTER_TRIGGER";
	case NOTIFICATION_COMMAND_TYPE_UNREGISTER_TRIGGER:
		return "UNREGISTER_TRIGGER";
	case NOTIFICATION_COMMAND_TYPE_ADD_CHANNEL:
		return "ADD_CHANNEL";
	case NOTIFICATION_COMMAND_TYPE_REMOVE_CHANNEL:
		return "REMOVE_CHANNEL";
	case NOTIFICATION_COMMAND_TYPE_ADD_SESSION:
		return "ADD_SESSION";
	case NOTIFICATION_COMMAND_TYPE_REMOVE_SESSION:
		return "REMOVE_SESSION";
	case NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_ONGOING:
		return "SESSION_ROTATION_ONGOING";
	case NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_COMPLETED:
		return "SESSION_ROTATION_COMPLETED";
	case NOTIFICATION_COMMAND_TYPE_ADD_TRACER_EVENT_SOURCE:
		return "ADD_TRACER_EVENT_SOURCE";
	case NOTIFICATION_COMMAND_TYPE_REMOVE_TRACER_EVENT_SOURCE:
		return "REMOVE_TRACER_EVENT_SOURCE";
	case NOTIFICATION_COMMAND_TYPE_LIST_TRIGGERS:
		return "LIST_TRIGGERS";
	case NOTIFICATION_COMMAND_TYPE_GET_TRIGGER:
		return "GET_TRIGGER";
	case NOTIFICATION_COMMAND_TYPE_QUIT:
		return "QUIT";
	case NOTIFICATION_COMMAND_TYPE_CLIENT_COMMUNICATION_UPDATE:
		return "CLIENT_COMMUNICATION_UPDATE";
	default:
		abort();
	}
}

/*
 * Match trigger based on name and credentials only.
 * Name duplication is NOT allowed for the same uid.
 */
static int match_trigger_by_name_uid(struct cds_lfht_node *node, const void *key)
{
	bool match = false;
	const char *element_trigger_name;
	const char *key_name;
	enum lttng_trigger_status status;
	const struct lttng_credentials *key_creds;
	const struct lttng_credentials *node_creds;
	const struct lttng_trigger *trigger_key = (const struct lttng_trigger *) key;
	const struct lttng_trigger_ht_element *trigger_ht_element =
		caa_container_of(node, struct lttng_trigger_ht_element, node_by_name_uid);

	status = lttng_trigger_get_name(trigger_ht_element->trigger, &element_trigger_name);
	element_trigger_name = status == LTTNG_TRIGGER_STATUS_OK ? element_trigger_name : nullptr;

	status = lttng_trigger_get_name(trigger_key, &key_name);
	key_name = status == LTTNG_TRIGGER_STATUS_OK ? key_name : nullptr;

	/*
	 * Compare the names.
	 * Consider null names as not equal. This is to maintain backwards
	 * compatibility with pre-2.13 anonymous triggers. Multiples anonymous
	 * triggers are allowed for a given user.
	 */
	if (!element_trigger_name || !key_name) {
		goto end;
	}

	if (strcmp(element_trigger_name, key_name) != 0) {
		goto end;
	}

	/* Compare the owners' UIDs. */
	key_creds = lttng_trigger_get_credentials(trigger_key);
	node_creds = lttng_trigger_get_credentials(trigger_ht_element->trigger);

	match = lttng_credentials_is_equal_uid(key_creds, node_creds);

end:
	return match;
}

/*
 * Hash trigger based on name and credentials only.
 */
static unsigned long hash_trigger_by_name_uid(const struct lttng_trigger *trigger)
{
	unsigned long hash = 0;
	const struct lttng_credentials *trigger_creds;
	const char *trigger_name;
	enum lttng_trigger_status status;

	status = lttng_trigger_get_name(trigger, &trigger_name);
	if (status == LTTNG_TRIGGER_STATUS_OK) {
		hash = hash_key_str(trigger_name, lttng_ht_seed);
	}

	trigger_creds = lttng_trigger_get_credentials(trigger);
	hash ^= hash_key_ulong((void *) (unsigned long) LTTNG_OPTIONAL_GET(trigger_creds->uid),
			       lttng_ht_seed);

	return hash;
}

static unsigned long hash_channel_key(struct channel_key *key)
{
	unsigned long key_hash = hash_key_u64(&key->key, lttng_ht_seed);
	unsigned long domain_hash =
		hash_key_ulong((void *) (unsigned long) key->domain, lttng_ht_seed);

	return key_hash ^ domain_hash;
}

static unsigned long hash_client_socket(int socket)
{
	return hash_key_ulong((void *) (unsigned long) socket, lttng_ht_seed);
}

static unsigned long hash_client_id(notification_client_id id)
{
	return hash_key_u64(&id, lttng_ht_seed);
}

/*
 * Get the type of object to which a given condition applies. Bindings let
 * the notification system evaluate a trigger's condition when a given
 * object's state is updated.
 *
 * For instance, a condition bound to a channel will be evaluated everytime
 * the channel's state is changed by a channel monitoring sample.
 */
static enum lttng_object_type get_condition_binding_object(const struct lttng_condition *condition)
{
	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		return LTTNG_OBJECT_TYPE_CHANNEL;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		return LTTNG_OBJECT_TYPE_SESSION;
	case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
		return LTTNG_OBJECT_TYPE_NONE;
	default:
		return LTTNG_OBJECT_TYPE_UNKNOWN;
	}
}

static void free_channel_info_rcu(struct rcu_head *node)
{
	free(lttng::utils::container_of(node, &channel_info::rcu_node));
}

static void channel_info_destroy(struct channel_info *channel_info)
{
	if (!channel_info) {
		return;
	}

	if (channel_info->session_info) {
		session_info_remove_channel(channel_info->session_info, channel_info);
		session_info_put(channel_info->session_info);
	}
	if (channel_info->name) {
		free(channel_info->name);
	}
	call_rcu(&channel_info->rcu_node, free_channel_info_rcu);
}

static void free_session_info_rcu(struct rcu_head *node)
{
	free(lttng::utils::container_of(node, &session_info::rcu_node));
}

/* Don't call directly, use the ref-counting mechanism. */
static void session_info_destroy(void *_data)
{
	struct session_info *session_info = (struct session_info *) _data;
	int ret;

	LTTNG_ASSERT(session_info);
	if (session_info->channel_infos_ht) {
		ret = cds_lfht_destroy(session_info->channel_infos_ht, nullptr);
		if (ret) {
			ERR("Failed to destroy channel information hash table");
		}
	}
	lttng_session_trigger_list_destroy(session_info->trigger_list);

	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_del(session_info->sessions_ht, &session_info->sessions_ht_node);
	free(session_info->name);
	lttng_trace_archive_location_put(session_info->last_state_sample.rotation.location);
	call_rcu(&session_info->rcu_node, free_session_info_rcu);
}

static void session_info_get(struct session_info *session_info)
{
	if (!session_info) {
		return;
	}
	lttng_ref_get(&session_info->ref);
}

static void session_info_put(struct session_info *session_info)
{
	if (!session_info) {
		return;
	}
	lttng_ref_put(&session_info->ref);
}

static struct session_info *session_info_create(uint64_t id,
						const char *name,
						uid_t uid,
						gid_t gid,
						struct lttng_session_trigger_list *trigger_list,
						struct cds_lfht *sessions_ht)
{
	struct session_info *session_info;

	LTTNG_ASSERT(name);

	session_info = zmalloc<struct session_info>();
	if (!session_info) {
		goto end;
	}

	lttng_ref_init(&session_info->ref, session_info_destroy);

	session_info->channel_infos_ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!session_info->channel_infos_ht) {
		goto error;
	}

	cds_lfht_node_init(&session_info->sessions_ht_node);
	session_info->id = id;
	session_info->name = strdup(name);
	if (!session_info->name) {
		goto error;
	}

	session_info->uid = uid;
	session_info->gid = gid;
	session_info->trigger_list = trigger_list;
	session_info->sessions_ht = sessions_ht;
end:
	return session_info;
error:
	session_info_put(session_info);
	return nullptr;
}

static void session_info_add_channel(struct session_info *session_info,
				     struct channel_info *channel_info)
{
	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_add(session_info->channel_infos_ht,
		     hash_channel_key(&channel_info->key),
		     &channel_info->session_info_channels_ht_node);
}

static void session_info_remove_channel(struct session_info *session_info,
					struct channel_info *channel_info)
{
	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_del(session_info->channel_infos_ht, &channel_info->session_info_channels_ht_node);
}

static struct channel_info *channel_info_create(const char *channel_name,
						struct channel_key *channel_key,
						uint64_t channel_capacity,
						struct session_info *session_info)
{
	struct channel_info *channel_info = zmalloc<struct channel_info>();

	if (!channel_info) {
		goto end;
	}

	cds_lfht_node_init(&channel_info->channels_ht_node);
	cds_lfht_node_init(&channel_info->session_info_channels_ht_node);
	memcpy(&channel_info->key, channel_key, sizeof(*channel_key));
	channel_info->capacity = channel_capacity;

	channel_info->name = strdup(channel_name);
	if (!channel_info->name) {
		goto error;
	}

	/*
	 * Set the references between session and channel infos:
	 *   - channel_info holds a strong reference to session_info
	 *   - session_info holds a weak reference to channel_info
	 */
	session_info_get(session_info);
	session_info_add_channel(session_info, channel_info);
	channel_info->session_info = session_info;
end:
	return channel_info;
error:
	channel_info_destroy(channel_info);
	return nullptr;
}

bool notification_client_list_get(struct notification_client_list *list)
{
	return urcu_ref_get_unless_zero(&list->ref);
}

static void free_notification_client_list_rcu(struct rcu_head *node)
{
	free(caa_container_of(node, struct notification_client_list, rcu_node));
}

static void notification_client_list_release(struct urcu_ref *list_ref)
{
	struct notification_client_list *list =
		lttng::utils::container_of(list_ref, &notification_client_list::ref);
	struct notification_client_list_element *client_list_element, *tmp;

	lttng_condition_put(list->condition);

	if (list->notification_trigger_clients_ht) {
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_del(list->notification_trigger_clients_ht,
			     &list->notification_trigger_clients_ht_node);
		list->notification_trigger_clients_ht = nullptr;
	}
	cds_list_for_each_entry_safe (client_list_element, tmp, &list->clients_list, node) {
		free(client_list_element);
	}

	LTTNG_ASSERT(cds_list_empty(&list->triggers_list));

	pthread_mutex_destroy(&list->lock);
	call_rcu(&list->rcu_node, free_notification_client_list_rcu);
}

static bool condition_applies_to_client(const struct lttng_condition *condition,
					struct notification_client *client)
{
	bool applies = false;
	struct lttng_condition_list_element *condition_list_element;

	cds_list_for_each_entry (condition_list_element, &client->condition_list, node) {
		applies = lttng_condition_is_equal(condition_list_element->condition, condition);
		if (applies) {
			break;
		}
	}

	return applies;
}

static struct notification_client_list *
notification_client_list_create(struct notification_thread_state *state,
				const struct lttng_condition *condition)
{
	struct notification_client *client;
	struct cds_lfht_iter iter;
	struct notification_client_list *client_list;

	client_list = zmalloc<notification_client_list>();
	if (!client_list) {
		PERROR("Failed to allocate notification client list");
		goto end;
	}

	pthread_mutex_init(&client_list->lock, nullptr);
	/*
	 * The trigger that owns the condition has the first reference to this
	 * client list.
	 */
	urcu_ref_init(&client_list->ref);
	cds_lfht_node_init(&client_list->notification_trigger_clients_ht_node);
	CDS_INIT_LIST_HEAD(&client_list->clients_list);
	CDS_INIT_LIST_HEAD(&client_list->triggers_list);

	/*
	 * Create a copy of the condition so that it's independent of any
	 * trigger. The client list may outlive the trigger object (which owns
	 * the condition) that is used to create it.
	 */
	client_list->condition = lttng_condition_copy(condition);

	{
		/* Build a list of clients to which this new condition applies. */
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			state->client_socket_ht, &iter, client, client_socket_ht_node) {
			struct notification_client_list_element *client_list_element;

			if (!condition_applies_to_client(condition, client)) {
				continue;
			}

			client_list_element = zmalloc<notification_client_list_element>();
			if (!client_list_element) {
				goto error_put_client_list;
			}

			CDS_INIT_LIST_HEAD(&client_list_element->node);
			client_list_element->client = client;
			cds_list_add(&client_list_element->node, &client_list->clients_list);
		}
	}

	client_list->notification_trigger_clients_ht = state->notification_trigger_clients_ht;

	/*
	 * Add the client list to the global list of client list.
	 */
	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_add_unique(state->notification_trigger_clients_ht,
				    lttng_condition_hash(client_list->condition),
				    match_client_list_condition,
				    client_list->condition,
				    &client_list->notification_trigger_clients_ht_node);
	}
	goto end;

error_put_client_list:
	notification_client_list_put(client_list);
	client_list = nullptr;

end:
	return client_list;
}

void notification_client_list_put(struct notification_client_list *list)
{
	if (!list) {
		return;
	}
	return urcu_ref_put(&list->ref, notification_client_list_release);
}

/* Provides a reference to the returned list. */
static struct notification_client_list *
get_client_list_from_condition(struct notification_thread_state *state,
			       const struct lttng_condition *condition)
{
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct notification_client_list *list = nullptr;

	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_lookup(state->notification_trigger_clients_ht,
			lttng_condition_hash(condition),
			match_client_list_condition,
			condition,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node) {
		list = lttng::utils::container_of(
			node, &notification_client_list::notification_trigger_clients_ht_node);
		list = notification_client_list_get(list) ? list : nullptr;
	}

	return list;
}

static int evaluate_channel_condition_for_client(const struct lttng_condition *condition,
						 struct notification_thread_state *state,
						 struct lttng_evaluation **evaluation,
						 uid_t *session_uid,
						 gid_t *session_gid)
{
	int ret;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct channel_info *channel_info = nullptr;
	struct channel_key *channel_key = nullptr;
	struct channel_state_sample *last_sample = nullptr;
	struct lttng_channel_trigger_list *channel_trigger_list = nullptr;

	lttng::urcu::read_lock_guard read_lock;

	/* Find the channel associated with the condition. */
	cds_lfht_for_each_entry (
		state->channel_triggers_ht, &iter, channel_trigger_list, channel_triggers_ht_node) {
		struct lttng_trigger_list_element *element;

		cds_list_for_each_entry (element, &channel_trigger_list->list, node) {
			const struct lttng_condition *current_condition =
				lttng_trigger_get_const_condition(element->trigger);

			LTTNG_ASSERT(current_condition);
			if (!lttng_condition_is_equal(condition, current_condition)) {
				continue;
			}

			/* Found the trigger, save the channel key. */
			channel_key = &channel_trigger_list->channel_key;
			break;
		}
		if (channel_key) {
			/* The channel key was found stop iteration. */
			break;
		}
	}

	if (!channel_key) {
		/* No channel found; normal exit. */
		DBG("No known channel associated with newly subscribed-to condition");
		ret = 0;
		goto end;
	}

	/* Fetch channel info for the matching channel. */
	cds_lfht_lookup(state->channels_ht,
			hash_channel_key(channel_key),
			match_channel_info,
			channel_key,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	LTTNG_ASSERT(node);
	channel_info = caa_container_of(node, struct channel_info, channels_ht_node);

	/* Retrieve the channel's last sample, if it exists. */
	cds_lfht_lookup(state->channel_state_ht,
			hash_channel_key(channel_key),
			match_channel_state_sample,
			channel_key,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node) {
		last_sample =
			caa_container_of(node, struct channel_state_sample, channel_state_ht_node);
	} else {
		/* Nothing to evaluate, no sample was ever taken. Normal exit */
		DBG("No channel sample associated with newly subscribed-to condition");
		ret = 0;
		goto end;
	}

	ret = evaluate_buffer_condition(
		condition, evaluation, state, nullptr, last_sample, channel_info);
	if (ret) {
		WARN("Fatal error occurred while evaluating a newly subscribed-to condition");
		goto end;
	}

	*session_uid = channel_info->session_info->uid;
	*session_gid = channel_info->session_info->gid;
end:
	return ret;
}

static const char *get_condition_session_name(const struct lttng_condition *condition)
{
	const char *session_name = nullptr;
	enum lttng_condition_status status;

	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		status = lttng_condition_buffer_usage_get_session_name(condition, &session_name);
		break;
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		status = lttng_condition_session_consumed_size_get_session_name(condition,
										&session_name);
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		status =
			lttng_condition_session_rotation_get_session_name(condition, &session_name);
		break;
	default:
		abort();
	}
	if (status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to retrieve session rotation condition's session name");
		goto end;
	}
end:
	return session_name;
}

static bool evaluate_session_rotation_ongoing_condition(const struct lttng_condition *condition
							__attribute__((unused)),
							const struct session_state_sample *sample)
{
	return sample->rotation.ongoing;
}

static bool evaluate_session_consumed_size_condition(const struct lttng_condition *condition,
						     const struct session_state_sample *sample)
{
	uint64_t threshold;
	const struct lttng_condition_session_consumed_size *size_condition =
		lttng::utils::container_of(condition,
					   &lttng_condition_session_consumed_size::parent);

	threshold = size_condition->consumed_threshold_bytes.value;
	DBG("Session consumed size condition being evaluated: threshold = %" PRIu64
	    ", current size = %" PRIu64,
	    threshold,
	    sample->consumed_data_size);
	return sample->consumed_data_size >= threshold;
}

/*
 * `new_state` can be NULL to indicate that we are not evaluating a
 * state transition. A client subscribed or a trigger was registered and
 * we wish to perform an initial evaluation.
 */
static int evaluate_session_condition(const struct lttng_condition *condition,
				      const struct session_info *session_info,
				      const struct session_state_sample *new_state,
				      struct lttng_evaluation **evaluation)
{
	int ret;
	bool previous_result, newest_result;

	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
		if (new_state) {
			previous_result = evaluate_session_rotation_ongoing_condition(
				condition, &session_info->last_state_sample);
			newest_result =
				evaluate_session_rotation_ongoing_condition(condition, new_state);
		} else {
			previous_result = false;
			newest_result = evaluate_session_rotation_ongoing_condition(
				condition, &session_info->last_state_sample);
		}
		break;
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		if (new_state) {
			previous_result = evaluate_session_consumed_size_condition(
				condition, &session_info->last_state_sample);
			newest_result =
				evaluate_session_consumed_size_condition(condition, new_state);
		} else {
			previous_result = false;
			newest_result = evaluate_session_consumed_size_condition(
				condition, &session_info->last_state_sample);
		}
		break;
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
		/*
		 * Note that LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED is
		 * evaluated differently to only consider state transitions without regard for the
		 * initial state. This is a deliberate choice as it is unlikely that a user would
		 * expect an action to occur for a rotation that occurred long before the trigger or
		 * subscription occurred.
		 */
		if (!new_state) {
			ret = 0;
			goto end;
		}

		previous_result = !session_info->last_state_sample.rotation.ongoing;
		newest_result = !new_state->rotation.ongoing;
		break;
	default:
		ret = 0;
		goto end;
	}

	if (!newest_result || (previous_result == newest_result)) {
		/* Not a state transition, evaluate to false. */
		ret = 0;
		goto end;
	}

	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
	{
		const auto rotation_id = new_state ? new_state->rotation.id :
						     session_info->last_state_sample.rotation.id;

		*evaluation = lttng_evaluation_session_rotation_ongoing_create(rotation_id);
		break;
	}
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
	{
		const auto& sample = new_state ? *new_state : session_info->last_state_sample;
		const auto rotation_id = sample.rotation.id;

		/* Callee acquires a reference to location. */
		*evaluation = lttng_evaluation_session_rotation_completed_create(
			rotation_id, sample.rotation.location);
		break;
	}
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
	{
		const auto latest_session_consumed_total = new_state ?
			new_state->consumed_data_size :
			session_info->last_state_sample.consumed_data_size;

		*evaluation = lttng_evaluation_session_consumed_size_create(
			latest_session_consumed_total);
		break;
	}
	default:
		abort();
	}

	if (!*evaluation) {
		/* Fatal error. */
		ERR("Failed to create session condition evaluation: session name = `%s`",
		    session_info->name);
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	return ret;
}

static int evaluate_condition_for_client(const struct lttng_trigger *trigger,
					 const struct lttng_condition *condition,
					 struct notification_client *client,
					 struct notification_thread_state *state)
{
	int ret;
	struct lttng_evaluation *evaluation = nullptr;
	struct notification_client_list client_list = {
		.lock = PTHREAD_MUTEX_INITIALIZER,
		.ref = {},
		.condition = nullptr,
		.triggers_list = {},
		.clients_list = {},
		.notification_trigger_clients_ht = nullptr,
		.notification_trigger_clients_ht_node = {},
		.rcu_node = {},
	};
	struct notification_client_list_element client_list_element = {};
	uid_t object_uid = 0;
	gid_t object_gid = 0;

	LTTNG_ASSERT(trigger);
	LTTNG_ASSERT(condition);
	LTTNG_ASSERT(client);
	LTTNG_ASSERT(state);

	switch (get_condition_binding_object(condition)) {
	case LTTNG_OBJECT_TYPE_SESSION:
	{
		/* Find the session associated with the condition. */
		const auto *session_name = get_condition_session_name(condition);
		auto session_info = get_session_info_by_name(state, session_name);
		if (!session_info) {
			/* Not an error, the session doesn't exist yet. */
			DBG("Session not found while evaluating session condition for client: session name = `%s`",
			    session_name);
			ret = 0;
			goto end;
		}

		object_uid = session_info->uid;
		object_gid = session_info->gid;

		ret = evaluate_session_condition(condition, session_info, nullptr, &evaluation);
		session_info_put(session_info);
		break;
	}
	case LTTNG_OBJECT_TYPE_CHANNEL:
		ret = evaluate_channel_condition_for_client(
			condition, state, &evaluation, &object_uid, &object_gid);
		break;
	case LTTNG_OBJECT_TYPE_NONE:
		DBG("Newly subscribed-to condition not bound to object, nothing to evaluate");
		ret = 0;
		goto end;
	case LTTNG_OBJECT_TYPE_UNKNOWN:
	default:
		ret = -1;
		goto end;
	}
	if (ret) {
		/* Fatal error. */
		goto end;
	}
	if (!evaluation) {
		/* Evaluation yielded nothing. Normal exit. */
		DBG("Newly subscribed-to condition evaluated to false, nothing to report to client");
		ret = 0;
		goto end;
	}

	/*
	 * Create a temporary client list with the client currently
	 * subscribing.
	 */
	cds_lfht_node_init(&client_list.notification_trigger_clients_ht_node);
	CDS_INIT_LIST_HEAD(&client_list.clients_list);

	CDS_INIT_LIST_HEAD(&client_list_element.node);
	client_list_element.client = client;
	cds_list_add(&client_list_element.node, &client_list.clients_list);

	/* Send evaluation result to the newly-subscribed client. */
	DBG("Newly subscribed-to condition evaluated to true, notifying client");
	ret = send_evaluation_to_clients(
		trigger, evaluation, &client_list, state, object_uid, object_gid);

end:
	return ret;
}

static int notification_thread_client_subscribe(struct notification_client *client,
						struct lttng_condition *condition,
						struct notification_thread_state *state,
						enum lttng_notification_channel_status *_status)
{
	int ret = 0;
	struct notification_client_list *client_list = nullptr;
	struct lttng_condition_list_element *condition_list_element = nullptr;
	struct notification_client_list_element *client_list_element = nullptr;
	struct lttng_trigger_ht_element *trigger_ht_element;
	enum lttng_notification_channel_status status = LTTNG_NOTIFICATION_CHANNEL_STATUS_OK;

	/*
	 * Ensure that the client has not already subscribed to this condition
	 * before.
	 */
	cds_list_for_each_entry (condition_list_element, &client->condition_list, node) {
		if (lttng_condition_is_equal(condition_list_element->condition, condition)) {
			status = LTTNG_NOTIFICATION_CHANNEL_STATUS_ALREADY_SUBSCRIBED;
			goto end;
		}
	}

	condition_list_element = zmalloc<lttng_condition_list_element>();
	if (!condition_list_element) {
		ret = -1;
		goto error;
	}
	client_list_element = zmalloc<notification_client_list_element>();
	if (!client_list_element) {
		ret = -1;
		goto error;
	}

	/*
	 * Add the newly-subscribed condition to the client's subscription list.
	 */
	CDS_INIT_LIST_HEAD(&condition_list_element->node);
	condition_list_element->condition = condition;
	condition = nullptr;
	cds_list_add(&condition_list_element->node, &client->condition_list);

	client_list = get_client_list_from_condition(state, condition_list_element->condition);
	if (!client_list) {
		/*
		 * No notification-emiting trigger registered with this
		 * condition. We don't evaluate the condition right away
		 * since this trigger is not registered yet.
		 */
		free(client_list_element);
		goto end;
	}

	/*
	 * The condition to which the client just subscribed is evaluated
	 * at this point so that conditions that are already TRUE result
	 * in a notification being sent out.
	 *
	 * Note the iteration on all triggers which share an identical
	 * `condition` than the one to which the client is registering. This is
	 * done to ensure that the client receives a distinct notification for
	 * all triggers that have a `notify` action that have this condition.
	 */
	pthread_mutex_lock(&client_list->lock);
	cds_list_for_each_entry (
		trigger_ht_element, &client_list->triggers_list, client_list_trigger_node) {
		if (evaluate_condition_for_client(trigger_ht_element->trigger,
						  condition_list_element->condition,
						  client,
						  state)) {
			WARN("Evaluation of a condition on client subscription failed, aborting.");
			ret = -1;
			free(client_list_element);
			pthread_mutex_unlock(&client_list->lock);
			goto end;
		}
	}
	pthread_mutex_unlock(&client_list->lock);

	/*
	 * Add the client to the list of clients interested in a given trigger
	 * if a "notification" trigger with a corresponding condition was
	 * added prior.
	 */
	client_list_element->client = client;
	CDS_INIT_LIST_HEAD(&client_list_element->node);

	pthread_mutex_lock(&client_list->lock);
	cds_list_add(&client_list_element->node, &client_list->clients_list);
	pthread_mutex_unlock(&client_list->lock);
end:
	if (_status) {
		*_status = status;
	}
	if (client_list) {
		notification_client_list_put(client_list);
	}
	lttng_condition_destroy(condition);
	return ret;
error:
	free(condition_list_element);
	free(client_list_element);
	lttng_condition_destroy(condition);
	return ret;
}

static int notification_thread_client_unsubscribe(struct notification_client *client,
						  struct lttng_condition *condition,
						  struct notification_thread_state *state,
						  enum lttng_notification_channel_status *_status)
{
	struct notification_client_list *client_list;
	struct lttng_condition_list_element *condition_list_element, *condition_tmp;
	struct notification_client_list_element *client_list_element, *client_tmp;
	bool condition_found = false;
	enum lttng_notification_channel_status status = LTTNG_NOTIFICATION_CHANNEL_STATUS_OK;

	/* Remove the condition from the client's condition list. */
	cds_list_for_each_entry_safe (
		condition_list_element, condition_tmp, &client->condition_list, node) {
		if (!lttng_condition_is_equal(condition_list_element->condition, condition)) {
			continue;
		}

		cds_list_del(&condition_list_element->node);
		/*
		 * The caller may be iterating on the client's conditions to
		 * tear down a client's connection. In this case, the condition
		 * will be destroyed at the end.
		 */
		if (condition != condition_list_element->condition) {
			lttng_condition_destroy(condition_list_element->condition);
		}
		free(condition_list_element);
		condition_found = true;
		break;
	}

	if (!condition_found) {
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_UNKNOWN_CONDITION;
		goto end;
	}

	/*
	 * Remove the client from the list of clients interested the trigger
	 * matching the condition.
	 */
	client_list = get_client_list_from_condition(state, condition);
	if (!client_list) {
		goto end;
	}

	pthread_mutex_lock(&client_list->lock);
	cds_list_for_each_entry_safe (
		client_list_element, client_tmp, &client_list->clients_list, node) {
		if (client_list_element->client->id != client->id) {
			continue;
		}
		cds_list_del(&client_list_element->node);
		free(client_list_element);
		break;
	}
	pthread_mutex_unlock(&client_list->lock);
	notification_client_list_put(client_list);
	client_list = nullptr;
end:
	lttng_condition_destroy(condition);
	if (_status) {
		*_status = status;
	}
	return 0;
}

static void free_notification_client_rcu(struct rcu_head *node)
{
	free(lttng::utils::container_of(node, &notification_client::rcu_node));
}

static void notification_client_destroy(struct notification_client *client)
{
	if (!client) {
		return;
	}

	/*
	 * The client object is not reachable by other threads, no need to lock
	 * the client here.
	 */
	if (client->socket >= 0) {
		(void) lttcomm_close_unix_sock(client->socket);
		client->socket = -1;
	}
	client->communication.active = false;
	lttng_payload_reset(&client->communication.inbound.payload);
	lttng_payload_reset(&client->communication.outbound.payload);
	pthread_mutex_destroy(&client->lock);
	call_rcu(&client->rcu_node, free_notification_client_rcu);
}

/*
 * Call with rcu_read_lock held (and hold for the lifetime of the returned
 * client pointer).
 */
static struct notification_client *get_client_from_socket(int socket,
							  struct notification_thread_state *state)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct notification_client *client = nullptr;

	ASSERT_RCU_READ_LOCKED();

	cds_lfht_lookup(state->client_socket_ht,
			hash_client_socket(socket),
			match_client_socket,
			(void *) (unsigned long) socket,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		goto end;
	}

	client = caa_container_of(node, struct notification_client, client_socket_ht_node);
end:
	return client;
}

/*
 * Call with rcu_read_lock held (and hold for the lifetime of the returned
 * client pointer).
 */
static struct notification_client *get_client_from_id(notification_client_id id,
						      struct notification_thread_state *state)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct notification_client *client = nullptr;

	ASSERT_RCU_READ_LOCKED();

	cds_lfht_lookup(state->client_id_ht, hash_client_id(id), match_client_id, &id, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		goto end;
	}

	client = caa_container_of(node, struct notification_client, client_id_ht_node);
end:
	return client;
}

static bool buffer_usage_condition_applies_to_channel(const struct lttng_condition *condition,
						      const struct channel_info *channel_info)
{
	enum lttng_condition_status status;
	enum lttng_domain_type condition_domain;
	const char *condition_session_name = nullptr;
	const char *condition_channel_name = nullptr;

	status = lttng_condition_buffer_usage_get_domain_type(condition, &condition_domain);
	LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);
	if (channel_info->key.domain != condition_domain) {
		goto fail;
	}

	status = lttng_condition_buffer_usage_get_session_name(condition, &condition_session_name);
	LTTNG_ASSERT((status == LTTNG_CONDITION_STATUS_OK) && condition_session_name);

	status = lttng_condition_buffer_usage_get_channel_name(condition, &condition_channel_name);
	LTTNG_ASSERT((status == LTTNG_CONDITION_STATUS_OK) && condition_channel_name);

	if (strcmp(channel_info->session_info->name, condition_session_name) != 0) {
		goto fail;
	}
	if (strcmp(channel_info->name, condition_channel_name) != 0) {
		goto fail;
	}

	return true;
fail:
	return false;
}

static bool trigger_applies_to_channel(const struct lttng_trigger *trigger,
				       const struct channel_info *channel_info)
{
	const struct lttng_condition *condition;
	bool trigger_applies;

	condition = lttng_trigger_get_const_condition(trigger);
	if (!condition) {
		goto fail;
	}

	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		trigger_applies =
			buffer_usage_condition_applies_to_channel(condition, channel_info);
		break;
	default:
		goto fail;
	}

	return trigger_applies;
fail:
	return false;
}

/* Must be called with RCU read lock held. */
static struct lttng_session_trigger_list *
get_session_trigger_list(struct notification_thread_state *state, const char *session_name)
{
	struct lttng_session_trigger_list *list = nullptr;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	ASSERT_RCU_READ_LOCKED();

	cds_lfht_lookup(state->session_triggers_ht,
			hash_key_str(session_name, lttng_ht_seed),
			match_session_trigger_list,
			session_name,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		/*
		 * Not an error, the list of triggers applying to that session
		 * will be initialized when the session is created.
		 */
		DBG("No trigger list found for session \"%s\" as it is not yet known to the notification system",
		    session_name);
		goto end;
	}

	list = caa_container_of(node, struct lttng_session_trigger_list, session_triggers_ht_node);
end:
	return list;
}

/*
 * Allocate an empty lttng_session_trigger_list for the session named
 * 'session_name'.
 */
static struct lttng_session_trigger_list *
lttng_session_trigger_list_create(const char *session_name, struct cds_lfht *session_triggers_ht)
{
	struct lttng_session_trigger_list *list = nullptr;
	char *session_name_copy = strdup(session_name);

	if (!session_name_copy) {
		PERROR("Failed to allocate session name while building trigger list");
		goto end;
	}

	list = zmalloc<lttng_session_trigger_list>();
	if (!list) {
		PERROR("Failed to allocate session trigger list while building trigger list");
		goto end;
	}

	list->session_name = session_name_copy;
	CDS_INIT_LIST_HEAD(&list->list);
	cds_lfht_node_init(&list->session_triggers_ht_node);
	list->session_triggers_ht = session_triggers_ht;

	/* Publish the list through the session_triggers_ht. */
	{
		lttng::urcu::read_lock_guard read_lock;
		cds_lfht_add(session_triggers_ht,
			     hash_key_str(session_name, lttng_ht_seed),
			     &list->session_triggers_ht_node);
	}
end:
	return list;
}

static void free_session_trigger_list_rcu(struct rcu_head *node)
{
	struct lttng_session_trigger_list *list =
		caa_container_of(node, struct lttng_session_trigger_list, rcu_node);

	free(list->session_name);
	free(list);
}

static void lttng_session_trigger_list_destroy(struct lttng_session_trigger_list *list)
{
	struct lttng_trigger_list_element *trigger_list_element, *tmp;

	/* Empty the list element by element, and then free the list itself. */
	cds_list_for_each_entry_safe (trigger_list_element, tmp, &list->list, node) {
		cds_list_del(&trigger_list_element->node);
		free(trigger_list_element);
	}
	lttng::urcu::read_lock_guard read_lock;
	/* Unpublish the list from the session_triggers_ht. */
	cds_lfht_del(list->session_triggers_ht, &list->session_triggers_ht_node);
	call_rcu(&list->rcu_node, free_session_trigger_list_rcu);
}

static int lttng_session_trigger_list_add(struct lttng_session_trigger_list *list,
					  struct lttng_trigger *trigger)
{
	int ret = 0;
	struct lttng_trigger_list_element *new_element = zmalloc<lttng_trigger_list_element>();

	if (!new_element) {
		ret = -1;
		goto end;
	}
	CDS_INIT_LIST_HEAD(&new_element->node);
	new_element->trigger = trigger;
	cds_list_add(&new_element->node, &list->list);
end:
	return ret;
}

static bool trigger_applies_to_session(const struct lttng_trigger *trigger,
				       const char *session_name)
{
	bool applies = false;
	const struct lttng_condition *condition;

	condition = lttng_trigger_get_const_condition(trigger);
	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_ONGOING:
	case LTTNG_CONDITION_TYPE_SESSION_ROTATION_COMPLETED:
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
	{
		const char *condition_session_name;

		condition_session_name = get_condition_session_name(condition);
		LTTNG_ASSERT(condition_session_name);
		applies = !strcmp(condition_session_name, session_name);
		break;
	}
	default:
		goto end;
	}
end:
	return applies;
}

/*
 * Allocate and initialize an lttng_session_trigger_list which contains
 * all triggers that apply to the session named 'session_name'.
 */
static struct lttng_session_trigger_list *
lttng_session_trigger_list_build(const struct notification_thread_state *state,
				 const char *session_name)
{
	int trigger_count = 0;
	struct lttng_session_trigger_list *session_trigger_list = nullptr;
	struct lttng_trigger_ht_element *trigger_ht_element = nullptr;
	struct cds_lfht_iter iter;

	session_trigger_list =
		lttng_session_trigger_list_create(session_name, state->session_triggers_ht);

	{
		/* Add all triggers applying to the session named 'session_name'. */
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (state->triggers_ht, &iter, trigger_ht_element, node) {
			int ret;

			if (!trigger_applies_to_session(trigger_ht_element->trigger,
							session_name)) {
				continue;
			}

			ret = lttng_session_trigger_list_add(session_trigger_list,
							     trigger_ht_element->trigger);
			if (ret) {
				goto error;
			}

			trigger_count++;
		}
	}

	DBG("Found %i triggers that apply to newly created session", trigger_count);
	return session_trigger_list;
error:
	lttng_session_trigger_list_destroy(session_trigger_list);
	return nullptr;
}

static struct session_info *create_and_publish_session_info(struct notification_thread_state *state,
							    uint64_t id,
							    const char *name,
							    uid_t uid,
							    gid_t gid)
{
	struct session_info *session = nullptr;
	struct lttng_session_trigger_list *trigger_list;

	lttng::urcu::read_lock_guard read_lock;
	trigger_list = lttng_session_trigger_list_build(state, name);
	if (!trigger_list) {
		goto error;
	}

	session = session_info_create(id, name, uid, gid, trigger_list, state->sessions_ht);
	if (!session) {
		ERR("Failed to allocation session info for session \"%s\" (uid = %i, gid = %i)",
		    name,
		    uid,
		    gid);
		lttng_session_trigger_list_destroy(trigger_list);
		goto error;
	}

	/* Transferred ownership to the new session. */
	trigger_list = nullptr;

	if (cds_lfht_add_unique(state->sessions_ht,
				hash_session_info(session),
				match_session_info,
				&id,
				&session->sessions_ht_node) != &session->sessions_ht_node) {
		ERR("Duplicate session found: name = `%s`, id = %" PRIu64, name, id);
		goto error;
	}

	return session;
error:
	session_info_put(session);
	return nullptr;
}

static int handle_notification_thread_command_add_channel(struct notification_thread_state *state,
							  uint64_t session_id,
							  const char *channel_name,
							  enum lttng_domain_type channel_domain,
							  uint64_t channel_key_int,
							  uint64_t channel_capacity,
							  enum lttng_error_code *cmd_result)
{
	struct cds_list_head trigger_list;
	struct channel_info *new_channel_info = nullptr;
	struct channel_key channel_key = {
		.key = channel_key_int,
		.domain = channel_domain,
	};
	struct lttng_channel_trigger_list *channel_trigger_list = nullptr;
	struct lttng_trigger_ht_element *trigger_ht_element = nullptr;
	int trigger_count = 0;
	struct cds_lfht_iter iter;
	struct session_info *session_info = nullptr;
	lttng::urcu::read_lock_guard read_lock;

	DBG("Adding channel: channel name = `%s`, session id = %" PRIu64 ", channel key = %" PRIu64
	    ", domain = %s",
	    channel_name,
	    session_id,
	    channel_key_int,
	    lttng_domain_type_str(channel_domain));

	CDS_INIT_LIST_HEAD(&trigger_list);

	session_info = get_session_info_by_id(state, session_id);
	if (!session_info) {
		/* Fatal logic error. */
		ERR("Failed to find session while adding channel: session id = %" PRIu64,
		    session_id);
		goto error;
	}

	new_channel_info =
		channel_info_create(channel_name, &channel_key, channel_capacity, session_info);
	if (!new_channel_info) {
		goto error;
	}

	/* Build a list of all triggers applying to the new channel. */
	cds_lfht_for_each_entry (state->triggers_ht, &iter, trigger_ht_element, node) {
		struct lttng_trigger_list_element *new_element;

		if (!trigger_applies_to_channel(trigger_ht_element->trigger, new_channel_info)) {
			continue;
		}

		new_element = zmalloc<lttng_trigger_list_element>();
		if (!new_element) {
			goto error;
		}
		CDS_INIT_LIST_HEAD(&new_element->node);
		new_element->trigger = trigger_ht_element->trigger;
		cds_list_add(&new_element->node, &trigger_list);
		trigger_count++;
	}

	DBG("Found %i triggers that apply to newly added channel", trigger_count);
	channel_trigger_list = zmalloc<lttng_channel_trigger_list>();
	if (!channel_trigger_list) {
		goto error;
	}
	channel_trigger_list->channel_key = new_channel_info->key;
	CDS_INIT_LIST_HEAD(&channel_trigger_list->list);
	cds_lfht_node_init(&channel_trigger_list->channel_triggers_ht_node);
	cds_list_splice(&trigger_list, &channel_trigger_list->list);

	/* Add channel to the channel_ht which owns the channel_infos. */
	cds_lfht_add(state->channels_ht,
		     hash_channel_key(&new_channel_info->key),
		     &new_channel_info->channels_ht_node);
	/*
	 * Add the list of triggers associated with this channel to the
	 * channel_triggers_ht.
	 */
	cds_lfht_add(state->channel_triggers_ht,
		     hash_channel_key(&new_channel_info->key),
		     &channel_trigger_list->channel_triggers_ht_node);
	session_info_put(session_info);
	*cmd_result = LTTNG_OK;
	return 0;
error:
	channel_info_destroy(new_channel_info);
	session_info_put(session_info);
	return 1;
}

static int handle_notification_thread_command_add_session(struct notification_thread_state *state,
							  uint64_t session_id,
							  const char *session_name,
							  uid_t session_uid,
							  gid_t session_gid,
							  enum lttng_error_code *cmd_result)
{
	int ret;

	DBG("Adding session: session name = `%s`, session id = %" PRIu64
	    ", session uid = %d, session gid = %d",
	    session_name,
	    session_id,
	    session_uid,
	    session_gid);

	auto session = create_and_publish_session_info(
		state, session_id, session_name, session_uid, session_gid);
	if (!session) {
		PERROR("Failed to add session: session name = `%s`, session id = %" PRIu64
		       ", session uid = %d, session gid = %d",
		       session_name,
		       session_id,
		       session_uid,
		       session_gid);
		ret = -1;
		*cmd_result = LTTNG_ERR_NOMEM;
		goto end;
	}

	/*
	 * Note that the reference to `session` is not released; this reference is
	 * the "global" reference that is used to allow look-ups. This reference will
	 * only be released when the session is removed. See
	 * handle_notification_thread_command_remove_session.
	 */
	ret = 0;
	*cmd_result = LTTNG_OK;
end:
	return ret;
}

static int
handle_notification_thread_command_remove_session(struct notification_thread_state *state,
						  uint64_t session_id,
						  enum lttng_error_code *cmd_result)
{
	int ret;

	DBG("Removing session: session id = %" PRIu64, session_id);

	auto session = get_session_info_by_id(state, session_id);
	if (!session) {
		ERR("Failed to remove session: session id = %" PRIu64, session_id);
		ret = -1;
		*cmd_result = LTTNG_ERR_NO_SESSION;
		goto end;
	}

	/* Release the reference returned by the look-up, and then release the global reference. */
	session_info_put(session);
	session_info_put(session);
	ret = 0;
	*cmd_result = LTTNG_OK;
end:
	return ret;
}

static void free_channel_trigger_list_rcu(struct rcu_head *node)
{
	free(caa_container_of(node, struct lttng_channel_trigger_list, rcu_node));
}

static void free_channel_state_sample_rcu(struct rcu_head *node)
{
	free(caa_container_of(node, struct channel_state_sample, rcu_node));
}

static int
handle_notification_thread_command_remove_channel(struct notification_thread_state *state,
						  uint64_t channel_key,
						  enum lttng_domain_type domain,
						  enum lttng_error_code *cmd_result)
{
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct lttng_channel_trigger_list *trigger_list;
	struct lttng_trigger_list_element *trigger_list_element, *tmp;
	struct channel_key key = { .key = channel_key, .domain = domain };
	struct channel_info *channel_info;

	DBG("Removing channel key = %" PRIu64 " in %s domain",
	    channel_key,
	    lttng_domain_type_str(domain));

	lttng::urcu::read_lock_guard read_lock;

	cds_lfht_lookup(state->channel_triggers_ht,
			hash_channel_key(&key),
			match_channel_trigger_list,
			&key,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	/*
	 * There is a severe internal error if we are being asked to remove a
	 * channel that doesn't exist.
	 */
	if (!node) {
		ERR("Channel being removed is unknown to the notification thread");
		goto end;
	}

	/* Free the list of triggers associated with this channel. */
	trigger_list =
		caa_container_of(node, struct lttng_channel_trigger_list, channel_triggers_ht_node);
	cds_list_for_each_entry_safe (trigger_list_element, tmp, &trigger_list->list, node) {
		cds_list_del(&trigger_list_element->node);
		free(trigger_list_element);
	}
	cds_lfht_del(state->channel_triggers_ht, node);
	call_rcu(&trigger_list->rcu_node, free_channel_trigger_list_rcu);

	/* Free sampled channel state. */
	cds_lfht_lookup(state->channel_state_ht,
			hash_channel_key(&key),
			match_channel_state_sample,
			&key,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	/*
	 * This is expected to be NULL if the channel is destroyed before we
	 * received a sample.
	 */
	if (node) {
		struct channel_state_sample *sample =
			caa_container_of(node, struct channel_state_sample, channel_state_ht_node);

		cds_lfht_del(state->channel_state_ht, node);
		call_rcu(&sample->rcu_node, free_channel_state_sample_rcu);
	}

	/* Remove the channel from the channels_ht and free it. */
	cds_lfht_lookup(
		state->channels_ht, hash_channel_key(&key), match_channel_info, &key, &iter);
	node = cds_lfht_iter_get_node(&iter);
	LTTNG_ASSERT(node);
	channel_info = caa_container_of(node, struct channel_info, channels_ht_node);
	cds_lfht_del(state->channels_ht, node);
	channel_info_destroy(channel_info);
end:
	*cmd_result = LTTNG_OK;
	return 0;
}

static int
handle_notification_thread_command_session_rotation(struct notification_thread_state *state,
						    enum notification_thread_command_type cmd_type,
						    uint64_t session_id,
						    uint64_t trace_archive_chunk_id,
						    struct lttng_trace_archive_location *location,
						    enum lttng_error_code *_cmd_result)
{
	int ret = 0;
	enum lttng_error_code cmd_result = LTTNG_OK;
	struct lttng_session_trigger_list *trigger_list;
	struct lttng_trigger_list_element *trigger_list_element;
	struct session_info *session_info;
	struct lttng_credentials session_creds;
	struct session_state_sample new_session_state;

	lttng::urcu::read_lock_guard read_lock;

	session_info = get_session_info_by_id(state, session_id);
	if (!session_info) {
		/* Fatal logic error. */
		ERR("Failed to find session while handling rotation state change: session id = %" PRIu64,
		    session_id);
		ret = -1;
		cmd_result = LTTNG_ERR_FATAL;
		goto end;
	}

	new_session_state = session_info->last_state_sample;
	if (location) {
		lttng_trace_archive_location_get(location);
		new_session_state.rotation.location = location;
	} else {
		new_session_state.rotation.location = nullptr;
	}

	session_creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(session_info->uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE(session_info->gid),
	};

	new_session_state.rotation.ongoing = cmd_type ==
		NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_ONGOING;
	new_session_state.rotation.id = trace_archive_chunk_id;

	trigger_list = get_session_trigger_list(state, session_info->name);
	LTTNG_ASSERT(trigger_list);

	cds_list_for_each_entry (trigger_list_element, &trigger_list->list, node) {
		const struct lttng_condition *condition;
		struct lttng_trigger *trigger;
		struct notification_client_list *client_list;
		struct lttng_evaluation *evaluation = nullptr;
		enum action_executor_status executor_status;

		trigger = trigger_list_element->trigger;
		condition = lttng_trigger_get_const_condition(trigger);
		LTTNG_ASSERT(condition);

		ret = evaluate_session_condition(
			condition, session_info, &new_session_state, &evaluation);
		if (ret) {
			ret = -1;
			cmd_result = LTTNG_ERR_NOMEM;
			goto end;
		}

		if (!evaluation) {
			continue;
		}

		/*
		 * Ownership of `evaluation` transferred to the action executor
		 * no matter the result. The callee acquires a reference to the
		 * client list: we can release our own.
		 */
		client_list = get_client_list_from_condition(state, condition);
		executor_status = action_executor_enqueue_trigger(
			state->executor, trigger, evaluation, &session_creds, client_list);
		notification_client_list_put(client_list);
		evaluation = nullptr;
		switch (executor_status) {
		case ACTION_EXECUTOR_STATUS_OK:
			break;
		case ACTION_EXECUTOR_STATUS_ERROR:
		case ACTION_EXECUTOR_STATUS_INVALID:
			/*
			 * TODO Add trigger identification (name/id) when
			 * it is added to the API.
			 */
			ERR("Fatal error occurred while enqueuing action associated with session rotation trigger");
			ret = -1;
			goto end;
		case ACTION_EXECUTOR_STATUS_OVERFLOW:
			/*
			 * TODO Add trigger identification (name/id) when
			 * it is added to the API.
			 *
			 * Not a fatal error.
			 */
			WARN("No space left when enqueuing action associated with session rotation trigger");
			ret = 0;
			goto end;
		default:
			abort();
		}
	}

end:
	if (session_info) {
		/* Ownership of new_session_state::location is transferred. */
		lttng_trace_archive_location_put(session_info->last_state_sample.rotation.location);
		session_info->last_state_sample = new_session_state;
	}

	session_info_put(session_info);
	*_cmd_result = cmd_result;
	return ret;
}

static int
handle_notification_thread_command_add_tracer_event_source(struct notification_thread_state *state,
							   int tracer_event_source_fd,
							   enum lttng_domain_type domain_type,
							   enum lttng_error_code *_cmd_result)
{
	int ret = 0;
	enum lttng_error_code cmd_result = LTTNG_OK;
	struct notification_event_tracer_event_source_element *element = nullptr;

	element = zmalloc<notification_event_tracer_event_source_element>();
	if (!element) {
		cmd_result = LTTNG_ERR_NOMEM;
		ret = -1;
		goto end;
	}

	element->fd = tracer_event_source_fd;
	element->domain = domain_type;

	cds_list_add(&element->node, &state->tracer_event_sources_list);

	DBG3("Adding tracer event source fd to poll set: tracer_event_source_fd = %d, domain = '%s'",
	     tracer_event_source_fd,
	     lttng_domain_type_str(domain_type));

	/* Adding the read side pipe to the event poll. */
	ret = lttng_poll_add(&state->events, tracer_event_source_fd, LPOLLPRI | LPOLLIN);
	if (ret < 0) {
		ERR("Failed to add tracer event source to poll set: tracer_event_source_fd = %d, domain = '%s'",
		    tracer_event_source_fd,
		    lttng_domain_type_str(element->domain));
		cds_list_del(&element->node);
		free(element);
		goto end;
	}

	element->is_fd_in_poll_set = true;

end:
	*_cmd_result = cmd_result;
	return ret;
}

static int drain_event_notifier_notification_pipe(struct notification_thread_state *state,
						  int pipe,
						  enum lttng_domain_type domain)
{
	struct lttng_poll_event events = {};
	int ret;

	ret = lttng_poll_create(&events, 1, LTTNG_CLOEXEC);
	if (ret < 0) {
		ERR("Error creating lttng_poll_event");
		goto end;
	}

	ret = lttng_poll_add(&events, pipe, LPOLLIN);
	if (ret < 0) {
		ERR("Error adding fd event notifier notification pipe to lttng_poll_event: fd = %d",
		    pipe);
		goto end;
	}

	while (true) {
		/*
		 * Continue to consume notifications as long as there are new
		 * ones coming in. The tracer has been asked to stop producing
		 * them.
		 *
		 * LPOLLIN is explicitly checked since LPOLLHUP is implicitly
		 * monitored (on Linux, at least) and will be returned when
		 * the pipe is closed but empty.
		 */
		ret = lttng_poll_wait_interruptible(&events, 0);
		if (ret == 0 || (LTTNG_POLL_GETEV(&events, 0) & LPOLLIN) == 0) {
			/* No more notification to be read on this pipe. */
			ret = 0;
			goto end;
		} else if (ret < 0) {
			PERROR("Failed on lttng_poll_wait_interruptible() call");
			ret = -1;
			goto end;
		}

		ret = handle_one_event_notifier_notification(state, pipe, domain);
		if (ret) {
			ERR("Error consuming an event notifier notification from pipe: fd = %d",
			    pipe);
		}
	}
end:
	lttng_poll_clean(&events);
	return ret;
}

static struct notification_event_tracer_event_source_element *
find_tracer_event_source_element(struct notification_thread_state *state,
				 int tracer_event_source_fd)
{
	struct notification_event_tracer_event_source_element *source_element;

	cds_list_for_each_entry (source_element, &state->tracer_event_sources_list, node) {
		if (source_element->fd == tracer_event_source_fd) {
			goto end;
		}
	}

	source_element = nullptr;
end:
	return source_element;
}

static int remove_tracer_event_source_from_pollset(
	struct notification_thread_state *state,
	struct notification_event_tracer_event_source_element *source_element)
{
	int ret = 0;

	LTTNG_ASSERT(source_element->is_fd_in_poll_set);

	DBG3("Removing tracer event source from poll set: tracer_event_source_fd = %d, domain = '%s'",
	     source_element->fd,
	     lttng_domain_type_str(source_element->domain));

	/* Removing the fd from the event poll set. */
	ret = lttng_poll_del(&state->events, source_element->fd);
	if (ret < 0) {
		ERR("Failed to remove tracer event source from poll set: tracer_event_source_fd = %d, domain = '%s'",
		    source_element->fd,
		    lttng_domain_type_str(source_element->domain));
		ret = -1;
		goto end;
	}

	source_element->is_fd_in_poll_set = false;

	/*
	 * Force the notification thread to restart the poll() loop to ensure
	 * that any events from the removed fd are removed.
	 */
	state->restart_poll = true;

	ret = drain_event_notifier_notification_pipe(
		state, source_element->fd, source_element->domain);
	if (ret) {
		ERR("Error draining event notifier notification: tracer_event_source_fd = %d, domain = %s",
		    source_element->fd,
		    lttng_domain_type_str(source_element->domain));
		ret = -1;
		goto end;
	}

end:
	return ret;
}

int handle_notification_thread_tracer_event_source_died(struct notification_thread_state *state,
							int tracer_event_source_fd)
{
	int ret = 0;
	struct notification_event_tracer_event_source_element *source_element;

	source_element = find_tracer_event_source_element(state, tracer_event_source_fd);

	LTTNG_ASSERT(source_element);

	ret = remove_tracer_event_source_from_pollset(state, source_element);
	if (ret) {
		ERR("Failed to remove dead tracer event source from poll set");
	}

	return ret;
}

static int handle_notification_thread_command_remove_tracer_event_source(
	struct notification_thread_state *state,
	int tracer_event_source_fd,
	enum lttng_error_code *_cmd_result)
{
	int ret = 0;
	enum lttng_error_code cmd_result = LTTNG_OK;
	struct notification_event_tracer_event_source_element *source_element = nullptr;

	source_element = find_tracer_event_source_element(state, tracer_event_source_fd);

	LTTNG_ASSERT(source_element);

	/* Remove the tracer source from the list. */
	cds_list_del(&source_element->node);

	if (!source_element->is_fd_in_poll_set) {
		/* Skip the poll set removal. */
		goto end;
	}

	ret = remove_tracer_event_source_from_pollset(state, source_element);
	if (ret) {
		ERR("Failed to remove tracer event source from poll set");
		cmd_result = LTTNG_ERR_FATAL;
	}

end:
	free(source_element);
	*_cmd_result = cmd_result;
	return ret;
}

static int
handle_notification_thread_command_list_triggers(struct notification_thread_handle *handle
						 __attribute__((unused)),
						 struct notification_thread_state *state,
						 uid_t client_uid,
						 struct lttng_triggers **triggers,
						 enum lttng_error_code *_cmd_result)
{
	int ret = 0;
	enum lttng_error_code cmd_result = LTTNG_OK;
	struct cds_lfht_iter iter;
	struct lttng_trigger_ht_element *trigger_ht_element;
	struct lttng_triggers *local_triggers = nullptr;
	const struct lttng_credentials *creds;

	lttng::urcu::read_lock_guard read_lock;

	local_triggers = lttng_triggers_create();
	if (!local_triggers) {
		/* Not a fatal error. */
		cmd_result = LTTNG_ERR_NOMEM;
		goto end;
	}

	cds_lfht_for_each_entry (state->triggers_ht, &iter, trigger_ht_element, node) {
		/*
		 * Only return the triggers to which the client has access.
		 * The root user has visibility over all triggers.
		 */
		creds = lttng_trigger_get_credentials(trigger_ht_element->trigger);
		if (client_uid != lttng_credentials_get_uid(creds) && client_uid != 0) {
			continue;
		}

		ret = lttng_triggers_add(local_triggers, trigger_ht_element->trigger);
		if (ret < 0) {
			/* Not a fatal error. */
			ret = 0;
			cmd_result = LTTNG_ERR_NOMEM;
			goto end;
		}
	}

	/* Transferring ownership to the caller. */
	*triggers = local_triggers;
	local_triggers = nullptr;

end:
	lttng_triggers_destroy(local_triggers);
	*_cmd_result = cmd_result;
	return ret;
}

static inline void get_trigger_info_for_log(const struct lttng_trigger *trigger,
					    const char **trigger_name,
					    uid_t *trigger_owner_uid)
{
	enum lttng_trigger_status trigger_status;

	trigger_status = lttng_trigger_get_name(trigger, trigger_name);
	switch (trigger_status) {
	case LTTNG_TRIGGER_STATUS_OK:
		break;
	case LTTNG_TRIGGER_STATUS_UNSET:
		*trigger_name = "(anonymous)";
		break;
	default:
		abort();
	}

	trigger_status = lttng_trigger_get_owner_uid(trigger, trigger_owner_uid);
	LTTNG_ASSERT(trigger_status == LTTNG_TRIGGER_STATUS_OK);
}

static int handle_notification_thread_command_get_trigger(struct notification_thread_state *state,
							  const struct lttng_trigger *trigger,
							  struct lttng_trigger **registered_trigger,
							  enum lttng_error_code *_cmd_result)
{
	int ret = -1;
	struct cds_lfht_iter iter;
	struct lttng_trigger_ht_element *trigger_ht_element;
	enum lttng_error_code cmd_result = LTTNG_ERR_TRIGGER_NOT_FOUND;
	const char *trigger_name;
	uid_t trigger_owner_uid;

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (state->triggers_ht, &iter, trigger_ht_element, node) {
			if (lttng_trigger_is_equal(trigger, trigger_ht_element->trigger)) {
				/* Take one reference on the return trigger. */
				*registered_trigger = trigger_ht_element->trigger;
				lttng_trigger_get(*registered_trigger);
				ret = 0;
				cmd_result = LTTNG_OK;
				goto end;
			}
		}
	}

	/* Not a fatal error if the trigger is not found. */
	get_trigger_info_for_log(trigger, &trigger_name, &trigger_owner_uid);
	DBG("Failed to retrieve registered version of trigger: trigger name = '%s', trigger owner uid = %d",
	    trigger_name,
	    (int) trigger_owner_uid);

	ret = 0;

end:
	*_cmd_result = cmd_result;
	return ret;
}

static bool condition_is_supported(struct lttng_condition *condition)
{
	bool is_supported;

	switch (lttng_condition_get_type(condition)) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
	{
		int ret;
		enum lttng_domain_type domain;

		ret = lttng_condition_buffer_usage_get_domain_type(condition, &domain);
		LTTNG_ASSERT(ret == 0);

		if (domain != LTTNG_DOMAIN_KERNEL) {
			is_supported = true;
			goto end;
		}

		/*
		 * Older kernel tracers don't expose the API to monitor their
		 * buffers. Therefore, we reject triggers that require that
		 * mechanism to be available to be evaluated.
		 *
		 * Assume unsupported on error.
		 */
		is_supported = kernel_supports_ring_buffer_snapshot_sample_positions() == 1;
		break;
	}
	case LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES:
	{
		const struct lttng_event_rule *event_rule;
		enum lttng_domain_type domain;
		const enum lttng_condition_status status =
			lttng_condition_event_rule_matches_get_rule(condition, &event_rule);

		LTTNG_ASSERT(status == LTTNG_CONDITION_STATUS_OK);

		domain = lttng_event_rule_get_domain_type(event_rule);
		if (domain != LTTNG_DOMAIN_KERNEL) {
			is_supported = true;
			goto end;
		}

		/*
		 * Older kernel tracers can't emit notification. Therefore, we
		 * reject triggers that require that mechanism to be available
		 * to be evaluated.
		 *
		 * Assume unsupported on error.
		 */
		is_supported = kernel_supports_event_notifiers() == 1;
		break;
	}
	default:
		is_supported = true;
	}
end:
	return is_supported;
}

/* Must be called with RCU read lock held. */
static int bind_trigger_to_matching_session(struct lttng_trigger *trigger,
					    struct notification_thread_state *state)
{
	int ret = 0;
	const struct lttng_condition *condition;
	const char *session_name;
	struct lttng_session_trigger_list *trigger_list;

	ASSERT_RCU_READ_LOCKED();

	condition = lttng_trigger_get_const_condition(trigger);
	session_name = get_condition_session_name(condition);

	trigger_list = get_session_trigger_list(state, session_name);
	if (!trigger_list) {
		DBG("Unable to bind trigger applying to session \"%s\" as it is not yet known to the notification system",
		    session_name);
		goto end;
	}

	DBG("Newly registered trigger bound to session \"%s\"", session_name);
	ret = lttng_session_trigger_list_add(trigger_list, trigger);
end:
	return ret;
}

/* Must be called with RCU read lock held. */
static int bind_trigger_to_matching_channels(struct lttng_trigger *trigger,
					     struct notification_thread_state *state)
{
	int ret = 0;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct channel_info *channel;

	ASSERT_RCU_READ_LOCKED();

	cds_lfht_for_each_entry (state->channels_ht, &iter, channel, channels_ht_node) {
		struct lttng_trigger_list_element *trigger_list_element;
		struct lttng_channel_trigger_list *trigger_list;
		struct cds_lfht_iter lookup_iter;

		if (!trigger_applies_to_channel(trigger, channel)) {
			continue;
		}

		cds_lfht_lookup(state->channel_triggers_ht,
				hash_channel_key(&channel->key),
				match_channel_trigger_list,
				&channel->key,
				&lookup_iter);
		node = cds_lfht_iter_get_node(&lookup_iter);
		LTTNG_ASSERT(node);
		trigger_list = caa_container_of(
			node, struct lttng_channel_trigger_list, channel_triggers_ht_node);

		trigger_list_element = zmalloc<lttng_trigger_list_element>();
		if (!trigger_list_element) {
			ret = -1;
			goto end;
		}
		CDS_INIT_LIST_HEAD(&trigger_list_element->node);
		trigger_list_element->trigger = trigger;
		cds_list_add(&trigger_list_element->node, &trigger_list->list);
		DBG("Newly registered trigger bound to channel \"%s\"", channel->name);
	}
end:
	return ret;
}

static bool is_trigger_action_notify(const struct lttng_trigger *trigger)
{
	bool is_notify = false;
	const struct lttng_action *action = lttng_trigger_get_const_action(trigger);
	enum lttng_action_type action_type;

	LTTNG_ASSERT(action);
	action_type = lttng_action_get_type(action);
	if (action_type == LTTNG_ACTION_TYPE_NOTIFY) {
		is_notify = true;
		goto end;
	} else if (action_type != LTTNG_ACTION_TYPE_LIST) {
		goto end;
	}

	for (auto inner_action : lttng::ctl::const_action_list_view(action)) {
		if (lttng_action_get_type(inner_action) == LTTNG_ACTION_TYPE_NOTIFY) {
			is_notify = true;
			goto end;
		}
	}

end:
	return is_notify;
}

static bool trigger_name_taken(struct notification_thread_state *state,
			       const struct lttng_trigger *trigger)
{
	struct cds_lfht_iter iter;

	/*
	 * No duplicata is allowed in the triggers_by_name_uid_ht.
	 * The match is done against the trigger name and uid.
	 */
	cds_lfht_lookup(state->triggers_by_name_uid_ht,
			hash_trigger_by_name_uid(trigger),
			match_trigger_by_name_uid,
			trigger,
			&iter);
	return !!cds_lfht_iter_get_node(&iter);
}

static enum lttng_error_code generate_trigger_name(struct notification_thread_state *state,
						   struct lttng_trigger *trigger,
						   const char **name)
{
	enum lttng_error_code ret_code = LTTNG_OK;
	bool taken = false;
	enum lttng_trigger_status status;

	do {
		const int ret =
			lttng_trigger_generate_name(trigger, state->trigger_id.name_offset++);
		if (ret) {
			/* The only reason this can fail right now. */
			ret_code = LTTNG_ERR_NOMEM;
			break;
		}

		status = lttng_trigger_get_name(trigger, name);
		LTTNG_ASSERT(status == LTTNG_TRIGGER_STATUS_OK);

		taken = trigger_name_taken(state, trigger);
	} while (taken || state->trigger_id.name_offset == UINT64_MAX);

	return ret_code;
}

static inline void
notif_thread_state_remove_trigger_ht_elem(struct notification_thread_state *state,
					  struct lttng_trigger_ht_element *trigger_ht_element)
{
	LTTNG_ASSERT(state);
	LTTNG_ASSERT(trigger_ht_element);

	cds_lfht_del(state->triggers_ht, &trigger_ht_element->node);
	cds_lfht_del(state->triggers_by_name_uid_ht, &trigger_ht_element->node_by_name_uid);
}

static enum lttng_error_code setup_tracer_notifier(struct notification_thread_state *state,
						   struct lttng_trigger *trigger)
{
	enum lttng_error_code ret;
	enum event_notifier_error_accounting_status error_accounting_status;
	struct cds_lfht_node *node;
	uint64_t error_counter_index = 0;
	struct lttng_condition *condition = lttng_trigger_get_condition(trigger);
	struct notification_trigger_tokens_ht_element *trigger_tokens_ht_element = nullptr;

	trigger_tokens_ht_element = zmalloc<notification_trigger_tokens_ht_element>();
	if (!trigger_tokens_ht_element) {
		ret = LTTNG_ERR_NOMEM;
		goto end;
	}

	/* Add trigger token to the trigger_tokens_ht. */
	cds_lfht_node_init(&trigger_tokens_ht_element->node);
	trigger_tokens_ht_element->token = LTTNG_OPTIONAL_GET(trigger->tracer_token);
	trigger_tokens_ht_element->trigger = trigger;

	node = cds_lfht_add_unique(state->trigger_tokens_ht,
				   hash_key_u64(&trigger_tokens_ht_element->token, lttng_ht_seed),
				   match_trigger_token,
				   &trigger_tokens_ht_element->token,
				   &trigger_tokens_ht_element->node);
	if (node != &trigger_tokens_ht_element->node) {
		ret = LTTNG_ERR_TRIGGER_EXISTS;
		goto error_free_ht_element;
	}

	error_accounting_status = event_notifier_error_accounting_register_event_notifier(
		trigger, &error_counter_index);
	if (error_accounting_status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
		if (error_accounting_status ==
		    EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE) {
			DBG("Trigger list error accounting counter full.");
			ret = LTTNG_ERR_EVENT_NOTIFIER_ERROR_ACCOUNTING_FULL;
		} else {
			ERR("Error registering trigger for error accounting");
			ret = LTTNG_ERR_EVENT_NOTIFIER_REGISTRATION;
		}

		goto error_remove_ht_element;
	}

	lttng_condition_event_rule_matches_set_error_counter_index(condition, error_counter_index);

	ret = LTTNG_OK;
	goto end;

error_remove_ht_element:
	cds_lfht_del(state->trigger_tokens_ht, &trigger_tokens_ht_element->node);
error_free_ht_element:
	free(trigger_tokens_ht_element);
end:
	return ret;
}

/*
 * FIXME A client's credentials are not checked when registering a trigger.
 *
 * The effects of this are benign since:
 *     - The client will succeed in registering the trigger, as it is valid,
 *     - The trigger will, internally, be bound to the channel/session,
 *     - The notifications will not be sent since the client's credentials
 *       are checked against the channel at that moment.
 *
 * If this function returns a non-zero value, it means something is
 * fundamentally broken and the whole subsystem/thread will be torn down.
 *
 * If a non-fatal error occurs, just set the cmd_result to the appropriate
 * error code.
 */
static int
handle_notification_thread_command_register_trigger(struct notification_thread_state *state,
						    struct lttng_trigger *trigger,
						    bool is_trigger_anonymous,
						    enum lttng_error_code *cmd_result)
{
	int ret = 0;
	struct lttng_condition *condition;
	struct notification_client_list *client_list = nullptr;
	struct lttng_trigger_ht_element *trigger_ht_element = nullptr;
	struct cds_lfht_node *node;
	const char *trigger_name;
	bool free_trigger = true;
	struct lttng_evaluation *evaluation = nullptr;
	struct lttng_credentials object_creds;
	uid_t object_uid;
	gid_t object_gid;
	enum action_executor_status executor_status;
	const uint64_t trigger_tracer_token = state->trigger_id.next_tracer_token++;

	lttng::urcu::read_lock_guard read_lock;

	/* Set the trigger's tracer token. */
	lttng_trigger_set_tracer_token(trigger, trigger_tracer_token);

	if (!is_trigger_anonymous) {
		if (lttng_trigger_get_name(trigger, &trigger_name) == LTTNG_TRIGGER_STATUS_UNSET) {
			const enum lttng_error_code ret_code =
				generate_trigger_name(state, trigger, &trigger_name);

			if (ret_code != LTTNG_OK) {
				/* Fatal error. */
				ret = -1;
				*cmd_result = ret_code;
				goto error;
			}
		} else if (trigger_name_taken(state, trigger)) {
			/* Not a fatal error. */
			*cmd_result = LTTNG_ERR_TRIGGER_EXISTS;
			ret = 0;
			goto error;
		}
	} else {
		trigger_name = "(anonymous)";
	}

	condition = lttng_trigger_get_condition(trigger);
	LTTNG_ASSERT(condition);

	/* Some conditions require tracers to implement a minimal ABI version. */
	if (!condition_is_supported(condition)) {
		*cmd_result = LTTNG_ERR_NOT_SUPPORTED;
		goto error;
	}

	trigger_ht_element = zmalloc<lttng_trigger_ht_element>();
	if (!trigger_ht_element) {
		ret = -1;
		goto error;
	}

	/* Add trigger to the trigger_ht. */
	cds_lfht_node_init(&trigger_ht_element->node);
	cds_lfht_node_init(&trigger_ht_element->node_by_name_uid);
	trigger_ht_element->trigger = trigger;

	node = cds_lfht_add_unique(state->triggers_ht,
				   lttng_condition_hash(condition),
				   match_trigger,
				   trigger,
				   &trigger_ht_element->node);
	if (node != &trigger_ht_element->node) {
		/* Not a fatal error, simply report it to the client. */
		*cmd_result = LTTNG_ERR_TRIGGER_EXISTS;
		goto error_free_ht_element;
	}

	node = cds_lfht_add_unique(state->triggers_by_name_uid_ht,
				   hash_trigger_by_name_uid(trigger),
				   match_trigger_by_name_uid,
				   trigger,
				   &trigger_ht_element->node_by_name_uid);
	if (node != &trigger_ht_element->node_by_name_uid) {
		/* Internal error: add to triggers_ht should have failed. */
		ret = -1;
		goto error_free_ht_element;
	}

	/* From this point consider the trigger registered. */
	lttng_trigger_set_as_registered(trigger);

	/*
	 * Some triggers might need a tracer notifier depending on its
	 * condition and actions.
	 */
	if (lttng_trigger_needs_tracer_notifier(trigger)) {
		enum lttng_error_code error_code;

		error_code = setup_tracer_notifier(state, trigger);
		if (error_code != LTTNG_OK) {
			notif_thread_state_remove_trigger_ht_elem(state, trigger_ht_element);
			if (error_code == LTTNG_ERR_NOMEM) {
				ret = -1;
			} else {
				*cmd_result = error_code;
				ret = 0;
			}

			goto error_free_ht_element;
		}
	}

	/*
	 * The rest only applies to triggers that have a "notify" action.
	 * It is not skipped as this is the only action type currently
	 * supported.
	 */
	if (is_trigger_action_notify(trigger)) {
		/*
		 * Find or create the client list of this condition. It may
		 * already be present if another trigger is already registered
		 * with the same condition.
		 */
		client_list = get_client_list_from_condition(state, condition);
		if (!client_list) {
			/*
			 * No client list for this condition yet. We create new
			 * one and build it up.
			 */
			client_list = notification_client_list_create(state, condition);
			if (!client_list) {
				ERR("Error creating notification client list for trigger %s",
				    trigger->name);
				ret = -1;
				goto error_free_ht_element;
			}
		}

		CDS_INIT_LIST_HEAD(&trigger_ht_element->client_list_trigger_node);

		pthread_mutex_lock(&client_list->lock);
		cds_list_add(&trigger_ht_element->client_list_trigger_node,
			     &client_list->triggers_list);
		pthread_mutex_unlock(&client_list->lock);
	}

	/*
	 * Ownership of the trigger and of its wrapper was transfered to
	 * the triggers_ht. Same for token ht element if necessary.
	 */
	trigger_ht_element = nullptr;
	free_trigger = false;

	switch (get_condition_binding_object(condition)) {
	case LTTNG_OBJECT_TYPE_SESSION:
		/* Add the trigger to the list if it matches a known session. */
		ret = bind_trigger_to_matching_session(trigger, state);
		if (ret) {
			goto error_free_ht_element;
		}
		break;
	case LTTNG_OBJECT_TYPE_CHANNEL:
		/*
		 * Add the trigger to list of triggers bound to the channels
		 * currently known.
		 */
		ret = bind_trigger_to_matching_channels(trigger, state);
		if (ret) {
			goto error_free_ht_element;
		}
		break;
	case LTTNG_OBJECT_TYPE_NONE:
		break;
	default:
		ERR("Unknown object type on which to bind a newly registered trigger was encountered");
		ret = -1;
		goto error_free_ht_element;
	}

	/*
	 * The new trigger's condition must be evaluated against the current
	 * state.
	 *
	 * In the case of `notify` action, nothing preventing clients from
	 * subscribing to a condition before the corresponding trigger is
	 * registered, we have to evaluate this new condition right away.
	 *
	 * At some point, we were waiting for the next "evaluation" (e.g. on
	 * reception of a channel sample) to evaluate this new condition, but
	 * that was broken.
	 *
	 * The reason it was broken is that waiting for the next sample
	 * does not allow us to properly handle transitions for edge-triggered
	 * conditions.
	 *
	 * Consider this example: when we handle a new channel sample, we
	 * evaluate each conditions twice: once with the previous state, and
	 * again with the newest state. We then use those two results to
	 * determine whether a state change happened: a condition was false and
	 * became true. If a state change happened, we have to notify clients.
	 *
	 * Now, if a client subscribes to a given notification and registers
	 * a trigger *after* that subscription, we have to make sure the
	 * condition is evaluated at this point while considering only the
	 * current state. Otherwise, the next evaluation cycle may only see
	 * that the evaluations remain the same (true for samples n-1 and n) and
	 * the client will never know that the condition has been met.
	 */
	switch (get_condition_binding_object(condition)) {
	case LTTNG_OBJECT_TYPE_SESSION:
	{
		/* Find the session associated with the condition. */
		const auto *session_name = get_condition_session_name(condition);
		auto session_info = get_session_info_by_name(state, session_name);
		if (!session_info) {
			/* Not an error, the session doesn't exist yet. */
			DBG("Session not found while evaluating session condition during registration of trigger: session name = `%s`",
			    session_name);
			ret = 0;
			goto success;
		}

		LTTNG_OPTIONAL_SET(&object_creds.uid, session_info->uid);
		LTTNG_OPTIONAL_SET(&object_creds.gid, session_info->gid);

		ret = evaluate_session_condition(condition, session_info, nullptr, &evaluation);
		session_info_put(session_info);
		break;
	}
	case LTTNG_OBJECT_TYPE_CHANNEL:
		ret = evaluate_channel_condition_for_client(
			condition, state, &evaluation, &object_uid, &object_gid);
		LTTNG_OPTIONAL_SET(&object_creds.uid, object_uid);
		LTTNG_OPTIONAL_SET(&object_creds.gid, object_gid);
		break;
	case LTTNG_OBJECT_TYPE_NONE:
		ret = 0;
		break;
	case LTTNG_OBJECT_TYPE_UNKNOWN:
	default:
		ret = -1;
		break;
	}

	if (ret) {
		/* Fatal error. */
		goto error_free_ht_element;
	}

	DBG("Newly registered trigger's condition evaluated to %s", evaluation ? "true" : "false");
	if (!evaluation) {
		/* Evaluation yielded nothing. Normal exit. */
		ret = 0;
		goto success;
	}

	/*
	 * Ownership of `evaluation` transferred to the action executor
	 * no matter the result.
	 */
	executor_status = action_executor_enqueue_trigger(
		state->executor, trigger, evaluation, &object_creds, client_list);
	evaluation = nullptr;
	switch (executor_status) {
	case ACTION_EXECUTOR_STATUS_OK:
		break;
	case ACTION_EXECUTOR_STATUS_ERROR:
	case ACTION_EXECUTOR_STATUS_INVALID:
		/*
		 * TODO Add trigger identification (name/id) when
		 * it is added to the API.
		 */
		ERR("Fatal error occurred while enqueuing action associated to newly registered trigger");
		ret = -1;
		goto error_free_ht_element;
	case ACTION_EXECUTOR_STATUS_OVERFLOW:
		/*
		 * TODO Add trigger identification (name/id) when
		 * it is added to the API.
		 *
		 * Not a fatal error.
		 */
		WARN("No space left when enqueuing action associated to newly registered trigger");
		ret = 0;
		goto success;
	default:
		abort();
	}

success:
	*cmd_result = LTTNG_OK;
	DBG("Registered trigger: name = `%s`, tracer token = %" PRIu64,
	    trigger_name,
	    trigger_tracer_token);
	goto end;

error_free_ht_element:
	if (trigger_ht_element) {
		/* Delayed removal due to RCU constraint on delete. */
		call_rcu(&trigger_ht_element->rcu_node, free_lttng_trigger_ht_element_rcu);
	}
error:
	if (free_trigger) {
		/*
		 * Other objects might have a reference to the trigger, mark it
		 * as unregistered.
		 */
		lttng_trigger_set_as_unregistered(trigger);
		lttng_trigger_destroy(trigger);
	}
end:
	return ret;
}

static void free_lttng_trigger_ht_element_rcu(struct rcu_head *node)
{
	free(caa_container_of(node, struct lttng_trigger_ht_element, rcu_node));
}

static void free_notification_trigger_tokens_ht_element_rcu(struct rcu_head *node)
{
	free(caa_container_of(node, struct notification_trigger_tokens_ht_element, rcu_node));
}

static void teardown_tracer_notifier(struct notification_thread_state *state,
				     const struct lttng_trigger *trigger)
{
	struct cds_lfht_iter iter;
	struct notification_trigger_tokens_ht_element *trigger_tokens_ht_element;

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			state->trigger_tokens_ht, &iter, trigger_tokens_ht_element, node) {
			if (!lttng_trigger_is_equal(trigger, trigger_tokens_ht_element->trigger)) {
				continue;
			}

			event_notifier_error_accounting_unregister_event_notifier(
				trigger_tokens_ht_element->trigger);

			/* TODO talk to all app and remove it */
			DBG("Removed trigger from tokens_ht");
			cds_lfht_del(state->trigger_tokens_ht, &trigger_tokens_ht_element->node);

			call_rcu(&trigger_tokens_ht_element->rcu_node,
				 free_notification_trigger_tokens_ht_element_rcu);

			break;
		}
	}
}

static void
remove_trigger_from_session_trigger_list(struct lttng_session_trigger_list *trigger_list,
					 const struct lttng_trigger *trigger)
{
	bool found = false;
	struct lttng_trigger_list_element *trigger_element, *tmp;

	cds_list_for_each_entry_safe (trigger_element, tmp, &trigger_list->list, node) {
		if (!lttng_trigger_is_equal(trigger, trigger_element->trigger)) {
			continue;
		}

		DBG("Removed trigger from session_triggers_ht");
		cds_list_del(&trigger_element->node);
		free(trigger_element);
		/* A trigger can only appear once per session. */
		found = true;
		break;
	}

	if (!found) {
		ERR("Failed to find trigger associated with session: session name = `%s`",
		    trigger_list->session_name);
	}

	LTTNG_ASSERT(found);
}

static int
handle_notification_thread_command_unregister_trigger(struct notification_thread_state *state,
						      const struct lttng_trigger *trigger,
						      enum lttng_error_code *_cmd_reply)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *triggers_ht_node;
	struct notification_client_list *client_list;
	struct lttng_trigger_ht_element *trigger_ht_element = nullptr;
	const struct lttng_condition *condition = lttng_trigger_get_const_condition(trigger);
	enum lttng_error_code cmd_reply;

	lttng::urcu::read_lock_guard read_lock;

	cds_lfht_lookup(
		state->triggers_ht, lttng_condition_hash(condition), match_trigger, trigger, &iter);
	triggers_ht_node = cds_lfht_iter_get_node(&iter);
	if (!triggers_ht_node) {
		cmd_reply = LTTNG_ERR_TRIGGER_NOT_FOUND;
		goto end;
	} else {
		cmd_reply = LTTNG_OK;
	}

	trigger_ht_element =
		caa_container_of(triggers_ht_node, struct lttng_trigger_ht_element, node);

	switch (get_condition_binding_object(condition)) {
	case LTTNG_OBJECT_TYPE_CHANNEL:
	{
		struct lttng_channel_trigger_list *trigger_list;

		/*
		 * Remove trigger from channel_triggers_ht.
		 *
		 * Note that multiple channels may have matched the trigger's
		 * condition (e.g. all instances of a given channel in per-pid buffering
		 * mode).
		 *
		 * Iterate on all lists since we don't know the target channels' keys.
		 */
		cds_lfht_for_each_entry (
			state->channel_triggers_ht, &iter, trigger_list, channel_triggers_ht_node) {
			struct lttng_trigger_list_element *trigger_element, *tmp;

			cds_list_for_each_entry_safe (
				trigger_element, tmp, &trigger_list->list, node) {
				if (!lttng_trigger_is_equal(trigger, trigger_element->trigger)) {
					continue;
				}

				DBG("Removed trigger from channel_triggers_ht");
				cds_list_del(&trigger_element->node);
				free(trigger_element);
				/* A trigger can only appear once per channel */
				break;
			}
		}
		break;
	}
	case LTTNG_OBJECT_TYPE_SESSION:
	{
		auto session =
			get_session_info_by_name(state, get_condition_session_name(condition));

		/* Session doesn't exist, no trigger to remove. */
		if (!session) {
			break;
		}

		auto session_trigger_list = get_session_trigger_list(state, session->name);
		remove_trigger_from_session_trigger_list(session_trigger_list, trigger);
		session_info_put(session);
	}
	case LTTNG_OBJECT_TYPE_NONE:
		break;
	default:
		abort();
	}

	if (lttng_trigger_needs_tracer_notifier(trigger)) {
		teardown_tracer_notifier(state, trigger);
	}

	if (is_trigger_action_notify(trigger)) {
		/*
		 * Remove and release the client list from
		 * notification_trigger_clients_ht.
		 */
		client_list = get_client_list_from_condition(state, condition);
		LTTNG_ASSERT(client_list);

		pthread_mutex_lock(&client_list->lock);
		cds_list_del(&trigger_ht_element->client_list_trigger_node);
		pthread_mutex_unlock(&client_list->lock);

		/* Put new reference and the hashtable's reference. */
		notification_client_list_put(client_list);
		notification_client_list_put(client_list);
		client_list = nullptr;
	}

	/* Remove trigger from triggers_ht. */
	notif_thread_state_remove_trigger_ht_elem(state, trigger_ht_element);

	/* Release the ownership of the trigger. */
	lttng_trigger_destroy(trigger_ht_element->trigger);
	call_rcu(&trigger_ht_element->rcu_node, free_lttng_trigger_ht_element_rcu);
end:
	if (_cmd_reply) {
		*_cmd_reply = cmd_reply;
	}
	return 0;
}

static notification_thread_command *pop_cmd_queue(notification_thread_handle *handle)
{
	lttng::pthread::lock_guard queue_lock(handle->cmd_queue.lock);

	uint64_t counter;
	const auto read_ret = lttng_read(handle->cmd_queue.event_fd, &counter, sizeof(counter));
	if (read_ret != sizeof(counter)) {
		if (read_ret < 0) {
			LTTNG_THROW_POSIX("Failed to read counter value from event_fd", errno);
		} else {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to read counter value from event_fd because of a truncated read: ret={}, expected read size={}",
				read_ret,
				sizeof(counter)));
		}
	}

	auto command = cds_list_first_entry(
		&handle->cmd_queue.list, struct notification_thread_command, cmd_list_node);
	cds_list_del(&((command)->cmd_list_node));
	return command;
}

/* Returns 0 on success, 1 on exit requested, negative value on error. */
int handle_notification_thread_command(struct notification_thread_handle *handle,
				       struct notification_thread_state *state)
{
	int ret;
	struct notification_thread_command *cmd = nullptr;

	try {
		cmd = pop_cmd_queue(handle);
	} catch (const std::exception& ex) {
		ERR("Failed to get next notification thread command: %s", ex.what());
		goto error;
	}

	DBG("Received `%s` command", notification_command_type_str(cmd->type));
	switch (cmd->type) {
	case NOTIFICATION_COMMAND_TYPE_REGISTER_TRIGGER:
		ret = handle_notification_thread_command_register_trigger(
			state,
			cmd->parameters.register_trigger.trigger,
			cmd->parameters.register_trigger.is_trigger_anonymous,
			&cmd->reply_code);
		break;
	case NOTIFICATION_COMMAND_TYPE_UNREGISTER_TRIGGER:
		ret = handle_notification_thread_command_unregister_trigger(
			state, cmd->parameters.unregister_trigger.trigger, &cmd->reply_code);
		break;
	case NOTIFICATION_COMMAND_TYPE_ADD_CHANNEL:
		ret = handle_notification_thread_command_add_channel(
			state,
			cmd->parameters.add_channel.session.id,
			cmd->parameters.add_channel.channel.name,
			cmd->parameters.add_channel.channel.domain,
			cmd->parameters.add_channel.channel.key,
			cmd->parameters.add_channel.channel.capacity,
			&cmd->reply_code);
		break;
	case NOTIFICATION_COMMAND_TYPE_REMOVE_CHANNEL:
		ret = handle_notification_thread_command_remove_channel(
			state,
			cmd->parameters.remove_channel.key,
			cmd->parameters.remove_channel.domain,
			&cmd->reply_code);
		break;
	case NOTIFICATION_COMMAND_TYPE_ADD_SESSION:
		ret = handle_notification_thread_command_add_session(
			state,
			cmd->parameters.add_session.session_id,
			cmd->parameters.add_session.session_name,
			cmd->parameters.add_session.session_uid,
			cmd->parameters.add_session.session_gid,
			&cmd->reply_code);
		break;
	case NOTIFICATION_COMMAND_TYPE_REMOVE_SESSION:
		ret = handle_notification_thread_command_remove_session(
			state, cmd->parameters.remove_session.session_id, &cmd->reply_code);
		break;
	case NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_ONGOING:
	case NOTIFICATION_COMMAND_TYPE_SESSION_ROTATION_COMPLETED:
		ret = handle_notification_thread_command_session_rotation(
			state,
			cmd->type,
			cmd->parameters.session_rotation.session_id,
			cmd->parameters.session_rotation.trace_archive_chunk_id,
			cmd->parameters.session_rotation.location,
			&cmd->reply_code);
		break;
	case NOTIFICATION_COMMAND_TYPE_ADD_TRACER_EVENT_SOURCE:
		ret = handle_notification_thread_command_add_tracer_event_source(
			state,
			cmd->parameters.tracer_event_source.tracer_event_source_fd,
			cmd->parameters.tracer_event_source.domain,
			&cmd->reply_code);
		break;
	case NOTIFICATION_COMMAND_TYPE_REMOVE_TRACER_EVENT_SOURCE:
		ret = handle_notification_thread_command_remove_tracer_event_source(
			state,
			cmd->parameters.tracer_event_source.tracer_event_source_fd,
			&cmd->reply_code);
		break;
	case NOTIFICATION_COMMAND_TYPE_LIST_TRIGGERS:
	{
		struct lttng_triggers *triggers = nullptr;

		ret = handle_notification_thread_command_list_triggers(
			handle,
			state,
			cmd->parameters.list_triggers.uid,
			&triggers,
			&cmd->reply_code);
		cmd->reply.list_triggers.triggers = triggers;
		ret = 0;
		break;
	}
	case NOTIFICATION_COMMAND_TYPE_QUIT:
		cmd->reply_code = LTTNG_OK;
		ret = 1;
		goto end;
	case NOTIFICATION_COMMAND_TYPE_GET_TRIGGER:
	{
		struct lttng_trigger *trigger = nullptr;

		ret = handle_notification_thread_command_get_trigger(
			state, cmd->parameters.get_trigger.trigger, &trigger, &cmd->reply_code);
		cmd->reply.get_trigger.trigger = trigger;
		break;
	}
	case NOTIFICATION_COMMAND_TYPE_CLIENT_COMMUNICATION_UPDATE:
	{
		const enum client_transmission_status client_status =
			cmd->parameters.client_communication_update.status;
		const notification_client_id client_id =
			cmd->parameters.client_communication_update.id;
		struct notification_client *client;

		lttng::urcu::read_lock_guard read_lock;
		client = get_client_from_id(client_id, state);

		if (!client) {
			/*
			 * Client error was probably already picked-up by the
			 * notification thread or it has disconnected
			 * gracefully while this command was queued.
			 */
			DBG("Failed to find notification client to update communication status, client id = %" PRIu64,
			    client_id);
			ret = 0;
		} else {
			ret = client_handle_transmission_status(client, client_status, state);
		}
		break;
	}
	default:
		ERR("Unknown internal command received");
		goto error_unlock;
	}

	if (ret) {
		goto error_unlock;
	}

end:
	if (cmd) {
		if (cmd->is_async) {
			delete cmd;
			cmd = nullptr;
		} else {
			cmd->command_completed_waker->wake();
		}
	}

	return ret;

error_unlock:
	/* Wake-up and return a fatal error to the calling thread. */
	cmd->reply_code = LTTNG_ERR_FATAL;

error:
	ret = -1;
	goto end;
}

static int socket_set_non_blocking(int socket)
{
	int ret, flags;

	/* Set the pipe as non-blocking. */
	ret = fcntl(socket, F_GETFL, 0);
	if (ret == -1) {
		PERROR("fcntl get socket flags");
		goto end;
	}
	flags = ret;

	ret = fcntl(socket, F_SETFL, flags | O_NONBLOCK);
	if (ret == -1) {
		PERROR("fcntl set O_NONBLOCK socket flag");
		goto end;
	}
	DBG("Client socket (fd = %i) set as non-blocking", socket);
end:
	return ret;
}

static int client_reset_inbound_state(struct notification_client *client)
{
	int ret;

	lttng_payload_clear(&client->communication.inbound.payload);

	client->communication.inbound.bytes_to_receive =
		sizeof(struct lttng_notification_channel_message);
	client->communication.inbound.msg_type = LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_UNKNOWN;
	LTTNG_SOCK_SET_UID_CRED(&client->communication.inbound.creds, -1);
	LTTNG_SOCK_SET_GID_CRED(&client->communication.inbound.creds, -1);
	ret = lttng_dynamic_buffer_set_size(&client->communication.inbound.payload.buffer,
					    client->communication.inbound.bytes_to_receive);

	return ret;
}

int handle_notification_thread_client_connect(struct notification_thread_state *state)
{
	int ret;
	struct notification_client *client;

	DBG("Handling new notification channel client connection");

	client = zmalloc<notification_client>();
	if (!client) {
		/* Fatal error. */
		ret = -1;
		goto error;
	}

	pthread_mutex_init(&client->lock, nullptr);
	client->id = state->next_notification_client_id++;
	CDS_INIT_LIST_HEAD(&client->condition_list);
	lttng_payload_init(&client->communication.inbound.payload);
	lttng_payload_init(&client->communication.outbound.payload);
	client->communication.inbound.expect_creds = true;

	ret = client_reset_inbound_state(client);
	if (ret) {
		ERR("Failed to reset client communication's inbound state");
		ret = 0;
		goto error;
	}

	ret = lttcomm_accept_unix_sock(state->notification_channel_socket);
	if (ret < 0) {
		ERR("Failed to accept new notification channel client connection");
		ret = 0;
		goto error;
	}

	client->socket = ret;

	ret = socket_set_non_blocking(client->socket);
	if (ret) {
		ERR("Failed to set new notification channel client connection socket as non-blocking");
		goto error;
	}

	ret = lttcomm_setsockopt_creds_unix_sock(client->socket);
	if (ret < 0) {
		ERR("Failed to set socket options on new notification channel client socket");
		ret = 0;
		goto error;
	}

	client->communication.current_poll_events = CLIENT_POLL_EVENTS_IN;
	ret = lttng_poll_add(
		&state->events, client->socket, client->communication.current_poll_events);
	if (ret < 0) {
		ERR("Failed to add notification channel client socket to poll set");
		ret = 0;
		goto error;
	}
	DBG("Added new notification channel client socket (%i) to poll set", client->socket);

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_add(state->client_socket_ht,
			     hash_client_socket(client->socket),
			     &client->client_socket_ht_node);
		cds_lfht_add(state->client_id_ht,
			     hash_client_id(client->id),
			     &client->client_id_ht_node);
	}

	return ret;

error:
	notification_client_destroy(client);
	return ret;
}

/*
 * RCU read-lock must be held by the caller.
 * Client lock must _not_ be held by the caller.
 */
static int notification_thread_client_disconnect(struct notification_client *client,
						 struct notification_thread_state *state)
{
	int ret;
	struct lttng_condition_list_element *condition_list_element, *tmp;

	ASSERT_RCU_READ_LOCKED();

	/* Acquire the client lock to disable its communication atomically. */
	pthread_mutex_lock(&client->lock);
	client->communication.active = false;
	cds_lfht_del(state->client_socket_ht, &client->client_socket_ht_node);
	cds_lfht_del(state->client_id_ht, &client->client_id_ht_node);
	pthread_mutex_unlock(&client->lock);

	ret = lttng_poll_del(&state->events, client->socket);
	if (ret) {
		ERR("Failed to remove client socket %d from poll set", client->socket);
	}

	/* Release all conditions to which the client was subscribed. */
	cds_list_for_each_entry_safe (condition_list_element, tmp, &client->condition_list, node) {
		(void) notification_thread_client_unsubscribe(
			client, condition_list_element->condition, state, nullptr);
	}

	/*
	 * Client no longer accessible to other threads (through the
	 * client lists).
	 */
	notification_client_destroy(client);
	return ret;
}

int handle_notification_thread_client_disconnect(int client_socket,
						 struct notification_thread_state *state)
{
	int ret = 0;
	struct notification_client *client;

	lttng::urcu::read_lock_guard read_lock;

	DBG("Closing client connection (socket fd = %i)", client_socket);
	client = get_client_from_socket(client_socket, state);
	if (!client) {
		/* Internal state corruption, fatal error. */
		ERR("Unable to find client (socket fd = %i)", client_socket);
		ret = -1;
		goto end;
	}

	ret = notification_thread_client_disconnect(client, state);
end:
	return ret;
}

int handle_notification_thread_client_disconnect_all(struct notification_thread_state *state)
{
	struct cds_lfht_iter iter;
	struct notification_client *client;
	bool error_encoutered = false;

	DBG("Closing all client connections");

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			state->client_socket_ht, &iter, client, client_socket_ht_node) {
			int ret;

			ret = notification_thread_client_disconnect(client, state);
			if (ret) {
				error_encoutered = true;
			}
		}
	}

	return error_encoutered ? 1 : 0;
}

int handle_notification_thread_trigger_unregister_all(struct notification_thread_state *state)
{
	bool error_occurred = false;
	struct cds_lfht_iter iter;
	struct lttng_trigger_ht_element *trigger_ht_element;

	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_for_each_entry (state->triggers_ht, &iter, trigger_ht_element, node) {
		int ret = handle_notification_thread_command_unregister_trigger(
			state, trigger_ht_element->trigger, nullptr);
		if (ret) {
			error_occurred = true;
		}
	}
	return error_occurred ? -1 : 0;
}

static bool client_has_outbound_data_left(const struct notification_client *client)
{
	const struct lttng_payload_view pv =
		lttng_payload_view_from_payload(&client->communication.outbound.payload, 0, -1);
	const bool has_data = pv.buffer.size != 0;
	const bool has_fds = lttng_payload_view_get_fd_handle_count(&pv);

	return has_data || has_fds;
}

static int client_handle_transmission_status(struct notification_client *client,
					     enum client_transmission_status transmission_status,
					     struct notification_thread_state *state)
{
	int ret = 0;

	switch (transmission_status) {
	case CLIENT_TRANSMISSION_STATUS_COMPLETE:
	case CLIENT_TRANSMISSION_STATUS_QUEUED:
	{
		int current_poll_events;
		int new_poll_events;
		/*
		 * We want to be notified whenever there is buffer space
		 * available to send the rest of the payload if we are
		 * waiting to send data to the client.
		 *
		 * The state of the outbound queue being sampled here is
		 * fine since:
		 *   - it is okay to wake-up "for nothing" in case we see
		 *     that data is left, but another thread succeeds in
		 *     flushing it before us when handling the client "out"
		 *     event. We will simply stop monitoring that event the next
		 *     time it wakes us up and we see no data left to be sent,
		 *   - if another thread fails to flush the entire client
		 *     outgoing queue, it will issue a "communication update"
		 *     command and cause the client's (e)poll mask to be
		 *     re-evaluated.
		 *
		 * The situation we seek to avoid would be to disable the
		 * monitoring of "out" client events indefinitely when there is
		 * data to be sent, which can't happen because of the
		 * aforementioned "communication update" mechanism.
		 */
		pthread_mutex_lock(&client->lock);
		current_poll_events = client->communication.current_poll_events;
		new_poll_events = client_has_outbound_data_left(client) ?
			CLIENT_POLL_EVENTS_IN_OUT :
			CLIENT_POLL_EVENTS_IN;
		client->communication.current_poll_events = new_poll_events;
		pthread_mutex_unlock(&client->lock);

		/* Update the monitored event set only if it changed. */
		if (current_poll_events != new_poll_events) {
			ret = lttng_poll_mod(&state->events, client->socket, new_poll_events);
			if (ret) {
				goto end;
			}
		}

		break;
	}
	case CLIENT_TRANSMISSION_STATUS_FAIL:
		ret = notification_thread_client_disconnect(client, state);
		if (ret) {
			goto end;
		}
		break;
	case CLIENT_TRANSMISSION_STATUS_ERROR:
		ret = -1;
		goto end;
	default:
		abort();
	}
end:
	return ret;
}

/* Client lock must be acquired by caller. */
static enum client_transmission_status
client_flush_outgoing_queue(struct notification_client *client)
{
	ssize_t ret;
	size_t to_send_count;
	enum client_transmission_status status;
	struct lttng_payload_view pv =
		lttng_payload_view_from_payload(&client->communication.outbound.payload, 0, -1);
	const int fds_to_send_count = lttng_payload_view_get_fd_handle_count(&pv);

	ASSERT_LOCKED(client->lock);

	if (!client->communication.active) {
		status = CLIENT_TRANSMISSION_STATUS_FAIL;
		goto end;
	}

	if (pv.buffer.size == 0) {
		/*
		 * If both data and fds are equal to zero, we are in an invalid
		 * state.
		 */
		LTTNG_ASSERT(fds_to_send_count != 0);
		goto send_fds;
	}

	/* Send data. */
	to_send_count = pv.buffer.size;
	DBG("Flushing client (socket fd = %i) outgoing queue", client->socket);

	ret = lttcomm_send_unix_sock_non_block(client->socket, pv.buffer.data, to_send_count);
	if ((ret >= 0 && ret < to_send_count)) {
		DBG("Client (socket fd = %i) outgoing queue could not be completely flushed",
		    client->socket);
		to_send_count -= std::max(ret, (ssize_t) 0);

		memmove(client->communication.outbound.payload.buffer.data,
			pv.buffer.data + pv.buffer.size - to_send_count,
			to_send_count);
		ret = lttng_dynamic_buffer_set_size(&client->communication.outbound.payload.buffer,
						    to_send_count);
		if (ret) {
			goto error;
		}

		status = CLIENT_TRANSMISSION_STATUS_QUEUED;
		goto end;
	} else if (ret < 0) {
		/* Generic error, disable the client's communication. */
		ERR("Failed to flush outgoing queue, disconnecting client (socket fd = %i)",
		    client->socket);
		client->communication.active = false;
		status = CLIENT_TRANSMISSION_STATUS_FAIL;
		goto end;
	} else {
		/*
		 * No error and flushed the queue completely.
		 *
		 * The payload buffer size is used later to
		 * check if there is notifications queued. So albeit that the
		 * direct caller knows that the transmission is complete, we
		 * need to set the buffer size to zero.
		 */
		ret = lttng_dynamic_buffer_set_size(&client->communication.outbound.payload.buffer,
						    0);
		if (ret) {
			goto error;
		}
	}

send_fds:
	/* No fds to send, transmission is complete. */
	if (fds_to_send_count == 0) {
		status = CLIENT_TRANSMISSION_STATUS_COMPLETE;
		goto end;
	}

	ret = lttcomm_send_payload_view_fds_unix_sock_non_block(client->socket, &pv);
	if (ret < 0) {
		/* Generic error, disable the client's communication. */
		ERR("Failed to flush outgoing fds queue, disconnecting client (socket fd = %i)",
		    client->socket);
		client->communication.active = false;
		status = CLIENT_TRANSMISSION_STATUS_FAIL;
		goto end;
	} else if (ret == 0) {
		/* Nothing could be sent. */
		status = CLIENT_TRANSMISSION_STATUS_QUEUED;
	} else {
		/* Fd passing is an all or nothing kind of thing. */
		status = CLIENT_TRANSMISSION_STATUS_COMPLETE;
		/*
		 * The payload _fd_array count is used later to
		 * check if there is notifications queued. So although the
		 * direct caller knows that the transmission is complete, we
		 * need to clear the _fd_array for the queuing check.
		 */
		lttng_dynamic_pointer_array_clear(
			&client->communication.outbound.payload._fd_handles);
	}

end:
	if (status == CLIENT_TRANSMISSION_STATUS_COMPLETE) {
		client->communication.outbound.queued_command_reply = false;
		client->communication.outbound.dropped_notification = false;
		lttng_payload_clear(&client->communication.outbound.payload);
	}

	return status;
error:
	return CLIENT_TRANSMISSION_STATUS_ERROR;
}

/* Client lock must _not_ be held by the caller. */
static int client_send_command_reply(struct notification_client *client,
				     struct notification_thread_state *state,
				     enum lttng_notification_channel_status status)
{
	int ret;
	struct lttng_notification_channel_command_reply reply = {
		.status = (int8_t) status,
	};
	struct lttng_notification_channel_message msg;
	char buffer[sizeof(msg) + sizeof(reply)];
	enum client_transmission_status transmission_status;

	msg.type = (int8_t) LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_COMMAND_REPLY;
	msg.size = sizeof(reply);
	msg.fds = 0;

	memcpy(buffer, &msg, sizeof(msg));
	memcpy(buffer + sizeof(msg), &reply, sizeof(reply));
	DBG("Send command reply (%i)", (int) status);

	pthread_mutex_lock(&client->lock);
	if (client->communication.outbound.queued_command_reply) {
		/* Protocol error. */
		goto error_unlock;
	}

	/* Enqueue buffer to outgoing queue and flush it. */
	ret = lttng_dynamic_buffer_append(
		&client->communication.outbound.payload.buffer, buffer, sizeof(buffer));
	if (ret) {
		goto error_unlock;
	}

	transmission_status = client_flush_outgoing_queue(client);

	if (client_has_outbound_data_left(client)) {
		/* Queue could not be emptied. */
		client->communication.outbound.queued_command_reply = true;
	}

	pthread_mutex_unlock(&client->lock);
	ret = client_handle_transmission_status(client, transmission_status, state);
	if (ret) {
		goto error;
	}

	return 0;
error_unlock:
	pthread_mutex_unlock(&client->lock);
error:
	return -1;
}

static int client_handle_message_unknown(struct notification_client *client,
					 struct notification_thread_state *state
					 __attribute__((unused)))
{
	int ret;
	/*
	 * Receiving message header. The function will be called again
	 * once the rest of the message as been received and can be
	 * interpreted.
	 */
	const struct lttng_notification_channel_message *msg;

	LTTNG_ASSERT(sizeof(*msg) == client->communication.inbound.payload.buffer.size);
	msg = (const struct lttng_notification_channel_message *)
		      client->communication.inbound.payload.buffer.data;

	if (msg->size == 0 || msg->size > DEFAULT_MAX_NOTIFICATION_CLIENT_MESSAGE_PAYLOAD_SIZE) {
		ERR("Invalid notification channel message: length = %u", msg->size);
		ret = -1;
		goto end;
	}

	switch (msg->type) {
	case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_SUBSCRIBE:
	case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_UNSUBSCRIBE:
	case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_HANDSHAKE:
		break;
	default:
		ret = -1;
		ERR("Invalid notification channel message: unexpected message type");
		goto end;
	}

	client->communication.inbound.bytes_to_receive = msg->size;
	client->communication.inbound.fds_to_receive = msg->fds;
	client->communication.inbound.msg_type =
		(enum lttng_notification_channel_message_type) msg->type;
	ret = lttng_dynamic_buffer_set_size(&client->communication.inbound.payload.buffer,
					    msg->size);

	/* msg is not valid anymore due to lttng_dynamic_buffer_set_size. */
	msg = nullptr;
end:
	return ret;
}

static int client_handle_message_handshake(struct notification_client *client,
					   struct notification_thread_state *state)
{
	int ret;
	struct lttng_notification_channel_command_handshake *handshake_client;
	const struct lttng_notification_channel_command_handshake handshake_reply = {
		.major = LTTNG_NOTIFICATION_CHANNEL_VERSION_MAJOR,
		.minor = LTTNG_NOTIFICATION_CHANNEL_VERSION_MINOR,
	};
	struct lttng_notification_channel_message msg_header;
	enum lttng_notification_channel_status status = LTTNG_NOTIFICATION_CHANNEL_STATUS_OK;
	char send_buffer[sizeof(msg_header) + sizeof(handshake_reply)];

	msg_header.type = LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_HANDSHAKE;
	msg_header.size = sizeof(handshake_reply);
	msg_header.fds = 0;

	memcpy(send_buffer, &msg_header, sizeof(msg_header));
	memcpy(send_buffer + sizeof(msg_header), &handshake_reply, sizeof(handshake_reply));

	handshake_client = (struct lttng_notification_channel_command_handshake *)
				   client->communication.inbound.payload.buffer.data;
	client->major = handshake_client->major;
	client->minor = handshake_client->minor;
	if (!client->communication.inbound.creds_received) {
		ERR("No credentials received from client");
		ret = -1;
		goto end;
	}

	client->uid = LTTNG_SOCK_GET_UID_CRED(&client->communication.inbound.creds);
	client->gid = LTTNG_SOCK_GET_GID_CRED(&client->communication.inbound.creds);
	client->is_sessiond = LTTNG_SOCK_GET_PID_CRED(&client->communication.inbound.creds) ==
		getpid();
	DBG("Received handshake from client: uid = %u, gid = %u, protocol version = %i.%i, client is sessiond = %s",
	    client->uid,
	    client->gid,
	    (int) client->major,
	    (int) client->minor,
	    client->is_sessiond ? "true" : "false");

	if (handshake_client->major != LTTNG_NOTIFICATION_CHANNEL_VERSION_MAJOR) {
		status = LTTNG_NOTIFICATION_CHANNEL_STATUS_UNSUPPORTED_VERSION;
	}

	pthread_mutex_lock(&client->lock);
	/* Outgoing queue will be flushed when the command reply is sent. */
	ret = lttng_dynamic_buffer_append(
		&client->communication.outbound.payload.buffer, send_buffer, sizeof(send_buffer));
	if (ret) {
		ERR("Failed to send protocol version to notification channel client");
		goto end_unlock;
	}

	client->validated = true;
	client->communication.active = true;
	pthread_mutex_unlock(&client->lock);

	/* Set reception state to receive the next message header. */
	ret = client_reset_inbound_state(client);
	if (ret) {
		ERR("Failed to reset client communication's inbound state");
		goto end;
	}

	/* Flushes the outgoing queue. */
	ret = client_send_command_reply(client, state, status);
	if (ret) {
		ERR("Failed to send reply to notification channel client");
		goto end;
	}

	goto end;
end_unlock:
	pthread_mutex_unlock(&client->lock);
end:
	return ret;
}

static int client_handle_message_subscription(struct notification_client *client,
					      enum lttng_notification_channel_message_type msg_type,
					      struct notification_thread_state *state)
{
	int ret;
	struct lttng_condition *condition;
	enum lttng_notification_channel_status status = LTTNG_NOTIFICATION_CHANNEL_STATUS_OK;
	struct lttng_payload_view condition_view =
		lttng_payload_view_from_payload(&client->communication.inbound.payload, 0, -1);
	size_t expected_condition_size;

	/*
	 * No need to lock client to sample the inbound state as the only
	 * other thread accessing clients (action executor) only uses the
	 * outbound state.
	 */
	expected_condition_size = client->communication.inbound.payload.buffer.size;
	ret = lttng_condition_create_from_payload(&condition_view, &condition);
	if (ret != expected_condition_size) {
		ERR("Malformed condition received from client");
		goto end;
	}

	/* Ownership of condition is always transferred. */
	if (msg_type == LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_SUBSCRIBE) {
		ret = notification_thread_client_subscribe(client, condition, state, &status);
	} else {
		ret = notification_thread_client_unsubscribe(client, condition, state, &status);
	}

	if (ret) {
		goto end;
	}

	/* Set reception state to receive the next message header. */
	ret = client_reset_inbound_state(client);
	if (ret) {
		ERR("Failed to reset client communication's inbound state");
		goto end;
	}

	ret = client_send_command_reply(client, state, status);
	if (ret) {
		ERR("Failed to send reply to notification channel client");
		goto end;
	}

end:
	return ret;
}

static int client_dispatch_message(struct notification_client *client,
				   struct notification_thread_state *state)
{
	int ret = 0;

	if (client->communication.inbound.msg_type !=
		    LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_HANDSHAKE &&
	    client->communication.inbound.msg_type !=
		    LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_UNKNOWN &&
	    !client->validated) {
		WARN("client attempted a command before handshake");
		ret = -1;
		goto end;
	}

	switch (client->communication.inbound.msg_type) {
	case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_UNKNOWN:
	{
		ret = client_handle_message_unknown(client, state);
		break;
	}
	case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_HANDSHAKE:
	{
		ret = client_handle_message_handshake(client, state);
		break;
	}
	case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_SUBSCRIBE:
	case LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_UNSUBSCRIBE:
	{
		ret = client_handle_message_subscription(
			client, client->communication.inbound.msg_type, state);
		break;
	}
	default:
		abort();
	}
end:
	return ret;
}

/* Incoming data from client. */
int handle_notification_thread_client_in(struct notification_thread_state *state, int socket)
{
	int ret = 0;
	struct notification_client *client;
	ssize_t recv_ret;
	size_t offset;

	lttng::urcu::read_lock_guard read_lock;
	client = get_client_from_socket(socket, state);
	if (!client) {
		/* Internal error, abort. */
		ret = -1;
		goto end;
	}

	if (client->communication.inbound.bytes_to_receive == 0 &&
	    client->communication.inbound.fds_to_receive != 0) {
		/* Only FDs left to receive. */
		goto receive_fds;
	}

	offset = client->communication.inbound.payload.buffer.size -
		client->communication.inbound.bytes_to_receive;
	if (client->communication.inbound.expect_creds) {
		recv_ret = lttcomm_recv_creds_unix_sock(
			socket,
			client->communication.inbound.payload.buffer.data + offset,
			client->communication.inbound.bytes_to_receive,
			&client->communication.inbound.creds);
		if (recv_ret > 0) {
			client->communication.inbound.expect_creds = false;
			client->communication.inbound.creds_received = true;
		}
	} else {
		recv_ret = lttcomm_recv_unix_sock_non_block(
			socket,
			client->communication.inbound.payload.buffer.data + offset,
			client->communication.inbound.bytes_to_receive);
	}
	if (recv_ret >= 0) {
		client->communication.inbound.bytes_to_receive -= recv_ret;
	} else {
		goto error_disconnect_client;
	}

	if (client->communication.inbound.bytes_to_receive != 0) {
		/* Message incomplete wait for more data. */
		ret = 0;
		goto end;
	}

receive_fds:
	LTTNG_ASSERT(client->communication.inbound.bytes_to_receive == 0);

	/* Receive fds. */
	if (client->communication.inbound.fds_to_receive != 0) {
		ret = lttcomm_recv_payload_fds_unix_sock_non_block(
			client->socket,
			client->communication.inbound.fds_to_receive,
			&client->communication.inbound.payload);
		if (ret > 0) {
			/*
			 * Fds received. non blocking fds passing is all
			 * or nothing.
			 */
			ssize_t expected_size;

			expected_size = sizeof(int) * client->communication.inbound.fds_to_receive;
			LTTNG_ASSERT(ret == expected_size);
			client->communication.inbound.fds_to_receive = 0;
		} else if (ret == 0) {
			/* Received nothing. */
			ret = 0;
			goto end;
		} else {
			goto error_disconnect_client;
		}
	}

	/* At this point the message is complete.*/
	LTTNG_ASSERT(client->communication.inbound.bytes_to_receive == 0 &&
		     client->communication.inbound.fds_to_receive == 0);
	ret = client_dispatch_message(client, state);
	if (ret) {
		/*
		 * Only returns an error if this client must be
		 * disconnected.
		 */
		goto error_disconnect_client;
	}

end:
	return ret;

error_disconnect_client:
	ret = notification_thread_client_disconnect(client, state);
	goto end;
}

/* Client ready to receive outgoing data. */
int handle_notification_thread_client_out(struct notification_thread_state *state, int socket)
{
	int ret;
	struct notification_client *client;
	enum client_transmission_status transmission_status;

	lttng::urcu::read_lock_guard read_lock;
	client = get_client_from_socket(socket, state);
	if (!client) {
		/* Internal error, abort. */
		ret = -1;
		goto end;
	}

	pthread_mutex_lock(&client->lock);
	if (!client_has_outbound_data_left(client)) {
		/*
		 * A client "out" event can be received when no payload is left
		 * to send under some circumstances.
		 *
		 * Many threads can flush a client's outgoing queue and, if they
		 * had to queue their message (socket was full), will use the
		 * "communication update" command to signal the (e)poll thread
		 * to monitor for space being made available in the socket.
		 *
		 * Commands are sent over an internal pipe serviced by the same
		 * thread as the client sockets.
		 *
		 * When space is made available in the socket, there is a race
		 * between the (e)poll thread and the other threads that may
		 * wish to use the client's socket to flush its outgoing queue.
		 *
		 * A non-(e)poll thread may attempt (and succeed) in flushing
		 * the queue before the (e)poll thread gets a chance to service
		 * the client's "out" event.
		 *
		 * In this situation, the (e)poll thread processing the client
		 * out event will see an empty payload: there is nothing to do
		 * except unsubscribing (e)poll "out" events.
		 *
		 * Note that this thread is the (e)poll thread so it can modify
		 * the (e)poll mask directly without using a communication
		 * update command. Other threads that flush the outgoing queue
		 * will use the "communication update" command to wake up this
		 * thread and force it to monitor "out" events.
		 *
		 * When other threads succeed in emptying the outgoing queue,
		 * they don't need to update the (e)poll mask: if the "out"
		 * event is monitored, it will fire once and the (e)poll
		 * thread will reach this condition, causing the event to
		 * stop being monitored.
		 */
		transmission_status = CLIENT_TRANSMISSION_STATUS_COMPLETE;
	} else {
		transmission_status = client_flush_outgoing_queue(client);
	}
	pthread_mutex_unlock(&client->lock);

	ret = client_handle_transmission_status(client, transmission_status, state);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static bool evaluate_buffer_usage_condition(const struct lttng_condition *condition,
					    const struct channel_state_sample *sample,
					    uint64_t buffer_capacity)
{
	bool result = false;
	uint64_t threshold;
	enum lttng_condition_type condition_type;
	const struct lttng_condition_buffer_usage *use_condition =
		lttng::utils::container_of(condition, &lttng_condition_buffer_usage::parent);

	if (use_condition->threshold_bytes.set) {
		threshold = use_condition->threshold_bytes.value;
	} else {
		/*
		 * Threshold was expressed as a ratio.
		 *
		 * TODO the threshold (in bytes) of conditions expressed
		 * as a ratio of total buffer size could be cached to
		 * forego this double-multiplication or it could be performed
		 * as fixed-point math.
		 *
		 * Note that caching should accommodates the case where the
		 * condition applies to multiple channels (i.e. don't assume
		 * that all channels matching my_chann* have the same size...)
		 */
		threshold = (uint64_t) (use_condition->threshold_ratio.value *
					(double) buffer_capacity);
	}

	condition_type = lttng_condition_get_type(condition);
	if (condition_type == LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW) {
		DBG("Low buffer usage condition being evaluated: threshold = %" PRIu64
		    ", highest usage = %" PRIu64,
		    threshold,
		    sample->highest_usage);

		/*
		 * The low condition should only be triggered once _all_ of the
		 * streams in a channel have gone below the "low" threshold.
		 */
		if (sample->highest_usage <= threshold) {
			result = true;
		}
	} else {
		DBG("High buffer usage condition being evaluated: threshold = %" PRIu64
		    ", highest usage = %" PRIu64,
		    threshold,
		    sample->highest_usage);

		/*
		 * For high buffer usage scenarios, we want to trigger whenever
		 * _any_ of the streams has reached the "high" threshold.
		 */
		if (sample->highest_usage >= threshold) {
			result = true;
		}
	}

	return result;
}

static int evaluate_buffer_condition(const struct lttng_condition *condition,
				     struct lttng_evaluation **evaluation,
				     const struct notification_thread_state *state
				     __attribute__((unused)),
				     const struct channel_state_sample *previous_sample,
				     const struct channel_state_sample *latest_sample,
				     struct channel_info *channel_info)
{
	int ret = 0;
	enum lttng_condition_type condition_type;
	const bool previous_sample_available = !!previous_sample;
	bool previous_sample_result = false;
	bool latest_sample_result;

	condition_type = lttng_condition_get_type(condition);

	switch (condition_type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		if (caa_likely(previous_sample_available)) {
			previous_sample_result = evaluate_buffer_usage_condition(
				condition, previous_sample, channel_info->capacity);
		}
		latest_sample_result = evaluate_buffer_usage_condition(
			condition, latest_sample, channel_info->capacity);
		break;
	default:
		/* Unknown condition type; internal error. */
		abort();
	}

	if (!latest_sample_result || (previous_sample_result == latest_sample_result)) {
		/*
		 * Only trigger on a condition evaluation transition.
		 *
		 * NOTE: This edge-triggered logic may not be appropriate for
		 * future condition types.
		 */
		goto end;
	}

	if (!evaluation || !latest_sample_result) {
		goto end;
	}

	switch (condition_type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
		*evaluation = lttng_evaluation_buffer_usage_create(
			condition_type, latest_sample->highest_usage, channel_info->capacity);
		break;
	default:
		abort();
	}

	if (!*evaluation) {
		ret = -1;
		goto end;
	}
end:
	return ret;
}

static int client_notification_overflow(struct notification_client *client)
{
	int ret = 0;
	struct lttng_notification_channel_message msg;

	msg.type = (int8_t) LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_NOTIFICATION_DROPPED;
	msg.size = 0;
	msg.fds = 0;

	ASSERT_LOCKED(client->lock);

	DBG("Dropping notification addressed to client (socket fd = %i)", client->socket);
	if (client->communication.outbound.dropped_notification) {
		/*
		 * The client already has a "notification dropped" message
		 * in its outgoing queue. Nothing to do since all
		 * of those messages are coalesced.
		 */
		goto end;
	}

	client->communication.outbound.dropped_notification = true;
	ret = lttng_dynamic_buffer_append(
		&client->communication.outbound.payload.buffer, &msg, sizeof(msg));
	if (ret) {
		PERROR("Failed to enqueue \"dropped notification\" message in client's (socket fd = %i) outgoing queue",
		       client->socket);
	}
end:
	return ret;
}

static int client_handle_transmission_status_wrapper(struct notification_client *client,
						     enum client_transmission_status status,
						     void *user_data)
{
	return client_handle_transmission_status(
		client, status, (struct notification_thread_state *) user_data);
}

static int send_evaluation_to_clients(const struct lttng_trigger *trigger,
				      const struct lttng_evaluation *evaluation,
				      struct notification_client_list *client_list,
				      struct notification_thread_state *state,
				      uid_t object_uid,
				      gid_t object_gid)
{
	const struct lttng_credentials creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(object_uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE(object_gid),
	};

	return notification_client_list_send_evaluation(client_list,
							trigger,
							evaluation,
							&creds,
							client_handle_transmission_status_wrapper,
							state);
}

/*
 * Permission checks relative to notification channel clients are performed
 * here. Notice how object, client, and trigger credentials are involved in
 * this check.
 *
 * The `object` credentials are the credentials associated with the "subject"
 * of a condition. For instance, a `rotation completed` condition applies
 * to a session. When that condition is met, it will produce an evaluation
 * against a session. Hence, in this case, the `object` credentials are the
 * credentials of the "subject" session.
 *
 * The `trigger` credentials are the credentials of the user that registered the
 * trigger.
 *
 * The `client` credentials are the credentials of the user that created a given
 * notification channel.
 *
 * In terms of visibility, it is expected that non-privilieged users can only
 * register triggers against "their" objects (their own sessions and
 * applications they are allowed to interact with). They can then open a
 * notification channel and subscribe to notifications associated with those
 * triggers.
 *
 * As for privilieged users, they can register triggers against the objects of
 * other users. They can then subscribe to the notifications associated to their
 * triggers. Privilieged users _can't_ subscribe to the notifications of
 * triggers owned by other users; they must create their own triggers.
 *
 * This is more a concern of usability than security. It would be difficult for
 * a root user reliably subscribe to a specific set of conditions without
 * interference from external users (those could, for instance, unregister
 * their triggers).
 */
int notification_client_list_send_evaluation(struct notification_client_list *client_list,
					     const struct lttng_trigger *trigger,
					     const struct lttng_evaluation *evaluation,
					     const struct lttng_credentials *source_object_creds,
					     report_client_transmission_result_cb client_report,
					     void *user_data)
{
	int ret = 0;
	struct lttng_payload msg_payload;
	struct notification_client_list_element *client_list_element, *tmp;
	const struct lttng_notification notification = {
		.trigger = (struct lttng_trigger *) trigger,
		.evaluation = (struct lttng_evaluation *) evaluation,
	};
	struct lttng_notification_channel_message msg_header;
	const struct lttng_credentials *trigger_creds = lttng_trigger_get_credentials(trigger);

	lttng_payload_init(&msg_payload);

	msg_header.type = (int8_t) LTTNG_NOTIFICATION_CHANNEL_MESSAGE_TYPE_NOTIFICATION;
	msg_header.size = 0;
	msg_header.fds = 0;

	ret = lttng_dynamic_buffer_append(&msg_payload.buffer, &msg_header, sizeof(msg_header));
	if (ret) {
		goto end;
	}

	ret = lttng_notification_serialize(&notification, &msg_payload);
	if (ret) {
		ERR("Failed to serialize notification");
		ret = -1;
		goto end;
	}

	/* Update payload size. */
	((struct lttng_notification_channel_message *) msg_payload.buffer.data)->size =
		(uint32_t) (msg_payload.buffer.size - sizeof(msg_header));

	/* Update the payload number of fds. */
	{
		const struct lttng_payload_view pv =
			lttng_payload_view_from_payload(&msg_payload, 0, -1);

		((struct lttng_notification_channel_message *) msg_payload.buffer.data)->fds =
			(uint32_t) lttng_payload_view_get_fd_handle_count(&pv);
	}

	pthread_mutex_lock(&client_list->lock);
	cds_list_for_each_entry_safe (client_list_element, tmp, &client_list->clients_list, node) {
		enum client_transmission_status transmission_status;
		struct notification_client *client = client_list_element->client;

		ret = 0;
		pthread_mutex_lock(&client->lock);
		if (!client->communication.active) {
			/*
			 * Skip inactive client (protocol error or
			 * disconnecting).
			 */
			DBG("Skipping client at it is marked as inactive");
			goto skip_client;
		}

		if (lttng_trigger_is_hidden(trigger) && !client->is_sessiond) {
			/*
			 * Notifications resulting from an hidden trigger are
			 * only sent to the session daemon.
			 */
			DBG("Skipping client as the trigger is hidden and the client is not the session daemon");
			goto skip_client;
		}

		if (source_object_creds) {
			if (client->uid != lttng_credentials_get_uid(source_object_creds) &&
			    client->gid != lttng_credentials_get_gid(source_object_creds) &&
			    client->uid != 0) {
				/*
				 * Client is not allowed to monitor this
				 * object.
				 */
				DBG("Skipping client at it does not have the object permission to receive notification for this trigger");
				goto skip_client;
			}
		}

		if (client->uid != lttng_credentials_get_uid(trigger_creds)) {
			DBG("Skipping client at it does not have the permission to receive notification for this trigger");
			goto skip_client;
		}

		DBG("Sending notification to client (fd = %i, %zu bytes)",
		    client->socket,
		    msg_payload.buffer.size);

		if (client_has_outbound_data_left(client)) {
			/*
			 * Outgoing data is already buffered for this client;
			 * drop the notification and enqueue a "dropped
			 * notification" message if this is the first dropped
			 * notification since the socket spilled-over to the
			 * queue.
			 */
			ret = client_notification_overflow(client);
			if (ret) {
				/* Fatal error. */
				goto skip_client;
			}
		}

		ret = lttng_payload_copy(&msg_payload, &client->communication.outbound.payload);
		if (ret) {
			/* Fatal error. */
			goto skip_client;
		}

		transmission_status = client_flush_outgoing_queue(client);
		pthread_mutex_unlock(&client->lock);
		ret = client_report(client, transmission_status, user_data);
		if (ret) {
			/* Fatal error. */
			goto end_unlock_list;
		}

		continue;

	skip_client:
		pthread_mutex_unlock(&client->lock);
		if (ret) {
			/* Fatal error. */
			goto end_unlock_list;
		}
	}
	ret = 0;

end_unlock_list:
	pthread_mutex_unlock(&client_list->lock);
end:
	lttng_payload_reset(&msg_payload);
	return ret;
}

static struct lttng_event_notifier_notification *
recv_one_event_notifier_notification(int notification_pipe_read_fd, enum lttng_domain_type domain)
{
	int ret;
	uint64_t token;
	struct lttng_event_notifier_notification *notification = nullptr;
	char *capture_buffer = nullptr;
	size_t capture_buffer_size;
	void *reception_buffer;
	size_t reception_size;

	struct lttng_ust_abi_event_notifier_notification ust_notification;
	struct lttng_kernel_abi_event_notifier_notification kernel_notification;

	/* Init lttng_event_notifier_notification */
	switch (domain) {
	case LTTNG_DOMAIN_UST:
		reception_buffer = (void *) &ust_notification;
		reception_size = sizeof(ust_notification);
		break;
	case LTTNG_DOMAIN_KERNEL:
		reception_buffer = (void *) &kernel_notification;
		reception_size = sizeof(kernel_notification);
		break;
	default:
		abort();
	}

	/*
	 * The monitoring pipe only holds messages smaller than PIPE_BUF,
	 * ensuring that read/write of tracer notifications are atomic.
	 */
	ret = lttng_read(notification_pipe_read_fd, reception_buffer, reception_size);
	if (ret != reception_size) {
		PERROR("Failed to read from event source notification pipe: fd = %d, size to read = %zu, ret = %d",
		       notification_pipe_read_fd,
		       reception_size,
		       ret);
		ret = -1;
		goto end;
	}

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		token = ust_notification.token;
		capture_buffer_size = ust_notification.capture_buf_size;
		break;
	case LTTNG_DOMAIN_KERNEL:
		token = kernel_notification.token;
		capture_buffer_size = kernel_notification.capture_buf_size;
		break;
	default:
		abort();
	}

	if (capture_buffer_size == 0) {
		capture_buffer = nullptr;
		goto skip_capture;
	}

	if (capture_buffer_size > MAX_CAPTURE_SIZE) {
		ERR("Event notifier has a capture payload size which exceeds the maximum allowed size: capture_payload_size = %zu bytes, max allowed size = %d bytes",
		    capture_buffer_size,
		    MAX_CAPTURE_SIZE);
		goto end;
	}

	capture_buffer = calloc<char>(capture_buffer_size);
	if (!capture_buffer) {
		ERR("Failed to allocate capture buffer");
		goto end;
	}

	/* Fetch additional payload (capture). */
	ret = lttng_read(notification_pipe_read_fd, capture_buffer, capture_buffer_size);
	if (ret != capture_buffer_size) {
		ERR("Failed to read from event source pipe (fd = %i)", notification_pipe_read_fd);
		goto end;
	}

skip_capture:
	notification = lttng_event_notifier_notification_create(
		token, domain, capture_buffer, capture_buffer_size);
	if (notification == nullptr) {
		goto end;
	}

	/*
	 * Ownership transfered to the lttng_event_notifier_notification object.
	 */
	capture_buffer = nullptr;

end:
	free(capture_buffer);
	return notification;
}

static int
dispatch_one_event_notifier_notification(struct notification_thread_state *state,
					 struct lttng_event_notifier_notification *notification)
{
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct notification_trigger_tokens_ht_element *element;
	struct lttng_evaluation *evaluation = nullptr;
	enum action_executor_status executor_status;
	struct notification_client_list *client_list = nullptr;
	int ret;
	unsigned int capture_count = 0;

	/* Find triggers associated with this token. */
	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_lookup(state->trigger_tokens_ht,
			hash_key_u64(&notification->tracer_token, lttng_ht_seed),
			match_trigger_token,
			&notification->tracer_token,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (caa_unlikely(!node)) {
		/*
		 * This is not an error, slow consumption of the tracer
		 * notifications can lead to situations where a trigger is
		 * removed but we still get tracer notifications matching a
		 * trigger that no longer exists.
		 */
		ret = 0;
		goto end_unlock;
	}

	element = caa_container_of(node, struct notification_trigger_tokens_ht_element, node);

	if (lttng_condition_event_rule_matches_get_capture_descriptor_count(
		    lttng_trigger_get_const_condition(element->trigger), &capture_count) !=
	    LTTNG_CONDITION_STATUS_OK) {
		ERR("Failed to get capture count");
		ret = -1;
		goto end;
	}

	if (!notification->capture_buffer && capture_count != 0) {
		ERR("Expected capture but capture buffer is null");
		ret = -1;
		goto end;
	}

	evaluation = lttng_evaluation_event_rule_matches_create(
		lttng::utils::container_of(lttng_trigger_get_const_condition(element->trigger),
					   &lttng_condition_event_rule_matches::parent),
		notification->capture_buffer,
		notification->capture_buf_size,
		false);

	if (evaluation == nullptr) {
		ERR("Failed to create event rule matches evaluation while creating and enqueuing action executor job");
		ret = -1;
		goto end_unlock;
	}

	client_list = get_client_list_from_condition(
		state, lttng_trigger_get_const_condition(element->trigger));
	executor_status = action_executor_enqueue_trigger(
		state->executor, element->trigger, evaluation, nullptr, client_list);
	switch (executor_status) {
	case ACTION_EXECUTOR_STATUS_OK:
		ret = 0;
		break;
	case ACTION_EXECUTOR_STATUS_OVERFLOW:
	{
		struct notification_client_list_element *client_list_element, *tmp;

		/*
		 * Not a fatal error; this is expected and simply means the
		 * executor has too much work queued already.
		 */
		ret = 0;

		/* No clients subscribed to notifications for this trigger. */
		if (!client_list) {
			break;
		}

		/* Warn clients that a notification (or more) was dropped. */
		pthread_mutex_lock(&client_list->lock);
		cds_list_for_each_entry_safe (
			client_list_element, tmp, &client_list->clients_list, node) {
			enum client_transmission_status transmission_status;
			struct notification_client *client = client_list_element->client;

			pthread_mutex_lock(&client->lock);
			ret = client_notification_overflow(client);
			if (ret) {
				/* Fatal error. */
				goto next_client;
			}

			transmission_status = client_flush_outgoing_queue(client);
			ret = client_handle_transmission_status(client, transmission_status, state);
			if (ret) {
				/* Fatal error. */
				goto next_client;
			}
		next_client:
			pthread_mutex_unlock(&client->lock);
			if (ret) {
				break;
			}
		}

		pthread_mutex_unlock(&client_list->lock);
		break;
	}
	case ACTION_EXECUTOR_STATUS_INVALID:
	case ACTION_EXECUTOR_STATUS_ERROR:
		/* Fatal error, shut down everything. */
		ERR("Fatal error encoutered while enqueuing action to the action executor");
		ret = -1;
		goto end_unlock;
	default:
		/* Unhandled error. */
		abort();
	}

end_unlock:
	notification_client_list_put(client_list);
end:
	return ret;
}

static int handle_one_event_notifier_notification(struct notification_thread_state *state,
						  int pipe,
						  enum lttng_domain_type domain)
{
	int ret = 0;
	struct lttng_event_notifier_notification *notification = nullptr;

	notification = recv_one_event_notifier_notification(pipe, domain);
	if (notification == nullptr) {
		/* Reception failed, don't consider it fatal. */
		ERR("Error receiving an event notifier notification from tracer: fd = %i, domain = %s",
		    pipe,
		    lttng_domain_type_str(domain));
		goto end;
	}

	ret = dispatch_one_event_notifier_notification(state, notification);
	if (ret) {
		ERR("Error dispatching an event notifier notification from tracer: fd = %i, domain = %s",
		    pipe,
		    lttng_domain_type_str(domain));
		goto end;
	}

end:
	lttng_event_notifier_notification_destroy(notification);
	return ret;
}

int handle_notification_thread_event_notification(struct notification_thread_state *state,
						  int pipe,
						  enum lttng_domain_type domain)
{
	return handle_one_event_notifier_notification(state, pipe, domain);
}

int handle_notification_thread_channel_sample(struct notification_thread_state *state,
					      int pipe,
					      enum lttng_domain_type domain)
{
	int ret = 0;
	struct lttcomm_consumer_channel_monitor_msg sample_msg;
	struct channel_info *channel_info = nullptr;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct lttng_channel_trigger_list *channel_trigger_list;
	struct lttng_session_trigger_list *session_trigger_list;
	struct lttng_trigger_list_element *trigger_list_element;
	bool previous_sample_available = false;
	struct channel_state_sample channel_previous_sample, channel_new_sample;
	struct session_state_sample session_new_sample;
	struct lttng_credentials channel_creds = {};
	struct lttng_credentials session_creds = {};
	struct session_info *session;
	lttng::urcu::read_lock_guard read_lock;

	/*
	 * The monitoring pipe only holds messages smaller than PIPE_BUF,
	 * ensuring that read/write of sampling messages are atomic.
	 */
	ret = lttng_read(pipe, &sample_msg, sizeof(sample_msg));
	if (ret != sizeof(sample_msg)) {
		ERR("Failed to read from monitoring pipe (fd = %i)", pipe);
		ret = -1;
		goto end;
	}

	ret = 0;
	channel_new_sample.key.key = sample_msg.key;
	channel_new_sample.key.domain = domain;
	channel_new_sample.highest_usage = sample_msg.highest;
	channel_new_sample.lowest_usage = sample_msg.lowest;

	session = get_session_info_by_id(state, sample_msg.session_id);
	if (!session) {
		DBG("Received a sample for an unknown session from consumerd: session id = %" PRIu64,
		    sample_msg.session_id);
		goto end_unlock;
	}

	session_new_sample = session->last_state_sample;
	session_new_sample.consumed_data_size += sample_msg.consumed_since_last_sample;
	session_creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(session->uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE(session->gid),
	};

	session_trigger_list = get_session_trigger_list(state, session->name);
	LTTNG_ASSERT(session_trigger_list);
	cds_list_for_each_entry (trigger_list_element, &session_trigger_list->list, node) {
		const struct lttng_condition *condition;
		struct lttng_trigger *trigger;
		struct notification_client_list *client_list = nullptr;
		struct lttng_evaluation *evaluation = nullptr;
		enum action_executor_status executor_status;

		ret = 0;
		trigger = trigger_list_element->trigger;
		condition = lttng_trigger_get_const_condition(trigger);
		LTTNG_ASSERT(condition);

		ret = evaluate_session_condition(
			condition, session, &session_new_sample, &evaluation);
		if (caa_unlikely(ret)) {
			break;
		}

		if (caa_likely(!evaluation)) {
			continue;
		}

		/*
		 * Ownership of `evaluation` transferred to the action executor
		 * no matter the result. The callee acquires a reference to the
		 * client list: we can release our own.
		 */
		client_list = get_client_list_from_condition(state, condition);
		executor_status = action_executor_enqueue_trigger(
			state->executor, trigger, evaluation, &session_creds, client_list);
		notification_client_list_put(client_list);
		evaluation = nullptr;
		switch (executor_status) {
		case ACTION_EXECUTOR_STATUS_OK:
			break;
		case ACTION_EXECUTOR_STATUS_ERROR:
		case ACTION_EXECUTOR_STATUS_INVALID:
			/*
			 * TODO Add trigger identification (name/id) when
			 * it is added to the API.
			 */
			ERR("Fatal error occurred while enqueuing action associated with buffer-condition trigger");
			ret = -1;
			goto end_unlock;
		case ACTION_EXECUTOR_STATUS_OVERFLOW:
			/*
			 * TODO Add trigger identification (name/id) when
			 * it is added to the API.
			 *
			 * Not a fatal error.
			 */
			WARN("No space left when enqueuing action associated with buffer-condition trigger");
			ret = 0;
			goto end_unlock;
		default:
			abort();
		}
	}

	/* Retrieve the channel's informations */
	cds_lfht_lookup(state->channels_ht,
			hash_channel_key(&channel_new_sample.key),
			match_channel_info,
			&channel_new_sample.key,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (caa_unlikely(!node)) {
		/*
		 * Not an error since the consumer can push a sample to the pipe
		 * and the rest of the session daemon could notify us of the
		 * channel's destruction before we get a chance to process that
		 * sample.
		 */
		DBG("Received a sample for an unknown channel from consumerd, key = %" PRIu64
		    " in %s domain",
		    channel_new_sample.key.key,
		    lttng_domain_type_str(domain));
		goto end_unlock;
	}

	channel_info = caa_container_of(node, struct channel_info, channels_ht_node);
	DBG("Handling channel sample for channel %s (key = %" PRIu64
	    ") in session %s (highest usage = %" PRIu64 ", lowest usage = %" PRIu64
	    ", consumed since last sample = %" PRIu64 ")",
	    channel_info->name,
	    channel_new_sample.key.key,
	    channel_info->session_info->name,
	    channel_new_sample.highest_usage,
	    channel_new_sample.lowest_usage,
	    sample_msg.consumed_since_last_sample);

	/* Retrieve the channel's last sample, if it exists, and update it. */
	cds_lfht_lookup(state->channel_state_ht,
			hash_channel_key(&channel_new_sample.key),
			match_channel_state_sample,
			&channel_new_sample.key,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (caa_likely(node)) {
		struct channel_state_sample *stored_sample;

		/* Update the sample stored. */
		stored_sample =
			caa_container_of(node, struct channel_state_sample, channel_state_ht_node);

		memcpy(&channel_previous_sample, stored_sample, sizeof(channel_previous_sample));
		stored_sample->highest_usage = channel_new_sample.highest_usage;
		stored_sample->lowest_usage = channel_new_sample.lowest_usage;
		previous_sample_available = true;
	} else {
		/*
		 * This is the channel's first sample, allocate space for and
		 * store the new sample.
		 */
		struct channel_state_sample *stored_sample;

		stored_sample = zmalloc<channel_state_sample>();
		if (!stored_sample) {
			ret = -1;
			goto end_unlock;
		}

		memcpy(stored_sample, &channel_new_sample, sizeof(*stored_sample));
		cds_lfht_node_init(&stored_sample->channel_state_ht_node);
		cds_lfht_add(state->channel_state_ht,
			     hash_channel_key(&stored_sample->key),
			     &stored_sample->channel_state_ht_node);
	}

	/* Find triggers associated with this channel. */
	cds_lfht_lookup(state->channel_triggers_ht,
			hash_channel_key(&channel_new_sample.key),
			match_channel_trigger_list,
			&channel_new_sample.key,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	LTTNG_ASSERT(node);

	channel_creds = (typeof(channel_creds)){
		.uid = LTTNG_OPTIONAL_INIT_VALUE(channel_info->session_info->uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE(channel_info->session_info->gid),
	};

	channel_trigger_list =
		caa_container_of(node, struct lttng_channel_trigger_list, channel_triggers_ht_node);
	cds_list_for_each_entry (trigger_list_element, &channel_trigger_list->list, node) {
		const struct lttng_condition *condition;
		struct lttng_trigger *trigger;
		struct notification_client_list *client_list = nullptr;
		struct lttng_evaluation *evaluation = nullptr;
		enum action_executor_status executor_status;

		ret = 0;
		trigger = trigger_list_element->trigger;
		condition = lttng_trigger_get_const_condition(trigger);
		LTTNG_ASSERT(condition);

		ret = evaluate_buffer_condition(
			condition,
			&evaluation,
			state,
			previous_sample_available ? &channel_previous_sample : nullptr,
			&channel_new_sample,
			channel_info);
		if (caa_unlikely(ret)) {
			break;
		}

		if (caa_likely(!evaluation)) {
			continue;
		}

		/*
		 * Ownership of `evaluation` transferred to the action executor
		 * no matter the result. The callee acquires a reference to the
		 * client list: we can release our own.
		 */
		client_list = get_client_list_from_condition(state, condition);
		executor_status = action_executor_enqueue_trigger(
			state->executor, trigger, evaluation, &channel_creds, client_list);
		notification_client_list_put(client_list);
		evaluation = nullptr;
		switch (executor_status) {
		case ACTION_EXECUTOR_STATUS_OK:
			break;
		case ACTION_EXECUTOR_STATUS_ERROR:
		case ACTION_EXECUTOR_STATUS_INVALID:
			/*
			 * TODO Add trigger identification (name/id) when
			 * it is added to the API.
			 */
			ERR("Fatal error occurred while enqueuing action associated with buffer-condition trigger");
			ret = -1;
			goto end_unlock;
		case ACTION_EXECUTOR_STATUS_OVERFLOW:
			/*
			 * TODO Add trigger identification (name/id) when
			 * it is added to the API.
			 *
			 * Not a fatal error.
			 */
			WARN("No space left when enqueuing action associated with buffer-condition trigger");
			ret = 0;
			goto end_unlock;
		default:
			abort();
		}
	}
end_unlock:
	if (session) {
		session->last_state_sample = session_new_sample;
	}
	session_info_put(session);
end:
	return ret;
}
