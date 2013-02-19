/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#define _GNU_SOURCE
#include <assert.h>

#include <common/common.h>
#include "ust-registry.h"

/*
 * Hash table match function for event in the registry.
 */
static int ht_match_event(struct cds_lfht_node *node, const void *_key)
{
	struct ust_registry_event *event;
	const struct ust_registry_event *key;

	assert(node);
	assert(_key);

	event = caa_container_of(node, struct ust_registry_event, node.node);
	assert(event);
	key = _key;

	/* It has to be a perfect match. */
	if (strncmp(event->name, key->name, sizeof(event->name)) != 0) {
		goto no_match;
	}

	/* It has to be a perfect match. */
	if (strncmp(event->signature, key->signature,
				strlen(event->signature) != 0)) {
		goto no_match;
	}

	/* Match */
	return 1;

no_match:
	return 0;
}

/*
 * Allocate event and initialize it. This does NOT set a valid event id from a
 * registry.
 */
static struct ust_registry_event *alloc_event(int session_objd,
		int channel_objd, char *name, char *sig, size_t nr_fields,
		struct ustctl_field *fields, int loglevel, char *model_emf_uri)
{
	struct ust_registry_event *event = NULL;

	event = zmalloc(sizeof(*event));
	if (!event) {
		PERROR("zmalloc ust registry event");
		goto error;
	}

	event->session_objd = session_objd;
	event->channel_objd = channel_objd;
	/* Allocated by ustctl. */
	event->signature = sig;
	event->nr_fields = nr_fields;
	event->fields = fields;
	event->loglevel = loglevel;
	event->model_emf_uri = model_emf_uri;
	if (name) {
		/* Copy event name and force NULL byte. */
		strncpy(event->name, name, sizeof(event->name));
		event->name[sizeof(event->name) - 1] = '\0';
	}
	lttng_ht_node_init_str(&event->node, event->name);

error:
	return event;
}

/*
 * Free event data structure. This does NOT delete it from any hash table. It's
 * safe to pass a NULL pointer. This shoudl be called inside a call RCU if the
 * event is previously deleted from a rcu hash table.
 */
static void destroy_event(struct ust_registry_event *event)
{
	if (!event) {
		return;
	}

	free(event->fields);
	free(event->model_emf_uri);
	free(event->signature);
	free(event);
}

/*
 * Destroy event function call of the call RCU.
 */
static void destroy_event_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_str *node =
		caa_container_of(head, struct lttng_ht_node_str, head);
	struct ust_registry_event *event =
		caa_container_of(node, struct ust_registry_event, node);

	destroy_event(event);
}

/*
 * Find an event using the name and signature in the given registry. RCU read
 * side lock MUST be acquired before calling this function and as long as the
 * event reference is kept by the caller.
 *
 * On success, the event pointer is returned else NULL.
 */
struct ust_registry_event *ust_registry_find_event(
		struct ust_registry_channel *chan, char *name, char *sig)
{
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct ust_registry_event *event = NULL;
	struct ust_registry_event key;

	assert(chan);
	assert(name);
	assert(sig);

	/* Setup key for the match function. */
	strncpy(key.name, name, sizeof(key.name));
	key.name[sizeof(key.name) - 1] = '\0';
	key.signature = sig;

	cds_lfht_lookup(chan->ht->ht, chan->ht->hash_fct(name, lttng_ht_seed),
			chan->ht->match_fct, &key, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (!node) {
		goto end;
	}
	event = caa_container_of(node, struct ust_registry_event, node);

end:
	return event;
}

/*
 * Create a ust_registry_event from the given parameters and add it to the
 * registry hash table. If event_id is valid, it is set with the newly created
 * event id.
 *
 * On success, return 0 else a negative value. The created event MUST be unique
 * so on duplicate entry -EINVAL is returned. On error, event_id is untouched.
 *
 * Should be called with session registry mutex held.
 */
int ust_registry_create_event(struct ust_registry_session *session,
		struct ust_registry_channel *chan,
		int session_objd, int channel_objd, char *name, char *sig,
		size_t nr_fields, struct ustctl_field *fields, int loglevel,
		char *model_emf_uri, uint32_t *event_id)
{
	int ret;
	struct cds_lfht_node *nptr;
	struct ust_registry_event *event = NULL;

	assert(session);
	assert(chan);
	assert(name);
	assert(sig);

	/*
	 * This should not happen but since it comes from the UST tracer, an
	 * external party, don't assert and simply validate values.
	 */
	if (session_objd < 0 || channel_objd < 0) {
		ret = -EINVAL;
		goto error;
	}

	/* Check if we've reached the maximum possible id. */
	if (ust_registry_is_max_id(chan->used_event_id)) {
		ret = -ENOENT;
		goto error;
	}

	event = alloc_event(session_objd, channel_objd, name, sig, nr_fields,
			fields, loglevel, model_emf_uri);
	if (!event) {
		ret = -ENOMEM;
		goto error;
	}

	event->id = ust_registry_get_next_event_id(chan);

	DBG3("UST registry creating event with event: %s, sig: %s, id: %u, "
			"chan_objd: %u, sess_objd: %u", event->name, event->signature,
			event->id, event->channel_objd, event->session_objd);

	rcu_read_lock();
	/*
	 * This is an add unique with a custom match function for event. The node
	 * are matched using the event name and signature.
	 */
	nptr = cds_lfht_add_unique(chan->ht->ht, chan->ht->hash_fct(event->node.key,
				lttng_ht_seed), chan->ht->match_fct, event, &event->node.node);
	if (nptr != &event->node.node) {
		ERR("UST registry create event add unique failed for event: %s, "
				"sig: %s, id: %u, chan_objd: %u, sess_objd: %u", event->name,
				event->signature, event->id, event->channel_objd,
				event->session_objd);
		ret = -EINVAL;
		goto error_unlock;
	}

	/* Set event id if user wants it. */
	if (event_id) {
		*event_id = event->id;
	}
	rcu_read_unlock();

	/* Append to metadata */
	ret = ust_metadata_event_statedump(session, chan, event);
	if (ret) {
		ERR("Error appending event metadata (errno = %d)", ret);
		return ret;
	}

	return 0;

error_unlock:
	rcu_read_unlock();
error:
	destroy_event(event);
	return ret;
}

/*
 * For a given event in a registry, delete the entry and destroy the event.
 * This MUST be called within a RCU read side lock section.
 */
void ust_registry_destroy_event(struct ust_registry_channel *chan,
		struct ust_registry_event *event)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(chan);
	assert(event);

	/* Delete the node first. */
	iter.iter.node = &event->node.node;
	ret = lttng_ht_del(chan->ht, &iter);
	assert(!ret);

	call_rcu(&event->node.head, destroy_event_rcu);

	return;
}

/*
 * Initialize registry with default values.
 */
void ust_registry_channel_init(struct ust_registry_session *session,
		struct ust_registry_channel *chan)
{
	assert(chan);

	memset(chan, 0, sizeof(struct ust_registry_channel));

	chan->ht = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	assert(chan->ht);

	/* Set custom match function. */
	chan->ht->match_fct = ht_match_event;
}

/*
 * Destroy every element of the registry and free the memory. This does NOT
 * free the registry pointer since it might not have been allocated before so
 * it's the caller responsability.
 *
 * This MUST be called within a RCU read side lock section.
 */
void ust_registry_channel_destroy(struct ust_registry_session *session,
		struct ust_registry_channel *chan)
{
	struct lttng_ht_iter iter;
	struct ust_registry_event *event;

	assert(chan);

	/* Destroy all event associated with this registry. */
	cds_lfht_for_each_entry(chan->ht->ht, &iter.iter, event, node.node) {
		/* Delete the node from the ht and free it. */
		ust_registry_destroy_event(chan, event);
	}
	lttng_ht_destroy(chan->ht);
}

/*
 * Initialize registry with default values.
 */
int ust_registry_session_init(struct ust_registry_session *session,
		struct ust_app *app,
		uint32_t bits_per_long,
		uint32_t uint8_t_alignment,
		uint32_t uint16_t_alignment,
		uint32_t uint32_t_alignment,
		uint32_t uint64_t_alignment,
		uint32_t long_alignment,
		int byte_order)
{
	int ret;

	assert(session);

	memset(session, 0, sizeof(struct ust_registry_session));

	pthread_mutex_init(&session->lock, NULL);
	session->bits_per_long = bits_per_long;
	session->uint8_t_alignment = uint8_t_alignment;
	session->uint16_t_alignment = uint16_t_alignment;
	session->uint32_t_alignment = uint32_t_alignment;
	session->uint64_t_alignment = uint64_t_alignment;
	session->long_alignment = long_alignment;
	session->byte_order = byte_order;

	ret = lttng_uuid_generate(session->uuid);
	if (ret) {
		ERR("Failed to generate UST uuid (errno = %d)", ret);
		goto error;
	}

	pthread_mutex_lock(&session->lock);
	ret = ust_metadata_session_statedump(session, app);
	pthread_mutex_unlock(&session->lock);
	if (ret) {
		ERR("Failed to generate session metadata (errno = %d)", ret);
		goto error;
	}

	return 0;

error:
	return -1;
}

/*
 * Destroy session registry. This does NOT free the given pointer since it
 * might get passed as a reference. The registry lock should NOT be acquired.
 */
void ust_registry_session_destroy(struct ust_registry_session *reg)
{
	int ret;

	/* On error, EBUSY can be returned if lock. Code flow error. */
	ret = pthread_mutex_destroy(&reg->lock);
	assert(!ret);

	free(reg->metadata);
}
