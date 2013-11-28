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
#include <inttypes.h>

#include <common/common.h>
#include <common/hashtable/utils.h>
#include <lttng/lttng.h>

#include "ust-registry.h"
#include "ust-app.h"
#include "utils.h"

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

static unsigned long ht_hash_event(void *_key, unsigned long seed)
{
	uint64_t xored_key;
	struct ust_registry_event *key = _key;

	assert(key);

	xored_key = (uint64_t) (hash_key_str(key->name, seed) ^
			hash_key_str(key->signature, seed));

	return hash_key_u64(&xored_key, seed);
}

/*
 * Return negative value on error, 0 if OK.
 *
 * TODO: we could add stricter verification of more types to catch
 * errors in liblttng-ust implementation earlier than consumption by the
 * trace reader.
 */
static
int validate_event_field(struct ustctl_field *field,
		const char *event_name,
		struct ust_app *app)
{
	switch(field->type.atype) {
	case ustctl_atype_integer:
	case ustctl_atype_enum:
	case ustctl_atype_array:
	case ustctl_atype_sequence:
	case ustctl_atype_string:
		break;

	case ustctl_atype_float:
		switch (field->type.u.basic._float.mant_dig) {
		case 0:
			WARN("UST application '%s' (pid: %d) has unknown float mantissa '%u' "
				"in field '%s', rejecting event '%s'",
				app->name, app->pid,
				field->type.u.basic._float.mant_dig,
				field->name,
				event_name);
			return -EINVAL;
		default:
			break;
		}
		break;

	default:
		return -ENOENT;
	}
	return 0;
}

static
int validate_event_fields(size_t nr_fields, struct ustctl_field *fields,
		const char *event_name, struct ust_app *app)
{
	unsigned int i;

	for (i = 0; i < nr_fields; i++) {
		if (validate_event_field(&fields[i], event_name, app) < 0)
			return -EINVAL;
	}
	return 0;
}

/*
 * Allocate event and initialize it. This does NOT set a valid event id from a
 * registry.
 */
static struct ust_registry_event *alloc_event(int session_objd,
		int channel_objd, char *name, char *sig, size_t nr_fields,
		struct ustctl_field *fields, int loglevel, char *model_emf_uri,
		struct ust_app *app)
{
	struct ust_registry_event *event = NULL;

	/*
	 * Ensure that the field content is valid.
	 */
	if (validate_event_fields(nr_fields, fields, name, app) < 0) {
		return NULL;
	}

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
	cds_lfht_node_init(&event->node.node);

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
	struct lttng_ht_node_u64 *node =
		caa_container_of(head, struct lttng_ht_node_u64, head);
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
	struct lttng_ht_node_u64 *node;
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

	cds_lfht_lookup(chan->ht->ht, chan->ht->hash_fct(&key, lttng_ht_seed),
			chan->ht->match_fct, &key, &iter.iter);
	node = lttng_ht_iter_get_node_u64(&iter);
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
		uint64_t chan_key, int session_objd, int channel_objd, char *name,
		char *sig, size_t nr_fields, struct ustctl_field *fields, int loglevel,
		char *model_emf_uri, int buffer_type, uint32_t *event_id_p,
		struct ust_app *app)
{
	int ret;
	uint32_t event_id;
	struct cds_lfht_node *nptr;
	struct ust_registry_event *event = NULL;
	struct ust_registry_channel *chan;

	assert(session);
	assert(name);
	assert(sig);
	assert(event_id_p);

	rcu_read_lock();

	/*
	 * This should not happen but since it comes from the UST tracer, an
	 * external party, don't assert and simply validate values.
	 */
	if (session_objd < 0 || channel_objd < 0) {
		ret = -EINVAL;
		goto error_free;
	}

	chan = ust_registry_channel_find(session, chan_key);
	if (!chan) {
		ret = -EINVAL;
		goto error_free;
	}

	/* Check if we've reached the maximum possible id. */
	if (ust_registry_is_max_id(chan->used_event_id)) {
		ret = -ENOENT;
		goto error_free;
	}

	event = alloc_event(session_objd, channel_objd, name, sig, nr_fields,
			fields, loglevel, model_emf_uri, app);
	if (!event) {
		ret = -ENOMEM;
		goto error_free;
	}

	DBG3("UST registry creating event with event: %s, sig: %s, id: %u, "
			"chan_objd: %u, sess_objd: %u, chan_id: %u", event->name,
			event->signature, event->id, event->channel_objd,
			event->session_objd, chan->chan_id);

	/*
	 * This is an add unique with a custom match function for event. The node
	 * are matched using the event name and signature.
	 */
	nptr = cds_lfht_add_unique(chan->ht->ht, chan->ht->hash_fct(event,
				lttng_ht_seed), chan->ht->match_fct, event, &event->node.node);
	if (nptr != &event->node.node) {
		if (buffer_type == LTTNG_BUFFER_PER_UID) {
			/*
			 * This is normal, we just have to send the event id of the
			 * returned node and make sure we destroy the previously allocated
			 * event object.
			 */
			destroy_event(event);
			event = caa_container_of(nptr, struct ust_registry_event,
					node.node);
			assert(event);
			event_id = event->id;
		} else {
			ERR("UST registry create event add unique failed for event: %s, "
					"sig: %s, id: %u, chan_objd: %u, sess_objd: %u",
					event->name, event->signature, event->id,
					event->channel_objd, event->session_objd);
			ret = -EINVAL;
			goto error_unlock;
		}
	} else {
		/* Request next event id if the node was successfully added. */
		event_id = event->id = ust_registry_get_next_event_id(chan);
	}

	*event_id_p = event_id;

	if (!event->metadata_dumped) {
		/* Append to metadata */
		ret = ust_metadata_event_statedump(session, chan, event);
		if (ret) {
			ERR("Error appending event metadata (errno = %d)", ret);
			rcu_read_unlock();
			return ret;
		}
	}

	rcu_read_unlock();
	return 0;

error_free:
	free(sig);
	free(fields);
	free(model_emf_uri);
error_unlock:
	rcu_read_unlock();
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
 * We need to execute ht_destroy outside of RCU read-side critical
 * section and outside of call_rcu thread, so we postpone its execution
 * using ht_cleanup_push. It is simpler than to change the semantic of
 * the many callers of delete_ust_app_session().
 */
static
void destroy_channel_rcu(struct rcu_head *head)
{
	struct ust_registry_channel *chan =
		caa_container_of(head, struct ust_registry_channel, rcu_head);

	if (chan->ht) {
		ht_cleanup_push(chan->ht);
	}
	free(chan->ctx_fields);
	free(chan);
}

/*
 * Destroy every element of the registry and free the memory. This does NOT
 * free the registry pointer since it might not have been allocated before so
 * it's the caller responsability.
 */
static void destroy_channel(struct ust_registry_channel *chan)
{
	struct lttng_ht_iter iter;
	struct ust_registry_event *event;

	assert(chan);

	rcu_read_lock();
	/* Destroy all event associated with this registry. */
	cds_lfht_for_each_entry(chan->ht->ht, &iter.iter, event, node.node) {
		/* Delete the node from the ht and free it. */
		ust_registry_destroy_event(chan, event);
	}
	rcu_read_unlock();
	call_rcu(&chan->rcu_head, destroy_channel_rcu);
}

/*
 * Initialize registry with default values.
 */
int ust_registry_channel_add(struct ust_registry_session *session,
		uint64_t key)
{
	int ret = 0;
	struct ust_registry_channel *chan;

	assert(session);

	chan = zmalloc(sizeof(*chan));
	if (!chan) {
		PERROR("zmalloc ust registry channel");
		ret = -ENOMEM;
		goto error_alloc;
	}

	chan->ht = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!chan->ht) {
		ret = -ENOMEM;
		goto error;
	}

	/* Set custom match function. */
	chan->ht->match_fct = ht_match_event;
	chan->ht->hash_fct = ht_hash_event;

	/*
	 * Assign a channel ID right now since the event notification comes
	 * *before* the channel notify so the ID needs to be set at this point so
	 * the metadata can be dumped for that event.
	 */
	if (ust_registry_is_max_id(session->used_channel_id)) {
		ret = -1;
		goto error;
	}
	chan->chan_id = ust_registry_get_next_chan_id(session);

	rcu_read_lock();
	lttng_ht_node_init_u64(&chan->node, key);
	lttng_ht_add_unique_u64(session->channels, &chan->node);
	rcu_read_unlock();

	return 0;

error:
	destroy_channel(chan);
error_alloc:
	return ret;
}

/*
 * Find a channel in the given registry. RCU read side lock MUST be acquired
 * before calling this function and as long as the event reference is kept by
 * the caller.
 *
 * On success, the pointer is returned else NULL.
 */
struct ust_registry_channel *ust_registry_channel_find(
		struct ust_registry_session *session, uint64_t key)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct ust_registry_channel *chan = NULL;

	assert(session);
	assert(session->channels);

	DBG3("UST registry channel finding key %" PRIu64, key);

	lttng_ht_lookup(session->channels, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		goto end;
	}
	chan = caa_container_of(node, struct ust_registry_channel, node);

end:
	return chan;
}

/*
 * Remove channel using key from registry and free memory.
 */
void ust_registry_channel_del_free(struct ust_registry_session *session,
		uint64_t key)
{
	struct lttng_ht_iter iter;
	struct ust_registry_channel *chan;
	int ret;

	assert(session);

	rcu_read_lock();
	chan = ust_registry_channel_find(session, key);
	if (!chan) {
		rcu_read_unlock();
		goto end;
	}

	iter.iter.node = &chan->node.node;
	ret = lttng_ht_del(session->channels, &iter);
	assert(!ret);
	rcu_read_unlock();
	destroy_channel(chan);

end:
	return;
}

/*
 * Initialize registry with default values and set the newly allocated session
 * pointer to sessionp.
 *
 * Return 0 on success and sessionp is set or else return -1 and sessionp is
 * kept untouched.
 */
int ust_registry_session_init(struct ust_registry_session **sessionp,
		struct ust_app *app,
		uint32_t bits_per_long,
		uint32_t uint8_t_alignment,
		uint32_t uint16_t_alignment,
		uint32_t uint32_t_alignment,
		uint32_t uint64_t_alignment,
		uint32_t long_alignment,
		int byte_order,
		uint32_t major,
		uint32_t minor)
{
	int ret;
	struct ust_registry_session *session;

	assert(sessionp);

	session = zmalloc(sizeof(*session));
	if (!session) {
		PERROR("zmalloc ust registry session");
		goto error_alloc;
	}

	pthread_mutex_init(&session->lock, NULL);
	session->bits_per_long = bits_per_long;
	session->uint8_t_alignment = uint8_t_alignment;
	session->uint16_t_alignment = uint16_t_alignment;
	session->uint32_t_alignment = uint32_t_alignment;
	session->uint64_t_alignment = uint64_t_alignment;
	session->long_alignment = long_alignment;
	session->byte_order = byte_order;

	session->channels = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!session->channels) {
		goto error;
	}

	ret = lttng_uuid_generate(session->uuid);
	if (ret) {
		ERR("Failed to generate UST uuid (errno = %d)", ret);
		goto error;
	}

	pthread_mutex_lock(&session->lock);
	ret = ust_metadata_session_statedump(session, app, major, minor);
	pthread_mutex_unlock(&session->lock);
	if (ret) {
		ERR("Failed to generate session metadata (errno = %d)", ret);
		goto error;
	}

	*sessionp = session;

	return 0;

error:
	ust_registry_session_destroy(session);
	free(session);
error_alloc:
	return -1;
}

/*
 * Destroy session registry. This does NOT free the given pointer since it
 * might get passed as a reference. The registry lock should NOT be acquired.
 */
void ust_registry_session_destroy(struct ust_registry_session *reg)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ust_registry_channel *chan;

	/* On error, EBUSY can be returned if lock. Code flow error. */
	ret = pthread_mutex_destroy(&reg->lock);
	assert(!ret);

	rcu_read_lock();
	/* Destroy all event associated with this registry. */
	cds_lfht_for_each_entry(reg->channels->ht, &iter.iter, chan, node.node) {
		/* Delete the node from the ht and free it. */
		ret = lttng_ht_del(reg->channels, &iter);
		assert(!ret);
		destroy_channel(chan);
	}
	rcu_read_unlock();

	ht_cleanup_push(reg->channels);
	free(reg->metadata);
}
