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

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>

#include <common/common.h>
#include <common/hashtable/utils.h>
#include <lttng/lttng.h>

#include "ust-registry.h"
#include "ust-app.h"
#include "utils.h"
#include "lttng-sessiond.h"
#include "notification-thread-commands.h"

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
	if (strncmp(event->name, key->name, sizeof(event->name))) {
		goto no_match;
	}

	/* It has to be a perfect match. */
	if (strncmp(event->signature, key->signature,
			strlen(event->signature))) {
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

static int compare_enums(const struct ust_registry_enum *reg_enum_a,
		const struct ust_registry_enum *reg_enum_b)
{
	int ret = 0;
	size_t i;

	assert(strcmp(reg_enum_a->name, reg_enum_b->name) == 0);
	if (reg_enum_a->nr_entries != reg_enum_b->nr_entries) {
		ret = -1;
		goto end;
	}
	for (i = 0; i < reg_enum_a->nr_entries; i++) {
		const struct ustctl_enum_entry *entries_a, *entries_b;

		entries_a = &reg_enum_a->entries[i];
		entries_b = &reg_enum_b->entries[i];
		if (entries_a->start.value != entries_b->start.value) {
			ret = -1;
			goto end;
		}
		if (entries_a->end.value != entries_b->end.value) {
			ret = -1;
			goto end;
		}
		if (entries_a->start.signedness != entries_b->start.signedness) {
			ret = -1;
			goto end;
		}
		if (entries_a->end.signedness != entries_b->end.signedness) {
			ret = -1;
			goto end;
		}

		if (strcmp(entries_a->string, entries_b->string)) {
			ret = -1;
			goto end;
		}
	}
end:
	return ret;
}

/*
 * Hash table match function for enumerations in the session. Match is
 * performed on enumeration name, and confirmed by comparing the enum
 * entries.
 */
static int ht_match_enum(struct cds_lfht_node *node, const void *_key)
{
	struct ust_registry_enum *_enum;
	const struct ust_registry_enum *key;

	assert(node);
	assert(_key);

	_enum = caa_container_of(node, struct ust_registry_enum,
			node.node);
	assert(_enum);
	key = _key;

	if (strncmp(_enum->name, key->name, LTTNG_UST_SYM_NAME_LEN)) {
		goto no_match;
	}
	if (compare_enums(_enum, key)) {
		goto no_match;
	}

	/* Match. */
	return 1;

no_match:
	return 0;
}

/*
 * Hash table match function for enumerations in the session. Match is
 * performed by enumeration ID.
 */
static int ht_match_enum_id(struct cds_lfht_node *node, const void *_key)
{
	struct ust_registry_enum *_enum;
	const struct ust_registry_enum *key = _key;

	assert(node);
	assert(_key);

	_enum = caa_container_of(node, struct ust_registry_enum, node.node);
	assert(_enum);

	if (_enum->id != key->id) {
		goto no_match;
	}

	/* Match. */
	return 1;

no_match:
	return 0;
}

/*
 * Hash table hash function for enumerations in the session. The
 * enumeration name is used for hashing.
 */
static unsigned long ht_hash_enum(void *_key, unsigned long seed)
{
	struct ust_registry_enum *key = _key;

	assert(key);
	return hash_key_str(key->name, seed);
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
	int ret = 0;

	switch(field->type.atype) {
	case ustctl_atype_integer:
	case ustctl_atype_enum:
	case ustctl_atype_array:
	case ustctl_atype_sequence:
	case ustctl_atype_string:
	case ustctl_atype_variant:
		break;
	case ustctl_atype_struct:
		if (field->type.u._struct.nr_fields != 0) {
			WARN("Unsupported non-empty struct field.");
			ret = -EINVAL;
			goto end;
		}
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
			ret = -EINVAL;
			goto end;
		default:
			break;
		}
		break;

	default:
		ret = -ENOENT;
		goto end;
	}
end:
	return ret;
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
		struct ustctl_field *fields, int loglevel_value,
		char *model_emf_uri, struct ust_app *app)
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
	event->loglevel_value = loglevel_value;
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
		char *sig, size_t nr_fields, struct ustctl_field *fields,
		int loglevel_value, char *model_emf_uri, int buffer_type,
		uint32_t *event_id_p, struct ust_app *app)
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
			fields, loglevel_value, model_emf_uri, app);
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

static void destroy_enum(struct ust_registry_enum *reg_enum)
{
	if (!reg_enum) {
		return;
	}
	free(reg_enum->entries);
	free(reg_enum);
}

static void destroy_enum_rcu(struct rcu_head *head)
{
	struct ust_registry_enum *reg_enum =
		caa_container_of(head, struct ust_registry_enum, rcu_head);

	destroy_enum(reg_enum);
}

/*
 * Lookup enumeration by name and comparing enumeration entries.
 * Needs to be called from RCU read-side critical section.
 */
struct ust_registry_enum *
	ust_registry_lookup_enum(struct ust_registry_session *session,
		const struct ust_registry_enum *reg_enum_lookup)
{
	struct ust_registry_enum *reg_enum = NULL;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;

	cds_lfht_lookup(session->enums->ht,
			ht_hash_enum((void *) &reg_enum_lookup, lttng_ht_seed),
			ht_match_enum, &reg_enum_lookup, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (!node) {
	        goto end;
	}
	reg_enum = caa_container_of(node, struct ust_registry_enum, node);
end:
	return reg_enum;
}

/*
 * Lookup enumeration by enum ID.
 * Needs to be called from RCU read-side critical section.
 */
struct ust_registry_enum *
	ust_registry_lookup_enum_by_id(struct ust_registry_session *session,
		const char *enum_name, uint64_t enum_id)
{
	struct ust_registry_enum *reg_enum = NULL;
	struct lttng_ht_node_str *node;
	struct lttng_ht_iter iter;
	struct ust_registry_enum reg_enum_lookup;

	memset(&reg_enum_lookup, 0, sizeof(reg_enum_lookup));
	strncpy(reg_enum_lookup.name, enum_name, LTTNG_UST_SYM_NAME_LEN);
	reg_enum_lookup.name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
	reg_enum_lookup.id = enum_id;
	cds_lfht_lookup(session->enums->ht,
			ht_hash_enum((void *) &reg_enum_lookup, lttng_ht_seed),
			ht_match_enum_id, &reg_enum_lookup, &iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (!node) {
	        goto end;
	}
	reg_enum = caa_container_of(node, struct ust_registry_enum, node);
end:
	return reg_enum;
}

/*
 * Create a ust_registry_enum from the given parameters and add it to the
 * registry hash table, or find it if already there.
 *
 * On success, return 0 else a negative value.
 *
 * Should be called with session registry mutex held.
 *
 * We receive ownership of entries.
 */
int ust_registry_create_or_find_enum(struct ust_registry_session *session,
		int session_objd, char *enum_name,
		struct ustctl_enum_entry *entries, size_t nr_entries,
		uint64_t *enum_id)
{
	int ret = 0;
	struct cds_lfht_node *nodep;
	struct ust_registry_enum *reg_enum = NULL, *old_reg_enum;

	assert(session);
	assert(enum_name);

	rcu_read_lock();

	/*
	 * This should not happen but since it comes from the UST tracer, an
	 * external party, don't assert and simply validate values.
	 */
	if (session_objd < 0) {
		ret = -EINVAL;
		goto end;
	}

	/* Check if the enumeration was already dumped */
	reg_enum = zmalloc(sizeof(*reg_enum));
	if (!reg_enum) {
		PERROR("zmalloc ust registry enumeration");
		ret = -ENOMEM;
		goto end;
	}
	strncpy(reg_enum->name, enum_name, LTTNG_UST_SYM_NAME_LEN);
	reg_enum->name[LTTNG_UST_SYM_NAME_LEN - 1] = '\0';
	/* entries will be owned by reg_enum. */
	reg_enum->entries = entries;
	reg_enum->nr_entries = nr_entries;
	entries = NULL;

	old_reg_enum = ust_registry_lookup_enum(session, reg_enum);
	if (old_reg_enum) {
		DBG("enum %s already in sess_objd: %u", enum_name, session_objd);
		/* Fall through. Use prior enum. */
		destroy_enum(reg_enum);
		reg_enum = old_reg_enum;
	} else {
		DBG("UST registry creating enum: %s, sess_objd: %u",
				enum_name, session_objd);
		if (session->next_enum_id == -1ULL) {
			ret = -EOVERFLOW;
			destroy_enum(reg_enum);
			goto end;
		}
		reg_enum->id = session->next_enum_id++;
		cds_lfht_node_init(&reg_enum->node.node);
		nodep = cds_lfht_add_unique(session->enums->ht,
				ht_hash_enum(reg_enum, lttng_ht_seed),
				ht_match_enum_id, reg_enum,
				&reg_enum->node.node);
		assert(nodep == &reg_enum->node.node);
	}
	DBG("UST registry reply with enum %s with id %" PRIu64 " in sess_objd: %u",
			enum_name, reg_enum->id, session_objd);
	*enum_id = reg_enum->id;
end:
	free(entries);
	rcu_read_unlock();
	return ret;
}

/*
 * For a given enumeration in a registry, delete the entry and destroy
 * the enumeration.
 * This MUST be called within a RCU read side lock section.
 */
void ust_registry_destroy_enum(struct ust_registry_session *reg_session,
		struct ust_registry_enum *reg_enum)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(reg_session);
	assert(reg_enum);

	/* Delete the node first. */
	iter.iter.node = &reg_enum->node.node;
	ret = lttng_ht_del(reg_session->enums, &iter);
	assert(!ret);
	call_rcu(&reg_enum->rcu_head, destroy_enum_rcu);
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
static void destroy_channel(struct ust_registry_channel *chan, bool notif)
{
	struct lttng_ht_iter iter;
	struct ust_registry_event *event;
	enum lttng_error_code cmd_ret;

	assert(chan);

	if (notif) {
		cmd_ret = notification_thread_command_remove_channel(
				notification_thread_handle, chan->consumer_key,
				LTTNG_DOMAIN_UST);
		if (cmd_ret != LTTNG_OK) {
			ERR("Failed to remove channel from notification thread");
		}
	}

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
	destroy_channel(chan, false);
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
		uint64_t key, bool notif)
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
	destroy_channel(chan, notif);

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
		uint32_t minor,
		const char *root_shm_path,
		const char *shm_path,
		uid_t euid,
		gid_t egid)
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
	session->metadata_fd = -1;
	session->uid = euid;
	session->gid = egid;
	session->next_enum_id = 0;
	session->major = major;
	session->minor = minor;
	strncpy(session->root_shm_path, root_shm_path,
		sizeof(session->root_shm_path));
	session->root_shm_path[sizeof(session->root_shm_path) - 1] = '\0';
	if (shm_path[0]) {
		strncpy(session->shm_path, shm_path,
			sizeof(session->shm_path));
		session->shm_path[sizeof(session->shm_path) - 1] = '\0';
		strncpy(session->metadata_path, shm_path,
			sizeof(session->metadata_path));
		session->metadata_path[sizeof(session->metadata_path) - 1] = '\0';
		strncat(session->metadata_path, "/metadata",
			sizeof(session->metadata_path)
				- strlen(session->metadata_path) - 1);
	}
	if (session->shm_path[0]) {
		ret = run_as_mkdir_recursive(session->shm_path,
			S_IRWXU | S_IRWXG,
			euid, egid);
		if (ret) {
			PERROR("run_as_mkdir_recursive");
			goto error;
		}
	}
	if (session->metadata_path[0]) {
		/* Create metadata file */
		ret = run_as_open(session->metadata_path,
			O_WRONLY | O_CREAT | O_EXCL,
			S_IRUSR | S_IWUSR, euid, egid);
		if (ret < 0) {
			PERROR("Opening metadata file");
			goto error;
		}
		session->metadata_fd = ret;
	}

	session->enums = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!session->enums) {
		ERR("Failed to create enums hash table");
		goto error;
	}
	/* hash/match functions are specified at call site. */
	session->enums->match_fct = NULL;
	session->enums->hash_fct = NULL;

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
	struct ust_registry_enum *reg_enum;

	if (!reg) {
		return;
	}

	/* On error, EBUSY can be returned if lock. Code flow error. */
	ret = pthread_mutex_destroy(&reg->lock);
	assert(!ret);

	if (reg->channels) {
		rcu_read_lock();
		/* Destroy all event associated with this registry. */
		cds_lfht_for_each_entry(reg->channels->ht, &iter.iter, chan,
				node.node) {
			/* Delete the node from the ht and free it. */
			ret = lttng_ht_del(reg->channels, &iter);
			assert(!ret);
			destroy_channel(chan, true);
		}
		rcu_read_unlock();
		ht_cleanup_push(reg->channels);
	}

	free(reg->metadata);
	if (reg->metadata_fd >= 0) {
		ret = close(reg->metadata_fd);
		if (ret) {
			PERROR("close");
		}
		ret = run_as_unlink(reg->metadata_path,
				reg->uid, reg->gid);
		if (ret) {
			PERROR("unlink");
		}
	}
	if (reg->root_shm_path[0]) {
		/*
		 * Try deleting the directory hierarchy.
		 */
		(void) run_as_rmdir_recursive(reg->root_shm_path,
				reg->uid, reg->gid);
	}
	/* Destroy the enum hash table */
	if (reg->enums) {
		rcu_read_lock();
		/* Destroy all enum entries associated with this registry. */
		cds_lfht_for_each_entry(reg->enums->ht, &iter.iter, reg_enum,
				node.node) {
			ust_registry_destroy_enum(reg, reg_enum);
		}
		rcu_read_unlock();
		ht_cleanup_push(reg->enums);
	}
}
