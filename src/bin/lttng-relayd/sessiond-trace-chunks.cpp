/*
 * SPDX-FileCopyrightText: 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "sessiond-trace-chunks.hpp"

#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/hashtable/utils.hpp>
#include <common/macros.hpp>
#include <common/string-utils/format.hpp>
#include <common/trace-chunk-registry.hpp>
#include <common/urcu.hpp>

#include <inttypes.h>
#include <stdio.h>
#include <urcu.h>
#include <urcu/rculfhash.h>
#include <urcu/ref.h>

/*
 * Lifetime of trace chunks within the relay daemon.
 *
 * Trace chunks are shared accross connections initiated from a given
 * session daemon. When a session is created by a consumer daemon, the
 * UUID of its associated session daemon is transmitted (in the case of
 * 2.11+ consumer daemons).
 *
 * The sessiond_trace_chunk_registry_new_session() and
 * sessiond_trace_chunk_registry_session_closed() methods create and
 * manage the reference count of lttng_trace_chunk_registry objects
 * associated to the various sessiond instances served by the relay daemon.
 *
 * When all sessions associated with a given sessiond instance are
 * destroyed, its registry is destroyed.
 *
 * lttng_trace_chunk objects are uniquely identified by the
 * (sessiond_uuid, sessiond_session_id, chunk_id) tuple. If a trace chunk
 * matching that tuple already exists, a new reference to the trace chunk
 * is acquired and it is returned to the caller. Otherwise, a new trace
 * chunk is created. This is how trace chunks are de-duplicated across
 * multiple consumer daemons managed by the same session daemon.
 *
 * Note that trace chunks are always added to their matching
 * lttng_trace_chunk_registry. They are automatically removed from the
 * trace chunk registry when their reference count reaches zero.
 */

/*
 * It is assumed that the sessiond_trace_chunk_registry is created and
 * destroyed by the same thread.
 */
struct sessiond_trace_chunk_registry {
	/* Maps an lttng_uuid to an lttng_trace_chunk_registry. */
	struct cds_lfht *ht;
};

namespace {
struct trace_chunk_registry_ht_key {
	lttng_uuid sessiond_uuid;
};

struct trace_chunk_registry_ht_element {
	struct trace_chunk_registry_ht_key key;
	struct urcu_ref ref;
	/* Node into the sessiond_trace_chunk_registry's hash table. */
	struct cds_lfht_node ht_node;
	/* Used for defered call_rcu reclaim. */
	struct rcu_head rcu_node;
	struct lttng_trace_chunk_registry *trace_chunk_registry;
	struct sessiond_trace_chunk_registry *sessiond_trace_chunk_registry;
};
} /* namespace */

static unsigned long trace_chunk_registry_ht_key_hash(const struct trace_chunk_registry_ht_key *key)
{
	const uint64_t uuid_h1 = reinterpret_cast<const uint64_t *>(key->sessiond_uuid.data())[0];
	const uint64_t uuid_h2 = reinterpret_cast<const uint64_t *>(key->sessiond_uuid.data())[1];

	return hash_key_u64(&uuid_h1, lttng_ht_seed) ^ hash_key_u64(&uuid_h2, lttng_ht_seed);
}

/* cds_lfht match function */
static int trace_chunk_registry_ht_key_match(struct cds_lfht_node *node, const void *_key)
{
	const struct trace_chunk_registry_ht_key *key = (struct trace_chunk_registry_ht_key *) _key;
	struct trace_chunk_registry_ht_element *registry;

	registry = lttng::utils::container_of(node, &trace_chunk_registry_ht_element::ht_node);
	return key->sessiond_uuid == registry->key.sessiond_uuid;
}

static void trace_chunk_registry_ht_element_free(struct rcu_head *node)
{
	struct trace_chunk_registry_ht_element *element =
		lttng::utils::container_of(node, &trace_chunk_registry_ht_element::rcu_node);

	free(element);
}

static void trace_chunk_registry_ht_element_release(struct urcu_ref *ref)
{
	struct trace_chunk_registry_ht_element *element =
		lttng::utils::container_of(ref, &trace_chunk_registry_ht_element::ref);
	char uuid_str[LTTNG_UUID_STR_LEN];

	lttng_uuid_to_str(element->key.sessiond_uuid, uuid_str);

	DBG("Destroying trace chunk registry associated to sessiond {%s}", uuid_str);
	if (element->sessiond_trace_chunk_registry) {
		/* Unpublish. */
		const lttng::urcu::read_lock_guard read_lock;
		cds_lfht_del(element->sessiond_trace_chunk_registry->ht, &element->ht_node);
		element->sessiond_trace_chunk_registry = nullptr;
	}

	lttng_trace_chunk_registry_destroy(element->trace_chunk_registry);
	/* Defered reclaim of the object */
	call_rcu(&element->rcu_node, trace_chunk_registry_ht_element_free);
}

static bool trace_chunk_registry_ht_element_get(struct trace_chunk_registry_ht_element *element)
{
	return urcu_ref_get_unless_zero(&element->ref);
}

static void trace_chunk_registry_ht_element_put(struct trace_chunk_registry_ht_element *element)
{
	if (!element) {
		return;
	}

	urcu_ref_put(&element->ref, trace_chunk_registry_ht_element_release);
}

/* Acquires a reference to the returned element on behalf of the caller. */
static struct trace_chunk_registry_ht_element *
trace_chunk_registry_ht_element_find(struct sessiond_trace_chunk_registry *sessiond_registry,
				     const struct trace_chunk_registry_ht_key *key)
{
	struct trace_chunk_registry_ht_element *element = nullptr;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	const lttng::urcu::read_lock_guard read_lock;
	cds_lfht_lookup(sessiond_registry->ht,
			trace_chunk_registry_ht_key_hash(key),
			trace_chunk_registry_ht_key_match,
			key,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node) {
		element =
			lttng::utils::container_of(node, &trace_chunk_registry_ht_element::ht_node);
		/*
		 * Only consider the look-up as successful if a reference
		 * could be acquired.
		 */
		if (!trace_chunk_registry_ht_element_get(element)) {
			element = nullptr;
		}
	}
	return element;
}

static int
trace_chunk_registry_ht_element_create(struct sessiond_trace_chunk_registry *sessiond_registry,
				       const struct trace_chunk_registry_ht_key *key)
{
	int ret = 0;
	struct trace_chunk_registry_ht_element *new_element;
	struct lttng_trace_chunk_registry *trace_chunk_registry;
	char uuid_str[LTTNG_UUID_STR_LEN];

	lttng_uuid_to_str(key->sessiond_uuid, uuid_str);

	trace_chunk_registry = lttng_trace_chunk_registry_create();
	if (!trace_chunk_registry) {
		ret = -1;
		goto end;
	}

	new_element = zmalloc<trace_chunk_registry_ht_element>();
	if (!new_element) {
		ret = -1;
		goto end;
	}

	memcpy(&new_element->key, key, sizeof(new_element->key));
	urcu_ref_init(&new_element->ref);
	cds_lfht_node_init(&new_element->ht_node);
	new_element->trace_chunk_registry = trace_chunk_registry;
	trace_chunk_registry = nullptr;

	/* Attempt to publish the new element. */
	{
		/*
		 * Keep the rcu read lock is held accross all attempts
		 * purely for efficiency reasons.
		 */
		const lttng::urcu::read_lock_guard read_lock;
		while (true) {
			struct cds_lfht_node *published_node;
			struct trace_chunk_registry_ht_element *published_element;

			published_node = cds_lfht_add_unique(
				sessiond_registry->ht,
				trace_chunk_registry_ht_key_hash(&new_element->key),
				trace_chunk_registry_ht_key_match,
				&new_element->key,
				&new_element->ht_node);
			if (published_node == &new_element->ht_node) {
				/* New element published successfully. */
				DBG("Created trace chunk registry for sessiond {%s}", uuid_str);
				new_element->sessiond_trace_chunk_registry = sessiond_registry;
				break;
			}

			/*
			 * An equivalent element was published during the creation of
			 * this element. Attempt to acquire a reference to the one that
			 * was already published and release the reference to the copy
			 * we created if successful.
			 */
			published_element = lttng::utils::container_of(
				published_node, &trace_chunk_registry_ht_element::ht_node);
			if (trace_chunk_registry_ht_element_get(published_element)) {
				DBG("Acquired reference to trace chunk registry of sessiond {%s}",
				    uuid_str);
				trace_chunk_registry_ht_element_put(new_element);
				new_element = nullptr;
				break;
			}
			/*
			 * A reference to the previously published element could not
			 * be acquired. Hence, retry to publish our copy of the
			 * element.
			 */
		}
	}
end:
	if (ret < 0) {
		ERR("Failed to create trace chunk registry for session daemon {%s}", uuid_str);
	}
	lttng_trace_chunk_registry_destroy(trace_chunk_registry);
	return ret;
}

struct sessiond_trace_chunk_registry *sessiond_trace_chunk_registry_create()
{
	struct sessiond_trace_chunk_registry *sessiond_registry =
		zmalloc<sessiond_trace_chunk_registry>();

	if (!sessiond_registry) {
		goto end;
	}

	sessiond_registry->ht = cds_lfht_new(
		DEFAULT_HT_SIZE, 1, 0, CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, nullptr);
	if (!sessiond_registry->ht) {
		goto error;
	}

end:
	return sessiond_registry;
error:
	sessiond_trace_chunk_registry_destroy(sessiond_registry);
	return nullptr;
}

void sessiond_trace_chunk_registry_destroy(struct sessiond_trace_chunk_registry *sessiond_registry)
{
	const int ret = cds_lfht_destroy(sessiond_registry->ht, nullptr);

	LTTNG_ASSERT(!ret);
	free(sessiond_registry);
}

int sessiond_trace_chunk_registry_session_created(
	struct sessiond_trace_chunk_registry *sessiond_registry, const lttng_uuid& sessiond_uuid)
{
	int ret = 0;
	struct trace_chunk_registry_ht_key key;
	struct trace_chunk_registry_ht_element *element;

	key.sessiond_uuid = sessiond_uuid;

	element = trace_chunk_registry_ht_element_find(sessiond_registry, &key);
	if (element) {
		char uuid_str[LTTNG_UUID_STR_LEN];

		lttng_uuid_to_str(sessiond_uuid, uuid_str);
		DBG("Acquired reference to trace chunk registry of sessiond {%s}", uuid_str);
		goto end;
	} else {
		ret = trace_chunk_registry_ht_element_create(sessiond_registry, &key);
	}
end:
	return ret;
}

int sessiond_trace_chunk_registry_session_destroyed(
	struct sessiond_trace_chunk_registry *sessiond_registry, const lttng_uuid& sessiond_uuid)
{
	int ret = 0;
	struct trace_chunk_registry_ht_key key;
	struct trace_chunk_registry_ht_element *element;
	char uuid_str[LTTNG_UUID_STR_LEN];

	lttng_uuid_to_str(sessiond_uuid, uuid_str);
	key.sessiond_uuid = sessiond_uuid;

	element = trace_chunk_registry_ht_element_find(sessiond_registry, &key);
	if (element) {
		DBG("Releasing reference to trace chunk registry of sessiond {%s}", uuid_str);
		/*
		 * Release the reference held by the session and the reference
		 * acquired through the "find" operation.
		 */
		trace_chunk_registry_ht_element_put(element);
		trace_chunk_registry_ht_element_put(element);
	} else {
		ERR("Failed to find trace chunk registry of sessiond {%s}", uuid_str);
		ret = -1;
	}
	return ret;
}

struct lttng_trace_chunk *
sessiond_trace_chunk_registry_publish_chunk(struct sessiond_trace_chunk_registry *sessiond_registry,
					    const lttng_uuid& sessiond_uuid,
					    uint64_t session_id,
					    struct lttng_trace_chunk *new_chunk)
{
	enum lttng_trace_chunk_status status;
	uint64_t chunk_id;
	bool is_anonymous_chunk;
	struct trace_chunk_registry_ht_key key;
	struct trace_chunk_registry_ht_element *element = nullptr;
	char uuid_str[LTTNG_UUID_STR_LEN];
	char chunk_id_str[MAX_INT_DEC_LEN(typeof(chunk_id))] = "-1";
	struct lttng_trace_chunk *published_chunk = nullptr;
	bool trace_chunk_already_published;

	lttng_uuid_to_str(sessiond_uuid, uuid_str);
	key.sessiond_uuid = sessiond_uuid;

	status = lttng_trace_chunk_get_id(new_chunk, &chunk_id);
	if (status == LTTNG_TRACE_CHUNK_STATUS_OK) {
		int ret;

		ret = snprintf(chunk_id_str, sizeof(chunk_id_str), "%" PRIu64, chunk_id);
		if (ret < 0) {
			lttng_strncpy(chunk_id_str, "-1", sizeof(chunk_id_str));
			WARN("Failed to format trace chunk id");
		}
		is_anonymous_chunk = false;
	} else if (status == LTTNG_TRACE_CHUNK_STATUS_NONE) {
		is_anonymous_chunk = true;
	} else {
		ERR("Failed to get trace chunk id");
		goto end;
	}

	DBG("Attempting to publish trace chunk: sessiond {%s}, session_id = "
	    "%" PRIu64 ", chunk_id = %s",
	    uuid_str,
	    session_id,
	    is_anonymous_chunk ? "anonymous" : chunk_id_str);

	element = trace_chunk_registry_ht_element_find(sessiond_registry, &key);
	if (!element) {
		ERR("Failed to find registry of sessiond {%s}", uuid_str);
		goto end;
	}

	published_chunk = lttng_trace_chunk_registry_publish_chunk(element->trace_chunk_registry,
								   session_id,
								   new_chunk,
								   &trace_chunk_already_published);
	/*
	 * When the trace chunk is first published, two references to the
	 * published chunks exist. One is taken by the registry while the other
	 * is being returned to the caller. In the use case of the relay daemon,
	 * the reference held by the registry itself is undesirable.
	 *
	 * We want the trace chunk to be removed from the registry as soon
	 * as it is not being used by the relay daemon (through a session
	 * or a stream). This differs from the behaviour of the consumer
	 * daemon which relies on an explicit command from the session
	 * daemon to release the registry's reference.
	 *
	 * In cases where the trace chunk had already been published,
	 * the reference belonging to the sessiond trace chunk
	 * registry instance has already been 'put'. We simply return
	 * the published trace chunk with a reference taken on behalf of the
	 * caller.
	 */
	if (!trace_chunk_already_published) {
		lttng_trace_chunk_put(published_chunk);
	}
end:
	trace_chunk_registry_ht_element_put(element);
	return published_chunk;
}

struct lttng_trace_chunk *sessiond_trace_chunk_registry_get_anonymous_chunk(
	struct sessiond_trace_chunk_registry *sessiond_registry,
	const lttng_uuid& sessiond_uuid,
	uint64_t session_id)
{
	struct lttng_trace_chunk *chunk = nullptr;
	struct trace_chunk_registry_ht_element *element;
	struct trace_chunk_registry_ht_key key;
	char uuid_str[LTTNG_UUID_STR_LEN];

	lttng_uuid_to_str(sessiond_uuid, uuid_str);

	key.sessiond_uuid = sessiond_uuid;
	element = trace_chunk_registry_ht_element_find(sessiond_registry, &key);
	if (!element) {
		ERR("Failed to find trace chunk registry of sessiond {%s}", uuid_str);
		goto end;
	}

	chunk = lttng_trace_chunk_registry_find_anonymous_chunk(element->trace_chunk_registry,
								session_id);
	trace_chunk_registry_ht_element_put(element);
end:
	return chunk;
}

struct lttng_trace_chunk *
sessiond_trace_chunk_registry_get_chunk(struct sessiond_trace_chunk_registry *sessiond_registry,
					const lttng_uuid& sessiond_uuid,
					uint64_t session_id,
					uint64_t chunk_id)
{
	struct lttng_trace_chunk *chunk = nullptr;
	struct trace_chunk_registry_ht_element *element;
	struct trace_chunk_registry_ht_key key;
	char uuid_str[LTTNG_UUID_STR_LEN];

	lttng_uuid_to_str(sessiond_uuid, uuid_str);

	key.sessiond_uuid = sessiond_uuid;
	element = trace_chunk_registry_ht_element_find(sessiond_registry, &key);
	if (!element) {
		ERR("Failed to find trace chunk registry of sessiond {%s}", uuid_str);
		goto end;
	}

	chunk = lttng_trace_chunk_registry_find_chunk(
		element->trace_chunk_registry, session_id, chunk_id);
	trace_chunk_registry_ht_element_put(element);
end:
	return chunk;
}

int sessiond_trace_chunk_registry_chunk_exists(
	struct sessiond_trace_chunk_registry *sessiond_registry,
	const lttng_uuid& sessiond_uuid,
	uint64_t session_id,
	uint64_t chunk_id,
	bool *chunk_exists)
{
	int ret;
	struct trace_chunk_registry_ht_element *element;
	struct trace_chunk_registry_ht_key key;

	key.sessiond_uuid = sessiond_uuid;
	element = trace_chunk_registry_ht_element_find(sessiond_registry, &key);
	if (!element) {
		char uuid_str[LTTNG_UUID_STR_LEN];

		lttng_uuid_to_str(sessiond_uuid, uuid_str);
		/*
		 * While this certainly means that the chunk does not exist,
		 * it is unexpected for a chunk existence query to target a
		 * session daemon that does not have an active
		 * connection/registry. This would indicate a protocol
		 * (or internal) error.
		 */
		ERR("Failed to find trace chunk registry of sessiond {%s}", uuid_str);
		ret = -1;
		goto end;
	}

	ret = lttng_trace_chunk_registry_chunk_exists(
		element->trace_chunk_registry, session_id, chunk_id, chunk_exists);
	trace_chunk_registry_ht_element_put(element);
end:
	return ret;
}
