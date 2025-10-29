/*
 * SPDX-FileCopyrightText: 2013 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "buffer-registry.hpp"
#include "fd-limit.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "ust-consumer.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/hashtable/utils.hpp>
#include <common/urcu.hpp>

#include <inttypes.h>

/*
 * Set in main.c during initialization process of the daemon. This contains
 * buffer_reg_uid object which are global registry for per UID buffer. Object
 * are indexed by session id and matched by the triplet
 * <session_id/bits_per_long/uid>.
 */
static struct lttng_ht *buffer_registry_uid;

/*
 * Initialized at the daemon start. This contains buffer_reg_pid object and
 * indexed by session id.
 */
static struct lttng_ht *buffer_registry_pid;

/*
 * Match function for the per UID registry hash table. It matches a registry
 * uid object with the triplet <session_id/abi/uid>.
 */
static int ht_match_reg_uid(struct cds_lfht_node *node, const void *_key)
{
	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	auto *reg = lttng_ht_node_container_of(node, &buffer_reg_uid::node);
	const auto *key = (buffer_reg_uid *) _key;

	if (key->session_id != reg->session_id || key->bits_per_long != reg->bits_per_long ||
	    key->uid != reg->uid) {
		goto no_match;
	}

	/* Match */
	return 1;
no_match:
	return 0;
}

/*
 * Hash function for the per UID registry hash table. This XOR the triplet
 * together.
 */
static unsigned long ht_hash_reg_uid(const void *_key, unsigned long seed)
{
	uint64_t xored_key;
	const struct buffer_reg_uid *key = (buffer_reg_uid *) _key;

	LTTNG_ASSERT(key);

	xored_key = (uint64_t) (key->session_id ^ key->bits_per_long ^ key->uid);
	return hash_key_u64(&xored_key, seed);
}

/*
 * Initialize global buffer per UID registry. Should only be called ONCE!.
 */
void buffer_reg_init_uid_registry()
{
	/* Should be called once. */
	LTTNG_ASSERT(!buffer_registry_uid);
	buffer_registry_uid = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	LTTNG_ASSERT(buffer_registry_uid);
	buffer_registry_uid->match_fct = ht_match_reg_uid;
	buffer_registry_uid->hash_fct = ht_hash_reg_uid;

	DBG3("Global buffer per UID registry initialized");
}

/*
 * Allocate and initialize object. Set regp with the object pointer.
 *
 * Return 0 on success else a negative value and regp is untouched.
 */
int buffer_reg_uid_create(uint64_t session_id,
			  uint32_t bits_per_long,
			  uid_t uid,
			  enum lttng_domain_type domain,
			  struct buffer_reg_uid **regp,
			  const char *root_shm_path,
			  const char *shm_path)
{
	int ret = 0;
	struct buffer_reg_uid *reg = nullptr;

	LTTNG_ASSERT(regp);

	reg = zmalloc<buffer_reg_uid>();
	if (!reg) {
		PERROR("zmalloc buffer registry uid");
		ret = -ENOMEM;
		goto error;
	}

	reg->registry = zmalloc<buffer_reg_session>();
	if (!reg->registry) {
		PERROR("zmalloc buffer registry uid session");
		ret = -ENOMEM;
		goto error;
	}

	reg->session_id = session_id;
	reg->bits_per_long = bits_per_long;
	reg->uid = uid;
	reg->domain = domain;
	if (shm_path[0]) {
		strncpy(reg->root_shm_path, root_shm_path, sizeof(reg->root_shm_path));
		reg->root_shm_path[sizeof(reg->root_shm_path) - 1] = '\0';
		strncpy(reg->shm_path, shm_path, sizeof(reg->shm_path));
		reg->shm_path[sizeof(reg->shm_path) - 1] = '\0';
		DBG3("shm path '%s' is assigned to uid buffer registry for session id %" PRIu64,
		     reg->shm_path,
		     session_id);
	}
	reg->registry->channels = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!reg->registry->channels) {
		ret = -ENOMEM;
		goto error_session;
	}

	cds_lfht_node_init(&reg->node.node);
	*regp = reg;

	DBG3("Buffer registry per UID created id: %" PRIu64 ", ABI: %u, uid: %d, domain: %d",
	     session_id,
	     bits_per_long,
	     uid,
	     domain);

	return 0;

error_session:
	free(reg->registry);
error:
	free(reg);
	return ret;
}

/*
 * Add a buffer registry per UID object to the global registry.
 */
void buffer_reg_uid_add(struct buffer_reg_uid *reg)
{
	struct cds_lfht_node *nodep;
	struct lttng_ht *ht = buffer_registry_uid;

	LTTNG_ASSERT(reg);

	DBG3("Buffer registry per UID adding to global registry with id: %" PRIu64,
	     reg->session_id);

	const lttng::urcu::read_lock_guard read_lock;
	nodep = cds_lfht_add_unique(
		ht->ht, ht->hash_fct(reg, lttng_ht_seed), ht->match_fct, reg, &reg->node.node);
	LTTNG_ASSERT(nodep == &reg->node.node);
}

/*
 * Find a buffer registry per UID object with given params. RCU read side lock
 * MUST be acquired before calling this and hold on to protect the object.
 *
 * Return the object pointer or NULL on error.
 */
struct buffer_reg_uid *buffer_reg_uid_find(uint64_t session_id, uint32_t bits_per_long, uid_t uid)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct buffer_reg_uid *reg = nullptr, key;
	struct lttng_ht *ht = buffer_registry_uid;

	ASSERT_RCU_READ_LOCKED();

	/* Setup key we are looking for. */
	key.session_id = session_id;
	key.bits_per_long = bits_per_long;
	key.uid = uid;

	DBG3("Buffer registry per UID find id: %" PRIu64 ", ABI: %u, uid: %d",
	     session_id,
	     bits_per_long,
	     uid);

	/* Custom lookup function since it's a different key. */
	cds_lfht_lookup(ht->ht, ht->hash_fct(&key, lttng_ht_seed), ht->match_fct, &key, &iter.iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (!node) {
		goto end;
	}
	reg = lttng::utils::container_of(node, &buffer_reg_uid::node);

end:
	return reg;
}

/*
 * Initialize global buffer per PID registry. Should only be called ONCE!.
 */
void buffer_reg_init_pid_registry()
{
	/* Should be called once. */
	LTTNG_ASSERT(!buffer_registry_pid);
	buffer_registry_pid = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	LTTNG_ASSERT(buffer_registry_pid);

	DBG3("Global buffer per PID registry initialized");
}

/*
 * Allocate and initialize object. Set regp with the object pointer.
 *
 * Return 0 on success else a negative value and regp is untouched.
 */
int buffer_reg_pid_create(uint64_t session_id,
			  struct buffer_reg_pid **regp,
			  const char *root_shm_path,
			  const char *shm_path)
{
	int ret = 0;
	struct buffer_reg_pid *reg = nullptr;

	LTTNG_ASSERT(regp);

	reg = zmalloc<buffer_reg_pid>();
	if (!reg) {
		PERROR("zmalloc buffer registry pid");
		ret = -ENOMEM;
		goto error;
	}

	reg->registry = zmalloc<buffer_reg_session>();
	if (!reg->registry) {
		PERROR("zmalloc buffer registry pid session");
		ret = -ENOMEM;
		goto error;
	}

	/* A cast is done here so we can use the session ID as a u64 ht node. */
	reg->session_id = session_id;
	if (shm_path[0]) {
		strncpy(reg->root_shm_path, root_shm_path, sizeof(reg->root_shm_path));
		reg->root_shm_path[sizeof(reg->root_shm_path) - 1] = '\0';
		strncpy(reg->shm_path, shm_path, sizeof(reg->shm_path));
		reg->shm_path[sizeof(reg->shm_path) - 1] = '\0';
		DBG3("shm path '%s' is assigned to pid buffer registry for session id %" PRIu64,
		     reg->shm_path,
		     session_id);
	}
	reg->registry->channels = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!reg->registry->channels) {
		ret = -ENOMEM;
		goto error_session;
	}

	lttng_ht_node_init_u64(&reg->node, reg->session_id);
	*regp = reg;

	DBG3("Buffer registry per PID created with session id: %" PRIu64, session_id);

	return 0;

error_session:
	free(reg->registry);
error:
	free(reg);
	return ret;
}

/*
 * Add a buffer registry per PID object to the global registry.
 */
void buffer_reg_pid_add(struct buffer_reg_pid *reg)
{
	LTTNG_ASSERT(reg);

	DBG3("Buffer registry per PID adding to global registry with id: %" PRIu64,
	     reg->session_id);

	const lttng::urcu::read_lock_guard read_lock;
	lttng_ht_add_unique_u64(buffer_registry_pid, &reg->node);
}

/*
 * Find a buffer registry per PID object with given params. RCU read side lock
 * MUST be acquired before calling this and hold on to protect the object.
 *
 * Return the object pointer or NULL on error.
 */
struct buffer_reg_pid *buffer_reg_pid_find(uint64_t session_id)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct buffer_reg_pid *reg = nullptr;
	struct lttng_ht *ht = buffer_registry_pid;

	DBG3("Buffer registry per PID find id: %" PRIu64, session_id);

	lttng_ht_lookup(ht, &session_id, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (!node) {
		goto end;
	}
	reg = lttng::utils::container_of(node, &buffer_reg_pid::node);

end:
	return reg;
}

/*
 * Find the consumer channel key from a UST session per-uid channel key.
 *
 * Return the matching key or -1 if not found.
 */
int buffer_reg_uid_consumer_channel_key(struct cds_list_head *buffer_reg_uid_list,
					uint64_t chan_key,
					uint64_t *consumer_chan_key)
{
	int ret = -1;

	/*
	 * For the per-uid registry, we have to iterate since we don't have the
	 * uid and bitness key.
	 */
	for (auto uid_reg :
	     lttng::urcu::list_iteration_adapter<buffer_reg_uid, &buffer_reg_uid::lnode>(
		     *buffer_reg_uid_list)) {
		auto *session_reg = uid_reg->registry;
		for (auto *reg_chan :
		     lttng::urcu::lfht_iteration_adapter<buffer_reg_channel,
							 decltype(buffer_reg_channel::node),
							 &buffer_reg_channel::node>(
			     *session_reg->channels->ht)) {
			if (reg_chan->key == chan_key) {
				*consumer_chan_key = reg_chan->consumer_key;
				ret = 0;
				goto end;
			}
		}
	}
end:
	return ret;
}

/*
 * Allocate and initialize a buffer registry channel with the given key. Set
 * regp with the object pointer.
 *
 * Return 0 on success or else a negative value keeping regp untouched.
 */
int buffer_reg_channel_create(uint64_t key, struct buffer_reg_channel **regp)
{
	struct buffer_reg_channel *reg;

	LTTNG_ASSERT(regp);

	DBG3("Buffer registry channel create with key: %" PRIu64, key);

	reg = zmalloc<buffer_reg_channel>();
	if (!reg) {
		PERROR("zmalloc buffer registry channel");
		return -ENOMEM;
	}

	reg->key = key;
	CDS_INIT_LIST_HEAD(&reg->streams);
	pthread_mutex_init(&reg->stream_list_lock, nullptr);

	lttng_ht_node_init_u64(&reg->node, key);
	*regp = reg;

	return 0;
}

/*
 * Allocate and initialize a buffer registry stream. Set regp with the object
 * pointer.
 *
 * Return 0 on success or else a negative value keeping regp untouched.
 */
int buffer_reg_stream_create(struct buffer_reg_stream **regp)
{
	struct buffer_reg_stream *reg;

	LTTNG_ASSERT(regp);

	DBG3("Buffer registry creating stream");

	reg = zmalloc<buffer_reg_stream>();
	if (!reg) {
		PERROR("zmalloc buffer registry stream");
		return -ENOMEM;
	}

	*regp = reg;

	return 0;
}

/*
 * Add stream to the list in the channel.
 */
void buffer_reg_stream_add(struct buffer_reg_stream *stream, struct buffer_reg_channel *channel)
{
	LTTNG_ASSERT(stream);
	LTTNG_ASSERT(channel);

	pthread_mutex_lock(&channel->stream_list_lock);
	cds_list_add_tail(&stream->lnode, &channel->streams);
	channel->stream_count++;
	pthread_mutex_unlock(&channel->stream_list_lock);
}

/*
 * Add a buffer registry channel object to the given session.
 */
void buffer_reg_channel_add(struct buffer_reg_session *session, struct buffer_reg_channel *channel)
{
	LTTNG_ASSERT(session);
	LTTNG_ASSERT(channel);

	const lttng::urcu::read_lock_guard read_lock;
	lttng_ht_add_unique_u64(session->channels, &channel->node);
}

/*
 * Find a buffer registry channel object with the given key. RCU read side lock
 * MUST be acquired and hold on until the object reference is not needed
 * anymore.
 *
 * Return the object pointer or NULL on error.
 */
struct buffer_reg_channel *buffer_reg_channel_find(uint64_t key, struct buffer_reg_uid *reg)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct buffer_reg_channel *chan = nullptr;
	struct lttng_ht *ht;

	LTTNG_ASSERT(reg);

	switch (reg->domain) {
	case LTTNG_DOMAIN_UST:
		ht = reg->registry->channels;
		break;
	default:
		abort();
		goto end;
	}

	lttng_ht_lookup(ht, &key, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (!node) {
		goto end;
	}
	chan = lttng::utils::container_of(node, &buffer_reg_channel::node);

end:
	return chan;
}

/*
 * Destroy a buffer registry stream with the given domain.
 */
void buffer_reg_stream_destroy(struct buffer_reg_stream *regp, enum lttng_domain_type domain)
{
	if (!regp) {
		return;
	}

	DBG3("Buffer registry stream destroy with handle %d", regp->obj.ust->header.handle);

	switch (domain) {
	case LTTNG_DOMAIN_UST:
	{
		int ret;

		ret = ust_app_release_object(nullptr, regp->obj.ust);
		if (ret < 0 && ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
			ERR("Buffer reg stream release obj handle %d failed with ret %d",
			    regp->obj.ust->header.handle,
			    ret);
		}
		free(regp->obj.ust);
		lttng_fd_put(LTTNG_FD_APPS, 2);
		break;
	}
	default:
		abort();
	}

	free(regp);
	return;
}

/*
 * Remove buffer registry channel object from the session hash table. RCU read
 * side lock MUST be acquired before calling this.
 */
void buffer_reg_channel_remove(struct buffer_reg_session *session, struct buffer_reg_channel *regp)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(session);
	LTTNG_ASSERT(regp);

	iter.iter.node = &regp->node.node;
	ret = lttng_ht_del(session->channels, &iter);
	LTTNG_ASSERT(!ret);
}

/*
 * Destroy a buffer registry channel with the given domain.
 */
void buffer_reg_channel_destroy(struct buffer_reg_channel *regp, enum lttng_domain_type domain)
{
	if (!regp) {
		return;
	}

	DBG3("Buffer registry channel destroy with key %" PRIu32, regp->key);

	switch (domain) {
	case LTTNG_DOMAIN_UST:
	{
		int ret;

		/* Wipe stream */
		for (auto reg_stream :
		     lttng::urcu::list_iteration_adapter<buffer_reg_stream,
							 &buffer_reg_stream::lnode>(
			     regp->streams)) {
			cds_list_del(&reg_stream->lnode);
			regp->stream_count--;
			buffer_reg_stream_destroy(reg_stream, domain);
		}

		if (regp->obj.ust) {
			ret = ust_app_release_object(nullptr, regp->obj.ust);
			if (ret < 0 && ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
				ERR("Buffer reg channel release obj handle %d failed with ret %d",
				    regp->obj.ust->header.handle,
				    ret);
			}
			free(regp->obj.ust);
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
		break;
	}
	default:
		abort();
	}

	free(regp);
	return;
}

/*
 * Destroy a buffer registry session with the given domain.
 */
static void buffer_reg_session_destroy(struct buffer_reg_session *regp,
				       enum lttng_domain_type domain)
{
	DBG3("Buffer registry session destroy");

	/* Destroy all channels. */
	for (auto *reg_chan :
	     lttng::urcu::lfht_iteration_adapter<buffer_reg_channel,
						 decltype(buffer_reg_channel::node),
						 &buffer_reg_channel::node>(*regp->channels->ht)) {
		const auto ret = cds_lfht_del(regp->channels->ht, &reg_chan->node.node);
		LTTNG_ASSERT(!ret);
		buffer_reg_channel_destroy(reg_chan, domain);
	}

	lttng_ht_destroy(regp->channels);

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		ust_registry_session_destroy(regp->reg.ust);
		break;
	default:
		abort();
	}

	free(regp);
	return;
}

/*
 * Remove buffer registry UID object from the global hash table.
 */
void buffer_reg_uid_remove(struct buffer_reg_uid *regp)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(regp);

	const lttng::urcu::read_lock_guard read_lock;
	iter.iter.node = &regp->node.node;
	ret = lttng_ht_del(buffer_registry_uid, &iter);
	LTTNG_ASSERT(!ret);
}

static void rcu_free_buffer_reg_uid(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node = lttng::utils::container_of(head, &lttng_ht_node_u64::head);
	struct buffer_reg_uid *reg = lttng::utils::container_of(node, &buffer_reg_uid::node);

	buffer_reg_session_destroy(reg->registry, reg->domain);
	free(reg);
}

static void rcu_free_buffer_reg_pid(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node = lttng::utils::container_of(head, &lttng_ht_node_u64::head);
	struct buffer_reg_pid *reg = lttng::utils::container_of(node, &buffer_reg_pid::node);

	buffer_reg_session_destroy(reg->registry, LTTNG_DOMAIN_UST);
	free(reg);
}

/*
 * Destroy buffer registry per UID. The given pointer is NOT removed from any
 * list or hash table. Use buffer_reg_pid_remove() before calling this function
 * for the case that the object is in the global hash table.
 */
void buffer_reg_uid_destroy(struct buffer_reg_uid *regp, struct consumer_output *consumer)
{
	struct consumer_socket *socket;

	if (!regp) {
		return;
	}

	DBG3("Buffer registry per UID destroy with id: %" PRIu64 ", ABI: %u, uid: %d",
	     regp->session_id,
	     regp->bits_per_long,
	     regp->uid);

	if (!consumer) {
		goto destroy;
	}

	{
		const lttng::urcu::read_lock_guard read_lock;
		/* Get the right socket from the consumer object. */
		socket = consumer_find_socket_by_bitness(regp->bits_per_long, consumer);
		if (!socket) {
			goto destroy;
		}

		switch (regp->domain) {
		case LTTNG_DOMAIN_UST:
			if (regp->registry->reg.ust->_metadata_key) {
				/* Return value does not matter. This call will print errors. */
				(void) consumer_close_metadata(
					socket, regp->registry->reg.ust->_metadata_key);
			}
			break;
		default:
			abort();
			return;
		}
	}

destroy:
	call_rcu(&regp->node.head, rcu_free_buffer_reg_uid);
}

/*
 * Remove buffer registry UID object from the global hash table. RCU read side
 * lock MUST be acquired before calling this.
 */
void buffer_reg_pid_remove(struct buffer_reg_pid *regp)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(regp);

	iter.iter.node = &regp->node.node;
	ret = lttng_ht_del(buffer_registry_pid, &iter);
	LTTNG_ASSERT(!ret);
}

/*
 * Destroy buffer registry per PID. The pointer is NOT removed from the global
 * hash table. Call buffer_reg_pid_remove() before that if the object was
 * previously added to the global hash table.
 */
void buffer_reg_pid_destroy(struct buffer_reg_pid *regp)
{
	if (!regp) {
		return;
	}

	DBG3("Buffer registry per PID destroy with id: %" PRIu64, regp->session_id);

	/* This registry is only used by UST. */
	call_rcu(&regp->node.head, rcu_free_buffer_reg_pid);
}

/*
 * Destroy per PID and UID registry hash table.
 */
void buffer_reg_destroy_registries()
{
	DBG3("Buffer registry destroy all registry");
	lttng_ht_destroy(buffer_registry_uid);
	lttng_ht_destroy(buffer_registry_pid);
}
