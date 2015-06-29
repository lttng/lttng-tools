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
#include <inttypes.h>

#include <common/common.h>
#include <common/hashtable/utils.h>

#include "buffer-registry.h"
#include "fd-limit.h"
#include "ust-consumer.h"
#include "ust-ctl.h"
#include "utils.h"

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
	struct buffer_reg_uid *reg;
	const struct buffer_reg_uid *key;

	assert(node);
	assert(_key);

	reg = caa_container_of(node, struct buffer_reg_uid, node.node);
	assert(reg);
	key = _key;

	if (key->session_id != reg->session_id ||
			key->bits_per_long != reg->bits_per_long ||
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
static unsigned long ht_hash_reg_uid(void *_key, unsigned long seed)
{
	uint64_t xored_key;
	struct buffer_reg_uid *key = _key;

	assert(key);

	xored_key = (uint64_t)(key->session_id ^ key->bits_per_long ^ key->uid);
	return hash_key_u64(&xored_key, seed);
}

/*
 * Initialize global buffer per UID registry. Should only be called ONCE!.
 */
void buffer_reg_init_uid_registry(void)
{
	/* Should be called once. */
	assert(!buffer_registry_uid);
	buffer_registry_uid = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	assert(buffer_registry_uid);
	buffer_registry_uid->match_fct = ht_match_reg_uid;
	buffer_registry_uid->hash_fct = ht_hash_reg_uid;

	DBG3("Global buffer per UID registry initialized");
}

/*
 * Allocate and initialize object. Set regp with the object pointer.
 *
 * Return 0 on success else a negative value and regp is untouched.
 */
int buffer_reg_uid_create(uint64_t session_id, uint32_t bits_per_long, uid_t uid,
		enum lttng_domain_type domain, struct buffer_reg_uid **regp,
		const char *root_shm_path, const char *shm_path)
{
	int ret = 0;
	struct buffer_reg_uid *reg = NULL;

	assert(regp);

	reg = zmalloc(sizeof(*reg));
	if (!reg) {
		PERROR("zmalloc buffer registry uid");
		ret = -ENOMEM;
		goto error;
	}

	reg->registry = zmalloc(sizeof(struct buffer_reg_session));
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
			reg->shm_path, session_id);
	}
	reg->registry->channels = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!reg->registry->channels) {
		ret = -ENOMEM;
		goto error_session;
	}

	cds_lfht_node_init(&reg->node.node);
	*regp = reg;

	DBG3("Buffer registry per UID created id: %" PRIu64 ", ABI: %u, uid: %d, domain: %d",
			session_id, bits_per_long, uid, domain);

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

	assert(reg);

	DBG3("Buffer registry per UID adding to global registry with id: %" PRIu64 ,
			reg->session_id);

	rcu_read_lock();
	nodep = cds_lfht_add_unique(ht->ht, ht->hash_fct(reg, lttng_ht_seed),
			ht->match_fct, reg, &reg->node.node);
	assert(nodep == &reg->node.node);
	rcu_read_unlock();
}

/*
 * Find a buffer registry per UID object with given params. RCU read side lock
 * MUST be acquired before calling this and hold on to protect the object.
 *
 * Return the object pointer or NULL on error.
 */
struct buffer_reg_uid *buffer_reg_uid_find(uint64_t session_id,
		uint32_t bits_per_long, uid_t uid)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct buffer_reg_uid *reg = NULL, key;
	struct lttng_ht *ht = buffer_registry_uid;

	/* Setup key we are looking for. */
	key.session_id = session_id;
	key.bits_per_long = bits_per_long;
	key.uid = uid;

	DBG3("Buffer registry per UID find id: %" PRIu64 ", ABI: %u, uid: %d",
			session_id, bits_per_long, uid);

	/* Custom lookup function since it's a different key. */
	cds_lfht_lookup(ht->ht, ht->hash_fct(&key, lttng_ht_seed), ht->match_fct,
			&key, &iter.iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		goto end;
	}
	reg = caa_container_of(node, struct buffer_reg_uid, node);

end:
	return reg;
}

/*
 * Initialize global buffer per PID registry. Should only be called ONCE!.
 */
void buffer_reg_init_pid_registry(void)
{
	/* Should be called once. */
	assert(!buffer_registry_pid);
	buffer_registry_pid = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	assert(buffer_registry_pid);

	DBG3("Global buffer per PID registry initialized");
}

/*
 * Allocate and initialize object. Set regp with the object pointer.
 *
 * Return 0 on success else a negative value and regp is untouched.
 */
int buffer_reg_pid_create(uint64_t session_id, struct buffer_reg_pid **regp,
		const char *root_shm_path, const char *shm_path)
{
	int ret = 0;
	struct buffer_reg_pid *reg = NULL;

	assert(regp);

	reg = zmalloc(sizeof(*reg));
	if (!reg) {
		PERROR("zmalloc buffer registry pid");
		ret = -ENOMEM;
		goto error;
	}

	reg->registry = zmalloc(sizeof(struct buffer_reg_session));
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
				reg->shm_path, session_id);
	}
	reg->registry->channels = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!reg->registry->channels) {
		ret = -ENOMEM;
		goto error_session;
	}

	lttng_ht_node_init_u64(&reg->node, reg->session_id);
	*regp = reg;

	DBG3("Buffer registry per PID created with session id: %" PRIu64,
			session_id);

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
	assert(reg);

	DBG3("Buffer registry per PID adding to global registry with id: %" PRIu64,
			reg->session_id);

	rcu_read_lock();
	lttng_ht_add_unique_u64(buffer_registry_pid, &reg->node);
	rcu_read_unlock();
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
	struct buffer_reg_pid *reg = NULL;
	struct lttng_ht *ht = buffer_registry_pid;

	DBG3("Buffer registry per PID find id: %" PRIu64, session_id);

	lttng_ht_lookup(ht, &session_id, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		goto end;
	}
	reg = caa_container_of(node, struct buffer_reg_pid, node);

end:
	return reg;
}

/*
 * Find the consumer channel key from a UST session per-uid channel key.
 *
 * Return the matching key or -1 if not found.
 */
int buffer_reg_uid_consumer_channel_key(
		struct cds_list_head *buffer_reg_uid_list,
		uint64_t usess_id, uint64_t chan_key,
		uint64_t *consumer_chan_key)
{
	struct lttng_ht_iter iter;
	struct buffer_reg_uid *uid_reg = NULL;
	struct buffer_reg_session *session_reg = NULL;
	struct buffer_reg_channel *reg_chan;
	int ret = -1;

	rcu_read_lock();
	/*
	 * For the per-uid registry, we have to iterate since we don't have the
	 * uid and bitness key.
	 */
	cds_list_for_each_entry(uid_reg, buffer_reg_uid_list, lnode) {
		session_reg = uid_reg->registry;
		cds_lfht_for_each_entry(session_reg->channels->ht,
				&iter.iter, reg_chan, node.node) {
			if (reg_chan->key == chan_key) {
				*consumer_chan_key = reg_chan->consumer_key;
				ret = 0;
				goto end;
			}
		}
	}

end:
	rcu_read_unlock();
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

	assert(regp);

	DBG3("Buffer registry channel create with key: %" PRIu64, key);

	reg = zmalloc(sizeof(*reg));
	if (!reg) {
		PERROR("zmalloc buffer registry channel");
		return -ENOMEM;
	}

	reg->key = key;
	CDS_INIT_LIST_HEAD(&reg->streams);
	pthread_mutex_init(&reg->stream_list_lock, NULL);

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

	assert(regp);

	DBG3("Buffer registry creating stream");

	reg = zmalloc(sizeof(*reg));
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
void buffer_reg_stream_add(struct buffer_reg_stream *stream,
		struct buffer_reg_channel *channel)
{
	assert(stream);
	assert(channel);

	pthread_mutex_lock(&channel->stream_list_lock);
	cds_list_add_tail(&stream->lnode, &channel->streams);
	channel->stream_count++;
	pthread_mutex_unlock(&channel->stream_list_lock);
}

/*
 * Add a buffer registry channel object to the given session.
 */
void buffer_reg_channel_add(struct buffer_reg_session *session,
		struct buffer_reg_channel *channel)
{
	assert(session);
	assert(channel);

	rcu_read_lock();
	lttng_ht_add_unique_u64(session->channels, &channel->node);
	rcu_read_unlock();
}

/*
 * Find a buffer registry channel object with the given key. RCU read side lock
 * MUST be acquired and hold on until the object reference is not needed
 * anymore.
 *
 * Return the object pointer or NULL on error.
 */
struct buffer_reg_channel *buffer_reg_channel_find(uint64_t key,
		struct buffer_reg_uid *reg)
{
	struct lttng_ht_node_u64 *node;
	struct lttng_ht_iter iter;
	struct buffer_reg_channel *chan = NULL;
	struct lttng_ht *ht;

	assert(reg);

	switch (reg->domain) {
	case LTTNG_DOMAIN_UST:
		ht = reg->registry->channels;
		break;
	default:
		assert(0);
		goto end;
	}

	lttng_ht_lookup(ht, &key, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (!node) {
		goto end;
	}
	chan = caa_container_of(node, struct buffer_reg_channel, node);

end:
	return chan;
}

/*
 * Destroy a buffer registry stream with the given domain.
 */
void buffer_reg_stream_destroy(struct buffer_reg_stream *regp,
		enum lttng_domain_type domain)
{
	if (!regp) {
		return;
	}

	DBG3("Buffer registry stream destroy with handle %d",
			regp->obj.ust->handle);

	switch (domain) {
	case LTTNG_DOMAIN_UST:
	{
		int ret;

		ret = ust_app_release_object(NULL, regp->obj.ust);
		if (ret < 0 && ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
			ERR("Buffer reg stream release obj handle %d failed with ret %d",
					regp->obj.ust->handle, ret);
		}
		free(regp->obj.ust);
		lttng_fd_put(LTTNG_FD_APPS, 2);
		break;
	}
	default:
		assert(0);
	}

	free(regp);
	return;
}

/*
 * Remove buffer registry channel object from the session hash table. RCU read
 * side lock MUST be acquired before calling this.
 */
void buffer_reg_channel_remove(struct buffer_reg_session *session,
		struct buffer_reg_channel *regp)
{
	int ret;
	struct lttng_ht_iter iter;

	assert(session);
	assert(regp);

	iter.iter.node = &regp->node.node;
	ret = lttng_ht_del(session->channels, &iter);
	assert(!ret);
}

/*
 * Destroy a buffer registry channel with the given domain.
 */
void buffer_reg_channel_destroy(struct buffer_reg_channel *regp,
		enum lttng_domain_type domain)
{
	if (!regp) {
		return;
	}

	DBG3("Buffer registry channel destroy with key %" PRIu32, regp->key);

	switch (domain) {
	case LTTNG_DOMAIN_UST:
	{
		int ret;
		struct buffer_reg_stream *sreg, *stmp;
		/* Wipe stream */
		cds_list_for_each_entry_safe(sreg, stmp, &regp->streams, lnode) {
			cds_list_del(&sreg->lnode);
			regp->stream_count--;
			buffer_reg_stream_destroy(sreg, domain);
		}

		if (regp->obj.ust) {
			ret = ust_app_release_object(NULL, regp->obj.ust);
			if (ret < 0 && ret != -EPIPE && ret != -LTTNG_UST_ERR_EXITING) {
				ERR("Buffer reg channel release obj handle %d failed with ret %d",
						regp->obj.ust->handle, ret);
			}
			free(regp->obj.ust);
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
		break;
	}
	default:
		assert(0);
	}

	free(regp);
	return;
}

/*
 * Destroy a buffer registry session with the given domain.
 *
 * Should *NOT* be called with RCU read-side lock held.
 */
static void buffer_reg_session_destroy(struct buffer_reg_session *regp,
		enum lttng_domain_type domain)
{
	int ret;
	struct lttng_ht_iter iter;
	struct buffer_reg_channel *reg_chan;

	DBG3("Buffer registry session destroy");

	/* Destroy all channels. */
	rcu_read_lock();
	cds_lfht_for_each_entry(regp->channels->ht, &iter.iter, reg_chan,
			node.node) {
		ret = lttng_ht_del(regp->channels, &iter);
		assert(!ret);
		buffer_reg_channel_destroy(reg_chan, domain);
	}
	rcu_read_unlock();

	ht_cleanup_push(regp->channels);

	switch (domain) {
	case LTTNG_DOMAIN_UST:
		ust_registry_session_destroy(regp->reg.ust);
		free(regp->reg.ust);
		break;
	default:
		assert(0);
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

	assert(regp);

	rcu_read_lock();
	iter.iter.node = &regp->node.node;
	ret = lttng_ht_del(buffer_registry_uid, &iter);
	assert(!ret);
	rcu_read_unlock();
}

static void rcu_free_buffer_reg_uid(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node =
		caa_container_of(head, struct lttng_ht_node_u64, head);
	struct buffer_reg_uid *reg =
		caa_container_of(node, struct buffer_reg_uid, node);

	buffer_reg_session_destroy(reg->registry, reg->domain);
	free(reg);
}

static void rcu_free_buffer_reg_pid(struct rcu_head *head)
{
	struct lttng_ht_node_u64 *node =
		caa_container_of(head, struct lttng_ht_node_u64, head);
	struct buffer_reg_pid *reg =
		caa_container_of(node, struct buffer_reg_pid, node);

	buffer_reg_session_destroy(reg->registry, LTTNG_DOMAIN_UST);
	free(reg);
}

/*
 * Destroy buffer registry per UID. The given pointer is NOT removed from any
 * list or hash table. Use buffer_reg_pid_remove() before calling this function
 * for the case that the object is in the global hash table.
 */
void buffer_reg_uid_destroy(struct buffer_reg_uid *regp,
		struct consumer_output *consumer)
{
	struct consumer_socket *socket;

	if (!regp) {
		return;
	}

	DBG3("Buffer registry per UID destroy with id: %" PRIu64 ", ABI: %u, uid: %d",
			regp->session_id, regp->bits_per_long, regp->uid);

	if (!consumer) {
		goto destroy;
	}

	rcu_read_lock();
	/* Get the right socket from the consumer object. */
	socket = consumer_find_socket_by_bitness(regp->bits_per_long,
			consumer);
	if (!socket) {
		goto unlock;
	}

	switch (regp->domain) {
	case LTTNG_DOMAIN_UST:
		if (regp->registry->reg.ust->metadata_key) {
			/* Return value does not matter. This call will print errors. */
			(void) consumer_close_metadata(socket,
					regp->registry->reg.ust->metadata_key);
		}
		break;
	default:
		assert(0);
		rcu_read_unlock();
		return;
	}

unlock:
	rcu_read_unlock();
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

	assert(regp);

	iter.iter.node = &regp->node.node;
	ret = lttng_ht_del(buffer_registry_pid, &iter);
	assert(!ret);
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

	DBG3("Buffer registry per PID destroy with id: %" PRIu64,
			regp->session_id);

	/* This registry is only used by UST. */
	call_rcu(&regp->node.head, rcu_free_buffer_reg_pid);
}

/*
 * Destroy per PID and UID registry hash table.
 *
 * Should *NOT* be called with RCU read-side lock held.
 */
void buffer_reg_destroy_registries(void)
{
	DBG3("Buffer registry destroy all registry");
	ht_cleanup_push(buffer_registry_uid);
	ht_cleanup_push(buffer_registry_pid);
}
