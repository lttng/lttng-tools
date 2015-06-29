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

#ifndef LTTNG_BUFFER_REGISTRY_H
#define LTTNG_BUFFER_REGISTRY_H

#include <stdint.h>
#include <urcu/list.h>

#include <lttng/lttng.h>
#include <common/hashtable/hashtable.h>

#include "consumer.h"
#include "ust-ctl.h"
#include "ust-registry.h"

struct buffer_reg_stream {
	struct cds_list_head lnode;
	union {
		/* Original object data that MUST be copied over. */
		struct lttng_ust_object_data *ust;
	} obj;
};

struct buffer_reg_channel {
	/* This key is the same as a tracing channel key. */
	uint32_t key;
	/* Key of the channel on the consumer side. */
	uint64_t consumer_key;
	/* Stream registry object of this channel registry. */
	struct cds_list_head streams;
	/* Total number of stream in the list. */
	uint64_t stream_count;
	/* Used to ensure mutual exclusion to the stream's list. */
	pthread_mutex_t stream_list_lock;
	/* Node for hash table usage. */
	struct lttng_ht_node_u64 node;
	/* Size of subbuffers in this channel. */
	size_t subbuf_size;
	/* Number of subbuffers per stream. */
	size_t num_subbuf;
	union {
		/* Original object data that MUST be copied over. */
		struct lttng_ust_object_data *ust;
	} obj;
};

struct buffer_reg_session {
	/* Registry per domain. */
	union {
		struct ust_registry_session *ust;
	} reg;

	/* Contains buffer registry channel indexed by tracing channel key. */
	struct lttng_ht *channels;
};

/*
 * Registry object for per UID buffers.
 */
struct buffer_reg_uid {
	/*
	 * Keys to match this object in a hash table. The following three variables
	 * identify a unique per UID buffer registry.
	 */
	uint64_t session_id;	/* Unique tracing session id. */
	int bits_per_long;	/* ABI */
	uid_t uid;			/* Owner. */

	enum lttng_domain_type domain;
	struct buffer_reg_session *registry;

	/* Indexed by session id. */
	struct lttng_ht_node_u64 node;
	/* Node of a linked list used to teardown object at a destroy session. */
	struct cds_list_head lnode;

	char root_shm_path[PATH_MAX];
	char shm_path[PATH_MAX];
};

/*
 * Registry object for per PID buffers.
 */
struct buffer_reg_pid {
	uint64_t session_id;

	struct buffer_reg_session *registry;

	/* Indexed by session id. */
	struct lttng_ht_node_u64 node;

	char root_shm_path[PATH_MAX];
	char shm_path[PATH_MAX];
};

/* Buffer registry per UID. */
void buffer_reg_init_uid_registry(void);
int buffer_reg_uid_create(uint64_t session_id, uint32_t bits_per_long, uid_t uid,
		enum lttng_domain_type domain, struct buffer_reg_uid **regp,
		const char *root_shm_path, const char *shm_path);
void buffer_reg_uid_add(struct buffer_reg_uid *reg);
struct buffer_reg_uid *buffer_reg_uid_find(uint64_t session_id,
		uint32_t bits_per_long, uid_t uid);
void buffer_reg_uid_remove(struct buffer_reg_uid *regp);
void buffer_reg_uid_destroy(struct buffer_reg_uid *regp,
		struct consumer_output *consumer);

/* Buffer registry per PID. */
void buffer_reg_init_pid_registry(void);
int buffer_reg_pid_create(uint64_t session_id, struct buffer_reg_pid **regp,
		const char *root_shm_path, const char *shm_path);
void buffer_reg_pid_add(struct buffer_reg_pid *reg);
struct buffer_reg_pid *buffer_reg_pid_find(uint64_t session_id);
void buffer_reg_pid_remove(struct buffer_reg_pid *regp);
void buffer_reg_pid_destroy(struct buffer_reg_pid *regp);

/* Channel */
int buffer_reg_channel_create(uint64_t key, struct buffer_reg_channel **regp);
void buffer_reg_channel_add(struct buffer_reg_session *session,
		struct buffer_reg_channel *channel);
struct buffer_reg_channel *buffer_reg_channel_find(uint64_t key,
		struct buffer_reg_uid *reg);
void buffer_reg_channel_remove(struct buffer_reg_session *session,
		struct buffer_reg_channel *regp);
void buffer_reg_channel_destroy(struct buffer_reg_channel *regp,
		enum lttng_domain_type domain);

/* Stream */
int buffer_reg_stream_create(struct buffer_reg_stream **regp);
void buffer_reg_stream_add(struct buffer_reg_stream *stream,
		struct buffer_reg_channel *channel);
void buffer_reg_stream_destroy(struct buffer_reg_stream *regp,
		enum lttng_domain_type domain);

/* Global registry. */
void buffer_reg_destroy_registries(void);

int buffer_reg_uid_consumer_channel_key(
		struct cds_list_head *buffer_reg_uid_list,
		uint64_t usess_id, uint64_t chan_key,
		uint64_t *consumer_chan_key);

#endif /* LTTNG_BUFFER_REGISTRY_H */
