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

#ifndef LTTNG_UST_REGISTRY_H
#define LTTNG_UST_REGISTRY_H

#include <pthread.h>
#include <stdint.h>

#include <common/hashtable/hashtable.h>
#include <common/compat/uuid.h>

#include "ust-ctl.h"

#define CTF_SPEC_MAJOR	1
#define CTF_SPEC_MINOR	8

struct ust_app;

struct ust_registry_session {
	/*
	 * With multiple writers and readers, use this lock to access
	 * the registry. Can nest within the ust app session lock.
	 * Also acts as a registry serialization lock. Used by registry
	 * readers to serialize the registry information sent from the
	 * sessiond to the consumerd.
	 * The consumer socket lock nests within this lock.
	 */
	pthread_mutex_t lock;
	/* Next channel ID available for a newly registered channel. */
	uint32_t next_channel_id;
	/* Once this value reaches UINT32_MAX, no more id can be allocated. */
	uint32_t used_channel_id;
	/* Next enumeration ID available. */
	uint64_t next_enum_id;
	/* Universal unique identifier used by the tracer. */
	unsigned char uuid[UUID_LEN];

	/* session ABI description */

	/* Size of long, in bits */
	unsigned int bits_per_long;
	/* Alignment, in bits */
	unsigned int uint8_t_alignment,
		uint16_t_alignment,
		uint32_t_alignment,
		uint64_t_alignment,
		long_alignment;
	/* endianness */
	int byte_order;	/* BIG_ENDIAN or LITTLE_ENDIAN */

	/* Generated metadata. */
	char *metadata;		/* NOT null-terminated ! Use memcpy. */
	size_t metadata_len, metadata_alloc_len;
	/* Length of bytes sent to the consumer. */
	size_t metadata_len_sent;
	/* Current version of the metadata. */
	uint64_t metadata_version;

	char root_shm_path[PATH_MAX];
	char shm_path[PATH_MAX];
	char metadata_path[PATH_MAX];
	int metadata_fd;	/* file-backed metadata FD */

	/*
	 * Hash table containing channels sent by the UST tracer. MUST
	 * be accessed with a RCU read side lock acquired.
	 */
	struct lttng_ht *channels;
	/*
	 * Unique key to identify the metadata on the consumer side.
	 */
	uint64_t metadata_key;
	/*
	 * Indicates if the metadata is closed on the consumer side. This is to
	 * avoid double close of metadata when an application unregisters AND
	 * deletes its sessions.
	 */
	unsigned int metadata_closed;

	/* User and group owning the session. */
	uid_t uid;
	gid_t gid;

	/* Enumerations table. */
	struct lttng_ht *enums;

	/*
	 * Copy of the tracer version when the first app is registered.
	 * It is used if we need to regenerate the metadata.
	 */
	uint32_t major;
	uint32_t minor;
};

struct ust_registry_channel {
	uint64_t key;
	uint64_t consumer_key;
	/* Id set when replying to a register channel. */
	uint32_t chan_id;
	enum ustctl_channel_header header_type;

	/*
	 * Flag for this channel if the metadata was dumped once during
	 * registration. 0 means no, 1 yes.
	 */
	unsigned int metadata_dumped;
	/* Indicates if this channel registry has already been registered. */
	unsigned int register_done;

	/*
	 * Hash table containing events sent by the UST tracer. MUST be accessed
	 * with a RCU read side lock acquired.
	 */
	struct lttng_ht *ht;
	/* Next event ID available for a newly registered event. */
	uint32_t next_event_id;
	/* Once this value reaches UINT32_MAX, no more id can be allocated. */
	uint32_t used_event_id;
	/*
	 * Context fields of the registry. Context are per channel. Allocated by a
	 * register channel notification from the UST tracer.
	 */
	size_t nr_ctx_fields;
	struct ustctl_field *ctx_fields;
	struct lttng_ht_node_u64 node;
	/* For delayed reclaim */
	struct rcu_head rcu_head;
};

/*
 * Event registered from a UST tracer sent to the session daemon. This is
 * indexed and matched by <event_name/signature>.
 */
struct ust_registry_event {
	int id;
	/* Both objd are set by the tracer. */
	int session_objd;
	int channel_objd;
	/* Name of the event returned by the tracer. */
	char name[LTTNG_UST_SYM_NAME_LEN];
	char *signature;
	int loglevel_value;
	size_t nr_fields;
	struct ustctl_field *fields;
	char *model_emf_uri;
	/*
	 * Flag for this channel if the metadata was dumped once during
	 * registration. 0 means no, 1 yes.
	 */
	unsigned int metadata_dumped;
	/*
	 * Node in the ust-registry hash table. The event name is used to
	 * initialize the node and the event_name/signature for the match function.
	 */
	struct lttng_ht_node_u64 node;
};

struct ust_registry_enum {
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct ustctl_enum_entry *entries;
	size_t nr_entries;
	uint64_t id;	/* enum id in session */
	/* Enumeration node in session hash table. */
	struct lttng_ht_node_str node;
	/* For delayed reclaim. */
	struct rcu_head rcu_head;
};

/*
 * Validate that the id has reached the maximum allowed or not.
 *
 * Return 0 if NOT else 1.
 */
static inline int ust_registry_is_max_id(uint32_t id)
{
	return (id == UINT32_MAX) ? 1 : 0;
}

/*
 * Return next available event id and increment the used counter. The
 * ust_registry_is_max_id function MUST be called before in order to validate
 * if the maximum number of IDs have been reached. If not, it is safe to call
 * this function.
 *
 * Return a unique channel ID. If max is reached, the used_event_id counter is
 * returned.
 */
static inline uint32_t ust_registry_get_next_event_id(
		struct ust_registry_channel *r)
{
	if (ust_registry_is_max_id(r->used_event_id)) {
		return r->used_event_id;
	}

	r->used_event_id++;
	return r->next_event_id++;
}

/*
 * Return next available channel id and increment the used counter. The
 * ust_registry_is_max_id function MUST be called before in order to validate
 * if the maximum number of IDs have been reached. If not, it is safe to call
 * this function.
 *
 * Return a unique channel ID. If max is reached, the used_channel_id counter
 * is returned.
 */
static inline uint32_t ust_registry_get_next_chan_id(
		struct ust_registry_session *r)
{
	if (ust_registry_is_max_id(r->used_channel_id)) {
		return r->used_channel_id;
	}

	r->used_channel_id++;
	return r->next_channel_id++;
}

/*
 * Return registry event count. This is read atomically.
 */
static inline uint32_t ust_registry_get_event_count(
		struct ust_registry_channel *r)
{
	return (uint32_t) uatomic_read(&r->used_event_id);
}

#ifdef HAVE_LIBLTTNG_UST_CTL

void ust_registry_channel_destroy(struct ust_registry_session *session,
		struct ust_registry_channel *chan);
struct ust_registry_channel *ust_registry_channel_find(
		struct ust_registry_session *session, uint64_t key);
int ust_registry_channel_add(struct ust_registry_session *session,
		uint64_t key);
void ust_registry_channel_del_free(struct ust_registry_session *session,
		uint64_t key, bool notif);

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
		gid_t egid);
void ust_registry_session_destroy(struct ust_registry_session *session);

int ust_registry_create_event(struct ust_registry_session *session,
		uint64_t chan_key, int session_objd, int channel_objd, char *name,
		char *sig, size_t nr_fields, struct ustctl_field *fields,
		int loglevel_value, char *model_emf_uri, int buffer_type,
		uint32_t *event_id_p, struct ust_app *app);
struct ust_registry_event *ust_registry_find_event(
		struct ust_registry_channel *chan, char *name, char *sig);
void ust_registry_destroy_event(struct ust_registry_channel *chan,
		struct ust_registry_event *event);

/* app can be NULL for registry shared across applications. */
int ust_metadata_session_statedump(struct ust_registry_session *session,
		struct ust_app *app, uint32_t major, uint32_t minor);
int ust_metadata_channel_statedump(struct ust_registry_session *session,
		struct ust_registry_channel *chan);
int ust_metadata_event_statedump(struct ust_registry_session *session,
		struct ust_registry_channel *chan,
		struct ust_registry_event *event);
int ust_registry_create_or_find_enum(struct ust_registry_session *session,
		int session_objd, char *name,
		struct ustctl_enum_entry *entries, size_t nr_entries,
		uint64_t *enum_id);
struct ust_registry_enum *
	ust_registry_lookup_enum_by_id(struct ust_registry_session *session,
		const char *name, uint64_t id);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline
void ust_registry_channel_destroy(struct ust_registry_session *session,
		struct ust_registry_channel *chan)
{}
static inline
struct ust_registry_channel *ust_registry_channel_find(
		struct ust_registry_session *session, uint64_t key)
{
	return NULL;
}
static inline
int ust_registry_channel_add(struct ust_registry_session *session,
		uint64_t key)
{
	return 0;
}
static inline
void ust_registry_channel_del_free(struct ust_registry_session *session,
		uint64_t key, bool notif)
{}
static inline
int ust_registry_session_init(struct ust_registry_session **sessionp,
		struct ust_app *app,
		uint32_t bits_per_long,
		uint32_t uint8_t_alignment,
		uint32_t uint16_t_alignment,
		uint32_t uint32_t_alignment,
		uint32_t uint64_t_alignment,
		uint32_t long_alignment,
		int byte_order)
{
	return 0;
}
static inline
void ust_registry_session_destroy(struct ust_registry_session *session)
{}
static inline
int ust_registry_create_event(struct ust_registry_session *session,
		uint64_t chan_key, int session_objd, int channel_objd, char *name,
		char *sig, size_t nr_fields, struct ustctl_field *fields,
		int loglevel_value, char *model_emf_uri, int buffer_type,
		uint32_t *event_id_p)
{
	return 0;
}
static inline
struct ust_registry_event *ust_registry_find_event(
		struct ust_registry_channel *chan, char *name, char *sig)
{
	return NULL;
}
static inline
void ust_registry_destroy_event(struct ust_registry_channel *chan,
		struct ust_registry_event *event)
{}

/* The app object can be NULL for registry shared across applications. */
static inline
int ust_metadata_session_statedump(struct ust_registry_session *session,
		struct ust_app *app, uint32_t major, uint32_t minor)
{
	return 0;
}
static inline
int ust_metadata_channel_statedump(struct ust_registry_session *session,
		struct ust_registry_channel *chan)
{
	return 0;
}
static inline
int ust_metadata_event_statedump(struct ust_registry_session *session,
		struct ust_registry_channel *chan,
		struct ust_registry_event *event)
{
	return 0;
}
static inline
int ust_registry_create_or_find_enum(struct ust_registry_session *session,
		int session_objd, char *name,
		struct ustctl_enum_entry *entries, size_t nr_entries,
		uint64_t *enum_id)
{
	return 0;
}
static inline
struct ust_registry_enum *
	ust_registry_lookup_enum_by_id(struct ust_registry_session *session,
		const char *name, uint64_t id)
{
	return NULL;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_UST_REGISTRY_H */
