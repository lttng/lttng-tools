/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_REGISTRY_H
#define LTTNG_UST_REGISTRY_H

#include <pthread.h>
#include <stdint.h>
#include <ctime>
#include <string>
#include <memory>

#include <common/hashtable/hashtable.hpp>
#include <common/uuid.hpp>

#include <lttng/domain.h>

#include "lttng-ust-ctl.hpp"

#define CTF_SPEC_MAJOR	1
#define CTF_SPEC_MINOR	8

struct ust_app;

class ust_registry_session {
public:
	virtual lttng_buffer_type get_buffering_scheme() const = 0;
	virtual ~ust_registry_session();

protected:
	/* Prevent instanciation of this base class. */
	ust_registry_session(unsigned int bits_per_long,
			unsigned int uint8_t_alignment,
			unsigned int uint16_t_alignment,
			unsigned int uint32_t_alignment,
			unsigned int uint64_t_alignment,
			unsigned int long_alignment,
			int byte_order,
			unsigned int app_tracer_version_major,
			unsigned int app_tracer_version_minor,
			const char *root_shm_path,
			const char *shm_path,
			uid_t euid,
			gid_t egid,
			uint64_t tracing_id);

	void statedump();

public:
	/*
	 * With multiple writers and readers, use this lock to access
	 * the registry. Can nest within the ust app session lock.
	 * Also acts as a registry serialization lock. Used by registry
	 * readers to serialize the registry information sent from the
	 * sessiond to the consumerd.
	 * The consumer socket lock nests within this lock.
	 */
	pthread_mutex_t _lock;
	/* Next channel ID available for a newly registered channel. */
	uint32_t _next_channel_id = 0;
	/* Once this value reaches UINT32_MAX, no more id can be allocated. */
	uint32_t _used_channel_id = 0;
	/* Next enumeration ID available. */
	uint64_t _next_enum_id = 0;
	/* Universal unique identifier used by the tracer. */
	unsigned char _uuid[LTTNG_UUID_LEN] = {};

	/* session ABI description */

	/* Size of long, in bits */
	unsigned int _bits_per_long;
	/* Alignment, in bits */
	unsigned int _uint8_t_alignment, _uint16_t_alignment, _uint32_t_alignment,
			_uint64_t_alignment, _long_alignment;
	/* endianness: BIG_ENDIAN or LITTLE_ENDIAN */
	int _byte_order;

	/* Generated metadata. */
	char *_metadata = nullptr; /* NOT null-terminated ! Use memcpy. */
	size_t _metadata_len = 0, _metadata_alloc_len = 0;
	/* Length of bytes sent to the consumer. */
	size_t _metadata_len_sent = 0;
	/* Current version of the metadata. */
	uint64_t _metadata_version = 0;

	/*
	 * Those fields are only used when a session is created with
	 * the --shm-path option. In this case, the metadata is output
	 * twice: once to the consumer, as ususal, but a second time
	 * also in the shm path directly. This is done so that a copy
	 * of the metadata that is as fresh as possible is available
	 * on the event of a crash.
	 *
	 * root_shm_path contains the shm-path provided by the user, along with
	 * the session's name and timestamp:
	 *   e.g. /tmp/my_shm/my_session-20180612-135822
	 *
	 * shm_path contains the full path of the memory buffers:
	 *   e.g. /tmp/my_shm/my_session-20180612-135822/ust/uid/1000/64-bit
	 *
	 * metadata_path contains the full path to the metadata file that
	 * is kept for the "crash buffer" extraction:
	 *  e.g.
	 * /tmp/my_shm/my_session-20180612-135822/ust/uid/1000/64-bit/metadata
	 *
	 * Note that this is not the trace's final metadata file. It is
	 * only meant to be used to read the contents of the ring buffers
	 * in the event of a crash.
	 *
	 * metadata_fd is a file descriptor that points to the file at
	 * 'metadata_path'.
	 */
	char _root_shm_path[PATH_MAX] = {};
	char _shm_path[PATH_MAX] = {};
	char _metadata_path[PATH_MAX] = {};
	/* File-backed metadata FD */
	int _metadata_fd = -1;

	/*
	 * Hash table containing channels sent by the UST tracer. MUST
	 * be accessed with a RCU read side lock acquired.
	 */
	lttng_ht::uptr _channels;

	/*
	 * Unique key to identify the metadata on the consumer side.
	 */
	uint64_t _metadata_key = 0;
	/*
	 * Indicates if the metadata is closed on the consumer side. This is to
	 * avoid double close of metadata when an application unregisters AND
	 * deletes its sessions.
	 */
	bool _metadata_closed = false;

	/* User and group owning the session. */
	uid_t _uid = -1;
	gid_t _gid = -1;

	/* Enumerations table. */
	lttng_ht::uptr _enums;

	/*
	 * Copy of the tracer version when the first app is registered.
	 * It is used if we need to regenerate the metadata.
	 */
	uint32_t _app_tracer_version_major = 0;
	uint32_t _app_tracer_version_minor = 0;

	/* The id of the parent session */
	uint64_t _tracing_id = -1ULL;
};

class ust_registry_session_per_uid : public ust_registry_session {
public:
	ust_registry_session_per_uid(uint32_t bits_per_long,
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
			gid_t egid,
			uint64_t tracing_id,
			uid_t tracing_uid);

	virtual lttng_buffer_type get_buffering_scheme() const noexcept override final;

	const uid_t _tracing_uid;
};

class ust_registry_session_per_pid : public ust_registry_session {
public:
	ust_registry_session_per_pid(const struct ust_app &app,
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
			gid_t egid,
			uint64_t tracing_id);

	virtual lttng_buffer_type get_buffering_scheme() const noexcept override final;

	pid_t get_vpid() const
	{
		return _vpid;
	}

	const unsigned int _tracer_patch_level_version;
	const pid_t _vpid;
	const std::string _procname;
	const std::time_t _app_creation_time;
};

struct ust_registry_channel {
	uint64_t key;
	uint64_t consumer_key;
	/* Id set when replying to a register channel. */
	uint32_t chan_id;
	enum lttng_ust_ctl_channel_header header_type;

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
	struct lttng_ht *events;
	/* Next event ID available for a newly registered event. */
	uint32_t next_event_id;
	/* Once this value reaches UINT32_MAX, no more id can be allocated. */
	uint32_t used_event_id;
	/*
	 * Context fields of the registry. Context are per channel. Allocated by a
	 * register channel notification from the UST tracer.
	 */
	size_t nr_ctx_fields;
	struct lttng_ust_ctl_field *ctx_fields;
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
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
	char *signature;
	int loglevel_value;
	size_t nr_fields;
	struct lttng_ust_ctl_field *fields;
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
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
	struct lttng_ust_ctl_enum_entry *entries;
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
		ust_registry_session *r)
{
	if (ust_registry_is_max_id(r->_used_channel_id)) {
		return r->_used_channel_id;
	}

	r->_used_channel_id++;
	return r->_next_channel_id++;
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

void ust_registry_channel_destroy(ust_registry_session *session,
		struct ust_registry_channel *chan);
struct ust_registry_channel *ust_registry_channel_find(
		ust_registry_session *session, uint64_t key);
int ust_registry_channel_add(ust_registry_session *session,
		uint64_t key);
void ust_registry_channel_del_free(ust_registry_session *session,
		uint64_t key, bool notif);
void ust_registry_channel_destroy(struct ust_registry_channel *chan, bool notify);

/*
 * Create per-uid registry with default values.
 *
 * Return new instance on success, nullptr on error.
 */
ust_registry_session *ust_registry_session_per_uid_create(
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
		gid_t egid,
		uint64_t tracing_id,
		uid_t tracing_uid);

/*
 * Create per-pid registry with default values.
 *
 * Return new instance on success, nullptr on error.
 */
ust_registry_session *ust_registry_session_per_pid_create(struct ust_app *app,
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
		gid_t egid,
		uint64_t tracing_id);
void ust_registry_session_destroy(ust_registry_session *session);

int ust_registry_create_event(ust_registry_session *session,
		uint64_t chan_key, int session_objd, int channel_objd, char *name,
		char *sig, size_t nr_fields, struct lttng_ust_ctl_field *fields,
		int loglevel_value, char *model_emf_uri, int buffer_type,
		uint32_t *event_id_p, struct ust_app *app);
struct ust_registry_event *ust_registry_find_event(
		struct ust_registry_channel *chan, char *name, char *sig);
void ust_registry_destroy_event(struct ust_registry_channel *chan,
		struct ust_registry_event *event);

/* app can be NULL for registry shared across applications. */
int ust_metadata_session_statedump(ust_registry_session *session);
int ust_metadata_channel_statedump(ust_registry_session *session,
		struct ust_registry_channel *chan);
int ust_metadata_event_statedump(ust_registry_session *session,
		struct ust_registry_channel *chan,
		struct ust_registry_event *event);
int ust_registry_create_or_find_enum(ust_registry_session *session,
		int session_objd, char *name,
		struct lttng_ust_ctl_enum_entry *entries, size_t nr_entries,
		uint64_t *enum_id);
struct ust_registry_enum *
	ust_registry_lookup_enum_by_id(ust_registry_session *session,
		const char *name, uint64_t id);
void ust_registry_destroy_enum(ust_registry_session *reg_session,
		struct ust_registry_enum *reg_enum);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline void ust_registry_channel_destroy(
		struct ust_registry_channel *chan __attribute__((unused)),
		bool notify __attribute__((unused)))
{
}

static inline
struct ust_registry_channel *ust_registry_channel_find(
		ust_registry_session *session __attribute__((unused)),
		uint64_t key __attribute__((unused)))
{
	return NULL;
}

static inline
int ust_registry_channel_add(
		ust_registry_session *session __attribute__((unused)),
		uint64_t key __attribute__((unused)))
{
	return 0;
}

static inline
void ust_registry_channel_del_free(
		ust_registry_session *session __attribute__((unused)),
		uint64_t key __attribute__((unused)),
		bool notif __attribute__((unused)))
{}

static inline
ust_registry_session *ust_registry_session_per_uid_create(
		uint32_t bits_per_long __attribute__((unused)),
		uint32_t uint8_t_alignment __attribute__((unused)),
		uint32_t uint16_t_alignment __attribute__((unused)),
		uint32_t uint32_t_alignment __attribute__((unused)),
		uint32_t uint64_t_alignment __attribute__((unused)),
		uint32_t long_alignment __attribute__((unused)),
		int byte_order __attribute__((unused)),
		uint32_t major __attribute__((unused)),
		uint32_t minor __attribute__((unused)),
		const char *root_shm_path __attribute__((unused)),
		const char *shm_path __attribute__((unused)),
		uid_t euid __attribute__((unused)),
		gid_t egid __attribute__((unused)),
		uint64_t tracing_id __attribute__((unused)),
		uid_t tracing_uid __attribute__((unused)))
{
	return nullptr;
}

static inline
ust_registry_session *ust_registry_session_per_pid_create(
		struct ust_app *app __attribute__((unused)),
		uint32_t bits_per_long __attribute__((unused)),
		uint32_t uint8_t_alignment __attribute__((unused)),
		uint32_t uint16_t_alignment __attribute__((unused)),
		uint32_t uint32_t_alignment __attribute__((unused)),
		uint32_t uint64_t_alignment __attribute__((unused)),
		uint32_t long_alignment __attribute__((unused)),
		int byte_order __attribute__((unused)),
		uint32_t major __attribute__((unused)),
		uint32_t minor __attribute__((unused)),
		const char *root_shm_path __attribute__((unused)),
		const char *shm_path __attribute__((unused)),
		uid_t euid __attribute__((unused)),
		gid_t egid __attribute__((unused)),
		uint64_t tracing_id __attribute__((unused)))
{
	return nullptr;
}

static inline
void ust_registry_session_destroy(
		ust_registry_session *session __attribute__((unused)))
{}

static inline
int ust_registry_create_event(
		ust_registry_session *session __attribute__((unused)),
		uint64_t chan_key __attribute__((unused)),
		int session_objd __attribute__((unused)),
		int channel_objd __attribute__((unused)),
		char *name __attribute__((unused)),
		char *sig __attribute__((unused)),
		size_t nr_fields __attribute__((unused)),
		struct lttng_ust_ctl_field *fields __attribute__((unused)),
		int loglevel_value __attribute__((unused)),
		char *model_emf_uri __attribute__((unused)),
		int buffer_type __attribute__((unused)),
		uint32_t *event_id_p __attribute__((unused)))
{
	return 0;
}
static inline
struct ust_registry_event *ust_registry_find_event(
		struct ust_registry_channel *chan __attribute__((unused)),
		char *name __attribute__((unused)),
		char *sig __attribute__((unused)))
{
	return NULL;
}

static inline
void ust_registry_destroy_event(
		struct ust_registry_channel *chan __attribute__((unused)),
		struct ust_registry_event *event __attribute__((unused)))
{}

/* The app object can be NULL for registry shared across applications. */
static inline
int ust_metadata_session_statedump(
		ust_registry_session *session __attribute__((unused)))
{
	return 0;
}

static inline
int ust_metadata_channel_statedump(
		ust_registry_session *session __attribute__((unused)),
		struct ust_registry_channel *chan __attribute__((unused)))
{
	return 0;
}

static inline
int ust_metadata_event_statedump(
		ust_registry_session *session __attribute__((unused)),
		struct ust_registry_channel *chan __attribute__((unused)),
		struct ust_registry_event *event __attribute__((unused)))
{
	return 0;
}

static inline
int ust_registry_create_or_find_enum(
		ust_registry_session *session __attribute__((unused)),
		int session_objd __attribute__((unused)),
		char *name __attribute__((unused)),
		struct lttng_ust_ctl_enum_entry *entries __attribute__((unused)),
		size_t nr_entries __attribute__((unused)),
		uint64_t *enum_id __attribute__((unused)))
{
	return 0;
}

static inline
struct ust_registry_enum *
	ust_registry_lookup_enum_by_id(
		ust_registry_session *session __attribute__((unused)),
		const char *name __attribute__((unused)),
		uint64_t id __attribute__((unused)))
{
	return NULL;
}

static inline
void ust_registry_destroy_enum(ust_registry_session *reg_session __attribute__((unused)),
		struct ust_registry_enum *reg_enum __attribute__((unused)))
{}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* LTTNG_UST_REGISTRY_H */
