/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTT_UST_APP_H 
#define _LTT_UST_APP_H

#include <stdint.h>

#include <common/compat/uuid.h>
#include "trace-ust.h"
#include "ust-registry.h"

/* lttng-ust supported version. */
//#define LTTNG_UST_COMM_MAJOR          2	/* comm protocol major version */
//#define UST_APP_MAJOR_VERSION         3 /* Internal UST version supported */

#define UST_APP_EVENT_LIST_SIZE 32

/* Process name (short). Extra for the NULL byte. */
#define UST_APP_PROCNAME_LEN 	17

struct lttng_filter_bytecode;
struct lttng_ust_filter_bytecode;

extern int ust_consumerd64_fd, ust_consumerd32_fd;

struct ust_app_ht_key {
	const char *name;
	const struct lttng_ust_filter_bytecode *filter;
	enum lttng_ust_loglevel_type loglevel;
};

/*
 * Application registration data structure.
 */
struct ust_register_msg {
	enum ustctl_socket_type type;
	uint32_t major;
	uint32_t minor;
	uint32_t abi_major;
	uint32_t abi_minor;
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	gid_t gid;
	uint32_t bits_per_long;
	uint32_t uint8_t_alignment;
	uint32_t uint16_t_alignment;
	uint32_t uint32_t_alignment;
	uint32_t uint64_t_alignment;
	uint32_t long_alignment;
	int byte_order;		/* BIG_ENDIAN or LITTLE_ENDIAN */
	char name[LTTNG_UST_ABI_PROCNAME_LEN];
};

/*
 * Global applications HT used by the session daemon. This table is indexed by
 * PID using the pid_n node and pid value of an ust_app.
 */
struct lttng_ht *ust_app_ht;

/*
 * Global applications HT used by the session daemon. This table is indexed by
 * socket using the sock_n node and sock value of an ust_app.
 */
struct lttng_ht *ust_app_ht_by_sock;

/*
 * Global applications HT used by the session daemon. This table is indexed by
 * socket using the notify_sock_n node and notify_sock value of an ust_app.
 */
struct lttng_ht *ust_app_ht_by_notify_sock;

/* Stream list containing ust_app_stream. */
struct ust_app_stream_list {
	unsigned int count;
	struct cds_list_head head;
};

struct ust_app_ctx {
	int handle;
	struct lttng_ust_context ctx;
	struct lttng_ust_object_data *obj;
	struct lttng_ht_node_ulong node;
};

struct ust_app_event {
	int enabled;
	int handle;
	struct lttng_ust_object_data *obj;
	struct lttng_ust_event attr;
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct lttng_ht_node_str node;
	struct lttng_ust_filter_bytecode *filter;
};

struct ust_app_stream {
	int handle;
	char pathname[PATH_MAX];
	/* Format is %s_%d respectively channel name and CPU number. */
	char name[DEFAULT_STREAM_NAME_LEN];
	struct lttng_ust_object_data *obj;
	/* Using a list of streams to keep order. */
	struct cds_list_head list;
};

struct ust_app_channel {
	int enabled;
	int handle;
	/* Channel and streams were sent to the UST tracer. */
	int is_sent;
	/* Unique key used to identify the channel on the consumer side. */
	unsigned long key;
	/* Number of stream that this channel is expected to receive. */
	unsigned int expected_stream_count;
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct lttng_ust_object_data *obj;
	struct ustctl_consumer_channel_attr attr;
	struct ust_app_stream_list streams;
	/* Session pointer that owns this object. */
	struct ust_app_session *session;
	struct lttng_ht *ctx;
	struct lttng_ht *events;
	/*
	 * UST event registry. The ONLY writer is the application thread.
	 */
	struct ust_registry_channel registry;
	/*
	 * Node indexed by channel name in the channels' hash table of a session.
	 */
	struct lttng_ht_node_str node;
	/*
	 * Node indexed by UST channel object descriptor (handle). Stored in the
	 * ust_objd hash table in the ust_app object.
	 */
	struct lttng_ht_node_ulong ust_objd_node;
};

struct ust_app_session {
	/*
	 * Lock protecting this session's ust app interaction. Held
	 * across command send/recv to/from app. Never nests within the
	 * session registry lock.
	 */
	pthread_mutex_t lock;

	int enabled;
	/* started: has the session been in started state at any time ? */
	int started;  /* allows detection of start vs restart. */
	int handle;   /* used has unique identifier for app session */
	int id;       /* session unique identifier */
	struct ust_app_channel *metadata;
	struct ust_registry_session registry;
	struct lttng_ht *channels; /* Registered channels */
	struct lttng_ht_node_ulong node;
	char path[PATH_MAX];
	/* UID/GID of the user owning the session */
	uid_t uid;
	gid_t gid;
	struct cds_list_head teardown_node;
};

/*
 * Registered traceable applications. Libust registers to the session daemon
 * and a linked list is kept of all running traceable app.
 */
struct ust_app {
	int sock;
	int notify_sock;
	pid_t pid;
	pid_t ppid;
	uid_t uid;           /* User ID that owns the apps */
	gid_t gid;           /* Group ID that owns the apps */

	/* App ABI */
	uint32_t bits_per_long;
	uint32_t uint8_t_alignment;
	uint32_t uint16_t_alignment;
	uint32_t uint32_t_alignment;
	uint32_t uint64_t_alignment;
	uint32_t long_alignment;
	int byte_order;		/* BIG_ENDIAN or LITTLE_ENDIAN */

	int compatible; /* If the lttng-ust tracer version does not match the
					   supported version of the session daemon, this flag is
					   set to 0 (NOT compatible) else 1. */
	struct lttng_ust_tracer_version version;
	uint32_t v_major;    /* Version major number */
	uint32_t v_minor;    /* Version minor number */
	char name[UST_APP_PROCNAME_LEN];
	struct lttng_ht *sessions;
	struct lttng_ht_node_ulong pid_n;
	struct lttng_ht_node_ulong sock_n;
	struct lttng_ht_node_ulong notify_sock_n;
	/*
	 * This is a list of ust app session that, once the app is going into
	 * teardown mode, in the RCU call, each node in this list is removed and
	 * deleted.
	 *
	 * Element of the list are added when an application unregisters after each
	 * ht_del of ust_app_session associated to this app. This list is NOT used
	 * when a session is destroyed.
	 */
	struct cds_list_head teardown_head;
	/*
	 * Hash table containing ust_app_channel indexed by channel objd.
	 */
	struct lttng_ht *ust_objd;
};

#ifdef HAVE_LIBLTTNG_UST_CTL

int ust_app_register(struct ust_register_msg *msg, int sock);
static inline
int ust_app_register_done(int sock)
{
	return ustctl_register_done(sock);
}
int ust_app_version(struct ust_app *app);
void ust_app_unregister(int sock);
unsigned long ust_app_list_count(void);
int ust_app_start_trace(struct ltt_ust_session *usess, struct ust_app *app);
int ust_app_stop_trace(struct ltt_ust_session *usess, struct ust_app *app);
int ust_app_start_trace_all(struct ltt_ust_session *usess);
int ust_app_stop_trace_all(struct ltt_ust_session *usess);
int ust_app_destroy_trace_all(struct ltt_ust_session *usess);
int ust_app_list_events(struct lttng_event **events);
int ust_app_list_event_fields(struct lttng_event_field **fields);
int ust_app_create_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_create_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent);
int ust_app_disable_event_pid(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent,
		pid_t pid);
int ust_app_enable_event_pid(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent,
		pid_t pid);
int ust_app_disable_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_enable_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_enable_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent);
int ust_app_disable_all_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_enable_all_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_disable_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent);
int ust_app_add_ctx_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_context *uctx);
void ust_app_global_update(struct ltt_ust_session *usess, int sock);

void ust_app_clean_list(void);
void ust_app_ht_alloc(void);
struct lttng_ht *ust_app_get_ht(void);
struct ust_app *ust_app_find_by_pid(pid_t pid);
int ust_app_calibrate_glb(struct lttng_ust_calibrate *calibrate);
struct ust_app_stream *ust_app_alloc_stream(void);
int ust_app_recv_registration(int sock, struct ust_register_msg *msg);
int ust_app_recv_notify(int sock);
void ust_app_add(struct ust_app *app);
struct ust_app *ust_app_create(struct ust_register_msg *msg, int sock);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline
int ust_app_destroy_trace_all(struct ltt_ust_session *usess)
{
	return 0;
}
static inline
int ust_app_start_trace(struct ltt_ust_session *usess, struct ust_app *app)
{
	return 0;
}
static inline
int ust_app_start_trace_all(struct ltt_ust_session *usess)
{
	return 0;
}
static inline
int ust_app_stop_trace_all(struct ltt_ust_session *usess)
{
	return 0;
}
static inline
int ust_app_list_events(struct lttng_event **events)
{
	return -ENOSYS;
}
static inline
int ust_app_list_event_fields(struct lttng_event_field **fields)
{
	return -ENOSYS;
}
static inline
int ust_app_register(struct ust_register_msg *msg, int sock)
{
	return -ENOSYS;
}
static inline
int ust_app_register_done(int sock)
{
	return -ENOSYS;
}
static inline
int ust_app_version(struct ust_app *app)
{
	return -ENOSYS;
}
static inline
void ust_app_unregister(int sock)
{
}
static inline
unsigned int ust_app_list_count(void)
{
	return 0;
}
static inline
void ust_app_lock_list(void)
{
}
static inline
void ust_app_unlock_list(void)
{
}
static inline
void ust_app_clean_list(void)
{
}
static inline
struct ust_app_list *ust_app_get_list(void)
{
	return NULL;
}
static inline
struct ust_app *ust_app_get_by_pid(pid_t pid)
{
	return NULL;
}
static inline
struct lttng_ht *ust_app_get_ht(void)
{
	return NULL;
}
static inline
void ust_app_ht_alloc(void)
{}
static inline
void ust_app_global_update(struct ltt_ust_session *usess, int sock)
{}
static inline
int ust_app_disable_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	return 0;
}
static inline
int ust_app_enable_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	return 0;
}
static inline
int ust_app_create_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	return 0;
}
static inline
int ust_app_disable_all_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	return 0;
}
static inline
int ust_app_enable_all_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	return 0;
}
static inline
int ust_app_create_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent)
{
	return 0;
}
static inline
int ust_app_disable_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent)
{
	return 0;
}
static inline
int ust_app_enable_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent)
{
	return 0;
}
static inline
int ust_app_add_ctx_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_context *uctx)
{
	return 0;
}
static inline
int ust_app_enable_event_pid(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent,
		pid_t pid)
{
	return 0;
}
static inline
int ust_app_disable_event_pid(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent,
		pid_t pid)
{
	return 0;
}
static inline
int ust_app_calibrate_glb(struct lttng_ust_calibrate *calibrate)
{
	return 0;
}
static inline
int ust_app_recv_registration(int sock, struct ust_register_msg *msg)
{
	return 0;
}
static inline
int ust_app_recv_notify(int sock)
{
	return 0;
}
static inline
struct ust_app *ust_app_create(struct ust_register_msg *msg, int sock)
{
	return NULL;
}
static inline
void ust_app_add(struct ust_app *app)
{
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_UST_APP_H */
