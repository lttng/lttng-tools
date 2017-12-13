/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2016 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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

#define UST_APP_EVENT_LIST_SIZE 32

/* Process name (short). */
#define UST_APP_PROCNAME_LEN	16

struct lttng_filter_bytecode;
struct lttng_ust_filter_bytecode;

extern int ust_consumerd64_fd, ust_consumerd32_fd;

/*
 * Object used to close the notify socket in a call_rcu(). Since the
 * application might not be found, we need an independant object containing the
 * notify socket fd.
 */
struct ust_app_notify_sock_obj {
	int fd;
	struct rcu_head head;
};

struct ust_app_ht_key {
	const char *name;
	const struct lttng_filter_bytecode *filter;
	enum lttng_ust_loglevel_type loglevel_type;
	const struct lttng_event_exclusion *exclusion;
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
 *
 * The 'sock' in question here is the 'command' socket.
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
	struct lttng_ust_context_attr ctx;
	struct lttng_ust_object_data *obj;
	struct lttng_ht_node_ulong node;
	struct cds_list_head list;
};

struct ust_app_event {
	int enabled;
	int handle;
	struct lttng_ust_object_data *obj;
	struct lttng_ust_event attr;
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct lttng_ht_node_str node;
	struct lttng_filter_bytecode *filter;
	struct lttng_event_exclusion *exclusion;
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
	uint64_t key;
	/* Id of the tracing channel set on creation. */
	uint64_t tracing_channel_id;
	/* Number of stream that this channel is expected to receive. */
	unsigned int expected_stream_count;
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct lttng_ust_object_data *obj;
	struct ustctl_consumer_channel_attr attr;
	struct ust_app_stream_list streams;
	/* Session pointer that owns this object. */
	struct ust_app_session *session;
	/*
	 * Contexts are kept in a hash table for fast lookup and in an ordered list
	 * so we are able to enable them on the tracer side in the same order the
	 * user added them.
	 */
	struct lttng_ht *ctx;
	struct cds_list_head ctx_list;

	struct lttng_ht *events;
	uint64_t tracefile_size;
	uint64_t tracefile_count;
	uint64_t monitor_timer_interval;
	/*
	 * Node indexed by channel name in the channels' hash table of a session.
	 */
	struct lttng_ht_node_str node;
	/*
	 * Node indexed by UST channel object descriptor (handle). Stored in the
	 * ust_objd hash table in the ust_app object.
	 */
	struct lttng_ht_node_ulong ust_objd_node;
	/* For delayed reclaim */
	struct rcu_head rcu_head;
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

	bool deleted;	/* Session deleted flag. Check with lock held. */

	/*
	 * Tracing session ID. Multiple ust app session can have the same tracing
	 * session id making this value NOT unique to the object.
	 */
	uint64_t tracing_id;
	uint64_t id;	/* Unique session identifier */
	struct lttng_ht *channels; /* Registered channels */
	struct lttng_ht_node_u64 node;
	/*
	 * Node indexed by UST session object descriptor (handle). Stored in the
	 * ust_sessions_objd hash table in the ust_app object.
	 */
	struct lttng_ht_node_ulong ust_objd_node;
	char path[PATH_MAX];
	/* UID/GID of the application owning the session */
	uid_t uid;
	gid_t gid;
	/* Effective UID and GID. Same as the tracing session. */
	uid_t euid;
	gid_t egid;
	struct cds_list_head teardown_node;
	/*
	 * Once at least *one* session is created onto the application, the
	 * corresponding consumer is set so we can use it on unregistration.
	 */
	struct consumer_output *consumer;
	enum lttng_buffer_type buffer_type;
	/* ABI of the session. Same value as the application. */
	uint32_t bits_per_long;
	/* For delayed reclaim */
	struct rcu_head rcu_head;
	/* If the channel's streams have to be outputed or not. */
	unsigned int output_traces;
	unsigned int live_timer_interval;	/* usec */

	/* Metadata channel attributes. */
	struct ustctl_consumer_channel_attr metadata_attr;

	char root_shm_path[PATH_MAX];
	char shm_path[PATH_MAX];
};

/*
 * Registered traceable applications. Libust registers to the session daemon
 * and a linked list is kept of all running traceable app.
 */
struct ust_app {
	int sock;
	pthread_mutex_t sock_lock;	/* Protects sock protocol. */

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
	/* Extra for the NULL byte. */
	char name[UST_APP_PROCNAME_LEN + 1];
	/* Type of buffer this application uses. */
	enum lttng_buffer_type buffer_type;
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
	/*
	 * Hash table containing ust_app_session indexed by objd.
	 */
	struct lttng_ht *ust_sessions_objd;

	/*
	 * If this application is of the agent domain and this is non negative then
	 * a lookup MUST be done to acquire a read side reference to the
	 * corresponding agent app object. If the lookup fails, this should be set
	 * to a negative value indicating that the agent application is gone.
	 */
	int agent_app_sock;
};

#ifdef HAVE_LIBLTTNG_UST_CTL

int ust_app_register(struct ust_register_msg *msg, int sock);
int ust_app_register_done(struct ust_app *app);
int ust_app_version(struct ust_app *app);
void ust_app_unregister(int sock);
int ust_app_start_trace_all(struct ltt_ust_session *usess);
int ust_app_stop_trace_all(struct ltt_ust_session *usess);
int ust_app_destroy_trace_all(struct ltt_ust_session *usess);
int ust_app_list_events(struct lttng_event **events);
int ust_app_list_event_fields(struct lttng_event_field **fields);
int ust_app_create_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_create_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent);
int ust_app_enable_event_pid(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent,
		pid_t pid);
int ust_app_disable_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_enable_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_enable_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent);
int ust_app_enable_all_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_disable_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent);
int ust_app_add_ctx_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_context *uctx);
void ust_app_global_update(struct ltt_ust_session *usess, struct ust_app *app);
void ust_app_global_update_all(struct ltt_ust_session *usess);

void ust_app_clean_list(void);
int ust_app_ht_alloc(void);
struct ust_app *ust_app_find_by_pid(pid_t pid);
struct ust_app_stream *ust_app_alloc_stream(void);
int ust_app_recv_registration(int sock, struct ust_register_msg *msg);
int ust_app_recv_notify(int sock);
void ust_app_add(struct ust_app *app);
struct ust_app *ust_app_create(struct ust_register_msg *msg, int sock);
void ust_app_notify_sock_unregister(int sock);
ssize_t ust_app_push_metadata(struct ust_registry_session *registry,
		struct consumer_socket *socket, int send_zero_data);
void ust_app_destroy(struct ust_app *app);
int ust_app_snapshot_record(struct ltt_ust_session *usess,
		struct snapshot_output *output, int wait,
		uint64_t nb_packets_per_stream);
uint64_t ust_app_get_size_one_more_packet_per_stream(
		struct ltt_ust_session *usess, uint64_t cur_nr_packets);
struct ust_app *ust_app_find_by_sock(int sock);
int ust_app_uid_get_channel_runtime_stats(uint64_t ust_session_id,
		struct cds_list_head *buffer_reg_uid_list,
		struct consumer_output *consumer, uint64_t uchan_id,
		int overwrite, uint64_t *discarded, uint64_t *lost);
int ust_app_pid_get_channel_runtime_stats(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan,
		struct consumer_output *consumer,
		int overwrite, uint64_t *discarded, uint64_t *lost);
int ust_app_regenerate_statedump_all(struct ltt_ust_session *usess);

static inline
int ust_app_supported(void)
{
	return 1;
}

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
int ust_app_register_done(struct ust_app *app)
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
int ust_app_ht_alloc(void)
{
	return 0;
}
static inline
void ust_app_global_update(struct ltt_ust_session *usess, struct ust_app *app)
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
static inline
void ust_app_notify_sock_unregister(int sock)
{
}
static inline
ssize_t ust_app_push_metadata(struct ust_registry_session *registry,
		struct consumer_socket *socket, int send_zero_data)
{
	return 0;
}
static inline
void ust_app_destroy(struct ust_app *app)
{
	return;
}
static inline
int ust_app_snapshot_record(struct ltt_ust_session *usess,
		struct snapshot_output *output, int wait, uint64_t max_stream_size)
{
	return 0;
}
static inline
unsigned int ust_app_get_nb_stream(struct ltt_ust_session *usess)
{
	return 0;
}

static inline
int ust_app_supported(void)
{
	return 0;
}
static inline
struct ust_app *ust_app_find_by_sock(int sock)
{
	return NULL;
}
static inline
struct ust_app *ust_app_find_by_pid(pid_t pid)
{
	return NULL;
}
static inline
uint64_t ust_app_get_size_one_more_packet_per_stream(
		struct ltt_ust_session *usess, uint64_t cur_nr_packets) {
	return 0;
}
static inline
int ust_app_uid_get_channel_runtime_stats(uint64_t ust_session_id,
		struct cds_list_head *buffer_reg_uid_list,
		struct consumer_output *consumer, int overwrite,
		uint64_t uchan_id, uint64_t *discarded, uint64_t *lost)
{
	return 0;
}

static inline
int ust_app_pid_get_channel_runtime_stats(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan,
		struct consumer_output *consumer,
		int overwrite, uint64_t *discarded, uint64_t *lost)
{
	return 0;
}

static inline
int ust_app_regenerate_statedump_all(struct ltt_ust_session *usess)
{
	return 0;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_UST_APP_H */
