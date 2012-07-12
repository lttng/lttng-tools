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

#include "trace-ust.h"

/* lttng-ust supported version. */
#define LTTNG_UST_COMM_MAJOR          2	/* comm protocol major version */
#define UST_APP_MAJOR_VERSION         2 /* UST version supported */

#define UST_APP_EVENT_LIST_SIZE 32

struct lttng_filter_bytecode;
struct lttng_ust_filter_bytecode;

extern int ust_consumerd64_fd, ust_consumerd32_fd;

/*
 * Application registration data structure.
 */
struct ust_register_msg {
	uint32_t major;
	uint32_t minor;
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	gid_t gid;
	uint32_t bits_per_long;
	char name[16];
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
	struct lttng_ht *ctx;
	struct lttng_ht_node_str node;
	struct lttng_ust_filter_bytecode *filter;
};

struct ust_app_channel {
	int enabled;
	int handle;
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct lttng_ust_channel attr;
	struct lttng_ust_object_data *obj;
	struct ltt_ust_stream_list streams;
	struct lttng_ht *ctx;
	struct lttng_ht *events;
	struct lttng_ht_node_str node;
};

struct ust_app_session {
	int enabled;
	/* started: has the session been in started state at any time ? */
	int started;  /* allows detection of start vs restart. */
	int handle;   /* used has unique identifier for app session */
	int id;       /* session unique identifier */
	struct ltt_ust_metadata *metadata;
	struct lttng_ht *channels; /* Registered channels */
	struct lttng_ht_node_ulong node;
	char path[PATH_MAX];
	/* UID/GID of the user owning the session */
	uid_t uid;
	gid_t gid;
};

/*
 * Registered traceable applications. Libust registers to the session daemon
 * and a linked list is kept of all running traceable app.
 */
struct ust_app {
	int sock;
	pid_t pid;
	pid_t ppid;
	uid_t uid;           /* User ID that owns the apps */
	gid_t gid;           /* Group ID that owns the apps */
	int bits_per_long;
	int compatible; /* If the lttng-ust tracer version does not match the
					   supported version of the session daemon, this flag is
					   set to 0 (NOT compatible) else 1. */
	struct lttng_ust_tracer_version version;
	uint32_t v_major;    /* Verion major number */
	uint32_t v_minor;    /* Verion minor number */
	char name[17];       /* Process name (short) */
	struct lttng_ht *sessions;
	struct lttng_ht_node_ulong pid_n;
	struct lttng_ht_node_ulong sock_n;
};

#ifdef HAVE_LIBLTTNG_UST_CTL

int ust_app_register(struct ust_register_msg *msg, int sock);
static inline
int ust_app_register_done(int sock)
{
	return ustctl_register_done(sock);
}
void ust_app_unregister(int sock);
unsigned long ust_app_list_count(void);
int ust_app_start_trace(struct ltt_ust_session *usess, struct ust_app *app);
int ust_app_stop_trace(struct ltt_ust_session *usess, struct ust_app *app);
int ust_app_start_trace_all(struct ltt_ust_session *usess);
int ust_app_stop_trace_all(struct ltt_ust_session *usess);
int ust_app_destroy_trace(struct ltt_ust_session *usess, struct ust_app *app);
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
int ust_app_add_ctx_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent,
		struct ltt_ust_context *uctx);
int ust_app_add_ctx_channel_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_context *uctx);
int ust_app_set_filter_event_glb(struct ltt_ust_session *usess,
                struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent,
		struct lttng_filter_bytecode *bytecode);
void ust_app_global_update(struct ltt_ust_session *usess, int sock);

void ust_app_clean_list(void);
void ust_app_ht_alloc(void);
struct lttng_ht *ust_app_get_ht(void);
struct ust_app *ust_app_find_by_pid(pid_t pid);
int ust_app_validate_version(int sock);
int ust_app_calibrate_glb(struct lttng_ust_calibrate *calibrate);

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
int ust_app_add_ctx_event_glb(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent,
		struct ltt_ust_context *uctx)
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
int ust_app_validate_version(int sock)
{
	return 0;
}
static inline
int ust_app_calibrate_glb(struct lttng_ust_calibrate *calibrate)
{
	return 0;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_UST_APP_H */
