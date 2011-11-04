/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTT_UST_APP_H 
#define _LTT_UST_APP_H

#include <stdint.h>
#include <urcu/list.h>

#include "trace-ust.h"

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
	char name[16];
};

/*
 * Global applications HT used by the session daemon.
 */
struct cds_lfht *ust_app_ht;

struct cds_lfht *ust_app_sock_key_map;

struct ust_app_key {
	pid_t pid;
	int sock;
	struct cds_lfht_node node;
};

struct ust_app_event {
	int enabled;
	int handle;
	struct lttng_ust_object_data *obj;
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct cds_lfht *ctx;
	struct cds_lfht_node node;
};

struct ust_app_channel {
	int enabled;
	int handle;
	char name[LTTNG_UST_SYM_NAME_LEN];
	struct lttng_ust_channel attr;
	struct lttng_ust_object_data *obj;
	struct cds_lfht *streams;
	struct cds_lfht *ctx;
	struct cds_lfht *events;
	struct cds_lfht_node node;
};

struct ust_app_session {
	int enabled;
	int handle;   /* Used has unique identifier */
	unsigned int uid;
	struct ltt_ust_metadata *metadata;
	struct lttng_ust_object_data *obj;
	struct cds_lfht *channels; /* Registered channels */
	struct cds_lfht_node node;
};

/*
 * Registered traceable applications. Libust registers to the session daemon
 * and a linked list is kept of all running traceable app.
 */
struct ust_app {
	pid_t ppid;
	uid_t uid;           /* User ID that owns the apps */
	gid_t gid;           /* Group ID that owns the apps */
	uint32_t v_major;    /* Verion major number */
	uint32_t v_minor;    /* Verion minor number */
	char name[17];       /* Process name (short) */
	struct cds_lfht *sessions;
	struct cds_lfht_node node;
	struct ust_app_key key;
};

#ifdef HAVE_LIBLTTNG_UST_CTL

int ust_app_register(struct ust_register_msg *msg, int sock);
void ust_app_unregister(int sock);
int ust_app_add_channel(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan);
int ust_app_add_event(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan, struct ltt_ust_event *uevent);
unsigned long ust_app_list_count(void);
int ust_app_start_trace(struct ltt_ust_session *usess);

void ust_app_clean_list(void);
void ust_app_ht_alloc(void);
struct cds_lfht *ust_app_get_ht(void);
struct ust_app *ust_app_find_by_pid(pid_t pid);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline
int ust_app_register(struct ust_register_msg *msg, int sock)
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
int ust_app_add_channel(struct ltt_ust_session *usess,
		struct ltt_ust_channel *uchan)
{
	return 0;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_UST_APP_H */
