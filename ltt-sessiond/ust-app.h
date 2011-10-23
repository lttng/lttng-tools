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

#ifndef _TRACEABLE_APP_H 
#define _TRACEABLE_APP_H

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
 * Traceable application list.
 */
struct ust_app_list {
	/*
	 * This lock protects any read/write access to the list and count (which is
	 * basically the list size). All public functions in traceable-app.c
	 * acquire this lock and release it before returning. If none of those
	 * functions are used, the lock MUST be acquired in order to iterate or/and
	 * do any actions on that list.
	 */
	pthread_mutex_t lock;

	/*
	 * Number of element in the list. The session list lock MUST be acquired if
	 * this counter is used when iterating over the session list.
	 */
	unsigned int count;

	/* Linked list head */
	struct cds_list_head head;
};

/* Registered traceable applications. Libust registers to the session daemon
 * and a linked list is kept of all running traceable app.
 */
struct ust_app {
	int sock;            /* Communication socket with the application */
	pid_t pid;
	pid_t ppid;
	uid_t uid;           /* User ID that owns the apps */
	gid_t gid;           /* Group ID that owns the apps */
	uint32_t v_major;    /* Verion major number */
	uint32_t v_minor;    /* Verion minor number */
	char name[17];       /* Process name (short) */
	struct ltt_ust_channel_list channels;
	struct cds_list_head list;
};

#ifdef CONFIG_LTTNG_TOOLS_HAVE_UST

int ust_app_register(struct ust_register_msg *msg, int sock);
void ust_app_unregister(int sock);
unsigned int ust_app_list_count(void);

void ust_app_lock_list(void);
void ust_app_unlock_list(void);
void ust_app_clean_list(void);
struct ust_app_list *ust_app_get_list(void);
struct ust_app *ust_app_get_by_pid(pid_t pid);

#else

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



#endif

#endif /* _TRACEABLE_APP_H */
