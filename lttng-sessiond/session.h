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

#ifndef _LTT_SESSION_H
#define _LTT_SESSION_H

#include <pthread.h>
#include <urcu/list.h>

#include "trace-kernel.h"
#include "trace-ust.h"

/*
 * Tracing session list
 *
 * Statically declared in session.c and can be accessed by using
 * session_get_list() function that returns the pointer to the list.
 */
struct ltt_session_list {
	/*
	 * This lock protects any read/write access to the list and count (which is
	 * basically the list size). All public functions in session.c acquire this
	 * lock and release it before returning. If none of those functions are
	 * used, the lock MUST be acquired in order to iterate or/and do any
	 * actions on that list.
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

/*
 * This data structure contains information needed to identify a tracing
 * session for both LTTng and UST.
 */
struct ltt_session {
	char name[NAME_MAX];
	char path[PATH_MAX];
	struct ltt_kernel_session *kernel_session;
	struct ltt_ust_session *ust_session;
	/*
	 * Protect any read/write on this session data structure. This lock must be
	 * acquired *before* using any public functions declared below. Use
	 * session_lock() and session_unlock() for that.
	 */
	pthread_mutex_t lock;
	struct cds_list_head list;
};

/* Prototypes */
int session_create(char *name, char *path);
int session_destroy(struct ltt_session *session);

void session_lock(struct ltt_session *session);
void session_lock_list(void);
void session_unlock(struct ltt_session *session);
void session_unlock_list(void);

struct ltt_session *session_find_by_name(char *name);
struct ltt_session_list *session_get_list(void);

#endif /* _LTT_SESSION_H */
