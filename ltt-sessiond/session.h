/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

//#include <lttng/lttng.h>
#include <urcu/list.h>

/*
 * Tracing session list
 *
 * Statically declared in session.c and can be accessed by using
 * get_session_list() function that returns the pointer to the list.
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
	char *name;
	char *path;
	struct ltt_kernel_session *kernel_session;
	struct cds_list_head ust_traces;
	unsigned int ust_trace_count;
	/*
	 * Protect any read/write on this session data structure. This lock must be
	 * acquired *before* using any public functions declared below. Use
	 * lock_session() and unlock_session() for that.
	 */
	pthread_mutex_t lock;
	struct cds_list_head list;
};

/* Prototypes */
int create_session(char *name, char *path);
int destroy_session(char *name);

void lock_session(struct ltt_session *session);
void lock_session_list(void);
void unlock_session(struct ltt_session *session);
void unlock_session_list(void);

struct ltt_session *find_session_by_name(char *name);
struct ltt_session_list *get_session_list(void);

#endif /* _LTT_SESSION_H */
