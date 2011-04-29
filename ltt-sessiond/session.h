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

/* Global session list */
struct ltt_session_list {
	struct cds_list_head head;
};

/* ltt-session - This data structure contains information needed
 * to identify a tracing session for both LTTng and UST.
 */
struct ltt_session {
	char *name;
	struct cds_list_head list;
	uuid_t uuid;
	struct cds_list_head ust_traces;
	struct cds_list_head lttng_traces;
	pid_t ust_consumer;
	pid_t lttng_consumer;
};

/* Prototypes */
int create_session(char *name, uuid_t *session_id);
int destroy_session(uuid_t *uuid);
void get_lttng_session(struct lttng_session *lt);
struct ltt_session *find_session_by_uuid(uuid_t session_id);
struct ltt_session *find_session_by_name(char *name);
unsigned int get_session_count(void);

#endif /* _LTT_SESSION_H */
