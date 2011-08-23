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

/* Traceable application list */
struct ltt_traceable_app_list {
	struct cds_list_head head;
};

/* Registered traceable applications. Libust registers to the session daemon
 * and a linked list is kept of all running traceable app.
 */
struct ltt_traceable_app {
	struct cds_list_head list;
	pid_t pid;
	uid_t uid;		/* User ID that owns the apps */
};

struct ltt_traceable_app *find_app_by_pid(pid_t pid);
int register_traceable_app(pid_t pid, uid_t uid);
void unregister_traceable_app(pid_t pid);
void get_app_list_pids(pid_t *pids);
unsigned int get_app_count(void);

#endif /* _TRACEABLE_APP_H */
