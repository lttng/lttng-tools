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

#ifndef _LIBLTTNGCTL_H
#define _LIBLTTNGCTL_H

#include <limits.h>
#include <uuid/uuid.h>

/* Default unix group name for tracing.
 */
#define DEFAULT_TRACING_GROUP "tracing"

/* Environment variable to set session daemon
 * binary path.
 */
#define LTTNG_SESSIOND_PATH_ENV "LTTNG_SESSIOND_PATH"

/* From libuuid
 */
#define UUID_STR_LEN 37

/* Simple structure representing a session.
 */
struct lttng_session {
	char name[NAME_MAX];
	char uuid[UUID_STR_LEN];
};

extern int lttng_create_session(char *name, uuid_t *session_id);
extern int lttng_destroy_session(uuid_t *uuid);
extern int lttng_connect_sessiond(void);
extern int lttng_set_tracing_group(const char *name);
extern int lttng_check_session_daemon(void);
extern const char *lttng_get_readable_code(int code);
extern int lttng_ust_list_apps(pid_t **pids);
extern int lttng_list_sessions(struct lttng_session **sessions);

#endif /* _LIBLTTNGCTL_H */
