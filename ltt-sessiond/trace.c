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

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <urcu/list.h>

#include "lttngerr.h"
#include "trace.h"
#include "session.h"

/*
 *  find_session_ust_trace_by_pid
 *
 *  Iterate over the session ust_traces and
 *  return a pointer or NULL if not found.
 */
struct ltt_ust_trace *find_session_ust_trace_by_pid(struct ltt_session *session, pid_t pid)
{
	struct ltt_ust_trace *iter;

	cds_list_for_each_entry(iter, &session->ust_traces, list) {
		if (iter->pid == pid) {
			/* Found */
			return iter;
		}
	}

	return NULL;
}

