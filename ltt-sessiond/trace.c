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
#include <string.h>
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

/*
 *  get_trace_count_per_session
 *
 *  Return the total count of traces (ust and kernel)
 *  for the specified session.
 */
int get_trace_count_per_session(struct ltt_session *session)
{
	return session->ust_trace_count + session->kern_trace_count;
}

/*
 *  get_traces_per_session
 *
 *  Fill the lttng_trace array of all the
 *  available trace of the session.
 */
void get_traces_per_session(struct ltt_session *session, struct lttng_trace *traces)
{
	int i = 0;
	struct ltt_ust_trace *ust_iter;
	struct ltt_kernel_trace *kern_iter;
	struct lttng_trace trace;

	DBG("Getting userspace traces for session %s", session->name);

	/* Getting userspace traces */
	cds_list_for_each_entry(ust_iter, &session->ust_traces, list) {
		trace.type = USERSPACE;
		trace.pid = ust_iter->pid;
		strncpy(trace.name, ust_iter->name, sizeof(trace.name));
		trace.name[sizeof(trace.name) - 1] = '\0';
		memcpy(&traces[i], &trace, sizeof(trace));
		memset(&trace, 0, sizeof(trace));
		i++;
	}

	DBG("Getting kernel traces for session %s", session->name);

	/* Getting kernel traces */
	cds_list_for_each_entry(kern_iter, &session->kernel_traces, list) {
		trace.type = KERNEL;
		strncpy(trace.name, kern_iter->name, sizeof(trace.name));
		trace.name[sizeof(trace.name) - 1] = '\0';
		memcpy(&traces[i], &trace, sizeof(trace));
		memset(&trace, 0, sizeof(trace));
		i++;
	}
}
