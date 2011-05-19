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
#include <ust/ustctl.h>

#include "liblttsessiondcomm.h"
#include "lttngerr.h"
#include "trace.h"
#include "session.h"
#include "ltt-sessiond.h"

static struct ltt_ust_trace *find_session_ust_trace_by_pid(
		struct ltt_session *session, pid_t pid);

/*
 *  find_session_ust_trace_by_pid
 *
 *  Iterate over the session ust_traces and
 *  return a pointer or NULL if not found.
 */
static struct ltt_ust_trace *find_session_ust_trace_by_pid(
		struct ltt_session *session, pid_t pid)
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
	return session->ust_trace_count + session->kern_session_count;
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
	if (session->kern_session_count > 0) {
		trace.type = KERNEL;
		strncpy(trace.name, "kernel", 6);
		memcpy(&traces[i], &trace, sizeof(trace));
	}
}

/*
 *  ust_create_trace
 *
 *  Create an userspace trace using pid.
 *  This trace is then appended to the current session
 *  ust trace list.
 */
int ust_create_trace(struct command_ctx *cmd_ctx)
{
	int ret;
	struct ltt_ust_trace *trace;

	DBG("Creating trace for pid %d", cmd_ctx->lsm->pid);

	trace = malloc(sizeof(struct ltt_ust_trace));
	if (trace == NULL) {
		perror("malloc");
		ret = -1;
		goto error;
	}

	/* Init */
	trace->pid = cmd_ctx->lsm->pid;
	trace->shmid = 0;
	/* NOTE: to be removed. Trace name will no longer be
	 * required for LTTng userspace tracer. For now, we set it
	 * to 'auto' for API compliance.
	 */
	snprintf(trace->name, 5, "auto");

	ret = ustctl_create_trace(cmd_ctx->ust_sock, trace->name);
	if (ret < 0) {
		ret = LTTCOMM_CREATE_FAIL;
		goto error_create;
	}

	/* Check if current session is valid */
	if (cmd_ctx->session) {
		cds_list_add(&trace->list, &cmd_ctx->session->ust_traces);
		cmd_ctx->session->ust_trace_count++;
	}

	return LTTCOMM_OK;

error_create:
	free(trace);
error:
	return ret;
}

/*
 *  ust_start_trace
 *
 *  Start a trace. This trace, identified by the pid, must be
 *  in the current session ust_traces list.
 */
int ust_start_trace(struct command_ctx *cmd_ctx)
{
	int ret;
	struct ltt_ust_trace *trace;

	DBG("Starting trace for pid %d", cmd_ctx->lsm->pid);

	trace = find_session_ust_trace_by_pid(cmd_ctx->session, cmd_ctx->lsm->pid);
	if (trace == NULL) {
		ret = LTTCOMM_NO_TRACE;
		goto error;
	}

	ret = ustctl_start_trace(cmd_ctx->ust_sock, "auto");
	if (ret < 0) {
		ret = LTTCOMM_START_FAIL;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

/*
 *  ust_stop_trace
 *
 *  Stop a trace. This trace, identified by the pid, must be
 *  in the current session ust_traces list.
 */
int ust_stop_trace(struct command_ctx *cmd_ctx)
{
	int ret;
	struct ltt_ust_trace *trace;

	DBG("Stopping trace for pid %d", cmd_ctx->lsm->pid);

	trace = find_session_ust_trace_by_pid(cmd_ctx->session, cmd_ctx->lsm->pid);
	if (trace == NULL) {
		ret = LTTCOMM_NO_TRACE;
		goto error;
	}

	ret = ustctl_stop_trace(cmd_ctx->ust_sock, trace->name);
	if (ret < 0) {
		ret = LTTCOMM_STOP_FAIL;
		goto error;
	}

	ret = LTTCOMM_OK;

error:
	return ret;
}

