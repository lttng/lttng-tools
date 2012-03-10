/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTT_SESSIOND_H
#define _LTT_SESSIOND_H

#define _LGPL_SOURCE
#include <urcu.h>
#include <urcu/wfqueue.h>

#include <common/sessiond-comm/sessiond-comm.h>
#include <common/compat/socket.h>

#include "session.h"
#include "ust-app.h"

const char *module_proc_lttng = "/proc/lttng";

extern const char default_home_dir[],
	default_tracing_group[],
	default_ust_sock_dir[],
	default_global_apps_pipe[];

/*
 * This contains extra data needed for processing a command received by the
 * session daemon from the lttng client.
 */
struct command_ctx {
	int ust_sock;
	unsigned int lttng_msg_size;
	struct ltt_session *session;
	struct lttcomm_lttng_msg *llm;
	struct lttcomm_session_msg *lsm;
	lttng_sock_cred creds;
};

struct ust_command {
	int sock;
	struct ust_register_msg reg_msg;
	struct cds_wfq_node node;
};

/*
 * Queue used to enqueue UST registration request (ust_commant) and protected
 * by a futex with a scheme N wakers / 1 waiters. See futex.c/.h
 */
struct ust_cmd_queue {
	int32_t futex;
	struct cds_wfq_queue queue;
};

#endif /* _LTT_SESSIOND_H */
