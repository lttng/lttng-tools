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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTT_SESSIOND_H
#define _LTT_SESSIOND_H

#define _LGPL_SOURCE
#include <urcu/wfqueue.h>

#include "traceable-app.h"

#define DEFAULT_HOME_DIR            "/tmp"
#define DEFAULT_UST_SOCK_DIR        DEFAULT_HOME_DIR "/ust-app-socks"
#define DEFAULT_GLOBAL_APPS_PIPE    DEFAULT_UST_SOCK_DIR "/global"
#define DEFAULT_TRACE_OUTPUT        DEFAULT_HOME_DIR "/lttng"

#define DEFAULT_GLOBAL_APPS_WAIT_SHM_PATH   "/lttng-ust-apps-wait"
#define DEFAULT_HOME_APPS_WAIT_SHM_PATH     "/lttng-ust-apps-wait-%u"

struct module_param {
	const char *name;
	int required;
};

/* LTTng kernel tracer modules list */
const struct module_param kernel_modules_list[] = {
	{ "lttng-ftrace", 0 },
	{ "lttng-kprobes", 0 },
	{ "lttng-kretprobes", 0 },
	{ "lib-ring-buffer", 1 },
	{ "ltt-relay", 1 },
	{ "ltt-ring-buffer-client-discard", 1 },
	{ "ltt-ring-buffer-client-overwrite", 1 },
	{ "ltt-ring-buffer-metadata-client", 1 },
	{ "ltt-ring-buffer-client-mmap-discard", 1 },
	{ "ltt-ring-buffer-client-mmap-overwrite", 1 },
	{ "ltt-ring-buffer-metadata-mmap-client", 1 },
	{ "lttng-probe-lttng", 1 },
	{ "lttng-types", 0 },
	{ "lttng-probe-block", 0 },
	{ "lttng-probe-irq", 0 },
	{ "lttng-probe-kvm", 0 },
	{ "lttng-probe-sched", 0 },
	{ "lttng-probe-syscalls", 0 },
};

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
