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

#ifndef _LTT_SESSIOND_H
#define _LTT_SESSIOND_H

#define DEFAULT_HOME_DIR			"/tmp"
#define DEFAULT_UST_SOCK_DIR		DEFAULT_HOME_DIR "/ust-app-socks"
#define DEFAULT_GLOBAL_APPS_PIPE	DEFAULT_UST_SOCK_DIR "/global"
#define DEFAULT_TRACE_OUTPUT        DEFAULT_HOME_DIR "/lttng"

/* LTTng kernel tracer modules list */
const char *kernel_modules_list[] = {
	"lib-ring-buffer",
	"ltt-relay",
	"ltt-ring-buffer-client-discard",
	"ltt-ring-buffer-client-overwrite",
	"ltt-ring-buffer-metadata-client",
	"ltt-ring-buffer-client-mmap-discard",
	"ltt-ring-buffer-client-mmap-overwrite",
	"ltt-ring-buffer-metadata-mmap-client",
	"lttng-ftrace",
	"lttng-kprobes",
	"lttng-kretprobes",
	"lttng-probe-block",
	"lttng-probe-irq",
	"lttng-probe-kvm",
	"lttng-probe-lttng",
	"lttng-probe-sched",
	"lttng-probe-syscalls",
	"lttng-types",
	NULL,
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

#endif /* _LTT_SESSIOND_H */
