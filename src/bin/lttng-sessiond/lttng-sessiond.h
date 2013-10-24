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
#include <common/compat/poll.h>
#include <common/compat/socket.h>

#include "session.h"
#include "ust-app.h"

extern const char default_home_dir[],
	default_tracing_group[],
	default_ust_sock_dir[],
	default_global_apps_pipe[];

/* Set in main.c at boot time of the daemon */
extern int kernel_tracer_fd;

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

/*
 * This is the wait queue containing wait nodes during the application
 * registration process.
 */
struct ust_reg_wait_queue {
	unsigned long count;
	struct cds_list_head head;
};

/*
 * Use by the dispatch registration to queue UST command socket to wait for the
 * notify socket.
 */
struct ust_reg_wait_node {
	struct ust_app *app;
	struct cds_list_head head;
};

/*
 * This pipe is used to inform the thread managing application notify
 * communication that a command is queued and ready to be processed.
 */
extern int apps_cmd_notify_pipe[2];

/*
 * Used to notify that a hash table needs to be destroyed by dedicated
 * thread. Required by design because we don't want to move destroy
 * paths outside of large RCU read-side lock paths, and destroy cannot
 * be called by call_rcu thread, because it may hang (waiting for
 * call_rcu completion).
 */
extern int ht_cleanup_pipe[2];

/*
 * Populated when the daemon starts with the current page size of the system.
 */
extern long page_size;

/*
 * Global set once in main(). JUL TCP port for registration.
 */
extern unsigned int jul_tcp_port;

int sessiond_set_thread_pollset(struct lttng_poll_event *events, size_t size);
int sessiond_check_thread_quit_pipe(int fd, uint32_t events);

void *thread_ht_cleanup(void *data);

#endif /* _LTT_SESSIOND_H */
