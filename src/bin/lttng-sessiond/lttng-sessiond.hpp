/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2013 Raphaël Beamonte <raphael.beamonte@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_SESSIOND_H
#define _LTT_SESSIOND_H

#include "notification-thread.hpp"
#include "rotation-thread.hpp"
#include "session.hpp"
#include "sessiond-config.hpp"
#include "ust-app.hpp"

#include <common/compat/poll.hpp>
#include <common/compat/socket.hpp>
#include <common/payload.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/uuid.hpp>

#include <urcu.h>
#include <urcu/wfcqueue.h>

/*
 * Consumer daemon state which is changed when spawning it, killing it or in
 * case of a fatal error.
 */
enum consumerd_state {
	CONSUMER_STARTED = 1,
	CONSUMER_STOPPED = 2,
	CONSUMER_ERROR = 3,
};

/* Unique identifier of a session daemon instance. */
extern lttng_uuid the_sessiond_uuid;

/*
 * This consumer daemon state is used to validate if a client command will be
 * able to reach the consumer. If not, the client is informed. For instance,
 * doing a "lttng start" when the consumer state is set to ERROR will return an
 * error to the client.
 *
 * The following example shows a possible race condition of this scheme:
 *
 * consumer thread error happens
 *                                    client cmd arrives
 *                                    client cmd checks state -> still OK
 * consumer thread exit, sets error
 *                                    client cmd try to talk to consumer
 *                                    ...
 *
 * However, since the consumer is a different daemon, we have no way of making
 * sure the command will reach it safely even with this state flag. This is why
 * we consider that up to the state validation during command processing, the
 * command is safe. After that, we can not guarantee the correctness of the
 * client request vis-a-vis the consumer.
 */
extern enum consumerd_state the_ust_consumerd_state;
extern enum consumerd_state the_kernel_consumerd_state;

/* Set in main.c at boot time of the daemon */
extern struct lttng_kernel_abi_tracer_version the_kernel_tracer_version;
extern struct lttng_kernel_abi_tracer_abi_version the_kernel_tracer_abi_version;

/* Notification thread handle. */
extern struct notification_thread_handle *the_notification_thread_handle;

/* Rotation thread handle. */
extern lttng::sessiond::rotation_thread::uptr the_rotation_thread_handle;

/*
 * This contains extra data needed for processing a command received by the
 * session daemon from the lttng client.
 */
struct command_ctx {
	unsigned int lttng_msg_size;
	struct ltt_session *session;
	/* Input message */
	struct lttcomm_session_msg lsm;
	/* Reply content, starts with an lttcomm_lttng_msg header. */
	struct lttng_payload reply_payload;
	lttng_sock_cred creds;
};

struct ust_command {
	int sock;
	struct ust_register_msg reg_msg;
	struct cds_wfcq_node node;
};

/*
 * Queue used to enqueue UST registration request (ust_command) and synchronized
 * by a futex with a scheme N wakers / 1 waiters. See futex.c/.h
 */
struct ust_cmd_queue {
	int32_t futex;
	struct cds_wfcq_head head;
	struct cds_wfcq_tail tail;
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

extern int the_kernel_poll_pipe[2];

/*
 * Populated when the daemon starts with the current page size of the system.
 * Set in main() with the current page size.
 */
extern long the_page_size;

/* Application health monitoring */
extern struct health_app *the_health_sessiond;

extern struct sessiond_config the_config;

extern int the_ust_consumerd64_fd, the_ust_consumerd32_fd;

/* Parent PID for --sig-parent option */
extern pid_t the_ppid;
/* Internal parent PID use with daemonize. */
extern pid_t the_child_ppid;

/* Consumer daemon specific control data. */
extern struct consumer_data the_ustconsumer32_data;
extern struct consumer_data the_ustconsumer64_data;
extern struct consumer_data the_kconsumer_data;

int sessiond_init_main_quit_pipe(void);
int sessiond_wait_for_main_quit_pipe(int timeout_ms);
int sessiond_notify_main_quit_pipe(void);
void sessiond_close_main_quit_pipe(void);

int sessiond_set_thread_pollset(struct lttng_poll_event *events, size_t size);
void sessiond_signal_parents(void);

void sessiond_set_client_thread_state(bool running);
void sessiond_wait_client_thread_stopped(void);

void *thread_manage_consumer(void *data);

#endif /* _LTT_SESSIOND_H */
