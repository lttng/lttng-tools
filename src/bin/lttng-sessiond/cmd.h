/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CMD_H
#define CMD_H

#include "context.h"
#include "filter.h"
#include "session.h"

/*
 * Init the command subsystem. Must be called before using any of the functions
 * above. This is called in the main() of the session daemon.
 */
void cmd_init(void);

/* Session commands */
int cmd_create_session_uri(char *name, struct lttng_uri *uris,
		size_t nb_uri, lttng_sock_cred *creds);
int cmd_destroy_session(struct ltt_session *session, int wpipe);

/* Channel commands */
int cmd_disable_channel(struct ltt_session *session, int domain,
		char *channel_name);
int cmd_enable_channel(struct ltt_session *session, int domain,
		struct lttng_channel *attr, int wpipe);

/* Event commands */
int cmd_disable_event(struct ltt_session *session, int domain,
		char *channel_name, char *event_name);
int cmd_disable_event_all(struct ltt_session *session, int domain,
		char *channel_name);
int cmd_add_context(struct ltt_session *session, int domain,
		char *channel_name, char *event_name, struct lttng_event_context *ctx);
int cmd_set_filter(struct ltt_session *session, int domain,
		char *channel_name, char *event_name,
		struct lttng_filter_bytecode *bytecode);
int cmd_enable_event(struct ltt_session *session, int domain,
		char *channel_name, struct lttng_event *event, int wpipe);
int cmd_enable_event_all(struct ltt_session *session, int domain,
		char *channel_name, int event_type, int wpipe);

/* Trace session action commands */
int cmd_start_trace(struct ltt_session *session);
int cmd_stop_trace(struct ltt_session *session);

/* Consumer commands */
int cmd_register_consumer(struct ltt_session *session, int domain,
		const char *sock_path, struct consumer_data *cdata);
int cmd_disable_consumer(int domain, struct ltt_session *session);
int cmd_enable_consumer(int domain, struct ltt_session *session);
int cmd_set_consumer_uri(int domain, struct ltt_session *session,
		size_t nb_uri, struct lttng_uri *uris);

/* Listing commands */
ssize_t cmd_list_domains(struct ltt_session *session,
		struct lttng_domain **domains);
ssize_t cmd_list_events(int domain, struct ltt_session *session,
		char *channel_name, struct lttng_event **events);
ssize_t cmd_list_channels(int domain, struct ltt_session *session,
		struct lttng_channel **channels);
ssize_t cmd_list_domains(struct ltt_session *session,
		struct lttng_domain **domains);
void cmd_list_lttng_sessions(struct lttng_session *sessions, uid_t uid,
		gid_t gid);
ssize_t cmd_list_tracepoint_fields(int domain,
		struct lttng_event_field **fields);
ssize_t cmd_list_tracepoints(int domain, struct lttng_event **events);

int cmd_calibrate(int domain, struct lttng_calibrate *calibrate);
int cmd_data_available(struct ltt_session *session);

#endif /* CMD_H */
