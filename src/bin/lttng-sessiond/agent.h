/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef LTTNG_SESSIOND_AGENT_H
#define LTTNG_SESSIOND_AGENT_H

#define _GNU_SOURCE
#include <inttypes.h>

#include <common/hashtable/hashtable.h>
#include <lttng/lttng.h>

/*
 * Hash table that contains the agent app created upon registration indexed by
 * socket.
 */
struct lttng_ht *agent_apps_ht_by_sock;

struct agent_ht_key {
	const char *name;
	int loglevel;
};

/*
 * Registration message payload from an agent application. The PID is used to
 * find back the corresponding UST app object so both socket can be linked.
 */
struct agent_register_msg {
	uint32_t pid;
};

/*
 * Agent application object created after a successful registration. This
 * object is linked to its associated UST app by their PID through hash table
 * lookups.
 */
struct agent_app {
	/*
	 * PID sent during registration of a AGENT application.
	 */
	pid_t pid;

	/*
	 * AGENT TCP socket that was created upon registration.
	 */
	struct lttcomm_sock *sock;

	/* Initialized with the AGENT sock value. */
	struct lttng_ht_node_ulong node;
};

/*
 * Agent event representation.
 */
struct agent_event {
	/* Name of the event. */
	char name[LTTNG_SYMBOL_NAME_LEN];
	int loglevel;
	enum lttng_loglevel_type loglevel_type;

	/*
	 * Tells if the event is enabled or not on the agent.
	 */
	unsigned int enabled:1;

	/* Hash table node of the agent domain object. */
	struct lttng_ht_node_str node;

	/* Bytecode filter associated with the event . NULL if none. */
	struct lttng_filter_bytecode *filter;
};

/*
 * Agent object containing events enabled/disabled for it.
 */
struct agent {
	/*
	 * This indicates if that domain is being used meaning if at least one
	 * event has been at some point in time added to it. This is used so when
	 * listing domains for a session, we can tell or not if the agent is
	 * actually enabled.
	 */
	unsigned int being_used:1;
	/* Contains event indexed by name. */
	struct lttng_ht *events;
};

/* Setup agent subsystem. */
int agent_setup(void);

/* Initialize an already allocated agent domain. */
int agent_init(struct agent *agt);
void agent_destroy(struct agent *agt);

/* Agent event API. */
struct agent_event *agent_create_event(const char *name,
		struct lttng_filter_bytecode *filter);
void agent_add_event(struct agent_event *event, struct agent *agt);

struct agent_event *agent_find_event(const char *name, int loglevel,
		struct agent *agt);
struct agent_event *agent_find_event_by_name(const char *name,
		struct agent *agt);
void agent_delete_event(struct agent_event *event, struct agent *agt);
void agent_destroy_event(struct agent_event *event);

/* Agent app API. */
struct agent_app *agent_create_app(pid_t pid, struct lttcomm_sock *sock);
void agent_add_app(struct agent_app *app);
void agent_delete_app(struct agent_app *app);
struct agent_app *agent_find_app_by_sock(int sock);
void agent_destroy_app(struct agent_app *app);
int agent_send_registration_done(struct agent_app *app);

/* Agent action API */
int agent_enable_event(struct agent_event *event);
int agent_disable_event(struct agent_event *event);
void agent_update(struct agent *agt, int sock);
int agent_list_events(struct lttng_event **events);

#endif /* LTTNG_SESSIOND_AGENT_H */
