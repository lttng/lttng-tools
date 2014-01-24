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

#ifndef LTTNG_SESSIOND_JUL_H
#define LTTNG_SESSIOND_JUL_H

#define _GNU_SOURCE
#include <inttypes.h>

#include <common/hashtable/hashtable.h>
#include <lttng/lttng.h>

/*
 * Hash table that contains the JUL app created upon registration indexed by
 * socket.
 */
struct lttng_ht *jul_apps_ht_by_sock;

/*
 * Registration message payload from a JUL application. The PID is used to find
 * back the corresponding UST app object so both socket can be linked.
 */
struct jul_register_msg {
	uint32_t pid;
};

/*
 * JUL application object created after a successful registration. This
 * object is linked to its associated UST app by their PID through hash
 * table lookups.
 */
struct jul_app {
	/*
	 * PID sent during registration of a JUL application.
	 */
	pid_t pid;

	/*
	 * JUL TCP socket that was created upon registration.
	 */
	struct lttcomm_sock *sock;

	/* Initialized with the JUL sock value. */
	struct lttng_ht_node_ulong node;
};

/*
 * Java Util Logging event representation.
 */
struct jul_event {
	/*
	 * Name of the event which is directly mapped to a Logger object name in
	 * the JUL API.
	 */
	char name[LTTNG_SYMBOL_NAME_LEN];
	enum lttng_loglevel_jul loglevel;
	enum lttng_loglevel_type loglevel_type;

	/*
	 * Tells if the event is enabled or not on the JUL Agent.
	 */
	unsigned int enabled:1;

	/*
	 * Hash table nodes of the JUL domain. Indexed by name string.
	 */
	struct lttng_ht_node_str node;
};

/*
 * Top level data structure in a UST session containing JUL event name created
 * for it.
 */
struct jul_domain {
	/*
	 * This indicates if that domain is being used meaning if at least one
	 * event has been at some point in time added to it. This is used so when
	 * listing domains for a session, we can tell or not if the JUL is actually
	 * enabled.
	 */
	unsigned int being_used:1;
	/*
	 * Contains JUL event indexed by name.
	 */
	struct lttng_ht *events;
};

/* Initialize JUL domain subsystem. */
int jul_init(void);

/* Initialize an already allocated JUL domain. */
int jul_init_domain(struct jul_domain *dom);
void jul_destroy_domain(struct jul_domain *dom);

/* JUL event API. */
struct jul_event *jul_create_event(const char *name);
void jul_add_event(struct jul_event *event, struct jul_domain *dom);
struct jul_event *jul_find_by_name(const char *name, struct jul_domain *dom);
void jul_delete_event(struct jul_event *event, struct jul_domain *dom);
void jul_destroy_event(struct jul_event *event);

/* JUL app API. */
struct jul_app *jul_create_app(pid_t pid, struct lttcomm_sock *sock);
void jul_add_app(struct jul_app *app);
void jul_delete_app(struct jul_app *app);
struct jul_app *jul_find_app_by_sock(int sock);
void jul_destroy_app(struct jul_app *app);

/* JUL action API */
int jul_enable_event(struct jul_event *event);
int jul_disable_event(struct jul_event *event);
void jul_update(struct jul_domain *domain, int sock);
int jul_list_events(struct lttng_event **events);

#endif /* LTTNG_SESSIOND_JUL_H */
