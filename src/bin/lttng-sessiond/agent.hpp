/*
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_AGENT_H
#define LTTNG_SESSIOND_AGENT_H

#include <common/hashtable/hashtable.hpp>

#include <lttng/lttng.h>

#include <inttypes.h>

/* Agent protocol version that is verified during the agent registration. */
#define AGENT_MAJOR_VERSION 2
#define AGENT_MINOR_VERSION 0

/*
 * Hash table that contains the agent app created upon registration indexed by
 * socket. Global to the session daemon.
 */
extern struct lttng_ht *the_agent_apps_ht_by_sock;

/*
 * Hash table that contains the trigger agents by domain */
extern struct lttng_ht *the_trigger_agents_ht_by_domain;

struct agent_ht_key {
	const char *name;
	int loglevel_value;
	enum lttng_loglevel_type loglevel_type;
	const char *filter_expression;
};

/*
 * Registration message payload from an agent application. The PID is used to
 * find back the corresponding UST app object so both socket can be linked.
 */
struct agent_register_msg {
	/* This maps to a lttng_domain_type. */
	uint32_t domain;
	uint32_t pid;
	uint32_t major_version;
	uint32_t minor_version;
};

/*
 * Agent application object created after a successful registration. This
 * object is linked to its associated UST app by their PID through hash table
 * lookups.
 */
struct agent_app {
	/*
	 * PID sent during registration of an agent application.
	 */
	pid_t pid;

	/* Domain of the application. */
	enum lttng_domain_type domain;

	/*
	 * AGENT TCP socket that was created upon registration.
	 */
	struct lttcomm_sock *sock;

	/* Initialized with the AGENT sock value. */
	struct lttng_ht_node_ulong node;
};

/*
 * Agent event representation.
 * Accesses to this structure are protected by the session list lock.
 */
struct agent_event {
	/* Name of the event. */
	char name[LTTNG_SYMBOL_NAME_LEN];
	int loglevel_value;
	enum lttng_loglevel_type loglevel_type;

	/*
	 * Tells if the event is enabled or not on the agent. While this can be
	 * implicitly tested as a boolean, it is in fact a reference count and
	 * the AGENT_EVENT_IS_ENABLED macro should be used to prevent accidental
	 * comparisons to non-zero literals (e.g. '1').
	 *
	 * Multiple triggers and events can map to the same agent event as it
	 * is merely a "filter" in front of a user space tracer enabler.
	 *
	 * This count is updated to ensure an event is only disabled when all
	 * matching enablers are disabled.
	 */
	unsigned int enabled_count;

	/* Hash table node of the agent domain object. */
	struct lttng_ht_node_str node;

	/* Filter associated with the event. NULL if none. */
	struct lttng_bytecode *filter;
	char *filter_expression;
	struct lttng_event_exclusion *exclusion;
};

#define AGENT_EVENT_IS_ENABLED(agent_event) (!!agent_event->enabled_count)

/*
 * Agent object containing events enabled/disabled for a given domain in a
 * scope. The scope is typically a session, but can also be "global" in the
 * context of event notifiers: see event_notifiers_find_agent().
 */
struct agent {
	/*
	 * This indicates if that domain is being used meaning if at least one
	 * event has been at some point in time added to it. This is used so when
	 * listing domains for a session, we can tell or not if the agent is
	 * actually enabled.
	 */
	unsigned int being_used:1;

	/* What domain this agent is. */
	enum lttng_domain_type domain;

	/* Contains event indexed by name. */
	struct lttng_ht *events;

	/* Application context list (struct agent_app_ctx). */
	struct cds_list_head app_ctx_list;

	/* Node used for the hash table indexed by domain type. */
	struct lttng_ht_node_u64 node;
};

/* Allocate agent apps hash table */
int agent_app_ht_alloc(void);
/* Clean-up agent apps hash table */
void agent_app_ht_clean(void);

/* Initialize an already allocated agent domain. */
int agent_init(struct agent *agt);
struct agent *agent_create(enum lttng_domain_type domain);
void agent_destroy(struct agent *agt);
void agent_add(struct agent *agt, struct lttng_ht *ht);

/* Agent event API. */
struct agent_event *agent_create_event(const char *name,
				       enum lttng_loglevel_type loglevel_type,
				       int loglevel_value,
				       struct lttng_bytecode *filter,
				       char *filter_expression);
void agent_add_event(struct agent_event *event, struct agent *agt);

struct agent_event *agent_find_event(const char *name,
				     enum lttng_loglevel_type loglevel_type,
				     int loglevel_value,
				     const char *filter_expression,
				     struct agent *agt);
void agent_find_events_by_name(const char *name, struct agent *agt, struct lttng_ht_iter *iter);
void agent_event_next_duplicate(const char *name, struct agent *agt, struct lttng_ht_iter *iter);
void agent_delete_event(struct agent_event *event, struct agent *agt);
void agent_destroy_event(struct agent_event *event);

/* Agent context API.*/
int agent_enable_context(const struct lttng_event_context *ctx, enum lttng_domain_type domain);
int agent_add_context(const struct lttng_event_context *ctx, struct agent *agt);

/* Agent app API. */
struct agent_app *
agent_create_app(pid_t pid, enum lttng_domain_type domain, struct lttcomm_sock *sock);
void agent_add_app(struct agent_app *app);
void agent_delete_app(struct agent_app *app);
struct agent_app *agent_find_app_by_sock(int sock);
void agent_destroy_app(struct agent_app *app);
void agent_destroy_app_by_sock(int sock);
int agent_send_registration_done(struct agent_app *app);

/* Agent action API */
int agent_enable_event(struct agent_event *event, enum lttng_domain_type domain);
int agent_disable_event(struct agent_event *event, enum lttng_domain_type domain);
void agent_update(const struct agent *agt, const struct agent_app *app);
int agent_list_events(struct lttng_event **events, enum lttng_domain_type domain);

struct agent_event *agent_find_event_by_trigger(const struct lttng_trigger *trigger,
						struct agent *agt);

/* Global event notifier per-domain agents. */
struct agent *agent_find_by_event_notifier_domain(enum lttng_domain_type domain_type);
void agent_by_event_notifier_domain_ht_destroy(void);
int agent_by_event_notifier_domain_ht_create(void);

#endif /* LTTNG_SESSIOND_AGENT_H */
