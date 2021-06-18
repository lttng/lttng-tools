/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_TRACE_UST_H
#define _LTT_TRACE_UST_H

#include "consumer.hpp"
#include "lttng-ust-ctl.hpp"

#include <common/defaults.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/tracker.hpp>

#include <lttng/lttng.h>

#include <limits.h>
#include <urcu/list.h>

struct agent;

struct ltt_ust_ht_key {
	const char *name;
	const struct lttng_bytecode *filter;
	enum lttng_ust_abi_loglevel_type loglevel_type;
	int loglevel_value;
	const struct lttng_event_exclusion *exclusion;
};

/* Context hash table nodes */
struct ltt_ust_context {
	struct lttng_ust_context_attr ctx;
	struct lttng_ht_node_ulong node;
	struct cds_list_head list;
};

/* UST event */
struct ltt_ust_event {
	bool enabled;
	struct lttng_ust_abi_event attr;
	struct lttng_ht_node_str node;
	char *filter_expression;
	struct lttng_bytecode *filter;
	struct lttng_event_exclusion *exclusion;
	/*
	 * An internal event is an event which was created by the session daemon
	 * through which, for example, events emitted in Agent domains are
	 * "funelled". This is used to hide internal events from external
	 * clients as they should never be modified by the external world.
	 */
	bool internal;
};

/* UST channel */
struct ltt_ust_channel {
	uint64_t id; /* unique id per session. */
	bool enabled;
	/*
	 * A UST channel can be part of a userspace sub-domain such as JUL,
	 * Log4j, Python.
	 */
	enum lttng_domain_type domain;
	char name[LTTNG_UST_ABI_SYM_NAME_LEN];
	struct lttng_ust_abi_channel_attr attr;
	struct lttng_ht *ctx;
	struct cds_list_head ctx_list;
	struct lttng_ht *events;
	struct lttng_ht_node_str node;
	uint64_t tracefile_size;
	uint64_t tracefile_count;
	uint64_t per_pid_closed_app_discarded;
	uint64_t per_pid_closed_app_lost;
	uint64_t monitor_timer_interval;
};

/* UST domain global (LTTNG_DOMAIN_UST) */
struct ltt_ust_domain_global {
	struct lttng_ht *channels;
	struct cds_list_head registry_buffer_uid_list;
};

struct ust_id_tracker_node {
	struct lttng_ht_node_ulong node;
};

struct ust_id_tracker {
	struct lttng_ht *ht;
};

/* UST session */
struct ltt_ust_session {
	uint64_t id; /* Unique identifier of session */
	struct ltt_ust_domain_global domain_global;
	/* Hash table of agent indexed by agent domain. */
	struct lttng_ht *agents;
	/* UID/GID of the user owning the session */
	uid_t uid;
	gid_t gid;
	/* Is the session active meaning has is been started or stopped. */
	bool active;
	struct consumer_output *consumer;
	/* Sequence number for filters so the tracer knows the ordering. */
	uint64_t filter_seq_num;
	/* This indicates which type of buffer this session is set for. */
	enum lttng_buffer_type buffer_type;
	/* If set to 1, the buffer_type can not be changed anymore. */
	int buffer_type_changed;
	/* For per UID buffer, every buffer reg object is kept of this session */
	struct cds_list_head buffer_reg_uid_list;
	/* Next channel ID available for a newly registered channel. */
	uint64_t next_event_container_id;
	/* Once this value reaches UINT64_MAX, no more id can be allocated. */
	uint64_t used_event_container_id;
	/* Tell or not if the session has to output the traces. */
	unsigned int output_traces;
	unsigned int snapshot_mode;
	unsigned int has_non_default_channel;
	unsigned int live_timer_interval; /* usec */

	/* Metadata channel attributes. */
	struct lttng_ust_abi_channel_attr metadata_attr;

	/*
	 * Path where to keep the shared memory files.
	 */
	char root_shm_path[PATH_MAX];
	char shm_path[PATH_MAX];

	/* Current trace chunk of the ltt_session. */
	struct lttng_trace_chunk *current_trace_chunk;

	/* Trackers used for actual lookup on app registration. */
	struct ust_id_tracker vpid_tracker;
	struct ust_id_tracker vuid_tracker;
	struct ust_id_tracker vgid_tracker;

	/* Tracker list of keys requested by users. */
	struct process_attr_tracker *tracker_vpid;
	struct process_attr_tracker *tracker_vuid;
	struct process_attr_tracker *tracker_vgid;
};

/*
 * Validate that the id has reached the maximum allowed or not.
 *
 * Return 0 if NOT else 1.
 */
static inline int trace_ust_is_max_id(uint64_t id)
{
	return (id == UINT64_MAX) ? 1 : 0;
}

/*
 * Return next available channel id and increment the used counter. The
 * trace_ust_is_max_id function MUST be called before in order to validate if
 * the maximum number of IDs have been reached. If not, it is safe to call this
 * function.
 *
 * Return a unique channel ID. If max is reached, the used_event_container_id counter
 * is returned.
 */
static inline uint64_t trace_ust_get_next_event_container_id(struct ltt_ust_session *s)
{
	if (trace_ust_is_max_id(s->used_event_container_id)) {
		return s->used_event_container_id;
	}

	s->used_event_container_id++;
	return s->next_event_container_id++;
}

#ifdef HAVE_LIBLTTNG_UST_CTL

int trace_ust_ht_match_event(struct cds_lfht_node *node, const void *_key);
int trace_ust_ht_match_event_by_name(struct cds_lfht_node *node, const void *_key);

/*
 * Lookup functions. NULL is returned if not found.
 */
struct ltt_ust_event *trace_ust_find_event(struct lttng_ht *ht,
					   char *name,
					   struct lttng_bytecode *filter,
					   enum lttng_ust_abi_loglevel_type loglevel_type,
					   int loglevel_value,
					   struct lttng_event_exclusion *exclusion);
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht, const char *name);
struct agent *trace_ust_find_agent(struct ltt_ust_session *session,
				   enum lttng_domain_type domain_type);

/*
 * Create functions malloc() the data structure.
 */
struct ltt_ust_session *trace_ust_create_session(uint64_t session_id);
struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *attr,
						 enum lttng_domain_type domain);

enum lttng_error_code trace_ust_create_event(struct lttng_event *ev,
					     char *filter_expression,
					     struct lttng_bytecode *filter,
					     struct lttng_event_exclusion *exclusion,
					     bool internal_event,
					     struct ltt_ust_event **ust_event);
struct ltt_ust_context *trace_ust_create_context(const struct lttng_event_context *ctx);
int trace_ust_match_context(const struct ltt_ust_context *uctx,
			    const struct lttng_event_context *ctx);
void trace_ust_delete_channel(struct lttng_ht *ht, struct ltt_ust_channel *channel);

int trace_ust_regenerate_metadata(struct ltt_ust_session *usess);

/*
 * Destroy functions free() the data structure and remove from linked list if
 * it's applies.
 */
void trace_ust_destroy_session(struct ltt_ust_session *session);
void trace_ust_destroy_channel(struct ltt_ust_channel *channel);
void trace_ust_destroy_event(struct ltt_ust_event *event);
void trace_ust_destroy_context(struct ltt_ust_context *ctx);
void trace_ust_free_session(struct ltt_ust_session *session);

int trace_ust_id_tracker_lookup(enum lttng_process_attr process_attr,
				struct ltt_ust_session *session,
				int id);
enum lttng_error_code
trace_ust_process_attr_tracker_set_tracking_policy(struct ltt_ust_session *session,
						   enum lttng_process_attr process_attr,
						   enum lttng_tracking_policy policy);
enum lttng_error_code
trace_ust_process_attr_tracker_inclusion_set_add_value(struct ltt_ust_session *session,
						       enum lttng_process_attr process_attr,
						       const struct process_attr_value *value);
enum lttng_error_code
trace_ust_process_attr_tracker_inclusion_set_remove_value(struct ltt_ust_session *session,
							  enum lttng_process_attr process_attr,
							  const struct process_attr_value *value);
const struct process_attr_tracker *
trace_ust_get_process_attr_tracker(struct ltt_ust_session *session,
				   enum lttng_process_attr process_attr);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline int trace_ust_ht_match_event(struct cds_lfht_node *node __attribute__((unused)),
					   const void *_key __attribute__((unused)))
{
	return 0;
}

static inline int trace_ust_ht_match_event_by_name(struct cds_lfht_node *node
						   __attribute__((unused)),
						   const void *_key __attribute__((unused)))
{
	return 0;
}

static inline struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht
								     __attribute__((unused)),
								     const char *name
								     __attribute__((unused)))
{
	return NULL;
}

static inline struct ltt_ust_session *trace_ust_create_session(unsigned int session_id
							       __attribute__((unused)))
{
	return NULL;
}

static inline struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *attr
							       __attribute__((unused)),
							       enum lttng_domain_type domain
							       __attribute__((unused)))
{
	return NULL;
}

static inline enum lttng_error_code
trace_ust_create_event(struct lttng_event *ev __attribute__((unused)),
		       const char *filter_expression __attribute__((unused)),
		       struct lttng_bytecode *filter __attribute__((unused)),
		       struct lttng_event_exclusion *exclusion __attribute__((unused)),
		       bool internal_event __attribute__((unused)),
		       struct ltt_ust_event **ust_event __attribute__((unused)))
{
	return LTTNG_ERR_NO_UST;
}

static inline void trace_ust_destroy_session(struct ltt_ust_session *session
					     __attribute__((unused)))
{
}

static inline void trace_ust_destroy_channel(struct ltt_ust_channel *channel
					     __attribute__((unused)))
{
}

static inline void trace_ust_destroy_event(struct ltt_ust_event *event __attribute__((unused)))
{
}

static inline void trace_ust_free_session(struct ltt_ust_session *session __attribute__((unused)))
{
}

static inline struct ltt_ust_context *trace_ust_create_context(const struct lttng_event_context *ctx
							       __attribute__((unused)))
{
	return NULL;
}

static inline int trace_ust_match_context(const struct ltt_ust_context *uctx
					  __attribute__((unused)),
					  const struct lttng_event_context *ctx
					  __attribute__((unused)))
{
	return 0;
}

static inline struct ltt_ust_event *
trace_ust_find_event(struct lttng_ht *ht __attribute__((unused)),
		     char *name __attribute__((unused)),
		     struct lttng_bytecode *filter __attribute__((unused)),
		     enum lttng_ust_abi_loglevel_type loglevel_type __attribute__((unused)),
		     int loglevel_value __attribute__((unused)),
		     struct lttng_event_exclusion *exclusion __attribute__((unused)))
{
	return NULL;
}

static inline void trace_ust_delete_channel(struct lttng_ht *ht __attribute__((unused)),
					    struct ltt_ust_channel *channel __attribute__((unused)))
{
	return;
}

static inline int trace_ust_regenerate_metadata(struct ltt_ust_session *usess
						__attribute__((unused)))
{
	return 0;
}

static inline struct agent *trace_ust_find_agent(struct ltt_ust_session *session
						 __attribute__((unused)),
						 enum lttng_domain_type domain_type
						 __attribute__((unused)))
{
	return NULL;
}

static inline int trace_ust_id_tracker_lookup(enum lttng_process_attr process_attr
					      __attribute__((unused)),
					      struct ltt_ust_session *session
					      __attribute__((unused)),
					      int id __attribute__((unused)))
{
	return 0;
}

static inline enum lttng_error_code trace_ust_process_attr_tracker_set_tracking_policy(
	struct ltt_ust_session *session __attribute__((unused)),
	enum lttng_process_attr process_attr __attribute__((unused)),
	enum lttng_tracking_policy policy __attribute__((unused)))
{
	return LTTNG_OK;
}

static inline enum lttng_error_code trace_ust_process_attr_tracker_inclusion_set_add_value(
	struct ltt_ust_session *session __attribute__((unused)),
	enum lttng_process_attr process_attr __attribute__((unused)),
	const struct process_attr_value *value __attribute__((unused)))
{
	return LTTNG_OK;
}

static inline enum lttng_error_code trace_ust_process_attr_tracker_inclusion_set_remove_value(
	struct ltt_ust_session *session __attribute__((unused)),
	enum lttng_process_attr process_attr __attribute__((unused)),
	const struct process_attr_value *value __attribute__((unused)))
{
	return LTTNG_OK;
}

static inline const struct process_attr_tracker *
trace_ust_get_process_attr_tracker(struct ltt_ust_session *session __attribute__((unused)),
				   enum lttng_process_attr process_attr __attribute__((unused)))
{
	return NULL;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_TRACE_UST_H */
