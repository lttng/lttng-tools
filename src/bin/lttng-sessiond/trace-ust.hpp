/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_TRACE_UST_H
#define _LTT_TRACE_UST_H

#include "consumer.hpp"
#include "lttng-ust-ctl.hpp"
#include "recording-channel-configuration.hpp"

#include <common/defaults.hpp>
#include <common/fs-utils.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/optional.hpp>

#include <lttng/lttng.h>

#include <limits.h>
#include <urcu/list.h>

struct agent;

/* Context hash table nodes */
struct ltt_ust_context {
	explicit ltt_ust_context(const lttng::sessiond::config::context_configuration& config);

	ltt_ust_context(const ltt_ust_context&) = delete;
	ltt_ust_context(ltt_ust_context&&) = delete;
	ltt_ust_context& operator=(const ltt_ust_context&) = delete;
	ltt_ust_context& operator=(ltt_ust_context&&) = delete;
	~ltt_ust_context() = default;

	const lttng::sessiond::config::context_configuration& context_config;
	struct lttng_ht_node_ulong node = {};
	struct cds_list_head list;
};

/* UST channel */
struct ltt_ust_channel {
	/*
	 * Opaque handle used to look up the stream_class within a
	 * trace_class (via trace_class::channel()). This is NOT the CTF
	 * stream class ID; it is a hash table key with no semantic
	 * meaning outside of trace_class internals.
	 */
	uint64_t trace_class_stream_class_handle = 0;
	bool enabled = false;
	/*
	 * A UST channel can be part of a userspace sub-domain such as JUL,
	 * Log4j, Log4j2, Python.
	 */
	enum lttng_domain_type domain = LTTNG_DOMAIN_NONE;
	char name[LTTNG_UST_ABI_SYM_NAME_LEN] = {};
	struct lttng_ust_abi_channel_attr attr = {};
	struct lttng_ht *ctx = nullptr; /* Context hash table */
	struct cds_list_head ctx_list = {};
	struct lttng_ht_node_str node = {};
	uint64_t tracefile_size = 0;
	uint64_t tracefile_count = 0;
	uint64_t per_pid_closed_app_discarded = 0;
	uint64_t per_pid_closed_app_lost = 0;
	uint64_t monitor_timer_interval = 0;
	LTTNG_OPTIONAL(uint64_t) watchdog_timer_interval = {};

	lttng::sessiond::config::recording_channel_configuration::buffer_preallocation_policy_t
		preallocation_policy = lttng::sessiond::config::recording_channel_configuration::
			buffer_preallocation_policy_t::PREALLOCATE;
	nonstd::optional<std::chrono::microseconds> automatic_memory_reclamation_maximal_age;
};

/* UST domain global (LTTNG_DOMAIN_UST) */
struct ltt_ust_domain_global {
	struct lttng_ht *channels;
	struct cds_list_head registry_buffer_uid_list;
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
	/*
	 * For per UID buffer, every buffer_reg_uid object is kept of this session.
	 * It contains separate instances on a per UID and ABI (32/64) basis.
	 */
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

	bool supports_madv_remove() const noexcept
	{
		return lttng::utils::fs_supports_madv_remove(
			this->shm_path[0] != '\0' ? this->shm_path : nullptr);
	}
};

/* Return next available channel id and increment the used counter. */
static inline uint64_t trace_ust_get_trace_class_stream_class_handle(struct ltt_ust_session *s)
{
	s->used_event_container_id++;
	return s->next_event_container_id++;
}

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * Lookup functions. NULL is returned if not found.
 */
struct ltt_ust_channel *trace_ust_find_channel_by_name(struct lttng_ht *ht, const char *name);
struct agent *trace_ust_find_agent(struct ltt_ust_session *session,
				   enum lttng_domain_type domain_type);

/*
 * Create functions malloc() the data structure.
 */
struct ltt_ust_session *trace_ust_create_session(uint64_t session_id);
struct ltt_ust_channel *trace_ust_create_channel(struct lttng_channel *attr,
						 enum lttng_domain_type domain);

struct ltt_ust_context *
trace_ust_create_context(const lttng::sessiond::config::context_configuration& context_config);
void trace_ust_delete_channel(struct lttng_ht *ht, struct ltt_ust_channel *channel);

int trace_ust_regenerate_metadata(struct ltt_ust_session *usess);

/*
 * Destroy functions free() the data structure and remove from linked list if
 * it's applies.
 */
void trace_ust_destroy_session(struct ltt_ust_session *session);
void trace_ust_destroy_channel(struct ltt_ust_channel *channel);
void trace_ust_destroy_context(ltt_ust_context *ctx);
void trace_ust_free_session(struct ltt_ust_session *session);

bool trace_ust_runtime_ctl_version_matches_build_version();

#else /* HAVE_LIBLTTNG_UST_CTL */

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

static inline void trace_ust_destroy_session(struct ltt_ust_session *session
					     __attribute__((unused)))
{
}

static inline void trace_ust_destroy_channel(struct ltt_ust_channel *channel
					     __attribute__((unused)))
{
}

static inline void trace_ust_free_session(struct ltt_ust_session *session __attribute__((unused)))
{
}

static inline struct ltt_ust_context *
trace_ust_create_context(const lttng::sessiond::config::context_configuration& context_config
			 __attribute__((unused)))
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

static inline bool trace_ust_runtime_ctl_version_matches_build_version()
{
	return true;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_TRACE_UST_H */
