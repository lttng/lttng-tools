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

#include <common/defaults.hpp>
#include <common/fs-utils.hpp>
#include <common/hashtable/hashtable.hpp>

#include <lttng/lttng.h>

#include <limits.h>
#include <urcu/list.h>

struct agent;

/* UST domain global (LTTNG_DOMAIN_UST) */
struct ltt_ust_domain_global {
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
	/* Tell or not if the session has to output the traces. */
	unsigned int output_traces;
	unsigned int snapshot_mode;
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

#ifdef HAVE_LIBLTTNG_UST_CTL

struct agent *trace_ust_find_agent(struct ltt_ust_session *session,
				   enum lttng_domain_type domain_type);

struct ltt_ust_session *trace_ust_create_session(uint64_t session_id);

void trace_ust_destroy_session(struct ltt_ust_session *session);
void trace_ust_free_session(struct ltt_ust_session *session);

bool trace_ust_runtime_ctl_version_matches_build_version();

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline struct ltt_ust_session *trace_ust_create_session(unsigned int session_id
							       __attribute__((unused)))
{
	return NULL;
}

static inline void trace_ust_destroy_session(struct ltt_ust_session *session
					     __attribute__((unused)))
{
}

static inline void trace_ust_free_session(struct ltt_ust_session *session __attribute__((unused)))
{
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
