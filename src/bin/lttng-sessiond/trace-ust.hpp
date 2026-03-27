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

struct agent;

/* UST session */
struct ltt_ust_session {
	uint64_t id; /* Unique identifier of session */
	/* Hash table of agent indexed by agent domain. */
	struct lttng_ht *agents;
	/* UID/GID of the user owning the session */
	uid_t uid;
	gid_t gid;
	/* Is the session active meaning has is been started or stopped. */
	bool active;
	struct consumer_output *consumer;
	/* This indicates which type of buffer this session is set for. */
	enum lttng_buffer_type buffer_type;
	/* If set to 1, the buffer_type can not be changed anymore. */
	int buffer_type_changed;

	/* Metadata channel attributes. */
	struct lttng_ust_abi_channel_attr metadata_attr;

	/*
	 * Path where to keep the shared memory files.
	 */
	char root_shm_path[PATH_MAX];
	char shm_path[PATH_MAX];

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
