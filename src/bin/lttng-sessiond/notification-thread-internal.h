/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef NOTIFICATION_THREAD_INTERNAL_H
#define NOTIFICATION_THREAD_INTERNAL_H

#include <lttng/ref-internal.h>
#include <urcu/rculfhash.h>
#include <unistd.h>

struct channel_key {
	uint64_t key;
	enum lttng_domain_type domain;
};

struct session_info {
	struct lttng_ref ref;
	char *name;
	uid_t uid;
	gid_t gid;
	/*
	 * Hashtable containing back-refs (weak) to all channels in this session.
	 * The hashtable's key is a hash of (struct channel_key) and
	 * the value is of type (struct channel_info *).
	 */
	struct cds_lfht *channel_infos_ht;
	struct lttng_session_trigger_list *trigger_list;
	/* Node in the notification thread state's sessions_ht. */
	struct cds_lfht_node sessions_ht_node;
	/*
	 * Weak reference to the thread state's sessions_ht. Used for removal on
	 * destruction.
	 */
	struct cds_lfht *sessions_ht;
	uint64_t consumed_data_size;
	struct {
		/* Whether a rotation is ongoing for this session. */
		bool ongoing;
		/* Identifier of the currently ongoing rotation. */
		uint64_t id;
	} rotation;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

struct channel_info {
	struct channel_key key;
	char *name;
	uint64_t capacity;
	/*
	 * A channel info holds a reference (lttng_ref) on session_info.
	 * session_info, in return, holds a weak reference to the channel.
	 */
	struct session_info *session_info;
	/* Node in the notification thread state's channels_ht. */
	struct cds_lfht_node channels_ht_node;
	/* Node in the session_info's channels_ht. */
	struct cds_lfht_node session_info_channels_ht_node;
	/* call_rcu delayed reclaim. */
	struct rcu_head rcu_node;
};

enum client_transmission_status {
	CLIENT_TRANSMISSION_STATUS_COMPLETE,
	CLIENT_TRANSMISSION_STATUS_QUEUED,
	/* Communication failure. */
	CLIENT_TRANSMISSION_STATUS_FAIL,
	/* Fatal error. */
	CLIENT_TRANSMISSION_STATUS_ERROR,
};
#endif /* NOTIFICATION_THREAD_INTERNAL_H */
