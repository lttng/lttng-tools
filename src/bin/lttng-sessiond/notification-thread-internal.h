/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
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
	 * Back-ref (weak) to all channels in this session.
	 * The hashtable's key is a hash of (struct channel_key) and
	 * the value is of type (struct channel_info *).
	 */
	struct cds_lfht *channel_infos_ht;
	/* Node in the notification thread state's sessions_ht. */
	struct cds_lfht_node sessions_ht_node;
	uint64_t consumed_data_size;
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
};

#endif /* NOTIFICATION_THREAD_INTERNAL_H */
