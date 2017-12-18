/*
 * Copyright (C) 2017 - Julien Desfossez <jdesfossez@efficios.com>
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

#ifndef ROTATE_H
#define ROTATE_H

#include "rotation-thread.h"

/*
 * Key in channel_pending_rotate_ht to map a channel to a
 * struct rotation_channel_info.
 */
struct rotation_channel_key {
	uint64_t key;
	enum lttng_domain_type domain;
};

/*
 * Added in channel_pending_rotate_ht everytime we start the rotation of a
 * channel. The consumer notifies the rotation thread with the channel_key to
 * inform a rotation is complete, we use that information to lookup the related
 * session from channel_pending_rotate_ht.
 */
struct rotation_channel_info {
	uint64_t session_id;
	struct rotation_channel_key channel_key;
	struct cds_lfht_node rotate_channels_ht_node;
};

extern struct cds_lfht *channel_pending_rotate_ht;

unsigned long hash_channel_key(struct rotation_channel_key *key);

int rename_complete_chunk(struct ltt_session *session, time_t ts);

/*
 * When we start the rotation of a channel, we add its information in
 * channel_pending_rotate_ht. This is called in the context of
 * thread_manage_client when the client asks for a rotation, in the context
 * of the sessiond_timer thread when periodic rotations are enabled and from
 * the rotation_thread when size-based rotations are enabled.
 */
int rotate_add_channel_pending(uint64_t key, enum lttng_domain_type domain,
		struct ltt_session *session);

#endif /* ROTATE_H */
