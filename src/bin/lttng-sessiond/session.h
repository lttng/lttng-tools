/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _LTT_SESSION_H
#define _LTT_SESSION_H

#include <limits.h>
#include <stdbool.h>
#include <urcu/list.h>

#include <common/hashtable/hashtable.h>
#include <lttng/rotation.h>
#include <lttng/location.h>

#include "snapshot.h"
#include "trace-kernel.h"
#include "consumer.h"

struct ltt_ust_session;

/*
 * Tracing session list
 *
 * Statically declared in session.c and can be accessed by using
 * session_get_list() function that returns the pointer to the list.
 */
struct ltt_session_list {
	/*
	 * This lock protects any read/write access to the list and
	 * next_uuid. All public functions in session.c acquire this
	 * lock and release it before returning. If none of those
	 * functions are used, the lock MUST be acquired in order to
	 * iterate or/and do any actions on that list.
	 */
	pthread_mutex_t lock;

	/*
	 * Session unique ID generator. The session list lock MUST be
	 * upon update and read of this counter.
	 */
	uint64_t next_uuid;

	/* Linked list head */
	struct cds_list_head head;
};

/*
 * This data structure contains information needed to identify a tracing
 * session for both LTTng and UST.
 */
struct ltt_session {
	char name[NAME_MAX];
	char hostname[HOST_NAME_MAX]; /* Local hostname. */
	struct ltt_kernel_session *kernel_session;
	struct ltt_ust_session *ust_session;
	/*
	 * Protect any read/write on this session data structure. This lock must be
	 * acquired *before* using any public functions declared below. Use
	 * session_lock() and session_unlock() for that.
	 */
	pthread_mutex_t lock;
	struct cds_list_head list;
	uint64_t id;		/* session unique identifier */
	/* UID/GID of the user owning the session */
	uid_t uid;
	gid_t gid;
	/*
	 * Network session handle. A value of 0 means that there is no remote
	 * session established.
	 */
	uint64_t net_handle;
	/*
	 * This consumer is only set when the create_session_uri call is made.
	 * This contains the temporary information for a consumer output. Upon
	 * creation of the UST or kernel session, this consumer, if available, is
	 * copied into those sessions.
	 */
	struct consumer_output *consumer;

	/* Did at least ONE start command has been triggered?. */
	unsigned int has_been_started:1;
	/*
	 * Is the session active? Start trace command sets this to 1 and the stop
	 * command reset it to 0.
	 */
	unsigned int active:1;

	/* Snapshot representation in a session. */
	struct snapshot snapshot;
	/* Indicate if the session has to output the traces or not. */
	unsigned int output_traces;
	/*
	 * This session is in snapshot mode. This means that every channel enabled
	 * will be set in overwrite mode and mmap. It is considered exclusively for
	 * snapshot purposes.
	 */
	unsigned int snapshot_mode;
	/*
	 * Timer set when the session is created for live reading.
	 */
	unsigned int live_timer;
	/*
	 * Path where to keep the shared memory files.
	 */
	char shm_path[PATH_MAX];
	/*
	 * Node in ltt_sessions_ht_by_id.
	 */
	struct lttng_ht_node_u64 node;
	/*
	 * The current archive id corresponds to the number of session rotations
	 * that have occured for this session. The archive id
	 * is used to tag the "generation" of a stream. This tag allows the
	 * consumer and relay daemons to track when a given stream was created
	 * during the lifetime of a session.
	 *
	 * For instance, if a stream is created after a session rotation was
	 * launched, the consumer and relay daemons must not check its position
	 * to determine if that specific session rotation was completed. It is
	 * implicitly "completed" since the stream appeared _after_ the session
	 * rotation was initiated.
	 */
	uint64_t current_archive_id;
	/*
	 * Rotation is considered pending between the time it is launched up
	 * until the moment when the data has been writen at the destination
	 * and the trace archive has been renamed.
	 *
	 * When tracing locally, only 'rotation_pending_local' is used since
	 * no remote checks are needed. However, when tracing to a relay daemon,
	 * a second check is needed to ensure that the data has been
	 * commited at the remote destination.
	 */
	bool rotation_pending_local;
	bool rotation_pending_relay;
	/* Current state of a rotation. */
	enum lttng_rotation_state rotation_state;
	struct {
		/*
		 * When the rotation is in progress, the temporary path name is
		 * stored here. When the rotation is complete, the final path name
		 * is here and can be queried with the rotate_pending call.
		 */
		char current_rotate_path[LTTNG_PATH_MAX];
		/*
		 * The path where the consumer is currently writing after the first
		 * session rotation.
		 */
		char active_tracing_path[LTTNG_PATH_MAX];
	} rotation_chunk;
	/*
	 * The timestamp of the beginning of the previous chunk. For the
	 * first chunk, this is the "lttng start" timestamp. For the
	 * subsequent ones, this copies the current_chunk_start_ts value when
	 * a new rotation starts. This value is used to set the name of a
	 * complete chunk directory, ex: "last_chunk_start_ts-now()".
	 */
	time_t last_chunk_start_ts;
	/*
	 * This is the timestamp when a new chunk starts. When a new rotation
	 * starts, we copy this value to last_chunk_start_ts and replace it
	 * with the current timestamp.
	 */
	time_t current_chunk_start_ts;
	/*
	 * Timer to check periodically if a relay and/or consumer has completed
	 * the last rotation.
	 */
	bool rotation_pending_check_timer_enabled;
	timer_t rotation_pending_check_timer;
	/* Timer to periodically rotate a session. */
	bool rotation_schedule_timer_enabled;
	timer_t rotation_schedule_timer;
	/* Value for periodic rotations, 0 if disabled. */
	uint64_t rotate_timer_period;
	/* Value for size-based rotations, 0 if disabled. */
	uint64_t rotate_size;
	/*
	 * Keep a state if this session was rotated after the last stop command.
	 * We only allow one rotation after a stop. At destroy, we also need to
	 * know if a rotation occured since the last stop to rename the current
	 * chunk.
	 */
	bool rotated_after_last_stop;
	/*
	 * Condition and trigger for size-based rotations.
	 */
	struct lttng_condition *rotate_condition;
	struct lttng_trigger *rotate_trigger;
};

/* Prototypes */
int session_create(char *name, uid_t uid, gid_t gid);
int session_destroy(struct ltt_session *session);

void session_lock(struct ltt_session *session);
void session_lock_list(void);
int session_trylock_list(void);
void session_unlock(struct ltt_session *session);
void session_unlock_list(void);

enum consumer_dst_type session_get_consumer_destination_type(
		const struct ltt_session *session);
const char *session_get_net_consumer_hostname(
		const struct ltt_session *session);
void session_get_net_consumer_ports(
		const struct ltt_session *session,
		uint16_t *control_port, uint16_t *data_port);
struct lttng_trace_archive_location *session_get_trace_archive_location(
		struct ltt_session *session);

struct ltt_session *session_find_by_name(const char *name);
struct ltt_session *session_find_by_id(uint64_t id);
struct ltt_session_list *session_get_list(void);

int session_access_ok(struct ltt_session *session, uid_t uid, gid_t gid);

int session_reset_rotation_state(struct ltt_session *session,
		enum lttng_rotation_state result);

#endif /* _LTT_SESSION_H */
