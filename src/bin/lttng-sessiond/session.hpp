/*
 * Copyright (C) 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_SESSION_H
#define _LTT_SESSION_H

#include "consumer.hpp"
#include "snapshot.hpp"
#include "trace-kernel.hpp"

#include <common/dynamic-array.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/pthread-lock.hpp>

#include <lttng/location.h>
#include <lttng/lttng-error.h>
#include <lttng/rotation.h>

#include <limits.h>
#include <stdbool.h>
#include <urcu/list.h>

#define ASSERT_SESSION_LIST_LOCKED() LTTNG_ASSERT(session_trylock_list())

struct ltt_ust_session;

using ltt_session_destroy_notifier = void (*)(const struct ltt_session *, void *);
using ltt_session_clear_notifier = void (*)(const struct ltt_session *, void *);

namespace lttng {
namespace sessiond {
namespace details {
void locked_session_release(ltt_session *session);
} /* namespace details */
} /* namespace sessiond */
} /* namespace lttng */

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
	 * This condition variable is signaled on every removal from
	 * the session list.
	 */
	pthread_cond_t removal_cond;

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
	using id_t = uint64_t;
	using locked_ptr =
		std::unique_ptr<ltt_session,
				lttng::details::create_unique_class<
					ltt_session,
					lttng::sessiond::details::locked_session_release>::deleter>;
	using sptr = std::shared_ptr<ltt_session>;

	char name[NAME_MAX];
	bool has_auto_generated_name;
	bool name_contains_creation_time;
	char hostname[LTTNG_HOST_NAME_MAX]; /* Local hostname. */
	/* Path of the last closed chunk. */
	char last_chunk_path[LTTNG_PATH_MAX];
	time_t creation_time;
	struct ltt_kernel_session *kernel_session;
	struct ltt_ust_session *ust_session;
	struct urcu_ref ref;
	/*
	 * Protect any read/write on this session data structure. This lock must be
	 * acquired *before* using any public functions declared below. Use
	 * session_lock() and session_unlock() for that.
	 */
	pthread_mutex_t lock;
	struct cds_list_head list;
	/* session unique identifier */
	id_t id;
	/* Indicates if the session has been added to the session list and ht.*/
	bool published;
	/* Indicates if a destroy command has been applied to this session. */
	bool destroyed;
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
	/*
	 * Indicates whether or not the user has specified an output directory
	 * or if it was configured using the default configuration.
	 */
	bool has_user_specified_directory;
	/* Did at least ONE start command has been triggered?. */
	bool has_been_started;
	/* Is the session active? */
	bool active;

	/* Snapshot representation in a session. */
	struct snapshot snapshot;
	/* Indicate if the session has to output the traces or not. */
	unsigned int output_traces;
	/*
	 * This session is in snapshot mode. This means that channels enabled
	 * will be set in overwrite mode by default and must be in mmap
	 * output mode. Note that snapshots can be taken on a session that
	 * is not in "snapshot_mode". This parameter only affects channel
	 * creation defaults.
	 */
	unsigned int snapshot_mode;
	/*
	 * A session that has channels that don't use 'mmap' output can't be
	 * used to capture snapshots. This is set to true whenever a
	 * 'splice' kernel channel is enabled.
	 */
	bool has_non_mmap_channel;
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
	 * Node in ltt_sessions_ht_by_name.
	 */
	struct lttng_ht_node_str node_by_name;
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
	 * know if a rotation occurred since the last stop to rename the current
	 * chunk. After a stop followed by rotate, all subsequent clear
	 * (without prior start) will succeed, but will be effect-less.
	 */
	bool rotated_after_last_stop;
	/*
	 * Track whether the session was cleared after last stop. All subsequent
	 * clear (without prior start) will succeed, but will be effect-less. A
	 * subsequent rotate (without prior start) will return an error.
	 */
	bool cleared_after_last_stop;
	/*
	 * True if the session has had an explicit non-quiet rotation.
	 */
	bool rotated;
	/*
	 * Trigger for size-based rotations.
	 */
	struct lttng_trigger *rotate_trigger;
	LTTNG_OPTIONAL(uint64_t) most_recent_chunk_id;
	struct lttng_trace_chunk *current_trace_chunk;
	struct lttng_trace_chunk *chunk_being_archived;
	/* Current state of a rotation. */
	enum lttng_rotation_state rotation_state;
	bool quiet_rotation;
	char *last_archived_chunk_name;
	LTTNG_OPTIONAL(uint64_t) last_archived_chunk_id;
	struct lttng_dynamic_array destroy_notifiers;
	struct lttng_dynamic_array clear_notifiers;
	/* Session base path override. Set non-null. */
	char *base_path;
};

enum lttng_error_code
session_create(const char *name, uid_t uid, gid_t gid, struct ltt_session **out_session);
void session_lock(struct ltt_session *session);
void session_unlock(struct ltt_session *session);

/*
 * The session list lock covers more ground than its name implies. While
 * it does protect against concurent mutations of the session list, it is
 * also used as a multi-session lock when synchronizing newly-registered
 * 'user space tracer' and 'agent' applications.
 *
 * In other words, it prevents tracer configurations from changing while they
 * are being transmitted to the various applications.
 */
void session_lock_list() noexcept;
int session_trylock_list() noexcept;
void session_unlock_list() noexcept;

void session_destroy(struct ltt_session *session);
int session_add_destroy_notifier(struct ltt_session *session,
				 ltt_session_destroy_notifier notifier,
				 void *user_data);

int session_add_clear_notifier(struct ltt_session *session,
			       ltt_session_clear_notifier notifier,
			       void *user_data);
void session_notify_clear(ltt_session& session);

bool session_get(struct ltt_session *session);
void session_put(struct ltt_session *session);

enum consumer_dst_type session_get_consumer_destination_type(const struct ltt_session *session);
const char *session_get_net_consumer_hostname(const struct ltt_session *session);
void session_get_net_consumer_ports(const struct ltt_session *session,
				    uint16_t *control_port,
				    uint16_t *data_port);
struct lttng_trace_archive_location *
session_get_trace_archive_location(const struct ltt_session *session);

struct ltt_session *session_find_by_name(const char *name);
struct ltt_session *session_find_by_id(ltt_session::id_t id);

struct ltt_session_list *session_get_list();
void session_list_wait_empty();

bool session_access_ok(struct ltt_session *session, uid_t uid);

int session_reset_rotation_state(ltt_session& session, enum lttng_rotation_state result);

/* Create a new trace chunk object from the session's configuration. */
struct lttng_trace_chunk *
session_create_new_trace_chunk(const struct ltt_session *session,
			       const struct consumer_output *consumer_output_override,
			       const char *session_base_path_override,
			       const char *chunk_name_override);

/*
 * Set `new_trace_chunk` as the session's current trace chunk. A reference
 * to `new_trace_chunk` is acquired by the session. The chunk is created
 * on remote peers (consumer and relay daemons).
 *
 * A reference to the session's current trace chunk is returned through
 * `current_session_trace_chunk` on success.
 */
int session_set_trace_chunk(struct ltt_session *session,
			    struct lttng_trace_chunk *new_trace_chunk,
			    struct lttng_trace_chunk **current_session_trace_chunk);

/*
 * Close a chunk on the remote peers of a session. Has no effect on the
 * ltt_session itself.
 */
int session_close_trace_chunk(struct ltt_session *session,
			      struct lttng_trace_chunk *trace_chunk,
			      enum lttng_trace_chunk_command_type close_command,
			      char *path);

/* Open a packet in all channels of a given session. */
enum lttng_error_code session_open_packets(struct ltt_session *session);

bool session_output_supports_trace_chunks(const struct ltt_session *session);

/*
 * Sample the id of a session looked up via its name.
 * Here the term "sampling" hint the caller that this return the id at a given
 * point in time with no guarantee that the session for which the id was
 * sampled still exist at that point.
 *
 * Return 0 when the session is not found,
 * Return 1 when the session is found and set `id`.
 */
bool sample_session_id_by_name(const char *name, uint64_t *id);

namespace lttng {
namespace sessiond {

/*
 * Session list lock must be acquired by the caller.
 * The caller must not keep the ownership of the returned locked session
 * for longer than strictly necessary. If your intention is to acquire
 * a reference to an ltt_session, see `find_session_by_id()`.
 */
ltt_session::locked_ptr find_locked_session_by_id(ltt_session::id_t id);

/*
 * Session list lock must be acquired by the caller.
 * The caller must not keep the ownership of the returned locked session
 * for longer than strictly necessary. If your intention is to acquire
 * a reference to an ltt_session, see `find_session_by_id()`.
 */
ltt_session::sptr find_session_by_id(ltt_session::id_t id);

} /* namespace sessiond */
} /* namespace lttng */

#endif /* _LTT_SESSION_H */
