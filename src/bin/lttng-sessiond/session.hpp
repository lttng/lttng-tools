/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_SESSION_H
#define _LTT_SESSION_H

#include "consumer.hpp"
#include "domain.hpp"
#include "snapshot.hpp"
#include "trace-kernel.hpp"
#include "trace-ust.hpp"
#include "ust-app.hpp"

#include <common/dynamic-array.hpp>
#include <common/exception.hpp>
#include <common/hashtable/hashtable.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/pthread-lock.hpp>
#include <common/reference.hpp>
#include <common/urcu.hpp>

#include <lttng/location.h>
#include <lttng/lttng-error.h>
#include <lttng/rotation.h>

#include <condition_variable>
#include <limits.h>
#include <mutex>
#include <stdbool.h>
#include <urcu/list.h>

#define ASSERT_SESSION_LIST_LOCKED() LTTNG_ASSERT(session_trylock_list())

struct ltt_ust_session;

struct ltt_session;
struct ltt_session_list;
struct buffer_reg_uid;

enum lttng_error_code
session_create(const char *name, uid_t uid, gid_t gid, struct ltt_session **out_session);
void session_lock(const ltt_session *session);
void session_unlock(const ltt_session *session);

bool session_get(struct ltt_session *session);
void session_put(struct ltt_session *session);

/*
 * The session list lock covers more ground than its name implies. While
 * it does protect against concurent mutations of the session list, it is
 * also used as a multi-session lock when synchronizing newly-registered
 * 'user space tracer' and 'agent' applications.
 *
 * In other words, it prevents tracer configurations from changing while they
 * are being transmitted to the various applications.
 */
int session_trylock_list() noexcept;

#define LTTNG_THROW_SESSION_NOT_FOUND_BY_NAME_ERROR(session_name)                \
	throw lttng::sessiond::exceptions::session_not_found_error(session_name, \
								   LTTNG_SOURCE_LOCATION())
#define LTTNG_THROW_SESSION_NOT_FOUND_BY_ID_ERROR(id) \
	throw lttng::sessiond::exceptions::session_not_found_error(id, LTTNG_SOURCE_LOCATION())

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
	std::mutex lock;
	/*
	 * This condition variable is signaled on every removal from
	 * the session list.
	 */
	std::condition_variable removal_cond;

	/*
	 * Session unique ID generator. The session list lock MUST be
	 * upon update and read of this counter.
	 */
	uint64_t next_uuid = 0;

	/* Linked list head */
	struct cds_list_head head = CDS_LIST_HEAD_INIT(head);
};

namespace lttng {
namespace sessiond {
class user_space_consumer_channel_keys {
	friend ltt_session;

public:
	class iterator;

	enum class consumer_bitness : std::uint8_t {
		ABI_32 = 32,
		ABI_64 = 64,
	};

	enum class channel_type : std::uint8_t {
		METADATA,
		DATA,
	};

	iterator begin() const noexcept;
	iterator end() const noexcept;

private:
	enum class _iteration_mode : std::uint8_t {
		PER_PID,
		PER_UID,

	};

	struct _iterator_creation_context {
		const _iteration_mode _mode;
		const ltt_ust_session& _session;
		union {
			lttng_ht *apps;
			const cds_list_head *buffer_registry;
		} _container;
	};

public:
	class iterator : public std::iterator<std::input_iterator_tag, std::uint64_t> {
		friend user_space_consumer_channel_keys;

	public:
		struct key {
			/* Bitness is needed to query the appropriate consumer daemon. */
			consumer_bitness bitness;
			std::uint64_t key_value;
			channel_type type;

			bool operator==(const key& other)
			{
				return bitness == other.bitness && key_value == other.key_value &&
					type == other.type;
			}
		};

		/*
		 * Copy constructor disabled since it would require handling the copy of locked
		 * references.
		 */
		iterator(const iterator& other) = delete;
		iterator(iterator&& other) = default;
		~iterator() = default;
		iterator& operator=(const iterator&) = delete;
		iterator& operator=(iterator&&) noexcept = delete;

		iterator& operator++();
		bool operator==(const iterator& other) const noexcept;
		bool operator!=(const iterator& other) const noexcept;
		key operator*() const;

		/*
		 * Get the session registry of the channel currently
		 * pointed by the iterator. Never returns nullptr.
		 */
		lttng::sessiond::ust::registry_session *get_registry_session();

	private:
		struct _iterator_position {
			struct {
				lttng_ht_iter app_iterator = {};
				nonstd::optional<ust_app_session::locked_weak_ref>
					current_app_session;
				lttng::sessiond::ust::registry_session *current_registry_session =
					nullptr;
			} _per_pid;
			struct {
				buffer_reg_uid *current_registry = nullptr;
			} _per_uid;

			lttng_ht_iter channel_iterator = {};
		};

		explicit iterator(const _iterator_creation_context& creation_context,
				  bool is_end = false);

		void _init_per_pid() noexcept;
		void _skip_to_next_app_per_pid(bool try_current) noexcept;
		void _advance_one_per_pid();
		key _get_current_value_per_pid() const noexcept;
		lttng::sessiond::ust::registry_session *_get_registry_session_per_pid();

		void _init_per_uid() noexcept;
		void _advance_one_per_uid();
		key _get_current_value_per_uid() const noexcept;
		lttng::sessiond::ust::registry_session *_get_registry_session_per_uid();

		const _iterator_creation_context& _creation_context;
		_iterator_position _position;
		bool _is_end;
	};

private:
	user_space_consumer_channel_keys(const ltt_ust_session& ust_session, lttng_ht& apps) :
		_creation_context{ _iteration_mode::PER_PID, ust_session, { .apps = &apps } }
	{
	}

	user_space_consumer_channel_keys(const ltt_ust_session& ust_session,
					 const cds_list_head& buffer_registry) :
		_creation_context{ _iteration_mode::PER_UID,
				   ust_session,
				   { .buffer_registry = &buffer_registry } }
	{
	}

	class _scoped_rcu_read_lock {
	public:
		_scoped_rcu_read_lock()
		{
			rcu_read_lock();
		}

		~_scoped_rcu_read_lock()
		{
			if (_armed) {
				rcu_read_unlock();
			}
		}

		_scoped_rcu_read_lock(_scoped_rcu_read_lock&& other) noexcept
		{
			other._armed = false;
		}

		_scoped_rcu_read_lock(_scoped_rcu_read_lock& other) = delete;
		_scoped_rcu_read_lock& operator=(const _scoped_rcu_read_lock&) = delete;
		_scoped_rcu_read_lock& operator=(_scoped_rcu_read_lock&&) noexcept = delete;

	private:
		bool _armed = true;
	};

	_scoped_rcu_read_lock _read_lock;
	_iterator_creation_context _creation_context;
};
} /* namespace sessiond */
} /* namespace lttng */

/*
 * This data structure contains information needed to identify a tracing
 * session for both LTTng and UST.
 */
struct ltt_session {
	using id_t = uint64_t;
	friend lttng::sessiond::user_space_consumer_channel_keys::iterator;

private:
	static void _locked_session_release(ltt_session *session);
	static void _locked_const_session_release(const ltt_session *session);
	static void _const_session_put(const ltt_session *session);
	static void _const_session_unlock(const ltt_session& session);

public:
	using locked_ref = lttng::non_copyable_reference<
		ltt_session,
		lttng::memory::create_deleter_class<ltt_session,
						    ltt_session::_locked_session_release>::deleter>;
	using ref = lttng::non_copyable_reference<
		ltt_session,
		lttng::memory::create_deleter_class<ltt_session, session_put>::deleter>;
	using const_locked_ref = lttng::non_copyable_reference<
		const ltt_session,
		lttng::memory::create_deleter_class<
			const ltt_session,
			ltt_session::_locked_const_session_release>::deleter>;
	using const_ref = lttng::non_copyable_reference<
		const ltt_session,
		lttng::memory::create_deleter_class<const ltt_session,
						    ltt_session::_const_session_put>::deleter>;

	static locked_ref make_locked_ref(ltt_session& session)
	{
		return lttng::make_non_copyable_reference<locked_ref::referenced_type,
							  locked_ref::deleter>(session);
	}

	static const_locked_ref make_locked_ref(const ltt_session& session)
	{
		return lttng::make_non_copyable_reference<const_locked_ref::referenced_type,
							  const_locked_ref::deleter>(session);
	}

	static ref make_ref(ltt_session& session)
	{
		return lttng::make_non_copyable_reference<ref::referenced_type, ref::deleter>(
			session);
	}

	static const_ref make_ref(const ltt_session& session)
	{
		return lttng::make_non_copyable_reference<const_ref::referenced_type,
							  const_ref::deleter>(session);
	}

	ltt_session() = default;
	~ltt_session() = default;
	ltt_session(ltt_session&&) = delete;
	ltt_session(const ltt_session&) = delete;
	ltt_session& operator=(ltt_session&&) = delete;
	ltt_session& operator=(const ltt_session&) = delete;

	void lock() const noexcept;
	void unlock() const noexcept;

	lttng::sessiond::domain& get_domain(lttng::sessiond::domain_class domain);
	const lttng::sessiond::domain& get_domain(lttng::sessiond::domain_class domain) const;

	lttng::sessiond::user_space_consumer_channel_keys user_space_consumer_channel_keys() const;

	/*
	 * Session list lock must be acquired by the caller.
	 *
	 * The caller must not keep the ownership of the returned locked session
	 * for longer than strictly necessary. If your intention is to acquire
	 * a reference to an ltt_session, see `find_session()`.
	 */
	static locked_ref find_locked_session(ltt_session::id_t id);
	static locked_ref find_locked_session(lttng::c_string_view name);
	static const_locked_ref find_locked_const_session(ltt_session::id_t id);
	static const_locked_ref find_locked_const_session(lttng::c_string_view name);

	static ref find_session(ltt_session::id_t id);
	static ref find_session(lttng::c_string_view name);
	static const_ref find_const_session(ltt_session::id_t id);
	static const_ref find_const_session(lttng::c_string_view name);

	char name[NAME_MAX] = {};
	bool has_auto_generated_name = false;
	bool name_contains_creation_time = false;
	char hostname[LTTNG_HOST_NAME_MAX] = {}; /* Local hostname. */
	/* Path of the last closed chunk. */
	char last_chunk_path[LTTNG_PATH_MAX] = {};
	time_t creation_time = 0;
	struct ltt_kernel_session *kernel_session = nullptr;
	struct ltt_ust_session *ust_session = nullptr;
	mutable struct urcu_ref ref_count = {};
	/*
	 * Protect any read/write on this session data structure. This lock must be
	 * acquired *before* using any public functions declared below. Use
	 * session_lock() and session_unlock() for that.
	 */
	mutable pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;
	struct cds_list_head list = {};
	/* session unique identifier */
	id_t id = 0;
	/* Indicates if the session has been added to the session list and ht.*/
	bool published = false;
	/* Indicates if a destroy command has been applied to this session. */
	bool destroyed = false;
	/* UID/GID of the user owning the session */
	uid_t uid = -1;
	gid_t gid = -1;
	/*
	 * Network session handle. A value of 0 means that there is no remote
	 * session established.
	 */
	uint64_t net_handle = 0;
	/*
	 * This consumer is only set when the create_session_uri call is made.
	 * This contains the temporary information for a consumer output. Upon
	 * creation of the UST or kernel session, this consumer, if available, is
	 * copied into those sessions.
	 */
	struct consumer_output *consumer = nullptr;
	/*
	 * Indicates whether or not the user has specified an output directory
	 * or if it was configured using the default configuration.
	 */
	bool has_user_specified_directory = false;
	/* Did at least ONE start command has been triggered?. */
	bool has_been_started = false;
	/* Is the session active? */
	bool active = false;

	/* Snapshot representation in a session. */
	struct snapshot snapshot = {};
	/* Indicate if the session has to output the traces or not. */
	bool output_traces = false;
	/*
	 * This session is in snapshot mode. This means that channels enabled
	 * will be set in overwrite mode by default and must be in mmap
	 * output mode. Note that snapshots can be taken on a session that
	 * is not in "snapshot_mode". This parameter only affects channel
	 * creation defaults.
	 */
	bool snapshot_mode = false;
	/*
	 * A session that has channels that don't use 'mmap' output can't be
	 * used to capture snapshots. This is set to true whenever a
	 * 'splice' kernel channel is enabled.
	 */
	bool has_non_mmap_channel = false;
	/*
	 * Timer set when the session is created for live reading.
	 */
	unsigned int live_timer = 0;
	/*
	 * Path where to keep the shared memory files.
	 */
	char shm_path[PATH_MAX] = {};
	/*
	 * Node in ltt_sessions_ht_by_id.
	 */
	struct lttng_ht_node_u64 node = {};
	/*
	 * Node in ltt_sessions_ht_by_name.
	 */
	struct lttng_ht_node_str node_by_name = {};
	/*
	 * Timer to check periodically if a relay and/or consumer has completed
	 * the last rotation.
	 */
	bool rotation_pending_check_timer_enabled = false;
	timer_t rotation_pending_check_timer = nullptr;
	/* Timer to periodically rotate a session. */
	bool rotation_schedule_timer_enabled = false;
	timer_t rotation_schedule_timer = nullptr;
	/* Value for periodic rotations, 0 if disabled. */
	uint64_t rotate_timer_period = 0;
	/* Value for size-based rotations, 0 if disabled. */
	uint64_t rotate_size = 0;
	/*
	 * Keep a state if this session was rotated after the last stop command.
	 * We only allow one rotation after a stop. At destroy, we also need to
	 * know if a rotation occurred since the last stop to rename the current
	 * chunk. After a stop followed by rotate, all subsequent clear
	 * (without prior start) will succeed, but will be effect-less.
	 */
	bool rotated_after_last_stop = false;
	/*
	 * Track whether the session was cleared after last stop. All subsequent
	 * clear (without prior start) will succeed, but will be effect-less. A
	 * subsequent rotate (without prior start) will return an error.
	 */
	bool cleared_after_last_stop = false;
	/*
	 * True if the session has had an explicit non-quiet rotation.
	 */
	bool rotated = false;
	/*
	 * Trigger for size-based rotations.
	 */
	struct lttng_trigger *rotate_trigger = nullptr;
	LTTNG_OPTIONAL(uint64_t) most_recent_chunk_id = {};
	struct lttng_trace_chunk *current_trace_chunk = nullptr;
	struct lttng_trace_chunk *chunk_being_archived = nullptr;
	/* Current state of a rotation. */
	enum lttng_rotation_state rotation_state = LTTNG_ROTATION_STATE_NO_ROTATION;
	bool quiet_rotation = false;
	char *last_archived_chunk_name = nullptr;
	LTTNG_OPTIONAL(uint64_t) last_archived_chunk_id = {};
	struct lttng_dynamic_array destroy_notifiers = {};
	struct lttng_dynamic_array clear_notifiers = {};
	/* Session base path override. Set non-null. */
	char *base_path = nullptr;

	lttng::sessiond::multi_channel_domain user_space_domain =
		lttng::sessiond::multi_channel_domain(lttng::sessiond::domain_class::USER_SPACE);
	lttng::sessiond::multi_channel_domain kernel_space_domain =
		lttng::sessiond::multi_channel_domain(lttng::sessiond::domain_class::KERNEL_SPACE);
};

/*
 * Destruction notifiers are invoked in an exclusive context. There is no need for the session to be
 * locked nor for a reference to be acquired.
 */
using ltt_session_destroy_notifier = void (*)(const ltt_session::locked_ref&, void *);
using ltt_session_clear_notifier = void (*)(const ltt_session::locked_ref&, void *);

namespace lttng {
namespace sessiond {

std::unique_lock<std::mutex> lock_session_list();

namespace exceptions {
/*
 * @class session_not_found_error
 * @brief Represents a session-not-found error and provides the parameters used to query the session
 * for use by error-reporting code.
 */
class session_not_found_error : public lttng::runtime_error {
public:
	class query_parameter {
	public:
		enum class query_type : std::uint8_t { BY_NAME, BY_ID };

		/*
		 * Intentionally not explicit to allow construction from c-style strings,
		 * std::string, and lttng::c_string_view.
		 *
		 * NOLINTBEGIN(google-explicit-constructor)
		 */
		query_parameter(const std::string& session_name) :
			type(query_type::BY_NAME), parameter(session_name)
		{
		}
		/* NOLINTEND(google-explicit-constructor) */

		explicit query_parameter(ltt_session::id_t id_) :
			type(query_type::BY_ID), parameter(id_)
		{
		}

		query_parameter(const query_parameter& other) : type(other.type)
		{
			if (type == query_type::BY_NAME) {
				new (&parameter.name) std::string(other.parameter.name);
			} else {
				parameter.id = other.parameter.id;
			}
		}

		~query_parameter()
		{
			if (type == query_type::BY_NAME) {
				parameter.name.~basic_string();
			}
		}

		query_parameter(query_parameter&& other) noexcept;
		query_parameter& operator=(const query_parameter&) = delete;
		query_parameter& operator=(query_parameter&&) noexcept = delete;

		query_type type;
		union parameter {
			explicit parameter(std::string name_) : name(std::move(name_))
			{
			}

			explicit parameter(ltt_session::id_t id_) : id(id_)
			{
			}

			/*
			 * parameter doesn't have enough information to do this safely; it it
			 * delegated to its parent which uses placement new.
			 *
			 * NOLINTBEGIN(modernize-use-equals-default)
			 *
			 * default can't be used as the default constructor and destructors are
			 * implicitly deleted.
			 */
			parameter()
			{
			}

			~parameter()
			{
			}
			/* NOLINTEND(modernize-use-equals-default) */

			parameter(const parameter&) = delete;
			parameter(const parameter&&) = delete;
			parameter& operator=(parameter&) = delete;
			parameter& operator=(parameter&&) = delete;

			std::string name;
			ltt_session::id_t id;
		} parameter;
	};

	session_not_found_error(const std::string& session_name,
				const lttng::source_location& source_location_) :
		lttng::runtime_error(fmt::format("Session not found: name=`{}`", session_name),
				     source_location_),
		query_parameter(session_name)
	{
	}

	session_not_found_error(ltt_session::id_t session_id,
				const lttng::source_location& source_location_) :
		lttng::runtime_error("Session not found: id=" + std::to_string(session_id),
				     source_location_),
		query_parameter(session_id)
	{
	}

	session_not_found_error(const session_not_found_error& other) = default;
	~session_not_found_error() noexcept override = default;
	/*
	 * Setting an explicit `noexcept` causes compilation failure on gcc < 5.0
	 * @see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=59526
	 */
	session_not_found_error(session_not_found_error&& other) /* noexcept */ = default;
	session_not_found_error& operator=(const session_not_found_error&) = delete;
	session_not_found_error& operator=(session_not_found_error&&) noexcept = delete;

	query_parameter query_parameter;
};
} /* namespace exceptions */
} /* namespace sessiond */
} /* namespace lttng */

void session_destroy(struct ltt_session *session);
int session_add_destroy_notifier(const ltt_session::locked_ref& session,
				 ltt_session_destroy_notifier notifier,
				 void *user_data);

int session_add_clear_notifier(const ltt_session::locked_ref& session,
			       ltt_session_clear_notifier notifier,
			       void *user_data);
void session_notify_clear(const ltt_session::locked_ref& session);

enum consumer_dst_type
session_get_consumer_destination_type(const ltt_session::locked_ref& session);
const char *session_get_net_consumer_hostname(const ltt_session::locked_ref& session);
void session_get_net_consumer_ports(const ltt_session::locked_ref& session,
				    uint16_t *control_port,
				    uint16_t *data_port);
struct lttng_trace_archive_location *
session_get_trace_archive_location(const ltt_session::locked_ref& session);

struct ltt_session_list *session_get_list();
void session_list_wait_empty(std::unique_lock<std::mutex> list_lock);

bool session_access_ok(const ltt_session::locked_ref& session, uid_t uid);

int session_reset_rotation_state(const ltt_session::locked_ref& session,
				 enum lttng_rotation_state result);

/* Create a new trace chunk object from the session's configuration. */
struct lttng_trace_chunk *
session_create_new_trace_chunk(const ltt_session::locked_ref& session,
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
int session_set_trace_chunk(const ltt_session::locked_ref& session,
			    struct lttng_trace_chunk *new_trace_chunk,
			    struct lttng_trace_chunk **current_session_trace_chunk);

/*
 * Close a chunk on the remote peers of a session. Has no effect on the
 * ltt_session itself.
 */
int session_close_trace_chunk(const ltt_session::locked_ref& session,
			      struct lttng_trace_chunk *trace_chunk,
			      enum lttng_trace_chunk_command_type close_command,
			      char *path);

/* Open a packet in all channels of a given session. */
enum lttng_error_code session_open_packets(const ltt_session::locked_ref& session);

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

const char *session_get_base_path(const ltt_session::locked_ref& session);

#ifdef HAVE_LIBLTTNG_UST_CTL

enum lttng_error_code ust_app_rotate_session(const ltt_session::locked_ref& session);
enum lttng_error_code ust_app_clear_session(const ltt_session::locked_ref& session);
enum lttng_error_code ust_app_open_packets(const ltt_session::locked_ref& session);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline enum lttng_error_code ust_app_rotate_session(const ltt_session::locked_ref& session
							   __attribute__((unused)))
{
	return LTTNG_ERR_UNK;
}

static inline enum lttng_error_code ust_app_clear_session(const ltt_session::locked_ref& session
							  __attribute__((unused)))
{
	return LTTNG_ERR_UNK;
}

static inline enum lttng_error_code ust_app_open_packets(const ltt_session::locked_ref& session
							 __attribute__((unused)))
{
	return LTTNG_ERR_UNK;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_SESSION_H */
