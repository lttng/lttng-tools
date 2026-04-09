/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTT_UST_APP_H
#define _LTT_UST_APP_H

#include "consumer.hpp"
#include "domain.hpp"
#include "lttng-ust-ctl.hpp"
#include "trace-class.hpp"
#include "ust-application-abi.hpp"
#include "ust-field-quirks.hpp"

#include <common/format.hpp>
#include <common/index-allocator.hpp>
#include <common/optional.hpp>
#include <common/reference.hpp>
#include <common/scope-exit.hpp>
#include <common/string-utils/c-string-view.hpp>
#include <common/uuid.hpp>

#include <vendor/optional.hpp>

#include <list>
#include <stdint.h>
#include <urcu/list.h>
#include <vector>

#define UST_APP_EVENT_LIST_SIZE 32

/* Process name (short). */
#define UST_APP_PROCNAME_LEN 16

struct lttng_bytecode;
struct lttng_ust_filter_bytecode;
struct lttng_pipe;

namespace lttng {
namespace sessiond {
namespace config {
class recording_channel_configuration;
class event_rule_configuration;
class context_configuration;
} /* namespace config */
namespace ust {
class trace_class;
class domain_orchestrator;
struct app;
struct app_session;
struct app_stream;
} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

struct ltt_session;

extern int the_ust_consumerd64_fd, the_ust_consumerd32_fd;

/*
 * Object used to close the notify socket in a call_rcu(). Since the
 * application might not be found, we need an independant object containing the
 * notify socket fd.
 */
struct ust_app_notify_sock_obj {
	int fd;
	struct rcu_head head;
};

/*
 * Application registration data structure.
 */
struct ust_register_msg {
	enum lttng_ust_ctl_socket_type type;
	uint32_t major;
	uint32_t minor;
	uint32_t abi_major;
	uint32_t abi_minor;
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	gid_t gid;
	uint32_t bits_per_long;
	uint32_t uint8_t_alignment;
	uint32_t uint16_t_alignment;
	uint32_t uint32_t_alignment;
	uint32_t uint64_t_alignment;
	uint32_t long_alignment;
	int byte_order; /* BIG_ENDIAN or LITTLE_ENDIAN */
	char name[LTTNG_UST_ABI_PROCNAME_LEN];
};

/*
 * Global applications HT used by the session daemon. This table is indexed by
 * PID using the pid_n node and pid value of an lttng::sessiond::ust::app.
 */
extern struct lttng_ht *ust_app_ht;

/*
 * Global applications HT used by the session daemon. This table is indexed by
 * socket using the sock_n node and sock value of an lttng::sessiond::ust::app.
 *
 * The 'sock' in question here is the 'command' socket.
 */
extern struct lttng_ht *ust_app_ht_by_sock;

/*
 * Global applications HT used by the session daemon. This table is indexed by
 * socket using the notify_sock_n node and notify_sock value of an lttng::sessiond::ust::app.
 */
extern struct lttng_ht *ust_app_ht_by_notify_sock;

/* Stream list containing lttng::sessiond::ust::app_stream. */
struct ust_app_stream_list {
	unsigned int count;
	struct cds_list_head head;
};

struct ust_app_ctx {
	explicit ust_app_ctx(const lttng::sessiond::config::context_configuration& context_config_) :
		context_config(context_config_)
	{
	}

	~ust_app_ctx() = default;
	ust_app_ctx(const ust_app_ctx&) = delete;
	ust_app_ctx(ust_app_ctx&&) = delete;
	ust_app_ctx& operator=(const ust_app_ctx&) = delete;
	ust_app_ctx& operator=(ust_app_ctx&&) = delete;

	int handle = 0;
	struct lttng_ust_context_attr ctx = {};
	struct lttng_ust_abi_object_data *obj = nullptr;
	struct lttng_ht_node_ulong node = {};
	const lttng::sessiond::config::context_configuration& context_config;
};

struct ust_app_event {
	explicit ust_app_event(
		const lttng::sessiond::config::event_rule_configuration& event_rule_config_) :
		event_rule_config(event_rule_config_)
	{
	}

	~ust_app_event() = default;
	ust_app_event(const ust_app_event&) = delete;
	ust_app_event(ust_app_event&&) = delete;
	ust_app_event& operator=(const ust_app_event&) = delete;
	ust_app_event& operator=(ust_app_event&&) = delete;

	bool enabled = false;
	int handle = 0;
	struct lttng_ust_abi_object_data *obj = nullptr;
	char name[LTTNG_UST_ABI_SYM_NAME_LEN] = {};
	struct lttng_ht_node_str node = {};
	const lttng::sessiond::config::event_rule_configuration& event_rule_config;
};

struct ust_app_event_notifier_rule {
	bool enabled;
	uint64_t error_counter_index;
	int handle;
	struct lttng_ust_abi_object_data *obj;
	/* Holds a strong reference. */
	struct lttng_trigger *trigger;
	/* Unique ID returned by the tracer to identify this event notifier. */
	uint64_t token;
	struct lttng_ht_node_u64 node;
	/* The trigger object owns the filter. */
	const struct lttng_bytecode *filter;
	/* Owned by this. */
	struct lttng_event_exclusion *exclusion;
	/* For delayed reclaim. */
	struct rcu_head rcu_head;
};

struct ust_app_channel {
	explicit ust_app_channel(
		const lttng::sessiond::config::channel_configuration& channel_config_) :
		channel_config(channel_config_)
	{
	}

	~ust_app_channel() = default;
	ust_app_channel(const ust_app_channel&) = delete;
	ust_app_channel(ust_app_channel&&) = delete;
	ust_app_channel& operator=(const ust_app_channel&) = delete;
	ust_app_channel& operator=(ust_app_channel&&) = delete;

	bool enabled = false;
	int handle = 0;
	/*
	 * Unique key used to identify the channel on the consumer side.
	 * 0 is a reserved 'invalid' value used to indicate that the consumer
	 * does not know about this channel (i.e. an error occurred).
	 */
	uint64_t key = 0;
	/*
	 * Opaque handle for trace_class::channel() lookups. Copied from
	 * ltt_ust_channel::trace_class_stream_class_handle during per-app
	 * channel creation.
	 */
	uint64_t trace_class_stream_class_handle = 0;
	/* Number of stream that this channel is expected to receive. */
	unsigned int expected_stream_count = 0;
	char name[LTTNG_UST_ABI_SYM_NAME_LEN] = {};
	struct lttng_ust_abi_object_data *obj = nullptr;
	struct lttng_ust_ctl_consumer_channel_attr attr = {};
	struct ust_app_stream_list streams = {};
	/* Session pointer that owns this object. */
	lttng::sessiond::ust::app_session *session = nullptr;
	/* Hashtable of ust_app_ctx instances. */
	struct lttng_ht *ctx = nullptr;
	/* Hashtable of ust_app_event instances. */
	struct lttng_ht *events = nullptr;
	/*
	 * Node indexed by channel name in the channels' hash table of a session.
	 */
	struct lttng_ht_node_str node = {};
	/*
	 * Node indexed by UST channel object descriptor (handle). Stored in the
	 * ust_objd hash table in the lttng::sessiond::ust::app object.
	 */
	struct lttng_ht_node_ulong ust_objd_node = {};
	/* For delayed reclaim */
	struct rcu_head rcu_head = {};
	/*
	 * Reference to the channel configuration from which this per-app
	 * channel was derived. Points to a recording_channel_configuration
	 * for data channels or a metadata_channel_configuration for the
	 * metadata channel. Use static_cast to the appropriate derived
	 * type as needed.
	 */
	const lttng::sessiond::config::channel_configuration& channel_config;
};

namespace lttng {
namespace sessiond {
namespace ust {

struct app_stream {
	int handle;
	char pathname[PATH_MAX];
	/* Format is %s_%d respectively channel name and CPU number. */
	char name[DEFAULT_STREAM_NAME_LEN];
	::lttng_ust_abi_object_data *obj;
	/* Using a list of streams to keep order. */
	cds_list_head list;
};

struct app_session {
private:
	static void _session_unlock(app_session *session)
	{
		_const_session_unlock(session);
	}

	static void _const_session_unlock(const app_session *session)
	{
		pthread_mutex_unlock(&session->_lock);
	}

public:
	using locked_weak_ref = lttng::non_copyable_reference<
		app_session,
		lttng::memory::create_deleter_class<app_session,
						    app_session::_session_unlock>::deleter>;
	using const_locked_weak_ref = lttng::non_copyable_reference<
		const app_session,
		lttng::memory::create_deleter_class<const app_session,
						    app_session::_const_session_unlock>::deleter>;

	static locked_weak_ref make_locked_weak_ref(app_session& ua_session)
	{
		return lttng::make_non_copyable_reference<locked_weak_ref::referenced_type,
							  locked_weak_ref::deleter>(ua_session);
	}

	static const_locked_weak_ref make_locked_weak_ref(const app_session& ua_session)
	{
		return lttng::make_non_copyable_reference<const_locked_weak_ref::referenced_type,
							  const_locked_weak_ref::deleter>(
			ua_session);
	}

	app_session::const_locked_weak_ref lock() const noexcept
	{
		pthread_mutex_lock(&_lock);
		return app_session::make_locked_weak_ref(*this);
	}

	app_session::locked_weak_ref lock() noexcept
	{
		pthread_mutex_lock(&_lock);
		return app_session::make_locked_weak_ref(*this);
	}

	struct identifier {
		using application_abi = lttng::sessiond::ust::application_abi;
		enum class buffer_allocation_policy : std::uint8_t { PER_PID, PER_UID };

		/* Unique identifier of the app_session. */
		std::uint64_t app_session_id;
		/* Unique identifier of the ltt_session (recording session). */
		std::uint64_t recording_session_id;
		/* Credentials of the application which owns the app_session. */
		lttng_credentials app_credentials;
		application_abi abi;
		buffer_allocation_policy allocation_policy;
	};

	identifier get_identifier() const noexcept
	{
		/*
		 * To work around synchro design issues, this method allows the sampling
		 * of an app_session's identifying properties without taking its lock.
		 *
		 * Since those properties are immutable, it is safe to sample them without
		 * holding the lock (as long as the existence of the instance is somehow
		 * guaranteed).
		 *
		 * The locking issue that motivates this method is that the application
		 * notitication handling thread needs to access the trace_class in response to
		 * a message from the application. The app_session's ID is needed to look-up the
		 * registry session.
		 *
		 * The application's message can be emited in response to a command from the
		 * session daemon that is emited by the client thread.
		 *
		 * During that command, the client thread holds the app_session lock until
		 * the application replies to the command. This causes the notification thread
		 * to block when it attempts to sample the app_session's ID properties.
		 */
		LTTNG_ASSERT(bits_per_long == 32 || bits_per_long == 64);
		LTTNG_ASSERT(buffer_type == LTTNG_BUFFER_PER_PID ||
			     buffer_type == LTTNG_BUFFER_PER_UID);

		return { .app_session_id = app_session_id,
			 .recording_session_id = recording_session_id,
			 .app_credentials = real_credentials,
			 .abi = bits_per_long == 32 ? identifier::application_abi::ABI_32 :
						      identifier::application_abi::ABI_64,
			 .allocation_policy = buffer_type == LTTNG_BUFFER_PER_PID ?
				 identifier::buffer_allocation_policy::PER_PID :
				 identifier::buffer_allocation_policy::PER_UID };
	}

	bool enabled = false;
	/* started: has the session been in started state at any time ? */
	bool started = false; /* allows detection of start vs restart. */
	int handle = 0; /* used has unique identifier for app session */

	bool deleted = false; /* Session deleted flag. Check with lock held. */

	/*
	 * Recording session ID (ltt_session::id). Multiple app_sessions
	 * can share the same recording_session_id since each application
	 * gets its own app_session for the same recording session.
	 */
	uint64_t recording_session_id = 0;
	/* Unique app_session identifier, allocated by sessiond. */
	uint64_t app_session_id = 0;
	::lttng_ht *channels = nullptr; /* Registered channels */
	lttng_ht_node_u64 node = {};
	/*
	 * Node indexed by UST session object descriptor (handle). Stored in the
	 * ust_sessions_objd hash table in the app object.
	 */
	lttng_ht_node_ulong ust_objd_node = {};
	/* Starts with 'ust'; no leading slash. */
	char path[PATH_MAX] = {};
	/* UID/GID of the application owning the session */
	lttng_credentials real_credentials = {};
	/* Effective UID and GID. Same as the tracing session. */
	lttng_credentials effective_credentials = {};
	/*
	 * Once at least *one* session is created onto the application, the
	 * corresponding consumer is set so we can use it on unregistration.
	 */
	::consumer_output *consumer = nullptr;
	enum lttng_buffer_type buffer_type = LTTNG_BUFFER_PER_PID;
	/* ABI of the session. Same value as the application. */
	uint32_t bits_per_long = 0;
	/* For delayed reclaim */
	::rcu_head rcu_head = {};
	/* If the channel's streams have to be outputed or not. */
	unsigned int output_traces = 0;
	unsigned int live_timer_interval = 0; /* usec */

	/* Metadata channel attributes. */
	lttng_ust_ctl_consumer_channel_attr metadata_attr = {};

	char root_shm_path[PATH_MAX] = {};
	char shm_path[PATH_MAX] = {};

private:
	/*
	 * Lock protecting this session's ust app interaction. Held
	 * across command send/recv to/from app. Never nests within the
	 * session registry lock.
	 */
	mutable pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;
};

/*
 * Registered traceable applications. Libust registers to the session daemon
 * and a linked list is kept of all running traceable app.
 */
struct app {
	/*
	 * The lifetime of 'sock' holds a reference to the application; the
	 * application management thread will release a reference to the
	 * application if the application dies.
	 */
	urcu_ref ref = {};

	/* Traffic initiated from the session daemon to the application. */
	int sock = -1;
	pthread_mutex_t sock_lock = {}; /* Protects sock protocol. */

	/* Traffic initiated from the application to the session daemon. */
	int notify_sock = static_cast<int>(-1);
	pid_t pid = static_cast<pid_t>(-1);
	pid_t ppid = static_cast<pid_t>(-1);
	uid_t uid = static_cast<uid_t>(-1); /* User ID that owns the apps */
	gid_t gid = static_cast<gid_t>(-1); /* Group ID that owns the apps */

	/* App ABI. */
	lttng::sessiond::trace::abi abi = {};

	int compatible = 0; /* If the lttng-ust tracer version does not match the
					   supported version of the session daemon, this flag is
					   set to 0 (NOT compatible) else 1. */
	lttng_ust_abi_tracer_version version = {};
	uint32_t v_major = static_cast<uint32_t>(-1); /* Version major number */
	uint32_t v_minor = static_cast<uint32_t>(-1); /* Version minor number */
	/* Extra for the NULL byte. */
	char name[UST_APP_PROCNAME_LEN + 1] = {};

	::lttng_ht *sessions = nullptr;
	lttng_ht_node_ulong pid_n = {};
	lttng_ht_node_ulong sock_n = {};
	lttng_ht_node_ulong notify_sock_n = {};
	lttng_ht_node_u64 owner_id_n = {};
	/*
	 * This is a list of ust app session that, once the app is going into
	 * teardown mode, in the RCU call, each node in this list is removed and
	 * deleted.
	 *
	 * Element of the list are added when an application unregisters after each
	 * ht_del of app_session associated to this app. This list is NOT used
	 * when a session is destroyed.
	 */
	std::list<app_session *> sessions_to_teardown;
	/*
	 * Hash table containing ust_app_channel indexed by channel objd.
	 */
	::lttng_ht *ust_objd = nullptr;
	/*
	 * Hash table containing app_session indexed by objd.
	 */
	::lttng_ht *ust_sessions_objd = nullptr;

	/*
	 * If this application is of the agent domain and this is non negative then
	 * a lookup MUST be done to acquire a read side reference to the
	 * corresponding agent app object. If the lookup fails, this should be set
	 * to a negative value indicating that the agent application is gone.
	 */
	int agent_app_sock = static_cast<int>(-1);
	/*
	 * Time at which the app is registred.
	 * Used for path creation
	 */
	time_t registration_time = static_cast<time_t>(-1);
	/*
	 * Event notifier
	 */
	struct {
		/*
		 * Handle to the lttng_ust object representing the event
		 * notifier group.
		 */
		::lttng_ust_abi_object_data *object = nullptr;
		::lttng_pipe *event_pipe = nullptr;
		::lttng_ust_abi_object_data *counter = nullptr;
		::lttng_ust_abi_object_data **counter_cpu = nullptr;
		int nr_counter_cpu = 0;
	} event_notifier_group;
	/*
	 * Hashtable indexing the application's event notifier rule's
	 * (ust_app_event_notifier_rule) by their token's value.
	 */
	::lttng_ht *token_to_event_notifier_rule_ht = nullptr;

	lttng::sessiond::ust::ctl_field_quirks ctl_field_quirks() const;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::ust::app> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(const lttng::sessiond::ust::app& app,
						    FormatContextType& ctx) const
	{
		return format_to(
			ctx.out(),
			"{{ procname = `{}`, ppid = {}, pid = {}, uid = {}, gid = {}, version = {}.{}, registration time = {} }}",
			app.name,
			app.ppid,
			app.pid,
			app.uid,
			app.gid,
			app.v_major,
			app.v_minor,
			lttng::utils::time_to_iso8601_str(app.registration_time));
	}
};
} /* namespace fmt */

#ifdef HAVE_LIBLTTNG_UST_CTL

int ust_app_register(struct ust_register_msg *msg, int sock);
int ust_app_register_done(lttng::sessiond::ust::app *app);
int ust_app_version(lttng::sessiond::ust::app *app);
void ust_app_unregister_by_socket(int sock);
int ust_app_destroy_trace_all(std::uint64_t session_id);
int ust_app_list_events(struct lttng_event **events);
int ust_app_list_event_fields(struct lttng_event_field **fields);
void ust_app_global_update_event_notifier_rules(lttng::sessiond::ust::app *app);
void ust_app_global_update_all_event_notifier_rules();

void ust_app_clean_list();
int ust_app_ht_alloc();

bool ust_app_get(lttng::sessiond::ust::app& app);
void ust_app_put(lttng::sessiond::ust::app *app);
void ust_app_unregister_and_destroy(lttng::sessiond::ust::app& app);
using ust_app_reference = std::unique_ptr<
	lttng::sessiond::ust::app,
	lttng::memory::create_deleter_class<lttng::sessiond::ust::app, ust_app_put>::deleter>;

nonstd::optional<ust_app_reference> ust_app_find_by_pid(pid_t pid);
lttng::sessiond::ust::app_stream *ust_app_alloc_stream();
int ust_app_recv_registration(int sock, struct ust_register_msg *msg);
int ust_app_recv_notify(int sock);
void ust_app_add(lttng::sessiond::ust::app *app);
lttng::sessiond::ust::app *ust_app_create(struct ust_register_msg *msg, int sock);
void ust_app_notify_sock_unregister(int sock);
nonstd::optional<ust_app_reference> ust_app_find_by_sock(int sock);
int ust_app_regenerate_statedump_all(std::uint64_t session_id);
int ust_app_release_object(lttng::sessiond::ust::app *app, struct lttng_ust_abi_object_data *data);

int ust_app_setup_event_notifier_group(lttng::sessiond::ust::app *app);

static inline int ust_app_supported()
{
	return 1;
}

lttng::sessiond::ust::app_session *ust_app_lookup_app_session(std::uint64_t session_id,
							      const lttng::sessiond::ust::app *app);
std::shared_ptr<lttng::sessiond::ust::trace_class>
ust_app_get_session_registry(const lttng::sessiond::ust::app_session::identifier& identifier);

lttng_ht *ust_app_get_all();

bool ust_app_supports_notifiers(const lttng::sessiond::ust::app *app);
bool ust_app_supports_counters(const lttng::sessiond::ust::app *app);

void ust_app_notify_reclaimed_owner_ids(const std::vector<uint32_t>& owners);

/*
 * Low-level channel helpers that remain in ust-app.cpp. They perform
 * I/O with applications and consumer daemons but do not access
 * orchestrator state. Exposed so the orchestrator's channel sync
 * methods can call them.
 */
struct ust_app_channel *
alloc_ust_app_channel(const char *name,
		      const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
		      struct lttng_ust_abi_channel_attr *attr,
		      const lttng::sessiond::config::recording_channel_configuration& config);
void init_ust_app_channel_from_config(struct ust_app_channel *ua_chan);
enum lttng_ust_abi_chan_type allocation_policy_to_ust_channel_type(
	lttng::sessiond::config::recording_channel_configuration::buffer_allocation_policy_t policy);
lttng::sessiond::config::recording_channel_configuration::buffer_allocation_policy_t
ust_channel_type_to_allocation_policy(enum lttng_ust_abi_chan_type type);
int do_consumer_create_channel(struct consumer_output *consumer,
			       lttng::sessiond::ust::app_session *ua_sess,
			       struct ust_app_channel *ua_chan,
			       int bitness,
			       lttng::sessiond::ust::trace_class *registry,
			       struct lttng_trace_chunk *current_trace_chunk,
			       enum lttng_trace_format trace_format);
int send_channel_pid_to_ust(lttng::sessiond::ust::app *app,
			    lttng::sessiond::ust::app_session *ua_sess,
			    struct ust_app_channel *ua_chan);
bool is_context_redundant(
	const lttng::sessiond::config::recording_channel_configuration& chan_config,
	const lttng::sessiond::config::context_configuration& ctx_config);
int enable_ust_channel(lttng::sessiond::ust::app *app,
		       const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
		       struct ust_app_channel *ua_chan);
int disable_ust_channel(lttng::sessiond::ust::app *app,
			const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
			struct ust_app_channel *ua_chan);
struct ust_app_channel *alloc_ust_app_metadata_channel(
	const char *name,
	const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
	const lttng::sessiond::config::metadata_channel_configuration& metadata_config);

/*
 * Per-app helpers shared between ust-app.cpp and the domain orchestrator.
 * These are low-level functions that operate on a single app session and
 * its channel/event structures. The orchestrator iterates its app session
 * index and calls these for each app.
 */
int enable_ust_app_channel(const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
			   lttng::c_string_view channel_name,
			   lttng::sessiond::ust::app *app);
int disable_ust_app_channel(const lttng::sessiond::ust::app_session::locked_weak_ref& ua_sess,
			    struct ust_app_channel *ua_chan,
			    lttng::sessiond::ust::app *app);
int enable_ust_app_event(struct ust_app_event *ua_event, lttng::sessiond::ust::app *app);
int disable_ust_app_event(struct ust_app_event *ua_event, lttng::sessiond::ust::app *app);
int create_ust_app_event(struct ust_app_channel *ua_chan,
			 lttng::sessiond::ust::app *app,
			 const lttng::sessiond::config::event_rule_configuration& event_config);
int create_ust_app_channel_context(struct ust_app_channel *ua_chan,
				   struct lttng_ust_context_attr *uctx,
				   lttng::sessiond::ust::app *app,
				   const lttng::sessiond::config::context_configuration& ctx_config);
struct ust_app_event *
find_ust_app_event_by_config(struct lttng_ht *ht,
			     const lttng::sessiond::config::event_rule_configuration& event_config);

/*
 * Disable an event on all applications tracked by the orchestrator.
 * Used by the agent event disable path (event.cpp) which does not have
 * direct access to the orchestrator's private iteration method.
 */
int ust_app_disable_event_on_apps(
	lttng::sessiond::ust::domain_orchestrator& orchestrator,
	lttng::c_string_view channel_name,
	const lttng::sessiond::config::event_rule_configuration& event_rule_config);

/*
 * App session allocation and deletion helpers. These remain in
 * ust-app.cpp as they manage app-level data structures (hash tables,
 * RCU callbacks, UST handle release). Exposed for the orchestrator's
 * _find_or_create_app_session() method.
 */
lttng::sessiond::ust::app_session *alloc_ust_app_session();
void delete_ust_app_session(int sock,
			    lttng::sessiond::ust::app_session *ua_sess,
			    lttng::sessiond::ust::app *app);
std::uint64_t get_next_session_id();

/*
 * Per-app trace control and synchronization helpers used by the
 * orchestrator. These remain in ust-app.cpp because they contain
 * app-level logic (lttng_ust_ctl calls, channel/metadata creation)
 * that has not yet been internalized.
 */
void ust_app_global_destroy(std::uint64_t session_id, lttng::sessiond::ust::app *app);

#else /* HAVE_LIBLTTNG_UST_CTL */

static inline int ust_app_destroy_trace_all(std::uint64_t /* session_id */)
{
	return 0;
}

static inline int ust_app_list_events(struct lttng_event **events __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int ust_app_list_event_fields(struct lttng_event_field **fields
					    __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int ust_app_register(struct ust_register_msg *msg __attribute__((unused)),
				   int sock __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int ust_app_register_done(lttng::sessiond::ust::app *app __attribute__((unused)))
{
	return -ENOSYS;
}

static inline int ust_app_version(lttng::sessiond::ust::app *app __attribute__((unused)))
{
	return -ENOSYS;
}

static inline void ust_app_unregister_by_socket(int sock __attribute__((unused)))
{
}

static inline void ust_app_clean_list(void)
{
}

static inline struct ust_app_list *ust_app_get_list(void)
{
	return NULL;
}

static inline lttng::sessiond::ust::app *ust_app_get_by_pid(pid_t pid __attribute__((unused)))
{
	return NULL;
}

static inline int ust_app_ht_alloc(void)
{
	return 0;
}

static inline void ust_app_global_update_event_notifier_rules(lttng::sessiond::ust::app *app
							      __attribute__((unused)))
{
}

static inline void ust_app_global_update_all_event_notifier_rules(void)
{
}

static inline int ust_app_setup_event_notifier_group(lttng::sessiond::ust::app *app
						     __attribute__((unused)))
{
	return 0;
}

static inline int ust_app_recv_registration(int sock __attribute__((unused)),
					    struct ust_register_msg *msg __attribute__((unused)))
{
	return 0;
}

static inline int ust_app_recv_notify(int sock __attribute__((unused)))
{
	return 0;
}

static inline lttng::sessiond::ust::app *ust_app_create(struct ust_register_msg *msg
							__attribute__((unused)),
							int sock __attribute__((unused)))
{
	return NULL;
}

static inline void ust_app_add(lttng::sessiond::ust::app *app __attribute__((unused)))
{
}

static inline void ust_app_notify_sock_unregister(int sock __attribute__((unused)))
{
}

static inline void ust_app_update_event_notifier_error_count(struct lttng_trigger *lttng_trigger
							     __attribute__((unused)))
{
	return;
}

static inline int ust_app_supported(void)
{
	return 0;
}

static inline bool ust_app_supports_notifiers(const lttng::sessiond::ust::app *app
					      __attribute__((unused)))
{
	return false;
}

static inline bool ust_app_supports_counters(const lttng::sessiond::ust::app *app
					     __attribute__((unused)))
{
	return false;
}

inline bool ust_app_get(lttng::sessiond::ust::app& app __attribute__((unused)))
{
	return false;
}

inline void ust_app_put(lttng::sessiond::ust::app *app __attribute__((unused)))
{
}

using ust_app_reference = std::unique_ptr<
	lttng::sessiond::ust::app,
	lttng::memory::create_deleter_class<lttng::sessiond::ust::app, ust_app_put>::deleter>;

static inline nonstd::optional<ust_app_reference> ust_app_find_by_sock(int sock
								       __attribute__((unused)))
{
	return nonstd::nullopt;
}

static inline nonstd::optional<ust_app_reference> ust_app_find_by_pid(pid_t pid
								      __attribute__((unused)))
{
	return nonstd::nullopt;
}

static inline int ust_app_regenerate_statedump_all(std::uint64_t /* session_id */)
{
	return 0;
}

static inline lttng::sessiond::ust::app_session *
ust_app_lookup_app_session(std::uint64_t, const lttng::sessiond::ust::app *)
{
	return nullptr;
}

static inline std::shared_ptr<lttng::sessiond::ust::trace_class>
ust_app_get_session_registry(const lttng::sessiond::ust::app_session::identifier&)
{
	return nullptr;
}

static inline lttng_ht *ust_app_get_all()
{
	return nullptr;
}

static inline int ust_app_release_object(lttng::sessiond::ust::app *app __attribute__((unused)),
					 struct lttng_ust_abi_object_data *data
					 __attribute__((unused)))
{
	return 0;
}

static inline void ust_app_notify_reclaimed_owner_ids(const std::vector<uint32_t>& owners
						      __attribute__((unused)))
{
}

static inline void ust_app_unregister_and_destroy(lttng::sessiond::ust::app& app
						  __attribute__((unused)))
{
}

static inline int ust_app_disable_event_on_apps(
	lttng::sessiond::ust::domain_orchestrator& /* orchestrator */,
	lttng::c_string_view /* channel_name */,
	const lttng::sessiond::config::event_rule_configuration& /* event_rule_config */)
{
	return 0;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

#endif /* _LTT_UST_APP_H */
