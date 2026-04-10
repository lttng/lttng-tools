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
#include "ust-app-ctx.hpp"
#include "ust-app-event.hpp"
#include "ust-app-session.hpp"
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
#include <unordered_map>
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
class domain_orchestrator;
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

namespace lttng {
namespace sessiond {
namespace ust {

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

lttng_ht *ust_app_get_all();

bool ust_app_supports_notifiers(const lttng::sessiond::ust::app *app);
bool ust_app_supports_counters(const lttng::sessiond::ust::app *app);

void ust_app_notify_reclaimed_owner_ids(const std::vector<uint32_t>& owners);

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
