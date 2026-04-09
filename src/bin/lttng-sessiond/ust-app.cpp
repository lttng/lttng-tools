/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "event-notifier-error-accounting.hpp"
#include "event.hpp"
#include "fd-limit.hpp"
#include "field.hpp"
#include "health-sessiond.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "manage-apps.hpp"
#include "notification-thread-commands.hpp"
#include "session.hpp"
#include "ust-app-channel-helpers.hpp"
#include "ust-app.hpp"
#include "ust-consumer.hpp"
#include "ust-domain-orchestrator.hpp"
#include "ust-field-quirks.hpp"
#include "ust-trace-class-index.hpp"
#include "utils.hpp"

#include <common/bytecode/bytecode.hpp>
#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/hashtable/utils.hpp>
#include <common/make-unique.hpp>
#include <common/pthread-lock.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/urcu.hpp>

#include <lttng/condition/condition.h>
#include <lttng/condition/event-rule-matches-internal.hpp>
#include <lttng/condition/event-rule-matches.h>
#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/user-tracepoint.h>
#include <lttng/trigger/trigger-internal.hpp>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mutex>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <urcu/compiler.h>
#include <vector>

namespace lsu = lttng::sessiond::ust;
namespace lst = lttng::sessiond::trace;
namespace lsc = lttng::sessiond::config;

/*
 * Bridge struct granting transitional access to the orchestrator's
 * private trace class, stream group, and statistics methods.
 *
 * This struct is declared as a friend of domain_orchestrator. It
 * exists solely so that static functions in this file (which cannot
 * be friended directly due to internal linkage) can continue to call
 * orchestrator methods that were moved from public to private.
 *
 * Each forwarding method here will be removed as the corresponding
 * caller is internalized into the orchestrator (Phases 1-4).
 */
struct ust_app_session_operations {
	static void
	accumulate_per_pid_closed_app_stats(lsu::domain_orchestrator& o,
					    const lsc::recording_channel_configuration& chan_config,
					    std::uint64_t discarded_events,
					    std::uint64_t lost_packets)
	{
		o.accumulate_per_pid_closed_app_stats(chan_config, discarded_events, lost_packets);
	}

	static int disable_event_on_apps(lsu::domain_orchestrator& o,
					 lttng::c_string_view channel_name,
					 const lsc::event_rule_configuration& event_rule_config)
	{
		return o._disable_event_on_apps(channel_name, event_rule_config);
	}
};

enum owner_id_allocation_status {
	OWNER_ID_ALLOCATION_STATUS_OK,
	OWNER_ID_ALLOCATION_STATUS_FAIL,
};

struct lttng_ht *ust_app_ht;
struct lttng_ht *ust_app_ht_by_sock;
struct lttng_ht *ust_app_ht_by_notify_sock;
struct lttng_ht *ust_app_ht_by_owner_id;

static int ust_app_flush_app_session(lsu::app& app, lsu::app_session& ua_sess);

/* Next available channel key. Access under next_channel_key_lock. */
static uint64_t _next_channel_key;
static pthread_mutex_t next_channel_key_lock = PTHREAD_MUTEX_INITIALIZER;

/* Next available session ID. Access under next_session_id_lock. */
static uint64_t _next_session_id;
static pthread_mutex_t next_session_id_lock = PTHREAD_MUTEX_INITIALIZER;

lttng::sessiond::config::recording_channel_configuration::buffer_allocation_policy_t
ust_channel_type_to_allocation_policy(enum lttng_ust_abi_chan_type type)
{
	switch (type) {
	case LTTNG_UST_ABI_CHAN_PER_CPU:
		return lttng::sessiond::config::recording_channel_configuration::
			buffer_allocation_policy_t::PER_CPU;
	case LTTNG_UST_ABI_CHAN_METADATA:
		/* fall-through  */
	case LTTNG_UST_ABI_CHAN_PER_CHANNEL:
		return lttng::sessiond::config::recording_channel_configuration::
			buffer_allocation_policy_t::PER_CHANNEL;
	default:
		abort();
	}
}

enum lttng_ust_abi_chan_type allocation_policy_to_ust_channel_type(
	lttng::sessiond::config::recording_channel_configuration::buffer_allocation_policy_t policy)
{
	namespace lsc = lttng::sessiond::config;

	switch (policy) {
	case lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CPU:
		return LTTNG_UST_ABI_CHAN_PER_CPU;
	case lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CHANNEL:
		return LTTNG_UST_ABI_CHAN_PER_CHANNEL;
	default:
		abort();
	}
}

/*
 * Return the session registry according to the buffer type of the given
 * session.
 *
 * A registry per UID object MUST exists before calling this function or else
 * it LTTNG_ASSERT() if not found. RCU read side lock must be acquired.
 */
std::shared_ptr<lsu::trace_class>
ust_app_get_session_registry(const lsu::app_session::identifier& ua_sess_id)
{
	switch (ua_sess_id.allocation_policy) {
	case lsu::app_session::identifier::buffer_allocation_policy::PER_PID:
		return the_trace_class_index->find_per_pid(ua_sess_id.app_session_id);
	case lsu::app_session::identifier::buffer_allocation_policy::PER_UID:
	{
		const std::uint32_t bits_per_long = ua_sess_id.abi ==
				lsu::app_session::identifier::application_abi::ABI_32 ?
			32 :
			64;

		return the_trace_class_index->find_per_uid(
			ua_sess_id.recording_session_id,
			bits_per_long,
			lttng_credentials_get_uid(&ua_sess_id.app_credentials));
	}
	default:
		abort();
	};
}

namespace {
/*
 * Bundles a shared_ptr (ownership) with a locked_ref (lock) so that
 * the trace_class cannot be destroyed while the lock is held.
 *
 * Callers that need a `const locked_ref&` (e.g. push_metadata) should
 * use the locked_ref() accessor.
 */
struct owned_locked_registry {
	std::shared_ptr<lsu::trace_class> _ownership;
	lsu::trace_class::locked_ref _lock;

	explicit operator bool() const noexcept
	{
		return _ownership != nullptr;
	}

	lsu::trace_class *operator->() const noexcept
	{
		return _ownership.get();
	}

	lsu::trace_class& operator*() const noexcept
	{
		return *_ownership;
	}

	lsu::trace_class::locked_ref& locked_ref() noexcept
	{
		return _lock;
	}

	const lsu::trace_class::locked_ref& locked_ref() const noexcept
	{
		return _lock;
	}

	void reset() noexcept
	{
		_lock.reset();
		_ownership.reset();
	}
};

owned_locked_registry get_locked_session_registry(const lsu::app_session::identifier& identifier)
{
	auto session = ust_app_get_session_registry(identifier);
	lsu::trace_class::locked_ref lock;

	if (session) {
		pthread_mutex_lock(&session->_lock);
		lock = lsu::trace_class::locked_ref{ session.get() };
	}

	return { std::move(session), std::move(lock) };
}
} /* namespace */

/*
 * An owner-id is spawned into existance if it is:
 *
 *  - not reserved by the UST ABI
 *
 *  - not currently used
 *
 *  - not pending for reclamation
 *
 *  Once a owner-id is created, it can not be used again until it is
 *  reclaimed. The reclamation process works by storing the owner-id in a
 *  reclamation table with a reference count equal to the number of channels
 *  used by the user application that has this owner-id. Channels independently
 *  check their stream's sub-buffers and notify the sessiond about the owner IDs
 *  that can be reclaimed, thus decrementing the reference count in the
 *  reclamation table. Once that refence count is zero, the owner-id is removed
 *  from the reclamation table and can thus be used again.
 */
class pending_owner_id_reclamations {
public:
	/*
	 * Mark `owner_id` for reclamation with `ref_count` left.
	 *
	 * `ref_count` represents the number of channels that were used by the
	 * application. Each channel will eventually reply an acknowledge (see
	 * `unmark_owner_id()`).
	 */
	void mark_owner_id(uint32_t owner_id, uint64_t ref_count)
	{
		std::lock_guard<std::mutex> lock(_pending_owner_ids_mutex);
		_pending_owner_ids[owner_id] = ref_count;
	}

	/*
	 * Decrement the reference count of `owner_id` in the pending
	 * table. When the reference count hits zero, `owner_id` is removed from
	 * table.
	 */
	void unmark_owner_id(uint32_t owner_id)
	{
		std::lock_guard<std::mutex> lock(_pending_owner_ids_mutex);
		const auto it = _pending_owner_ids.find(owner_id);

		if (it == _pending_owner_ids.end()) {
			ERR_FMT("Unmarking from garbage owner-id={} "
				"but not present in garbage",
				owner_id);
			return;
		}

		if (it->second == 1) {
			_pending_owner_ids.erase(it);
		} else {
			it->second -= 1;
		}
	}

	bool is_owner_id_pending_reclamation(uint32_t owner_id)
	{
		std::lock_guard<std::mutex> lock(_pending_owner_ids_mutex);
		return _pending_owner_ids.count(owner_id) != 0;
	}

private:
	std::unordered_map<uint32_t, uint64_t> _pending_owner_ids;

	/* Protect accesses of `_pending_owner_ids`. */
	std::mutex _pending_owner_ids_mutex;
};

static pending_owner_id_reclamations owner_id_reclamations;

/*
 * Return true if `owner_id` can be used for a new owner.
 */
static bool is_legal_owner_id(uint32_t owner_id)
{
	/*
	 * LTTng-UST's ABI defines two values that can never be used by
	 * applications.
	 *
	 * The UNSET value denotes the absence of owner.
	 *
	 * The CONSUMER value is used by the consumer-daemons to take ownership
	 * of sub-buffers in streams. e.g., when doing a stalled sub-buffer
	 * fixup or when flushing a stream.
	 *
	 * All other values are valid if not in the garbage table.
	 */
	switch (owner_id) {
	case LTTNG_UST_ABI_OWNER_ID_UNSET:
		/* fall-through */
	case LTTNG_UST_ABI_OWNER_ID_CONSUMER:
		return false;
	}

	return !owner_id_reclamations.is_owner_id_pending_reclamation(owner_id);
}

/*
 * Allocate the owner id for `app`.
 *
 * For guaranteeing forward progress, there is a maximum of UINT32_MAX attempts,
 * which is enough to scan the whole possible value for a owner id.
 */
static enum owner_id_allocation_status ust_app_allocate_owner_id(lsu::app& app)
{
	uint64_t attempt_count = 0;

	while (true) {
		/*
		 * Although the owner-id node of `app` and the global owner-id
		 * table are using unsigned 64-bit values as keys, the owner-id
		 * must be encoded on 32-bit for supporting 32-bit
		 * applications. This is because the application's producers
		 * will do atomic operations with their owner-id.
		 */
		static uint32_t next_owner_id;

		/*
		 * Use atomic builtins instead of std::atomic for old toolchains
		 * support.
		 *
		 * Mainly:
		 *
		 *   GCC 4 and older.
		 *   Clang 5 and older.
		 */
		const uint32_t new_id = __atomic_fetch_add(&next_owner_id, 1, __ATOMIC_RELAXED);

		if (caa_unlikely(!is_legal_owner_id(new_id))) {
			continue;
		}

		/*
		 * Try to take the ownership by storing the application owner-id
		 * node into the global owner-id table.
		 */
		lttng_ht_node_init_u64(&app.owner_id_n, new_id);
		if (lttng_ht_add_unique_u64_or_fail(ust_app_ht_by_owner_id, &app.owner_id_n)) {
			break;
		}

		if (++attempt_count == UINT32_MAX) {
			/*
			 * Wrapped-around looking for an available owner
			 * identity. This is extremely unlikely, but this check
			 * allows me to sleep at night.
			 */
			ERR("Wrapped around while attempting to allocate an owner identity");
			lttng_ht_node_init_u64(&app.owner_id_n, LTTNG_UST_ABI_OWNER_ID_UNSET);
			return OWNER_ID_ALLOCATION_STATUS_FAIL;
		}

		/* Owner identity already in use, retry allocation. */
	}

	return OWNER_ID_ALLOCATION_STATUS_OK;
}

/*
 * Release the owner-id of `app`. This only removes the ID from the global
 * owner-id table, but the ID could still be in the garbage table and not usable
 * yet.
 */
static void ust_app_release_owner_id(lsu::app& app)
{
	cds_lfht_del(ust_app_ht_by_owner_id->ht, &app.owner_id_n.node);
}

/*
 * Return the incremented value of next_channel_key.
 */
static uint64_t get_next_channel_key()
{
	uint64_t ret;

	pthread_mutex_lock(&next_channel_key_lock);
	ret = ++_next_channel_key;
	pthread_mutex_unlock(&next_channel_key_lock);
	return ret;
}

/*
 * Return the atomically incremented value of next_session_id.
 */
uint64_t get_next_session_id()
{
	uint64_t ret;

	pthread_mutex_lock(&next_session_id_lock);
	ret = ++_next_session_id;
	pthread_mutex_unlock(&next_session_id_lock);
	return ret;
}

/*
 * Match function for the hash table lookup.
 *
 * It matches an ust app event based on three attributes which are the event
 * name, the filter bytecode and the loglevel.
 */
/*
 * Match function for ust_app_event in the per-channel event hash table.
 * Events are uniquely identified by their event_rule_configuration pointer.
 */
static int ht_match_ust_app_event(struct cds_lfht_node *node, const void *_key)
{
	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	const auto *event = lttng_ht_node_container_of(node, &ust_app_event::node);
	const auto *key =
		static_cast<const lttng::sessiond::config::event_rule_configuration *>(_key);

	return &event->event_rule_config == key ? 1 : 0;
}

/*
 * Unique add of an ust app event in the given ht. This uses the custom
 * ht_match_ust_app_event match function and the event name as hash.
 */
static void add_unique_ust_app_event(struct ust_app_channel *ua_chan, struct ust_app_event *event)
{
	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(ua_chan->events);
	LTTNG_ASSERT(event);

	auto *ht = ua_chan->events;
	const auto *key = &event->event_rule_config;

	auto *node_ptr = cds_lfht_add_unique(ht->ht,
					     ht->hash_fct(event->node.key, lttng_ht_seed),
					     ht_match_ust_app_event,
					     key,
					     &event->node.node);
	LTTNG_ASSERT(node_ptr == &event->node.node);
}

/*
 * Close the notify socket from the given RCU head object. This MUST be called
 * through a call_rcu().
 */
static void close_notify_sock_rcu(struct rcu_head *head)
{
	int ret;
	struct ust_app_notify_sock_obj *obj =
		lttng::utils::container_of(head, &ust_app_notify_sock_obj::head);

	/* Must have a valid fd here. */
	LTTNG_ASSERT(obj->fd >= 0);

	ret = close(obj->fd);
	if (ret) {
		ERR("close notify sock %d RCU", obj->fd);
	}
	lttng_fd_put(LTTNG_FD_APPS, 1);

	free(obj);
}

/*
 * Delete ust context safely. RCU read lock must be held before calling
 * this function.
 */
static void delete_ust_app_ctx(int sock, struct ust_app_ctx *ua_ctx, lsu::app *app)
{
	int ret;

	LTTNG_ASSERT(ua_ctx);
	ASSERT_RCU_READ_LOCKED();

	if (ua_ctx->obj) {
		pthread_mutex_lock(&app->sock_lock);
		ret = lttng_ust_ctl_release_object(sock, ua_ctx->obj);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release ctx failed. Application is dead: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app release ctx failed. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else {
				ERR("UST app release ctx obj handle %d failed with ret %d: pid = %d, sock = %d",
				    ua_ctx->obj->header.handle,
				    ret,
				    app->pid,
				    app->sock);
			}
		}
		free(ua_ctx->obj);
	}

	if (ua_ctx->ctx.ctx == LTTNG_UST_ABI_CONTEXT_APP_CONTEXT) {
		free(ua_ctx->ctx.u.app_ctx.provider_name);
		free(ua_ctx->ctx.u.app_ctx.ctx_name);
	}

	delete ua_ctx;
}

/*
 * Delete ust app event safely. RCU read lock must be held before calling
 * this function.
 */
static void delete_ust_app_event(int sock, struct ust_app_event *ua_event, lsu::app *app)
{
	int ret;

	LTTNG_ASSERT(ua_event);
	ASSERT_RCU_READ_LOCKED();

	if (ua_event->obj != nullptr) {
		pthread_mutex_lock(&app->sock_lock);
		ret = lttng_ust_ctl_release_object(sock, ua_event->obj);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release event failed. Application is dead: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app release event failed. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else {
				ERR("UST app release event obj failed with ret %d: pid = %d, sock = %d",
				    ret,
				    app->pid,
				    app->sock);
			}
		}
		free(ua_event->obj);
	}
	delete ua_event;
}

/*
 * Delayed reclaim of a ust_app_event_notifier_rule object. This MUST be called
 * through a call_rcu().
 */
static void free_ust_app_event_notifier_rule_rcu(struct rcu_head *head)
{
	struct ust_app_event_notifier_rule *obj =
		lttng::utils::container_of(head, &ust_app_event_notifier_rule::rcu_head);

	free(obj);
}

/*
 * Delete ust app event notifier rule safely.
 */
static void delete_ust_app_event_notifier_rule(
	int sock, struct ust_app_event_notifier_rule *ua_event_notifier_rule, lsu::app *app)
{
	int ret;

	LTTNG_ASSERT(ua_event_notifier_rule);

	if (ua_event_notifier_rule->exclusion != nullptr) {
		free(ua_event_notifier_rule->exclusion);
	}

	if (ua_event_notifier_rule->obj != nullptr) {
		pthread_mutex_lock(&app->sock_lock);
		ret = lttng_ust_ctl_release_object(sock, ua_event_notifier_rule->obj);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release event notifier failed. Application is dead: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app release event notifier failed. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else {
				ERR("UST app release event notifier failed with ret %d: pid = %d, sock = %d",
				    ret,
				    app->pid,
				    app->sock);
			}
		}

		free(ua_event_notifier_rule->obj);
	}

	lttng_trigger_put(ua_event_notifier_rule->trigger);
	call_rcu(&ua_event_notifier_rule->rcu_head, free_ust_app_event_notifier_rule_rcu);
}

/*
 * Release ust data object of the given stream.
 *
 * Return 0 on success or else a negative value.
 */
static int release_ust_app_stream(int sock, lsu::app_stream *stream, lsu::app *app)
{
	int ret = 0;

	LTTNG_ASSERT(stream);

	if (stream->obj) {
		pthread_mutex_lock(&app->sock_lock);
		ret = lttng_ust_ctl_release_object(sock, stream->obj);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release stream failed. Application is dead: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app release stream failed. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else {
				ERR("UST app release stream obj failed with ret %d: pid = %d, sock = %d",
				    ret,
				    app->pid,
				    app->sock);
			}
		}
		lttng_fd_put(LTTNG_FD_APPS, 2);
		free(stream->obj);
	}

	return ret;
}

/*
 * Delete ust app stream safely. RCU read lock must be held before calling
 * this function.
 */
static void delete_ust_app_stream(int sock, lsu::app_stream *stream, lsu::app *app)
{
	LTTNG_ASSERT(stream);
	ASSERT_RCU_READ_LOCKED();

	(void) release_ust_app_stream(sock, stream, app);
	free(stream);
}

static void delete_ust_app_channel_rcu(struct rcu_head *head)
{
	struct ust_app_channel *ua_chan =
		lttng::utils::container_of(head, &ust_app_channel::rcu_head);

	lttng_ht_destroy(ua_chan->ctx);
	lttng_ht_destroy(ua_chan->events);
	delete ua_chan;
}

/*
 * Extract the lost packet or discarded events counter when a per-PID
 * channel is being deleted and accumulate the values in the UST domain
 * orchestrator so they can be included in runtime statistics after the
 * application has exited.
 *
 * The session list lock must be held by the caller.
 */
static void save_per_pid_lost_discarded_counters(struct ust_app_channel *ua_chan)
{
	uint64_t discarded = 0, lost = 0;

	/* Metadata channels do not have discarded counters. */
	switch (ua_chan->attr.type) {
	case LTTNG_UST_ABI_CHAN_METADATA:
		return;
	default:
		break;
	}

	const lttng::urcu::read_lock_guard read_lock;

	try {
		const auto session =
			ltt_session::find_session(ua_chan->session->recording_session_id);

		if (!session->ust_orchestrator) {
			/*
			 * Not finding the session is not an error because there are
			 * multiple ways the channels can be torn down.
			 *
			 * 1) The session daemon can initiate the destruction of the
			 *    ust app session after receiving a destroy command or
			 *    during its shutdown/teardown.
			 * 2) The application, since we are in per-pid tracing, is
			 *    unregistering and tearing down its ust app session.
			 *
			 * Both paths are protected by the session list lock which
			 * ensures that the accounting of lost packets and discarded
			 * events is done exactly once. The session is then unpublished
			 * from the session list, resulting in this condition.
			 */
			return;
		}

		auto& orchestrator =
			static_cast<lsu::domain_orchestrator&>(session->get_ust_orchestrator());

		if (ua_chan->attr.overwrite) {
			consumer_get_lost_packets(ua_chan->session->recording_session_id,
						  ua_chan->key,
						  orchestrator.get_consumer_output_ptr(),
						  &lost);
		} else {
			consumer_get_discarded_events(ua_chan->session->recording_session_id,
						      ua_chan->key,
						      orchestrator.get_consumer_output_ptr(),
						      &discarded);
		}
		const auto& recording_config =
			static_cast<const lttng::sessiond::config::recording_channel_configuration&>(
				ua_chan->channel_config);

		ust_app_session_operations::accumulate_per_pid_closed_app_stats(
			orchestrator, recording_config, discarded, lost);
	} catch (const lttng::sessiond::exceptions::session_not_found_error& ex) {
		DBG_FMT("Failed to save per-pid lost/discarded counters: {}, location='{}'",
			ex.what(),
			ex.source_location);
		return;
	}
}

/*
 * Delete ust app channel safely. RCU read lock must be held before calling
 * this function.
 *
 * The session list lock must be held by the caller.
 */
void delete_ust_app_channel(int sock,
			    struct ust_app_channel *ua_chan,
			    lsu::app *app,
			    const lsu::trace_class::locked_ref& locked_registry)
{
	int ret;

	LTTNG_ASSERT(ua_chan);
	ASSERT_RCU_READ_LOCKED();

	DBG3("UST app deleting channel %s", ua_chan->name);

	/* Wipe stream */
	for (auto *stream :
	     lttng::urcu::list_iteration_adapter<lsu::app_stream, &lsu::app_stream::list>(
		     ua_chan->streams.head)) {
		cds_list_del(&stream->list);
		delete_ust_app_stream(sock, stream, app);
	}

	/* Wipe context */
	for (auto ua_ctx :
	     lttng::urcu::lfht_iteration_adapter<ust_app_ctx,
						 decltype(ust_app_ctx::node),
						 &ust_app_ctx::node>(*ua_chan->ctx->ht)) {
		ret = cds_lfht_del(ua_chan->ctx->ht, &ua_ctx->node.node);
		LTTNG_ASSERT(!ret);
		delete_ust_app_ctx(sock, ua_ctx, app);
	}

	/* Wipe events */
	for (auto ua_event :
	     lttng::urcu::lfht_iteration_adapter<ust_app_event,
						 decltype(ust_app_event::node),
						 &ust_app_event::node>(*ua_chan->events->ht)) {
		ret = cds_lfht_del(ua_chan->events->ht, &ua_event->node.node);
		LTTNG_ASSERT(!ret);
		delete_ust_app_event(sock, ua_event, app);
	}

	if (ua_chan->session->buffer_type == LTTNG_BUFFER_PER_PID) {
		/* Wipe and free registry from session registry. */
		if (locked_registry) {
			try {
				locked_registry->remove_channel(ua_chan->key, sock >= 0);
			} catch (const std::exception& ex) {
				DBG("Could not find channel for removal: %s", ex.what());
			}
		}

		/*
		 * A negative socket can be used by the caller when
		 * cleaning-up a ua_chan in an error path. Skip the
		 * accounting in this case.
		 */
		if (sock >= 0) {
			save_per_pid_lost_discarded_counters(ua_chan);
		}
	}

	if (ua_chan->obj != nullptr) {
		lttng_ht_iter iter;

		/* Remove channel from application UST object descriptor. */
		iter.iter.node = &ua_chan->ust_objd_node.node;
		ret = lttng_ht_del(app->ust_objd, &iter);
		LTTNG_ASSERT(!ret);
		pthread_mutex_lock(&app->sock_lock);
		ret = lttng_ust_ctl_release_object(sock, ua_chan->obj);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app channel %s release failed. Application is dead: pid = %d, sock = %d",
				     ua_chan->name,
				     app->pid,
				     app->sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app channel %s release failed. Communication time out: pid = %d, sock = %d",
				     ua_chan->name,
				     app->pid,
				     app->sock);
			} else {
				ERR("UST app channel %s release failed with ret %d: pid = %d, sock = %d",
				    ua_chan->name,
				    ret,
				    app->pid,
				    app->sock);
			}
		}
		lttng_fd_put(LTTNG_FD_APPS, 1);
		free(ua_chan->obj);
	}
	call_rcu(&ua_chan->rcu_head, delete_ust_app_channel_rcu);
}

int ust_app_register_done(lsu::app *app)
{
	int ret;

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_register_done(app->sock);
	pthread_mutex_unlock(&app->sock_lock);
	return ret;
}

int ust_app_release_object(lsu::app *app, struct lttng_ust_abi_object_data *data)
{
	int ret, sock;

	if (app) {
		pthread_mutex_lock(&app->sock_lock);
		sock = app->sock;
	} else {
		sock = -1;
	}
	ret = lttng_ust_ctl_release_object(sock, data);
	if (app) {
		pthread_mutex_unlock(&app->sock_lock);
	}
	return ret;
}

/*
 * Push metadata to consumer socket.
 *
 * RCU read-side lock must be held to guarantee existence of socket.
 * Must be called with the ust app session lock held.
 * Must be called with the registry lock held.
 *
 * On success, return the len of metadata pushed or else a negative value.
 * Returning a -EPIPE return value means we could not send the metadata,
 * but it can be caused by recoverable errors (e.g. the application has
 * terminated concurrently).
 */
ssize_t ust_app_push_metadata(const lsu::trace_class::locked_ref& locked_registry,
			      struct consumer_socket *socket,
			      int send_zero_data)
{
	int ret;
	char *metadata_str = nullptr;
	size_t len, offset, new_metadata_len_sent;
	ssize_t ret_val;
	uint64_t metadata_key, metadata_version;

	LTTNG_ASSERT(locked_registry);
	LTTNG_ASSERT(socket);
	ASSERT_RCU_READ_LOCKED();

	metadata_key = locked_registry->_metadata_key;

	/*
	 * Means that no metadata was assigned to the session. This can
	 * happens if no start has been done previously.
	 */
	if (!metadata_key) {
		return 0;
	}

	offset = locked_registry->_metadata_len_sent;
	len = locked_registry->_metadata_len - locked_registry->_metadata_len_sent;
	new_metadata_len_sent = locked_registry->_metadata_len;
	metadata_version = locked_registry->_metadata_version;
	if (len == 0) {
		DBG3("No metadata to push for metadata key %" PRIu64,
		     locked_registry->_metadata_key);
		ret_val = len;
		if (send_zero_data) {
			DBG("No metadata to push");
			goto push_data;
		}
		goto end;
	}

	/* Allocate only what we have to send. */
	metadata_str = calloc<char>(len);
	if (!metadata_str) {
		PERROR("zmalloc ust app metadata string");
		ret_val = -ENOMEM;
		goto error;
	}
	/* Copy what we haven't sent out. */
	memcpy(metadata_str, locked_registry->_metadata + offset, len);

push_data:
	pthread_mutex_unlock(&locked_registry->_lock);
	/*
	 * We need to unlock the registry while we push metadata to
	 * break a circular dependency between the consumerd metadata
	 * lock and the sessiond registry lock. Indeed, pushing metadata
	 * to the consumerd awaits that it gets pushed all the way to
	 * relayd, but doing so requires grabbing the metadata lock. If
	 * a concurrent metadata request is being performed by
	 * consumerd, this can try to grab the registry lock on the
	 * sessiond while holding the metadata lock on the consumer
	 * daemon. Those push and pull schemes are performed on two
	 * different bidirectionnal communication sockets.
	 */
	ret = consumer_push_metadata(
		socket, metadata_key, metadata_str, len, offset, metadata_version);
	pthread_mutex_lock(&locked_registry->_lock);
	if (ret < 0) {
		/*
		 * There is an acceptable race here between the registry
		 * metadata key assignment and the creation on the
		 * consumer. The session daemon can concurrently push
		 * metadata for this registry while being created on the
		 * consumer since the metadata key of the registry is
		 * assigned *before* it is setup to avoid the consumer
		 * to ask for metadata that could possibly be not found
		 * in the session daemon.
		 *
		 * The metadata will get pushed either by the session
		 * being stopped or the consumer requesting metadata if
		 * that race is triggered.
		 */
		if (ret == -LTTCOMM_CONSUMERD_CHANNEL_FAIL) {
			ret = 0;
		} else {
			ERR("Error pushing metadata to consumer");
		}
		ret_val = ret;
		goto error_push;
	} else {
		/*
		 * Metadata may have been concurrently pushed, since
		 * we're not holding the registry lock while pushing to
		 * consumer.  This is handled by the fact that we send
		 * the metadata content, size, and the offset at which
		 * that metadata belongs. This may arrive out of order
		 * on the consumer side, and the consumer is able to
		 * deal with overlapping fragments. The consumer
		 * supports overlapping fragments, which must be
		 * contiguous starting from offset 0. We keep the
		 * largest metadata_len_sent value of the concurrent
		 * send.
		 */
		if (locked_registry->_metadata_version == metadata_version) {
			locked_registry->_metadata_len_sent = std::max(
				locked_registry->_metadata_len_sent, new_metadata_len_sent);
		}
	}
	free(metadata_str);
	return len;

end:
error:
	if (ret_val) {
		/*
		 * On error, flag the registry that the metadata is
		 * closed. We were unable to push anything and this
		 * means that either the consumer is not responding or
		 * the metadata cache has been destroyed on the
		 * consumer.
		 */
		locked_registry->_metadata_closed = true;
	}
error_push:
	free(metadata_str);
	return ret_val;
}

/*
 * For a given application and session, push metadata to consumer.
 * Either sock or consumer is required : if sock is NULL, the default
 * socket to send the metadata is retrieved from consumer, if sock
 * is not NULL we use it to send the metadata.
 * RCU read-side lock must be held while calling this function,
 * therefore ensuring existence of registry. It also ensures existence
 * of socket throughout this function.
 *
 * Return 0 on success else a negative error.
 * Returning a -EPIPE return value means we could not send the metadata,
 * but it can be caused by recoverable errors (e.g. the application has
 * terminated concurrently).
 */
static int push_metadata(const lsu::trace_class::locked_ref& locked_registry,
			 struct consumer_output *consumer)
{
	int ret_val;
	ssize_t ret;
	struct consumer_socket *socket;

	LTTNG_ASSERT(locked_registry);
	LTTNG_ASSERT(consumer);
	ASSERT_RCU_READ_LOCKED();

	if (locked_registry->_metadata_closed) {
		ret_val = -EPIPE;
		goto error;
	}

	/* Get consumer socket to use to push the metadata. */
	socket = consumer_find_socket_by_bitness(locked_registry->abi.bits_per_long, consumer);
	if (!socket) {
		ret_val = -1;
		goto error;
	}

	ret = ust_app_push_metadata(locked_registry, socket, 0);
	if (ret < 0) {
		ret_val = ret;
		goto error;
	}
	return 0;

error:
	return ret_val;
}

/*
 * Send to the consumer a close metadata command for the given session. Once
 * done, the metadata channel is deleted and the session metadata pointer is
 * nullified. The session lock MUST be held unless the application is
 * in the destroy path.
 *
 * Do not hold the registry lock while communicating with the consumerd, because
 * doing so causes inter-process deadlocks between consumerd and sessiond with
 * the metadata request notification.
 *
 * Return 0 on success else a negative value.
 */
static int close_metadata(uint64_t metadata_key,
			  unsigned int consumer_bitness,
			  struct consumer_output *consumer)
{
	int ret;
	struct consumer_socket *socket;
	const lttng::urcu::read_lock_guard read_lock_guard;

	LTTNG_ASSERT(consumer);

	/* Get consumer socket to use to push the metadata. */
	socket = consumer_find_socket_by_bitness(consumer_bitness, consumer);
	if (!socket) {
		ret = -1;
		goto end;
	}

	ret = consumer_close_metadata(socket, metadata_key);
	if (ret < 0) {
		goto end;
	}

end:
	return ret;
}

static void delete_ust_app_session_rcu(struct rcu_head *head)
{
	lsu::app_session *ua_sess = lttng::utils::container_of(head, &lsu::app_session::rcu_head);

	lttng_ht_destroy(ua_sess->channels);
	delete ua_sess;
}

/*
 * Delete ust app session safely. RCU read lock must be held before calling
 * this function.
 *
 * The session list lock must be held by the caller.
 */
void delete_ust_app_session(int sock, lsu::app_session *ua_sess, lsu::app *app)
{
	LTTNG_ASSERT(ua_sess);
	ASSERT_RCU_READ_LOCKED();

	/* Locked for the duration of the function. */
	auto locked_ua_sess = ua_sess->lock();

	LTTNG_ASSERT(!ua_sess->deleted);
	ua_sess->deleted = true;

	auto locked_registry = get_locked_session_registry(locked_ua_sess->get_identifier());
	/* Registry can be null on error path during initialization. */
	if (locked_registry) {
		/* Push metadata for application before freeing the application. */
		(void) push_metadata(locked_registry.locked_ref(), ua_sess->consumer);
	}

	for (auto *ua_chan :
	     lttng::urcu::lfht_iteration_adapter<ust_app_channel,
						 decltype(ust_app_channel::node),
						 &ust_app_channel::node>(*ua_sess->channels->ht)) {
		const auto ret = cds_lfht_del(ua_sess->channels->ht, &ua_chan->node.node);
		LTTNG_ASSERT(ret == 0);
		delete_ust_app_channel(sock, ua_chan, app, locked_registry.locked_ref());
	}

	if (locked_registry) {
		/*
		 * Don't ask to close metadata for global per UID buffers. Close
		 * metadata only on destroy trace session in this case. Also, the
		 * previous push metadata could have flag the metadata registry to
		 * close so don't send a close command if closed.
		 */
		if (ua_sess->buffer_type != LTTNG_BUFFER_PER_UID) {
			const auto metadata_key = locked_registry->_metadata_key;
			const auto consumer_bitness = locked_registry->abi.bits_per_long;

			if (!locked_registry->_metadata_closed && metadata_key != 0) {
				locked_registry->_metadata_closed = true;
			}

			/* Release lock before communication, see comments in close_metadata(). */
			locked_registry.reset();
			(void) close_metadata(metadata_key, consumer_bitness, ua_sess->consumer);
		}
	}

	if (ua_sess->handle != -1) {
		pthread_mutex_lock(&app->sock_lock);
		auto ret = lttng_ust_ctl_release_handle(sock, ua_sess->handle);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release session handle failed. Application is dead: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app release session handle failed. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else {
				ERR("UST app release session handle failed with ret %d: pid = %d, sock = %d",
				    ret,
				    app->pid,
				    app->sock);
			}
		}

		/* Remove session from application UST object descriptor. */
		ret = cds_lfht_del(app->ust_sessions_objd->ht, &ua_sess->ust_objd_node.node);
		LTTNG_ASSERT(!ret);
	}

	consumer_output_put(ua_sess->consumer);
	call_rcu(&ua_sess->rcu_head, delete_ust_app_session_rcu);
}

/*
 * Delete a traceable application structure from the global list. Never call
 * this function outside of a call_rcu call.
 */
static void delete_ust_app(lsu::app *app)
{
	int ret, sock;
	bool event_notifier_write_fd_is_open;

	/*
	 * The session list lock must be held during this function to guarantee
	 * the existence of ua_sess.
	 */
	const auto list_lock = lttng::sessiond::lock_session_list();
	/* Delete ust app sessions info */
	sock = app->sock;
	app->sock = -1;

	/* Wipe sessions */
	{
		const lttng::urcu::read_lock_guard read_lock;

		for (const auto ua_sess : app->sessions_to_teardown) {
			/* Free every object in the session and the session. */
			delete_ust_app_session(sock, ua_sess, app);
		}
	}

	/* Remove the event notifier rules associated with this app. */
	{
		const lttng::urcu::read_lock_guard read_lock;

		for (auto *event_notifier_rule :
		     lttng::urcu::lfht_iteration_adapter<ust_app_event_notifier_rule,
							 decltype(ust_app_event_notifier_rule::node),
							 &ust_app_event_notifier_rule::node>(
			     *app->token_to_event_notifier_rule_ht->ht)) {
			ret = cds_lfht_del(app->token_to_event_notifier_rule_ht->ht,
					   &event_notifier_rule->node.node);
			LTTNG_ASSERT(!ret);

			delete_ust_app_event_notifier_rule(app->sock, event_notifier_rule, app);
		}
	}

	lttng_ht_destroy(app->sessions);
	lttng_ht_destroy(app->ust_sessions_objd);
	lttng_ht_destroy(app->ust_objd);
	lttng_ht_destroy(app->token_to_event_notifier_rule_ht);

	/*
	 * This could be NULL if the event notifier setup failed (e.g the app
	 * was killed or the tracer does not support this feature).
	 */
	if (app->event_notifier_group.object) {
		enum lttng_error_code ret_code;
		enum event_notifier_error_accounting_status status;

		const int event_notifier_read_fd =
			lttng_pipe_get_readfd(app->event_notifier_group.event_pipe);

		ret_code = notification_thread_command_remove_tracer_event_source(
			the_notification_thread_handle, event_notifier_read_fd);
		if (ret_code != LTTNG_OK) {
			ERR("Failed to remove application tracer event source from notification thread");
		}

		status = event_notifier_error_accounting_unregister_app(app);
		if (status != EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK) {
			ERR("Error unregistering app from event notifier error accounting");
		}

		lttng_ust_ctl_release_object(sock, app->event_notifier_group.object);
		free(app->event_notifier_group.object);
	}

	event_notifier_write_fd_is_open =
		lttng_pipe_is_write_open(app->event_notifier_group.event_pipe);
	lttng_pipe_destroy(app->event_notifier_group.event_pipe);
	/*
	 * Release the file descriptors reserved for the event notifier pipe.
	 * The app could be destroyed before the write end of the pipe could be
	 * passed to the application (and closed). In that case, both file
	 * descriptors must be released.
	 */
	lttng_fd_put(LTTNG_FD_APPS, event_notifier_write_fd_is_open ? 2 : 1);

	/*
	 * Wait until we have deleted the application from the sock hash table
	 * before closing this socket, otherwise an application could re-use the
	 * socket ID and race with the teardown, using the same hash table entry.
	 *
	 * It's OK to leave the close in call_rcu. We want it to stay unique for
	 * all RCU readers that could run concurrently with unregister app,
	 * therefore we _need_ to only close that socket after a grace period. So
	 * it should stay in this RCU callback.
	 *
	 * This close() is a very important step of the synchronization model so
	 * every modification to this function must be carefully reviewed.
	 */
	ret = close(sock);
	if (ret) {
		PERROR("close");
	}
	lttng_fd_put(LTTNG_FD_APPS, 1);

	DBG2("UST app pid %d deleted", app->pid);
	delete app;
}

/*
 * URCU intermediate call to delete an UST app.
 */
static void delete_ust_app_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		lttng::utils::container_of(head, &lttng_ht_node_ulong::head);
	lsu::app *app = lttng::utils::container_of(node, &lsu::app::pid_n);

	DBG3("Call RCU deleting app PID %d", app->pid);
	delete_ust_app(app);
}

/*
 * Delete the session from the application ht and delete the data structure by
 * freeing every object inside and releasing them.
 *
 * The session list lock must be held by the caller.
 */
static void destroy_app_session(lsu::app *app, lsu::app_session *ua_sess)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess);

	/*
	 * For per-PID buffers, perform the same orchestrator and metadata
	 * cleanup that ust_app_unregister() performs for the app-going-away
	 * case. The sequence mirrors ust_app_unregister():
	 *
	 *   1. Get the registry, push metadata, capture close info, mark closed
	 *   2. Release the registry lock
	 *   3. Release per-PID stream groups and trace class from orchestrator
	 *   4. Remove ua_sess from app->sessions hash table
	 *   5. Close metadata on the consumer
	 *   6. Delegate remaining cleanup to delete_ust_app_session()
	 *
	 * Step 1 must happen before step 3 because releasing the trace
	 * class removes it from the_trace_class_index, after which
	 * get_locked_session_registry() (used by delete_ust_app_session)
	 * would return null and skip metadata handling.
	 *
	 * Step 3 must happen before step 4 so that
	 * for_each_consumer_stream_group() never visits entries whose
	 * consumer-side channels have been closed, and so that
	 * create_channel_subdirectories() can still look up ua_sess for
	 * apps present in the orchestrator's per-PID maps.
	 *
	 * The session list lock and the per-session lock are held by the
	 * caller (command handler).
	 */
	if (ua_sess->buffer_type == LTTNG_BUFFER_PER_PID) {
		uint64_t metadata_key_to_close = 0;
		unsigned int consumer_bitness_to_close = 0;
		struct consumer_output *consumer_to_close = nullptr;

		{
			auto locked_ua_sess = ua_sess->lock();

			auto locked_registry =
				get_locked_session_registry(locked_ua_sess->get_identifier());
			if (locked_registry) {
				(void) push_metadata(locked_registry.locked_ref(),
						     ua_sess->consumer);

				metadata_key_to_close = locked_registry->_metadata_key;
				consumer_bitness_to_close = locked_registry->abi.bits_per_long;
				consumer_to_close = ua_sess->consumer;

				if (!locked_registry->_metadata_closed &&
				    metadata_key_to_close != 0) {
					locked_registry->_metadata_closed = true;
				}
			}
		}

		try {
			const auto session =
				ltt_session::find_session(ua_sess->recording_session_id);

			auto& orchestrator = static_cast<lsu::domain_orchestrator&>(
				session->get_ust_orchestrator());

			orchestrator.on_app_departure(*app);
		} catch (const lttng::sessiond::exceptions::session_not_found_error&) {
			/* Session is already gone; orchestrator will clean up in its destructor. */
		}

		iter.iter.node = &ua_sess->node.node;
		ret = lttng_ht_del(app->sessions, &iter);
		if (ret) {
			/* Already scheduled for teardown. */
			return;
		}

		if (consumer_to_close) {
			(void) close_metadata(metadata_key_to_close,
					      consumer_bitness_to_close,
					      consumer_to_close);
		}

		delete_ust_app_session(app->sock, ua_sess, app);
		return;
	}

	/* Remove from orchestrator's app session index. */
	try {
		const auto session = ltt_session::find_session(ua_sess->recording_session_id);

		auto& orchestrator =
			static_cast<lsu::domain_orchestrator&>(session->get_ust_orchestrator());

		orchestrator.on_app_departure(*app);
	} catch (const lttng::sessiond::exceptions::session_not_found_error&) {
		/* Session already gone; orchestrator destroyed with it. */
	}

	iter.iter.node = &ua_sess->node.node;
	ret = lttng_ht_del(app->sessions, &iter);
	if (ret) {
		/* Already scheduled for teardown. */
		return;
	}

	/* Once deleted, free the data structure. */
	delete_ust_app_session(app->sock, ua_sess, app);
}

/*
 * Alloc new UST app session.
 */
lsu::app_session *alloc_ust_app_session()
{
	lsu::app_session *ua_sess;

	/* Init most of the default value by allocating and zeroing */
	ua_sess = new lsu::app_session;
	if (ua_sess == nullptr) {
		PERROR("malloc");
		goto error_free;
	}

	ua_sess->handle = -1;
	ua_sess->channels = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	ua_sess->metadata_attr.type = LTTNG_UST_ABI_CHAN_METADATA;

	return ua_sess;

error_free:
	return nullptr;
}

/*
 * Alloc new UST app channel.
 */
/*
 * Common initialization for ust_app_channel. Used by both the recording
 * channel and metadata channel allocation paths.
 */
static void init_ust_app_channel(struct ust_app_channel *ua_chan,
				 const char *name,
				 const lsu::app_session::locked_weak_ref& ua_sess,
				 struct lttng_ust_abi_channel_attr *attr)
{
	strncpy(ua_chan->name, name, sizeof(ua_chan->name));
	ua_chan->name[sizeof(ua_chan->name) - 1] = '\0';

	ua_chan->enabled = true;
	ua_chan->handle = -1;
	ua_chan->session = &ua_sess.get();
	ua_chan->key = get_next_channel_key();
	ua_chan->ctx = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	ua_chan->events = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	lttng_ht_node_init_str(&ua_chan->node, ua_chan->name);

	CDS_INIT_LIST_HEAD(&ua_chan->streams.head);

	/* By default, the channel is a per cpu channel. */
	ua_chan->attr.type = LTTNG_UST_ABI_CHAN_PER_CPU;

	/* Copy attributes */
	if (attr) {
		/* Translate from lttng_ust_channel to lttng_ust_ctl_consumer_channel_attr. */
		ua_chan->attr.subbuf_size = attr->subbuf_size;
		ua_chan->attr.num_subbuf = attr->num_subbuf;
		ua_chan->attr.overwrite = attr->overwrite;
		ua_chan->attr.switch_timer_interval = attr->switch_timer_interval;
		ua_chan->attr.read_timer_interval = attr->read_timer_interval;
		ua_chan->attr.output = (lttng_ust_abi_output) attr->output;
		ua_chan->attr.blocking_timeout = attr->blocking_timeout;
		ua_chan->attr.type = static_cast<enum lttng_ust_abi_chan_type>(attr->type);
	}

	DBG3("UST app channel %s allocated", ua_chan->name);
}

/*
 * Allocate a recording channel with an associated config reference.
 */
struct ust_app_channel *
alloc_ust_app_channel(const char *name,
		      const lsu::app_session::locked_weak_ref& ua_sess,
		      struct lttng_ust_abi_channel_attr *attr,
		      const lttng::sessiond::config::recording_channel_configuration& config)
{
	struct ust_app_channel *ua_chan;

	try {
		ua_chan = new ust_app_channel(config);
	} catch (const std::bad_alloc&) {
		PERROR("ust_app_channel allocation");
		return nullptr;
	}

	init_ust_app_channel(ua_chan, name, ua_sess, attr);
	return ua_chan;
}

/*
 * Allocate a metadata channel (no recording_channel_configuration).
 */
static struct ust_app_channel *alloc_ust_app_metadata_channel(
	const char *name,
	const lsu::app_session::locked_weak_ref& ua_sess,
	const lttng::sessiond::config::metadata_channel_configuration& metadata_config)
{
	struct ust_app_channel *ua_chan;

	try {
		ua_chan = new ust_app_channel(metadata_config);
	} catch (const std::bad_alloc&) {
		PERROR("ust_app_channel allocation");
		return nullptr;
	}

	init_ust_app_channel(ua_chan, name, ua_sess, nullptr);
	return ua_chan;
}

/*
 * Allocate and initialize a UST app stream.
 *
 * Return newly allocated stream pointer or NULL on error.
 */
lsu::app_stream *ust_app_alloc_stream()
{
	lsu::app_stream *stream = nullptr;

	stream = zmalloc<lsu::app_stream>();
	if (stream == nullptr) {
		PERROR("zmalloc ust app stream");
		goto error;
	}

	/* Zero could be a valid value for a handle so flag it to -1. */
	stream->handle = -1;

error:
	return stream;
}

/*
 * Build a lttng_ust_abi_event from an event rule. Only user tracepoint
 * rules are supported.
 */
static struct lttng_ust_abi_event
make_ust_abi_event_from_event_rule(const struct lttng_event_rule *rule)
{
	struct lttng_ust_abi_event ust_event = {};
	const char *pattern;
	int loglevel = -1;
	enum lttng_ust_abi_loglevel_type ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;

	if (lttng_event_rule_targets_agent_domain(rule)) {
		pattern = event_get_default_agent_ust_name(lttng_event_rule_get_domain_type(rule));
		loglevel = 0;
		ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
	} else {
		const struct lttng_log_level_rule *log_level_rule;

		LTTNG_ASSERT(lttng_event_rule_get_type(rule) ==
			     LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT);

		const auto status =
			lttng_event_rule_user_tracepoint_get_name_pattern(rule, &pattern);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			abort();
		}

		const auto llr_status =
			lttng_event_rule_user_tracepoint_get_log_level_rule(rule, &log_level_rule);
		if (llr_status == LTTNG_EVENT_RULE_STATUS_UNSET) {
			ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
		} else if (llr_status == LTTNG_EVENT_RULE_STATUS_OK) {
			enum lttng_log_level_rule_status level_status;

			switch (lttng_log_level_rule_get_type(log_level_rule)) {
			case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
				ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_SINGLE;
				level_status = lttng_log_level_rule_exactly_get_level(
					log_level_rule, &loglevel);
				break;
			case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
				ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_RANGE;
				level_status = lttng_log_level_rule_at_least_as_severe_as_get_level(
					log_level_rule, &loglevel);
				break;
			default:
				abort();
			}

			LTTNG_ASSERT(level_status == LTTNG_LOG_LEVEL_RULE_STATUS_OK);
		} else {
			abort();
		}
	}

	ust_event.instrumentation = LTTNG_UST_ABI_TRACEPOINT;
	lttng_strncpy(ust_event.name, pattern, sizeof(ust_event.name));
	ust_event.loglevel_type = ust_loglevel_type;
	ust_event.loglevel = loglevel;

	return ust_event;
}

/*
 * Alloc new UST app event from its event rule configuration.
 */
static struct ust_app_event *
alloc_ust_app_event(const lttng::sessiond::config::event_rule_configuration& event_config)
{
	struct ust_app_event *ua_event;

	try {
		ua_event = new ust_app_event(event_config);
	} catch (const std::bad_alloc&) {
		PERROR("Failed to allocate ust_app_event structure");
		goto error;
	}

	ua_event->enabled = true;
	ua_event->attr = make_ust_abi_event_from_event_rule(event_config.event_rule.get());
	strncpy(ua_event->name, ua_event->attr.name, sizeof(ua_event->name));
	ua_event->name[sizeof(ua_event->name) - 1] = '\0';
	lttng_ht_node_init_str(&ua_event->node, ua_event->name);

	DBG3("UST app event %s allocated", ua_event->name);

	return ua_event;

error:
	return nullptr;
}

/*
 * Allocate a new UST app event notifier rule.
 */
static struct ust_app_event_notifier_rule *
alloc_ust_app_event_notifier_rule(struct lttng_trigger *trigger)
{
	enum lttng_event_rule_generate_exclusions_status generate_exclusion_status;
	enum lttng_condition_status cond_status;
	struct ust_app_event_notifier_rule *ua_event_notifier_rule;
	struct lttng_condition *condition = nullptr;
	const struct lttng_event_rule *event_rule = nullptr;

	ua_event_notifier_rule = zmalloc<ust_app_event_notifier_rule>();
	if (ua_event_notifier_rule == nullptr) {
		PERROR("Failed to allocate ust_app_event_notifier_rule structure");
		goto error;
	}

	ua_event_notifier_rule->enabled = true;
	ua_event_notifier_rule->token = lttng_trigger_get_tracer_token(trigger);
	lttng_ht_node_init_u64(&ua_event_notifier_rule->node, ua_event_notifier_rule->token);

	condition = lttng_trigger_get_condition(trigger);
	LTTNG_ASSERT(condition);
	LTTNG_ASSERT(lttng_condition_get_type(condition) ==
		     LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES);

	cond_status = lttng_condition_event_rule_matches_get_rule(condition, &event_rule);
	LTTNG_ASSERT(cond_status == LTTNG_CONDITION_STATUS_OK);
	LTTNG_ASSERT(event_rule);

	ua_event_notifier_rule->error_counter_index =
		lttng_condition_event_rule_matches_get_error_counter_index(condition);
	/* Acquire the event notifier's reference to the trigger. */
	lttng_trigger_get(trigger);

	ua_event_notifier_rule->trigger = trigger;
	ua_event_notifier_rule->filter = lttng_event_rule_get_filter_bytecode(event_rule);
	generate_exclusion_status = lttng_event_rule_generate_exclusions(
		event_rule, &ua_event_notifier_rule->exclusion);
	switch (generate_exclusion_status) {
	case LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_OK:
	case LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE:
		break;
	default:
		/* Error occurred. */
		ERR("Failed to generate exclusions from trigger while allocating an event notifier rule");
		goto error_put_trigger;
	}

	DBG3("UST app event notifier rule allocated: token = %" PRIu64,
	     ua_event_notifier_rule->token);

	return ua_event_notifier_rule;

error_put_trigger:
	lttng_trigger_put(trigger);
error:
	free(ua_event_notifier_rule);
	return nullptr;
}

/*
 * Alloc new UST app context.
 */
static struct ust_app_ctx *
alloc_ust_app_ctx(struct lttng_ust_context_attr *uctx,
		  const lttng::sessiond::config::context_configuration& ctx_config)
{
	struct ust_app_ctx *ua_ctx;

	try {
		ua_ctx = new ust_app_ctx(ctx_config);
	} catch (const std::bad_alloc&) {
		goto error;
	}

	if (uctx) {
		memcpy(&ua_ctx->ctx, uctx, sizeof(ua_ctx->ctx));
		if (uctx->ctx == LTTNG_UST_ABI_CONTEXT_APP_CONTEXT) {
			char *provider_name = nullptr, *ctx_name = nullptr;

			provider_name = strdup(uctx->u.app_ctx.provider_name);
			ctx_name = strdup(uctx->u.app_ctx.ctx_name);
			if (!provider_name || !ctx_name) {
				free(provider_name);
				free(ctx_name);
				goto error;
			}

			ua_ctx->ctx.u.app_ctx.provider_name = provider_name;
			ua_ctx->ctx.u.app_ctx.ctx_name = ctx_name;
		}
	}

	DBG3("UST app context %d allocated", ua_ctx->ctx.ctx);
	return ua_ctx;
error:
	delete ua_ctx;
	return nullptr;
}

/*
 * Create a liblttng-ust filter bytecode from given bytecode.
 *
 * Return allocated filter or NULL on error.
 */
static struct lttng_ust_abi_filter_bytecode *
create_ust_filter_bytecode_from_bytecode(const struct lttng_bytecode *orig_f)
{
	struct lttng_ust_abi_filter_bytecode *filter = nullptr;

	/* Copy filter bytecode. */
	filter = zmalloc<lttng_ust_abi_filter_bytecode>(sizeof(*filter) + orig_f->len);
	if (!filter) {
		PERROR("Failed to allocate lttng_ust_filter_bytecode: bytecode len = %" PRIu32
		       " bytes",
		       orig_f->len);
		goto error;
	}

	LTTNG_ASSERT(sizeof(struct lttng_bytecode) == sizeof(struct lttng_ust_abi_filter_bytecode));
	memcpy(filter, orig_f, sizeof(*filter) + orig_f->len);
error:
	return filter;
}

/*
 * Create a liblttng-ust capture bytecode from given bytecode.
 *
 * Return allocated filter or NULL on error.
 */
static struct lttng_ust_abi_capture_bytecode *
create_ust_capture_bytecode_from_bytecode(const struct lttng_bytecode *orig_f)
{
	struct lttng_ust_abi_capture_bytecode *capture = nullptr;

	/* Copy capture bytecode. */
	capture = zmalloc<lttng_ust_abi_capture_bytecode>(sizeof(*capture) + orig_f->len);
	if (!capture) {
		PERROR("Failed to allocate lttng_ust_abi_capture_bytecode: bytecode len = %" PRIu32
		       " bytes",
		       orig_f->len);
		goto error;
	}

	LTTNG_ASSERT(sizeof(struct lttng_bytecode) ==
		     sizeof(struct lttng_ust_abi_capture_bytecode));
	memcpy(capture, orig_f, sizeof(*capture) + orig_f->len);
error:
	return capture;
}

/*
 * Find an lsu::app using the sock and return it. RCU read side lock must be
 * held before calling this helper function.
 */
nonstd::optional<ust_app_reference> ust_app_find_by_sock(int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(ust_app_ht_by_sock, (void *) ((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_ulong>(&iter);
	if (node == nullptr) {
		DBG2("UST app find by sock %d not found", sock);
		return nonstd::nullopt;
	}

	auto raw_app = lttng::utils::container_of(node, &lsu::app::sock_n);
	return ust_app_get(*raw_app) ? nonstd::make_optional<ust_app_reference>(raw_app) :
				       nonstd::nullopt;
}

/*
 * Find an lsu::app using the notify sock and return it. RCU read side lock must
 * be held before calling this helper function.
 */
static nonstd::optional<ust_app_reference> find_app_by_notify_sock(int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(ust_app_ht_by_notify_sock, (void *) ((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_ulong>(&iter);
	if (node == nullptr) {
		DBG2("UST app find by notify sock %d not found", sock);
		return nonstd::nullopt;
	}

	auto app = lttng::utils::container_of(node, &lsu::app::notify_sock_n);
	return ust_app_get(*app) ? nonstd::make_optional<ust_app_reference>(app) : nonstd::nullopt;
}

/*
 * Find a per-app event by matching its config pointer.
 *
 * Returns the matching ust_app_event or nullptr if not found.
 * Must be called with the RCU read lock held.
 */
struct ust_app_event *
find_ust_app_event_by_config(struct lttng_ht *ht,
			     const lttng::sessiond::config::event_rule_configuration& event_config)
{
	LTTNG_ASSERT(ht);

	for (auto *ua_event : lttng::urcu::lfht_iteration_adapter<ust_app_event,
								  decltype(ust_app_event::node),
								  &ust_app_event::node>(*ht->ht)) {
		if (&ua_event->event_rule_config == &event_config) {
			return ua_event;
		}
	}

	return nullptr;
}

/*
 * Look-up an event notifier rule based on its token id.
 *
 * Must be called with the RCU read lock held.
 * Return an ust_app_event_notifier_rule object or NULL on error.
 */
static struct ust_app_event_notifier_rule *find_ust_app_event_notifier_rule(struct lttng_ht *ht,
									    uint64_t token)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;
	struct ust_app_event_notifier_rule *event_notifier_rule = nullptr;

	LTTNG_ASSERT(ht);
	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(ht, &token, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (node == nullptr) {
		DBG2("UST app event notifier rule token not found: token = %" PRIu64, token);
		goto end;
	}

	event_notifier_rule = lttng::utils::container_of(node, &ust_app_event_notifier_rule::node);
end:
	return event_notifier_rule;
}

/*
 * Create the channel context on the tracer.
 *
 * Called with UST app session lock held.
 */
static int create_ust_channel_context(struct ust_app_channel *ua_chan,
				      struct ust_app_ctx *ua_ctx,
				      lsu::app *app)
{
	int ret;

	health_code_update();

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_add_context(app->sock, &ua_ctx->ctx, ua_chan->obj, &ua_ctx->obj);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app create channel context failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app create channel context failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app create channel context failed with ret %d: pid = %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error;
	}

	ua_ctx->handle = ua_ctx->obj->header.handle;

	DBG2("UST app context handle %d created successfully for channel %s",
	     ua_ctx->handle,
	     ua_chan->name);

error:
	health_code_update();
	return ret;
}

/*
 * Set the filter on the tracer.
 */
static int set_ust_object_filter(lsu::app *app,
				 const struct lttng_bytecode *bytecode,
				 struct lttng_ust_abi_object_data *ust_object)
{
	int ret;
	struct lttng_ust_abi_filter_bytecode *ust_bytecode = nullptr;

	health_code_update();

	ust_bytecode = create_ust_filter_bytecode_from_bytecode(bytecode);
	if (!ust_bytecode) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_set_filter(app->sock, ust_bytecode, ust_object);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app  set filter failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app  set filter failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app  set filter failed with ret %d: pid = %d, sock = %d, object = %p",
			    ret,
			    app->pid,
			    app->sock,
			    ust_object);
		}
		goto error;
	}

	DBG2("UST filter successfully set: object = %p", ust_object);

error:
	health_code_update();
	free(ust_bytecode);
	return ret;
}

/*
 * Set a capture bytecode for the passed object.
 * The sequence number enforces the ordering at runtime and on reception of
 * the captured payloads.
 */
static int set_ust_capture(lsu::app *app,
			   const struct lttng_bytecode *bytecode,
			   unsigned int capture_seqnum,
			   struct lttng_ust_abi_object_data *ust_object)
{
	int ret;
	struct lttng_ust_abi_capture_bytecode *ust_bytecode = nullptr;

	health_code_update();

	ust_bytecode = create_ust_capture_bytecode_from_bytecode(bytecode);
	if (!ust_bytecode) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}

	/*
	 * Set the sequence number to ensure the capture of fields is ordered.
	 */
	ust_bytecode->seqnum = capture_seqnum;

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_set_capture(app->sock, ust_bytecode, ust_object);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app set capture failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			DBG3("UST app set capture failed. Communication timeout: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app event set capture failed with ret %d: pid = %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
		}

		goto error;
	}

	DBG2("UST capture successfully set: object = %p", ust_object);

error:
	health_code_update();
	free(ust_bytecode);
	return ret;
}

static struct lttng_ust_abi_event_exclusion *
create_ust_exclusion_from_exclusion(const struct lttng_event_exclusion *exclusion)
{
	struct lttng_ust_abi_event_exclusion *ust_exclusion = nullptr;
	const size_t names_size = LTTNG_UST_ABI_SYM_NAME_LEN * exclusion->count;
	const size_t exclusion_alloc_size =
		sizeof(struct lttng_ust_abi_event_exclusion) + names_size;

	ust_exclusion = zmalloc<lttng_ust_abi_event_exclusion>(exclusion_alloc_size);
	if (!ust_exclusion) {
		PERROR("malloc");
		goto end;
	}

	ust_exclusion->count = exclusion->count;

	memcpy(ust_exclusion->names, exclusion->names, names_size);
end:
	return ust_exclusion;
}

/*
 * Set event exclusions on the tracer.
 */
static int set_ust_object_exclusions(lsu::app *app,
				     const struct lttng_event_exclusion *exclusions,
				     struct lttng_ust_abi_object_data *ust_object)
{
	int ret;
	struct lttng_ust_abi_event_exclusion *ust_exclusions = nullptr;

	LTTNG_ASSERT(exclusions && exclusions->count > 0);

	health_code_update();

	ust_exclusions = create_ust_exclusion_from_exclusion(exclusions);
	if (!ust_exclusions) {
		ret = -LTTNG_ERR_NOMEM;
		goto error;
	}
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_set_exclusion(app->sock, ust_exclusions, ust_object);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app event exclusion failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app event exclusion failed. Communication time out(pid: %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app event exclusions failed with ret %d: pid = %d, sock = %d, object = %p",
			    ret,
			    app->pid,
			    app->sock,
			    ust_object);
		}
		goto error;
	}

	DBG2("UST exclusions set successfully for object %p", ust_object);

error:
	health_code_update();
	free(ust_exclusions);
	return ret;
}

/*
 * Disable the specified event on to UST tracer for the UST session.
 */
static int disable_ust_object(lsu::app *app, struct lttng_ust_abi_object_data *object)
{
	int ret;

	health_code_update();

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_disable(app->sock, object);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app disable object failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app disable object failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app disable object failed with ret %d: pid = %d, sock = %d, object = %p",
			    ret,
			    app->pid,
			    app->sock,
			    object);
		}
		goto error;
	}

	DBG2("UST app object %p disabled successfully for app: pid = %d", object, app->pid);

error:
	health_code_update();
	return ret;
}

/*
 * Disable the specified channel on to UST tracer for the UST session.
 */
int disable_ust_channel(lsu::app *app,
			const lsu::app_session::locked_weak_ref& ua_sess,
			struct ust_app_channel *ua_chan)
{
	int ret;

	health_code_update();

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_disable(app->sock, ua_chan->obj);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app disable channel failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app disable channel failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app channel %s disable failed, session handle %d, with ret %d: pid = %d, sock = %d",
			    ua_chan->name,
			    ua_sess->handle,
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error;
	}

	DBG2("UST app channel %s disabled successfully for app: pid = %d", ua_chan->name, app->pid);

error:
	health_code_update();
	return ret;
}

/*
 * Enable the specified channel on to UST tracer for the UST session.
 */
int enable_ust_channel(lsu::app *app,
		       const lsu::app_session::locked_weak_ref& ua_sess,
		       struct ust_app_channel *ua_chan)
{
	int ret;

	health_code_update();

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_enable(app->sock, ua_chan->obj);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app channel %s enable failed. Application is dead: pid = %d, sock = %d",
			     ua_chan->name,
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app channel %s enable failed. Communication time out: pid = %d, sock = %d",
			     ua_chan->name,
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app channel %s enable failed, session handle %d, with ret %d: pid = %d, sock = %d",
			    ua_chan->name,
			    ua_sess->handle,
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error;
	}

	ua_chan->enabled = true;

	DBG2("UST app channel %s enabled successfully for app: pid = %d", ua_chan->name, app->pid);

error:
	health_code_update();
	return ret;
}

/*
 * Enable the specified event on to UST tracer for the UST session.
 */
static int enable_ust_object(lsu::app *app, struct lttng_ust_abi_object_data *ust_object)
{
	int ret;

	health_code_update();

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_enable(app->sock, ust_object);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app enable object failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app enable object failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app enable object failed with ret %d: pid = %d, sock = %d, object = %p",
			    ret,
			    app->pid,
			    app->sock,
			    ust_object);
		}
		goto error;
	}

	DBG2("UST app object %p enabled successfully for app: pid = %d", ust_object, app->pid);

error:
	health_code_update();
	return ret;
}

/*
 * Send channel and stream buffer to application.
 *
 * Return 0 on success. On error, a negative value is returned.
 */
int send_channel_pid_to_ust(lsu::app *app,
			    lsu::app_session *ua_sess,
			    struct ust_app_channel *ua_chan)
{
	int ret;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);

	health_code_update();

	DBG("UST app sending channel %s to UST app sock %d", ua_chan->name, app->sock);

	/* Send channel to the application. */
	ret = ust_consumer_send_channel_to_ust(app, ua_sess, ua_chan);
	if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
		ret = -ENOTCONN; /* Caused by app exiting. */
		goto error;
	} else if (ret == -EAGAIN) {
		/* Caused by timeout. */
		WARN("Communication with application %d timed out on send_channel for channel \"%s\" of session \"%" PRIu64
		     "\".",
		     app->pid,
		     ua_chan->name,
		     ua_sess->recording_session_id);
		/* Treat this the same way as an application that is exiting. */
		ret = -ENOTCONN;
		goto error;
	} else if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Send all streams to application. */
	for (auto *stream :
	     lttng::urcu::list_iteration_adapter<lsu::app_stream, &lsu::app_stream::list>(
		     ua_chan->streams.head)) {
		ret = ust_consumer_send_stream_to_ust(app, ua_chan, stream);
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = -ENOTCONN; /* Caused by app exiting. */
			goto error;
		} else if (ret == -EAGAIN) {
			/* Caused by timeout. */
			WARN("Communication with application %d timed out on send_stream for stream \"%s\" of channel \"%s\" of session \"%" PRIu64
			     "\".",
			     app->pid,
			     stream->name,
			     ua_chan->name,
			     ua_sess->recording_session_id);
			/*
			 * Treat this the same way as an application that is
			 * exiting.
			 */
			ret = -ENOTCONN;
		} else if (ret < 0) {
			goto error;
		}
		/* We don't need the stream anymore once sent to the tracer. */
		cds_list_del(&stream->list);
		delete_ust_app_stream(-1, stream, app);
	}

error:
	health_code_update();
	return ret;
}

/*
 * Create the specified event onto the UST tracer for a UST session.
 *
 * Should be called with session mutex held.
 */
static int
create_ust_event(lsu::app *app, struct ust_app_channel *ua_chan, struct ust_app_event *ua_event)
{
	int ret = 0;

	health_code_update();

	/* Create UST event on tracer */
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_create_event(app->sock, &ua_event->attr, ua_chan->obj, &ua_event->obj);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app create event failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app create event failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app create event '%s' failed with ret %d: pid = %d, sock = %d",
			    ua_event->attr.name,
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error;
	}

	ua_event->handle = ua_event->obj->header.handle;

	DBG2("UST app event %s created successfully for pid:%d object = %p",
	     ua_event->attr.name,
	     app->pid,
	     ua_event->obj);

	health_code_update();

	/* Set filter if one is present. */
	{
		const auto *filter_bytecode = lttng_event_rule_get_filter_bytecode(
			ua_event->event_rule_config.event_rule.get());
		if (filter_bytecode) {
			ret = set_ust_object_filter(app, filter_bytecode, ua_event->obj);
			if (ret < 0) {
				goto error;
			}
		}
	}

	/* Set exclusions for the event */
	{
		struct lttng_event_exclusion *exclusion = nullptr;
		const auto exclusion_status = lttng_event_rule_generate_exclusions(
			ua_event->event_rule_config.event_rule.get(), &exclusion);
		if (exclusion_status == LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_OK &&
		    exclusion) {
			ret = set_ust_object_exclusions(app, exclusion, ua_event->obj);
			free(exclusion);
			if (ret < 0) {
				goto error;
			}
		} else if (exclusion_status != LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_NONE &&
			   exclusion_status != LTTNG_EVENT_RULE_GENERATE_EXCLUSIONS_STATUS_OK) {
			ERR("Failed to generate exclusions from event rule");
		}
	}

	/* If event not enabled, disable it on the tracer */
	if (ua_event->enabled) {
		/*
		 * We now need to explicitly enable the event, since it
		 * is now disabled at creation.
		 */
		ret = enable_ust_object(app, ua_event->obj);
		if (ret < 0) {
			/*
			 * If we hit an EPERM, something is wrong with our enable call. If
			 * we get an EEXIST, there is a problem on the tracer side since we
			 * just created it.
			 */
			switch (ret) {
			case -LTTNG_UST_ERR_PERM:
				/* Code flow problem */
				abort();
			case -LTTNG_UST_ERR_EXIST:
				/* It's OK for our use case. */
				ret = 0;
				break;
			default:
				break;
			}
			goto error;
		}
	}

error:
	health_code_update();
	return ret;
}

static int
init_ust_event_notifier_from_event_rule(const struct lttng_event_rule *rule,
					struct lttng_ust_abi_event_notifier *event_notifier)
{
	enum lttng_event_rule_status status;
	enum lttng_ust_abi_loglevel_type ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
	int loglevel = -1, ret = 0;
	const char *pattern;

	memset(event_notifier, 0, sizeof(*event_notifier));

	if (lttng_event_rule_targets_agent_domain(rule)) {
		/*
		 * Special event for agents
		 * The actual meat of the event is in the filter that will be
		 * attached later on.
		 * Set the default values for the agent event.
		 */
		pattern = event_get_default_agent_ust_name(lttng_event_rule_get_domain_type(rule));
		loglevel = 0;
		ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
	} else {
		const struct lttng_log_level_rule *log_level_rule;

		LTTNG_ASSERT(lttng_event_rule_get_type(rule) ==
			     LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT);

		status = lttng_event_rule_user_tracepoint_get_name_pattern(rule, &pattern);
		if (status != LTTNG_EVENT_RULE_STATUS_OK) {
			/* At this point, this is a fatal error. */
			abort();
		}

		status = lttng_event_rule_user_tracepoint_get_log_level_rule(rule, &log_level_rule);
		if (status == LTTNG_EVENT_RULE_STATUS_UNSET) {
			ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_ALL;
		} else if (status == LTTNG_EVENT_RULE_STATUS_OK) {
			enum lttng_log_level_rule_status llr_status;

			switch (lttng_log_level_rule_get_type(log_level_rule)) {
			case LTTNG_LOG_LEVEL_RULE_TYPE_EXACTLY:
				ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_SINGLE;
				llr_status = lttng_log_level_rule_exactly_get_level(log_level_rule,
										    &loglevel);
				break;
			case LTTNG_LOG_LEVEL_RULE_TYPE_AT_LEAST_AS_SEVERE_AS:
				ust_loglevel_type = LTTNG_UST_ABI_LOGLEVEL_RANGE;
				llr_status = lttng_log_level_rule_at_least_as_severe_as_get_level(
					log_level_rule, &loglevel);
				break;
			default:
				abort();
			}

			LTTNG_ASSERT(llr_status == LTTNG_LOG_LEVEL_RULE_STATUS_OK);
		} else {
			/* At this point this is a fatal error. */
			abort();
		}
	}

	event_notifier->instrumentation = LTTNG_UST_ABI_TRACEPOINT;
	ret = lttng_strncpy(event_notifier->name, pattern, sizeof(event_notifier->name));
	if (ret) {
		ERR("Failed to copy event rule pattern to notifier: pattern = '%s' ", pattern);
		goto end;
	}

	event_notifier->loglevel_type = ust_loglevel_type;
	event_notifier->loglevel = loglevel;
end:
	return ret;
}

/*
 * Create the specified event notifier against the user space tracer of a
 * given application.
 */
static int create_ust_event_notifier(lsu::app *app,
				     struct ust_app_event_notifier_rule *ua_event_notifier_rule)
{
	int ret = 0;
	enum lttng_condition_status condition_status;
	const struct lttng_condition *condition = nullptr;
	struct lttng_ust_abi_event_notifier event_notifier;
	const struct lttng_event_rule *event_rule = nullptr;
	unsigned int capture_bytecode_count = 0, i;
	enum lttng_condition_status cond_status;
	enum lttng_event_rule_type event_rule_type;

	health_code_update();
	LTTNG_ASSERT(app->event_notifier_group.object);

	condition = lttng_trigger_get_const_condition(ua_event_notifier_rule->trigger);
	LTTNG_ASSERT(condition);
	LTTNG_ASSERT(lttng_condition_get_type(condition) ==
		     LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES);

	condition_status = lttng_condition_event_rule_matches_get_rule(condition, &event_rule);
	LTTNG_ASSERT(condition_status == LTTNG_CONDITION_STATUS_OK);

	LTTNG_ASSERT(event_rule);

	event_rule_type = lttng_event_rule_get_type(event_rule);
	LTTNG_ASSERT(event_rule_type == LTTNG_EVENT_RULE_TYPE_USER_TRACEPOINT ||
		     event_rule_type == LTTNG_EVENT_RULE_TYPE_JUL_LOGGING ||
		     event_rule_type == LTTNG_EVENT_RULE_TYPE_LOG4J_LOGGING ||
		     event_rule_type == LTTNG_EVENT_RULE_TYPE_LOG4J2_LOGGING ||
		     event_rule_type == LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING);

	init_ust_event_notifier_from_event_rule(event_rule, &event_notifier);
	event_notifier.token = ua_event_notifier_rule->token;
	event_notifier.error_counter_index = ua_event_notifier_rule->error_counter_index;

	/* Create UST event notifier against the tracer. */
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_create_event_notifier(app->sock,
						  &event_notifier,
						  app->event_notifier_group.object,
						  &ua_event_notifier_rule->obj);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app create event notifier failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app create event notifier failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app create event notifier '%s' failed with ret %d: pid = %d, sock = %d",
			    event_notifier.name,
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error;
	}

	ua_event_notifier_rule->handle = ua_event_notifier_rule->obj->header.handle;

	DBG2("UST app event notifier %s created successfully: app = '%s': pid = %d, object = %p",
	     event_notifier.name,
	     app->name,
	     app->pid,
	     ua_event_notifier_rule->obj);

	health_code_update();

	/* Set filter if one is present. */
	if (ua_event_notifier_rule->filter) {
		ret = set_ust_object_filter(
			app, ua_event_notifier_rule->filter, ua_event_notifier_rule->obj);
		if (ret < 0) {
			goto error;
		}
	}

	/* Set exclusions for the event. */
	if (ua_event_notifier_rule->exclusion) {
		ret = set_ust_object_exclusions(
			app, ua_event_notifier_rule->exclusion, ua_event_notifier_rule->obj);
		if (ret < 0) {
			goto error;
		}
	}

	/* Set the capture bytecodes. */
	cond_status = lttng_condition_event_rule_matches_get_capture_descriptor_count(
		condition, &capture_bytecode_count);
	LTTNG_ASSERT(cond_status == LTTNG_CONDITION_STATUS_OK);

	for (i = 0; i < capture_bytecode_count; i++) {
		const struct lttng_bytecode *capture_bytecode =
			lttng_condition_event_rule_matches_get_capture_bytecode_at_index(condition,
											 i);

		ret = set_ust_capture(app, capture_bytecode, i, ua_event_notifier_rule->obj);
		if (ret < 0) {
			goto error;
		}
	}

	/*
	 * We now need to explicitly enable the event, since it
	 * is disabled at creation.
	 */
	ret = enable_ust_object(app, ua_event_notifier_rule->obj);
	if (ret < 0) {
		/*
		 * If we hit an EPERM, something is wrong with our enable call.
		 * If we get an EEXIST, there is a problem on the tracer side
		 * since we just created it.
		 */
		switch (ret) {
		case -LTTNG_UST_ERR_PERM:
			/* Code flow problem. */
			abort();
		case -LTTNG_UST_ERR_EXIST:
			/* It's OK for our use case. */
			ret = 0;
			break;
		default:
			break;
		}

		goto error;
	}

	ua_event_notifier_rule->enabled = true;

error:
	health_code_update();
	return ret;
}

/*
 * Copy data between an UST app event and a LTT event.
 */
/*
 * Populate the per-app event's mutable fields from its associated
 * event rule configuration. The `attr` and `name` fields are already
 * set by `alloc_ust_app_event`, so this function only needs to copy
 * the enabled state, filter bytecode, and exclusions.
 */
static void shadow_copy_event(struct ust_app_event *ua_event)
{
	ua_event->enabled = ua_event->event_rule_config.is_enabled;
}

/*
 * Copy data between an UST app channel and a LTT channel.
 */
/*
 * Initialize per-app channel attributes from its recording_channel_configuration.
 *
 * This replaces the former shadow_copy_channel which copied from ltt_ust_channel.
 * The trace_class_stream_class_handle and channel type are set by the caller.
 */
void init_ust_app_channel_from_config(struct ust_app_channel *ua_chan)
{
	namespace lsc = lttng::sessiond::config;
	const auto& config =
		static_cast<const lsc::recording_channel_configuration&>(ua_chan->channel_config);

	DBG2("UST app initializing channel %s from config", ua_chan->name);

	ua_chan->tracefile_size = config.trace_file_size_limit_bytes.value_or(0);
	ua_chan->tracefile_count = config.trace_file_count_limit.value_or(0);

	ua_chan->attr.subbuf_size = config.subbuffer_size_bytes;
	ua_chan->attr.num_subbuf = config.subbuffer_count;
	ua_chan->attr.overwrite = config.buffer_full_policy ==
			lsc::channel_configuration::buffer_full_policy_t::OVERWRITE_OLDEST_PACKET ?
		1 :
		0;
	ua_chan->attr.switch_timer_interval = config.switch_timer_period_us.value_or(0);
	ua_chan->attr.read_timer_interval = config.read_timer_period_us.value_or(0);
	ua_chan->monitor_timer_interval = config.monitor_timer_period_us.value_or(0);

	if (config.watchdog_timer_period_us) {
		LTTNG_OPTIONAL_SET(&ua_chan->watchdog_timer_interval,
				   *config.watchdog_timer_period_us);
	} else {
		LTTNG_OPTIONAL_UNSET(&ua_chan->watchdog_timer_interval);
	}

	ua_chan->preallocation_policy = config.buffer_preallocation_policy;

	ua_chan->automatic_memory_reclamation_maximal_age =
		config.automatic_memory_reclamation_maximal_age;

	ua_chan->attr.output = config.buffer_consumption_backend ==
			lsc::channel_configuration::buffer_consumption_backend_t::MMAP ?
		LTTNG_UST_ABI_MMAP :
		static_cast<lttng_ust_abi_output>(-1);

	switch (config.consumption_blocking_policy_.mode_) {
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::NONE:
		ua_chan->attr.blocking_timeout = 0;
		break;
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::UNBOUNDED:
		ua_chan->attr.blocking_timeout = -1;
		break;
	case lsc::recording_channel_configuration::consumption_blocking_policy::mode::TIMED:
		ua_chan->attr.blocking_timeout = *config.consumption_blocking_policy_.timeout_us;
		break;
	}

	ua_chan->enabled = config.is_enabled;

	DBG3("UST app channel %s initialized from config", ua_chan->name);
}

/*
 * Lookup session wrapper.
 */
static void
__lookup_session_by_app(std::uint64_t session_id, const lsu::app *app, lttng_ht_iter *iter)
{
	/* Get right UST app session from app */
	lttng_ht_lookup(app->sessions, &session_id, iter);
}

/*
 * Return ust app session from the app session hashtable using the UST session
 * id.
 */
lsu::app_session *ust_app_lookup_app_session(std::uint64_t session_id, const lsu::app *app)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;

	__lookup_session_by_app(session_id, app, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (node == nullptr) {
		goto error;
	}

	return lttng::utils::container_of(node, &lsu::app_session::node);

error:
	return nullptr;
}

/*
 * Match function for a hash table lookup of ust_app_ctx.
 *
 * It matches an ust app context based on the context type and, in the case
 * of perf counters, their name.
 */
static int ht_match_ust_app_ctx(struct cds_lfht_node *node, const void *_key)
{
	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	auto *ctx = lttng_ht_node_container_of(node, &ust_app_ctx::node);
	const auto *key = (lttng_ust_context_attr *) _key;

	/* Context type */
	if (ctx->ctx.ctx != key->ctx) {
		goto no_match;
	}

	switch (key->ctx) {
	case LTTNG_UST_ABI_CONTEXT_PERF_THREAD_COUNTER:
		if (strncmp(key->u.perf_counter.name,
			    ctx->ctx.u.perf_counter.name,
			    sizeof(key->u.perf_counter.name)) != 0) {
			goto no_match;
		}
		break;
	case LTTNG_UST_ABI_CONTEXT_APP_CONTEXT:
		if (strcmp(key->u.app_ctx.provider_name, ctx->ctx.u.app_ctx.provider_name) != 0 ||
		    strcmp(key->u.app_ctx.ctx_name, ctx->ctx.u.app_ctx.ctx_name) != 0) {
			goto no_match;
		}
		break;
	default:
		break;
	}

	/* Match. */
	return 1;

no_match:
	return 0;
}

/*
 * Lookup for an ust app context from an lttng_ust_context.
 *
 * Must be called while holding RCU read side lock.
 * Return an ust_app_ctx object or NULL on error.
 */
static struct ust_app_ctx *find_ust_app_context(struct lttng_ht *ht,
						struct lttng_ust_context_attr *uctx)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_ulong *node;
	struct ust_app_ctx *app_ctx = nullptr;

	LTTNG_ASSERT(uctx);
	LTTNG_ASSERT(ht);
	ASSERT_RCU_READ_LOCKED();

	/* Lookup using the lttng_ust_context_type and a custom match fct. */
	cds_lfht_lookup(ht->ht,
			ht->hash_fct((void *) uctx->ctx, lttng_ht_seed),
			ht_match_ust_app_ctx,
			uctx,
			&iter.iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_ulong>(&iter);
	if (!node) {
		goto end;
	}

	app_ctx = lttng::utils::container_of(node, &ust_app_ctx::node);

end:
	return app_ctx;
}

/*
 * Create a context for the channel on the tracer.
 *
 * Called with UST app session lock held and a RCU read side lock.
 */
int create_ust_app_channel_context(struct ust_app_channel *ua_chan,
				   struct lttng_ust_context_attr *uctx,
				   lsu::app *app,
				   const lttng::sessiond::config::context_configuration& ctx_config)
{
	int ret = 0;
	struct ust_app_ctx *ua_ctx;

	ASSERT_RCU_READ_LOCKED();

	DBG2("UST app adding context to channel %s", ua_chan->name);

	ua_ctx = find_ust_app_context(ua_chan->ctx, uctx);
	if (ua_ctx) {
		ret = -EEXIST;
		goto error;
	}

	ua_ctx = alloc_ust_app_ctx(uctx, ctx_config);
	if (ua_ctx == nullptr) {
		/* malloc failed */
		ret = -ENOMEM;
		goto error;
	}

	lttng_ht_node_init_ulong(&ua_ctx->node, (unsigned long) ua_ctx->ctx.ctx);
	lttng_ht_add_ulong(ua_chan->ctx, &ua_ctx->node);

	ret = create_ust_channel_context(ua_chan, ua_ctx, app);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Enable on the tracer side a ust app event for the session and channel.
 *
 * Called with UST app session lock held.
 */
int enable_ust_app_event(struct ust_app_event *ua_event, lsu::app *app)
{
	int ret;

	ret = enable_ust_object(app, ua_event->obj);
	if (ret < 0) {
		goto error;
	}

	ua_event->enabled = true;

error:
	return ret;
}

/*
 * Disable on the tracer side a ust app event for the session and channel.
 */
int disable_ust_app_event(struct ust_app_event *ua_event, lsu::app *app)
{
	int ret;

	ret = disable_ust_object(app, ua_event->obj);
	if (ret < 0) {
		goto error;
	}

	ua_event->enabled = false;

error:
	return ret;
}

/*
 * Lookup ust app channel for session and disable it on the tracer side.
 */
int disable_ust_app_channel(const lsu::app_session::locked_weak_ref& ua_sess,
			    struct ust_app_channel *ua_chan,
			    lsu::app *app)
{
	int ret;

	ret = disable_ust_channel(app, ua_sess, ua_chan);
	if (ret < 0) {
		goto error;
	}

	ua_chan->enabled = false;

error:
	return ret;
}

/*
 * Lookup ust app channel for session and enable it on the tracer side. This
 * MUST be called with a RCU read side lock acquired.
 */
int enable_ust_app_channel(const lsu::app_session::locked_weak_ref& ua_sess,
			   lttng::c_string_view channel_name,
			   lsu::app *app)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app_channel *ua_chan;

	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(ua_sess->channels, (void *) channel_name.data(), &iter);
	ua_chan_node = lttng_ht_iter_get_node<lttng_ht_node_str>(&iter);
	if (ua_chan_node == nullptr) {
		DBG2("Unable to find channel %s in ust session id %" PRIu64,
		     channel_name.data(),
		     ua_sess->recording_session_id);
		goto error;
	}

	ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

	ret = enable_ust_channel(app, ua_sess, ua_chan);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Ask the consumer to create a channel and get it if successful.
 *
 * Called with UST app session lock held.
 *
 * Return 0 on success or else a negative value.
 */
int do_consumer_create_channel(struct consumer_output *consumer,
			       lsu::app_session *ua_sess,
			       struct ust_app_channel *ua_chan,
			       int bitness,
			       lsu::trace_class *registry,
			       struct lttng_trace_chunk *current_trace_chunk,
			       enum lttng_trace_format trace_format)
{
	int ret;
	unsigned int nb_fd = 0;
	struct consumer_socket *socket;

	LTTNG_ASSERT(consumer);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(registry);

	const lttng::urcu::read_lock_guard read_lock;
	health_code_update();

	/* Get the right consumer socket for the application. */
	socket = consumer_find_socket_by_bitness(bitness, consumer);
	if (!socket) {
		ret = -EINVAL;
		goto error;
	}

	health_code_update();

	/* Need one fd for the channel. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 1);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon create channel");
		goto error;
	}

	/*
	 * Ask consumer to create channel. The consumer will return the number of
	 * stream we have to expect.
	 */
	ret = ust_consumer_ask_channel(
		ua_sess, ua_chan, consumer, socket, registry, current_trace_chunk, trace_format);
	if (ret < 0) {
		goto error_ask;
	}

	/*
	 * Compute the number of fd needed before receiving them. It must be 2 per
	 * stream (2 being the default value here).
	 */
	nb_fd = DEFAULT_UST_STREAM_FD_NUM * ua_chan->expected_stream_count;

	/* Reserve the amount of file descriptor we need. */
	ret = lttng_fd_get(LTTNG_FD_APPS, nb_fd);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon create channel");
		goto error_fd_get_stream;
	}

	health_code_update();

	/*
	 * Now get the channel from the consumer. This call will populate the stream
	 * list of that channel and set the ust objects.
	 */
	if (consumer->enabled) {
		ret = ust_consumer_get_channel(socket, ua_chan);
		if (ret < 0) {
			goto error_destroy;
		}
	}

	return 0;

error_destroy:
	lttng_fd_put(LTTNG_FD_APPS, nb_fd);
error_fd_get_stream:
	/*
	 * Initiate a destroy channel on the consumer since we had an error
	 * handling it on our side. The return value is of no importance since we
	 * already have a ret value set by the previous error that we need to
	 * return.
	 */
	(void) ust_consumer_destroy_channel(socket, ua_chan);
error_ask:
	lttng_fd_put(LTTNG_FD_APPS, 1);
error:
	health_code_update();
	return ret;
}

/*
 * Send a per-UID stream group's channel and streams to the application by
 * duplicating the master objects held by the stream group.
 *
 * In per-UID mode, the stream group holds the "master" channel and stream
 * objects obtained from the consumer daemon when the first application
 * created the shared buffers. Each subsequent application receives
 * duplicated copies of these objects.
 *
 * Return 0 on success else a negative value.
 */
int send_channel_uid_to_ust(lsu::stream_group& stream_group,
			    lsu::app *app,
			    lsu::app_session *ua_sess,
			    struct ust_app_channel *ua_chan)
{
	int ret;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);

	DBG("UST app sending stream group channel to ust sock %d", app->sock);

	/* Duplicate the master channel object for this application. */
	{
		try {
			auto duplicated_channel = stream_group.duplicate_channel_object();
			ua_chan->obj = duplicated_channel.release();
		} catch (const std::exception& ex) {
			ERR("Failed to duplicate channel object for app pid %d: %s",
			    app->pid,
			    ex.what());
			ret = -ENOMEM;
			goto error;
		}

		ua_chan->handle = ua_chan->obj->header.handle;
	}

	/* Send channel to the application. */
	ret = ust_consumer_send_channel_to_ust(app, ua_sess, ua_chan);
	if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
		ret = -ENOTCONN; /* Caused by app exiting. */
		goto error;
	} else if (ret == -EAGAIN) {
		/* Caused by timeout. */
		WARN("Communication with application %d timed out on send_channel for channel \"%s\" of session \"%" PRIu64
		     "\".",
		     app->pid,
		     ua_chan->name,
		     ua_sess->recording_session_id);
		/* Treat this the same way as an application that is exiting. */
		ret = -ENOTCONN;
		goto error;
	} else if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Send all streams to application by duplicating from the stream group. */
	for (const auto& stream_ptr : stream_group.streams()) {
		lsu::app_stream app_stream = {};

		try {
			auto duplicated_stream = stream_ptr->handle.duplicate();
			app_stream.obj = duplicated_stream.release();
		} catch (const std::exception& ex) {
			ERR("Failed to duplicate stream object for app pid %d: %s",
			    app->pid,
			    ex.what());
			ret = -ENOMEM;
			goto error;
		}

		app_stream.handle = app_stream.obj->header.handle;

		ret = ust_consumer_send_stream_to_ust(app, ua_chan, &app_stream);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				ret = -ENOTCONN; /* Caused by app exiting. */
			} else if (ret == -EAGAIN) {
				WARN("Communication with application %d timed out on send_stream for stream of channel \"%s\" of session \"%" PRIu64
				     "\".",
				     app->pid,
				     ua_chan->name,
				     ua_sess->recording_session_id);
				ret = -ENOTCONN;
			}
			(void) release_ust_app_stream(-1, &app_stream, app);
			goto error;
		}

		(void) release_ust_app_stream(-1, &app_stream, app);
	}

error:
	return ret;
}

/*
 * Create UST app event and create it on the tracer side.
 *
 * Must be called with the RCU read side lock held.
 * Called with ust app session mutex held.
 */
int create_ust_app_event(struct ust_app_channel *ua_chan,
			 lsu::app *app,
			 const lttng::sessiond::config::event_rule_configuration& event_config)
{
	int ret = 0;
	struct ust_app_event *ua_event;

	ASSERT_RCU_READ_LOCKED();

	ua_event = alloc_ust_app_event(event_config);
	if (ua_event == nullptr) {
		/* Only failure mode of alloc_ust_app_event(). */
		ret = -ENOMEM;
		goto end;
	}
	shadow_copy_event(ua_event);

	/* Create it on the tracer side */
	ret = create_ust_event(app, ua_chan, ua_event);
	if (ret < 0) {
		if (ret == -LTTNG_UST_ERR_EXIST) {
			ERR("Tracer for application reported that an event being created already existed: "
			    "event_name = \"%s\", pid = %d, ppid = %d, uid = %d, gid = %d",
			    ua_event->attr.name,
			    app->pid,
			    app->ppid,
			    app->uid,
			    app->gid);
		}
		goto error;
	}

	add_unique_ust_app_event(ua_chan, ua_event);

	DBG2("UST app create event completed: app = '%s' pid = %d", app->name, app->pid);

end:
	return ret;

error:
	/* Valid. Calling here is already in a read side lock */
	delete_ust_app_event(-1, ua_event, app);
	return ret;
}

/*
 * Create UST app event notifier rule and create it on the tracer side.
 *
 * Must be called with the RCU read side lock held.
 * Called with ust app session mutex held.
 */
static int create_ust_app_event_notifier_rule(struct lttng_trigger *trigger, lsu::app *app)
{
	int ret = 0;
	struct ust_app_event_notifier_rule *ua_event_notifier_rule;

	ASSERT_RCU_READ_LOCKED();

	ua_event_notifier_rule = alloc_ust_app_event_notifier_rule(trigger);
	if (ua_event_notifier_rule == nullptr) {
		ret = -ENOMEM;
		goto end;
	}

	/* Create it on the tracer side. */
	ret = create_ust_event_notifier(app, ua_event_notifier_rule);
	if (ret < 0) {
		/*
		 * Not found previously means that it does not exist on the
		 * tracer. If the application reports that the event existed,
		 * it means there is a bug in the sessiond or lttng-ust
		 * (or corruption, etc.)
		 */
		if (ret == -LTTNG_UST_ERR_EXIST) {
			ERR("Tracer for application reported that an event notifier being created already exists: "
			    "token = \"%" PRIu64 "\", pid = %d, ppid = %d, uid = %d, gid = %d",
			    lttng_trigger_get_tracer_token(trigger),
			    app->pid,
			    app->ppid,
			    app->uid,
			    app->gid);
		}
		goto error;
	}

	lttng_ht_add_unique_u64(app->token_to_event_notifier_rule_ht,
				&ua_event_notifier_rule->node);

	DBG2("UST app create token event rule completed: app = '%s', pid = %d, token = %" PRIu64,
	     app->name,
	     app->pid,
	     lttng_trigger_get_tracer_token(trigger));

	goto end;

error:
	/* The RCU read side lock is already being held by the caller. */
	delete_ust_app_event_notifier_rule(-1, ua_event_notifier_rule, app);
end:
	return ret;
}

/*
 * Create UST metadata and open it on the tracer side.
 *
 * Called with UST app session lock held and RCU read side lock.
 */
int create_ust_app_metadata(const lsu::app_session::locked_weak_ref& ua_sess,
			    lsu::app *app,
			    struct consumer_output *consumer,
			    const ltt_session& session)
{
	int ret = 0;
	struct ust_app_channel *metadata;
	struct consumer_socket *socket;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(consumer);
	ASSERT_RCU_READ_LOCKED();

	auto locked_registry = get_locked_session_registry(ua_sess->get_identifier());
	/* The UST app session is held registry shall not be null. */
	LTTNG_ASSERT(locked_registry);

	ASSERT_LOCKED(session._lock);

	const auto& metadata_config =
		session.get_domain(lttng::domain_class::USER_SPACE).metadata_channel();

	/* Metadata already exists for this registry or it was closed previously */
	if (locked_registry->_metadata_key || locked_registry->_metadata_closed) {
		ret = 0;
		goto error;
	}

	/* Allocate UST metadata */
	metadata = alloc_ust_app_metadata_channel(DEFAULT_METADATA_NAME, ua_sess, metadata_config);
	if (!metadata) {
		/* malloc() failed */
		ret = -ENOMEM;
		goto error;
	}

	memcpy(&metadata->attr, &ua_sess->metadata_attr, sizeof(metadata->attr));

	/* Need one fd for the channel. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 1);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon create metadata");
		goto error;
	}

	/* Get the right consumer socket for the application. */
	socket = consumer_find_socket_by_bitness(app->abi.bits_per_long, consumer);
	if (!socket) {
		ret = -EINVAL;
		goto error_consumer;
	}

	/*
	 * Keep metadata key so we can identify it on the consumer side. Assign it
	 * to the registry *before* we ask the consumer so we avoid the race of the
	 * consumer requesting the metadata and the ask_channel call on our side
	 * did not returned yet.
	 */
	locked_registry->_metadata_key = metadata->key;

	/*
	 * Ask the metadata channel creation to the consumer. The metadata object
	 * will be created by the consumer and kept their. However, the stream is
	 * never added or monitored until we do a first push metadata to the
	 * consumer.
	 */
	ret = ust_consumer_ask_channel(&ua_sess.get(),
				       metadata,
				       consumer,
				       socket,
				       locked_registry.locked_ref().get(),
				       session.current_trace_chunk,
				       session.trace_format);
	if (ret < 0) {
		/* Nullify the metadata key so we don't try to close it later on. */
		locked_registry->_metadata_key = 0;
		goto error_consumer;
	}

	/*
	 * The setup command will make the metadata stream be sent to the relayd,
	 * if applicable, and the thread managing the metadatas. This is important
	 * because after this point, if an error occurs, the only way the stream
	 * can be deleted is to be monitored in the consumer.
	 */
	ret = consumer_setup_metadata(socket, metadata->key);
	if (ret < 0) {
		/* Nullify the metadata key so we don't try to close it later on. */
		locked_registry->_metadata_key = 0;
		goto error_consumer;
	}

	DBG2("UST metadata with key %" PRIu64 " created for app pid %d", metadata->key, app->pid);

error_consumer:
	lttng_fd_put(LTTNG_FD_APPS, 1);
	delete_ust_app_channel(-1, metadata, app, locked_registry.locked_ref());
error:
	return ret;
}

/*
 * Return ust app pointer or nullopt if not found. RCU read side lock MUST be
 * acquired before calling this function.
 */
nonstd::optional<ust_app_reference> ust_app_find_by_pid(pid_t pid)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	lttng_ht_lookup(ust_app_ht, (void *) ((unsigned long) pid), &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_ulong>(&iter);
	if (node == nullptr) {
		DBG2("UST app no found with pid %d", pid);
		return nonstd::nullopt;
	}

	DBG2("Found UST app by pid %d", pid);

	auto raw_app = lttng::utils::container_of(node, &lsu::app::pid_n);
	return ust_app_get(*raw_app) ? nonstd::make_optional(ust_app_reference{ raw_app }) :
				       nonstd::nullopt;
}

/*
 * Allocate and init an UST app object using the registration information and
 * the command socket. This is called when the command socket connects to the
 * session daemon.
 *
 * The object is returned on success or else NULL.
 */
lsu::app *ust_app_create(struct ust_register_msg *msg, int sock)
{
	int ret;
	lsu::app *lta = nullptr;
	struct lttng_pipe *event_notifier_event_source_pipe = nullptr;

	LTTNG_ASSERT(msg);
	LTTNG_ASSERT(sock >= 0);

	DBG3("UST app creating application for socket %d", sock);

	if ((msg->bits_per_long == 64 && (uatomic_read(&the_ust_consumerd64_fd) == -EINVAL)) ||
	    (msg->bits_per_long == 32 && (uatomic_read(&the_ust_consumerd32_fd) == -EINVAL))) {
		ERR("Registration failed: application \"%s\" (pid: %d) has "
		    "%d-bit long, but no consumerd for this size is available.\n",
		    msg->name,
		    msg->pid,
		    msg->bits_per_long);
		goto error;
	}

	/*
	 * Reserve the two file descriptors of the event source pipe. The write
	 * end will be closed once it is passed to the application, at which
	 * point a single 'put' will be performed.
	 */
	ret = lttng_fd_get(LTTNG_FD_APPS, 2);
	if (ret) {
		ERR("Failed to reserve two file descriptors for the event source pipe while creating a new application instance: app = '%s', pid = %d",
		    msg->name,
		    (int) msg->pid);
		goto error;
	}

	event_notifier_event_source_pipe = lttng_pipe_open(FD_CLOEXEC);
	if (!event_notifier_event_source_pipe) {
		PERROR("Failed to open application event source pipe: '%s' (pid = %d)",
		       msg->name,
		       msg->pid);
		goto error;
	}

	try {
		lta = new lsu::app;
	} catch (const std::bad_alloc&) {
		ERR_FMT("Failed to allocate ust application instance: name=`{}`, pid={}, uid={}",
			msg->name,
			msg->pid,
			msg->uid);
		goto error_free_pipe;
	}

	urcu_ref_init(&lta->ref);

	lta->event_notifier_group.event_pipe = event_notifier_event_source_pipe;

	lta->ppid = msg->ppid;
	lta->uid = msg->uid;
	lta->gid = msg->gid;

	lta->abi = {
		.bits_per_long = msg->bits_per_long,
		.long_alignment = msg->long_alignment,
		.uint8_t_alignment = msg->uint8_t_alignment,
		.uint16_t_alignment = msg->uint16_t_alignment,
		.uint32_t_alignment = msg->uint32_t_alignment,
		.uint64_t_alignment = msg->uint64_t_alignment,
		.byte_order = msg->byte_order == LITTLE_ENDIAN ?
			lttng::sessiond::trace::byte_order::LITTLE_ENDIAN_ :
			lttng::sessiond::trace::byte_order::BIG_ENDIAN_,
	};

	lta->v_major = msg->major;
	lta->v_minor = msg->minor;
	lta->sessions = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	lta->ust_objd = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	lta->ust_sessions_objd = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	lta->notify_sock = -1;
	lta->token_to_event_notifier_rule_ht = lttng_ht_new(0, LTTNG_HT_TYPE_U64);

	/* Copy name and make sure it's NULL terminated. */
	strncpy(lta->name, msg->name, sizeof(lta->name));
	lta->name[UST_APP_PROCNAME_LEN] = '\0';

	/*
	 * Before this can be called, when receiving the registration information,
	 * the application compatibility is checked. So, at this point, the
	 * application can work with this session daemon.
	 */
	lta->compatible = 1;

	lta->pid = msg->pid;
	lttng_ht_node_init_ulong(&lta->pid_n, (unsigned long) lta->pid);
	lta->sock = sock;
	pthread_mutex_init(&lta->sock_lock, nullptr);
	lttng_ht_node_init_ulong(&lta->sock_n, (unsigned long) lta->sock);

	if (ust_app_allocate_owner_id(*lta) != OWNER_ID_ALLOCATION_STATUS_OK) {
		ERR_FMT("Failed to allocate unique owner identity for application: name=`{}`, pid={}, uid={}",
			msg->name,
			msg->pid,
			msg->uid);
		goto error_free_app;
	}

	return lta;

error_free_app:
	delete lta;
error_free_pipe:
	lttng_pipe_destroy(event_notifier_event_source_pipe);
	lttng_fd_put(LTTNG_FD_APPS, 2);
error:
	return nullptr;
}

/*
 * For a given application object, add it to every hash table.
 */
void ust_app_add(lsu::app *app)
{
	LTTNG_ASSERT(app);
	LTTNG_ASSERT(app->notify_sock >= 0);

	app->registration_time = time(nullptr);

	const lttng::urcu::read_lock_guard read_lock;

	/*
	 * On a re-registration, we want to kick out the previous registration of
	 * that pid
	 */
	lttng_ht_add_replace_ulong(ust_app_ht, &app->pid_n);

	/*
	 * The socket _should_ be unique until _we_ call close. So, a add_unique
	 * for the ust_app_ht_by_sock is used which asserts fail if the entry was
	 * already in the table.
	 */
	lttng_ht_add_unique_ulong(ust_app_ht_by_sock, &app->sock_n);

	/* Add application to the notify socket hash table. */
	lttng_ht_node_init_ulong(&app->notify_sock_n, app->notify_sock);
	lttng_ht_add_unique_ulong(ust_app_ht_by_notify_sock, &app->notify_sock_n);

	DBG("App registered with pid:%d ppid:%d uid:%d gid:%d sock =%d name:%s "
	    "notify_sock =%d (version %d.%d)",
	    app->pid,
	    app->ppid,
	    app->uid,
	    app->gid,
	    app->sock,
	    app->name,
	    app->notify_sock,
	    app->v_major,
	    app->v_minor);
}

/*
 * Set the application version into the object.
 *
 * Return 0 on success else a negative value either an errno code or a
 * LTTng-UST error code.
 */
int ust_app_version(lsu::app *app)
{
	int ret;

	LTTNG_ASSERT(app);

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_tracer_version(app->sock, &app->version);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -LTTNG_UST_ERR_EXITING || ret == -EPIPE) {
			DBG3("UST app version failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app version failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app version failed with ret %d: pid = %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
		}
	}

	return ret;
}

bool ust_app_supports_notifiers(const lsu::app *app)
{
	return app->v_major >= 9;
}

bool ust_app_supports_counters(const lsu::app *app)
{
	return app->v_major >= 9;
}

void ust_app_notify_reclaimed_owner_ids(const std::vector<uint32_t>& owners)
{
	for (const auto owner : owners) {
		owner_id_reclamations.unmark_owner_id(owner);
	}
}

/*
 * Setup the base event notifier group.
 *
 * Return 0 on success else a negative value either an errno code or a
 * LTTng-UST error code.
 */
int ust_app_setup_event_notifier_group(lsu::app *app)
{
	int ret;
	int event_pipe_write_fd;
	struct lttng_ust_abi_object_data *event_notifier_group = nullptr;
	enum lttng_error_code lttng_ret;
	enum event_notifier_error_accounting_status event_notifier_error_accounting_status;

	LTTNG_ASSERT(app);

	if (!ust_app_supports_notifiers(app)) {
		ret = -ENOSYS;
		goto error;
	}

	/* Get the write side of the pipe. */
	event_pipe_write_fd = lttng_pipe_get_writefd(app->event_notifier_group.event_pipe);

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_create_event_notifier_group(
		app->sock, event_pipe_write_fd, &event_notifier_group);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			ret = 0;
			DBG3("UST app create event notifier group failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			ret = 0;
			WARN("UST app create event notifier group failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app create event notifier group failed with ret %d: pid = %d, sock = %d, event_pipe_write_fd: %d",
			    ret,
			    app->pid,
			    app->sock,
			    event_pipe_write_fd);
		}
		goto error;
	}

	ret = lttng_pipe_write_close(app->event_notifier_group.event_pipe);
	if (ret) {
		ERR("Failed to close write end of the application's event source pipe: app = '%s' (pid = %d)",
		    app->name,
		    app->pid);
		goto error;
	}

	/*
	 * Release the file descriptor that was reserved for the write-end of
	 * the pipe.
	 */
	lttng_fd_put(LTTNG_FD_APPS, 1);

	lttng_ret = notification_thread_command_add_tracer_event_source(
		the_notification_thread_handle,
		lttng_pipe_get_readfd(app->event_notifier_group.event_pipe),
		LTTNG_DOMAIN_UST);
	if (lttng_ret != LTTNG_OK) {
		ERR("Failed to add tracer event source to notification thread");
		ret = -1;
		goto error;
	}

	/* Assign handle only when the complete setup is valid. */
	app->event_notifier_group.object = event_notifier_group;

	event_notifier_error_accounting_status = event_notifier_error_accounting_register_app(app);
	switch (event_notifier_error_accounting_status) {
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK:
		break;
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_UNSUPPORTED:
		DBG3("Failed to setup event notifier error accounting (application does not support notifier error accounting): app socket fd = %d, app name = '%s', app pid = %d",
		     app->sock,
		     app->name,
		     (int) app->pid);
		ret = 0;
		goto error_accounting;
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD:
		DBG3("Failed to setup event notifier error accounting (application is dead): app socket fd = %d, app name = '%s', app pid = %d",
		     app->sock,
		     app->name,
		     (int) app->pid);
		ret = 0;
		goto error_accounting;
	default:
		ERR("Failed to setup event notifier error accounting for app");
		ret = -1;
		goto error_accounting;
	}

	return ret;

error_accounting:
	lttng_ret = notification_thread_command_remove_tracer_event_source(
		the_notification_thread_handle,
		lttng_pipe_get_readfd(app->event_notifier_group.event_pipe));
	if (lttng_ret != LTTNG_OK) {
		ERR("Failed to remove application tracer event source from notification thread");
	}

error:
	lttng_ust_ctl_release_object(app->sock, app->event_notifier_group.object);
	free(app->event_notifier_group.object);
	app->event_notifier_group.object = nullptr;
	return ret;
}

static void ust_app_unregister(lsu::app& app)
{
	const lttng::urcu::read_lock_guard read_lock;

	DBG_FMT("Unregistering application and building list "
		"of channels used by the application for "
		"owner id reclamation: "
		"app_name=`{}`, app_pid={}, app_uid={}",
		app.name,
		app.pid,
		app.uid);

	/*
	 * For per-PID buffers, perform "push metadata" and flush all
	 * application streams before removing app from hash tables,
	 * ensuring proper behavior of data_pending check.
	 *
	 * Sessions are removed from the hash table after the
	 * orchestrator maps have been cleaned up so that concurrent
	 * operations (e.g. rotation) can still look up the ua_sess
	 * for apps present in the orchestrator maps.
	 */
	for (auto *ua_sess :
	     lttng::urcu::lfht_iteration_adapter<lsu::app_session,
						 decltype(lsu::app_session::node),
						 &lsu::app_session::node>(*app.sessions->ht)) {
		if (ua_sess->buffer_type == LTTNG_BUFFER_PER_PID) {
			(void) ust_app_flush_app_session(app, *ua_sess);
		}

		/*
		 * Add session to list for teardown. This is safe since at this point we
		 * are the only one using this list.
		 */
		auto locked_ua_sess = ua_sess->lock();

		if (ua_sess->deleted) {
			continue;
		}

		/*
		 * Normally, this is done in the delete session process which is
		 * executed in the call rcu below. However, upon registration we can't
		 * afford to wait for the grace period before pushing data or else the
		 * data pending feature can race between the unregistration and stop
		 * command where the data pending command is sent *before* the grace
		 * period ended.
		 *
		 * The close metadata below nullifies the metadata pointer in the
		 * session so the delete session will NOT push/close a second time.
		 */
		uint64_t metadata_key_to_close = 0;
		unsigned int consumer_bitness_to_close = 0;
		struct consumer_output *consumer_to_close = nullptr;

		auto locked_registry =
			get_locked_session_registry(locked_ua_sess->get_identifier());
		if (locked_registry) {
			/* Push metadata for application before freeing the application. */
			(void) push_metadata(locked_registry.locked_ref(), ua_sess->consumer);

			/*
			 * Don't ask to close metadata for global per UID buffers. Close
			 * metadata only on destroy trace session in this case. Also, the
			 * previous push metadata could have flag the metadata registry to
			 * close so don't send a close command if closed.
			 */
			if (ua_sess->buffer_type != LTTNG_BUFFER_PER_UID) {
				metadata_key_to_close = locked_registry->_metadata_key;
				consumer_bitness_to_close = locked_registry->abi.bits_per_long;
				consumer_to_close = ua_sess->consumer;

				if (!locked_registry->_metadata_closed &&
				    metadata_key_to_close != 0) {
					locked_registry->_metadata_closed = true;
				}
			}

			locked_registry.reset();
		}

		/*
		 * Remove the app session from the orchestrator's parallel
		 * index and, for per-PID buffers, release the per-PID
		 * stream groups and trace class. This happens BEFORE
		 * closing metadata on the consumer and before removing
		 * the session from the hash table, all while holding the
		 * recording session lock.
		 *
		 * Holding the recording session lock across the entire
		 * sequence (orchestrator cleanup, hash table removal, and
		 * metadata close) ensures mutual exclusion with the
		 * rotation/clear path (cmd_clear_session ->
		 * for_each_consumer_stream_group), which holds the same
		 * lock. Either the unregistration completes first (entries
		 * removed, metadata closed: the clear sees nothing to
		 * rotate for this app) or the clear completes first (all
		 * entries are still present and properly rotated before
		 * removal).
		 *
		 * Without this, a window exists where the orchestrator
		 * entries are removed but the consumer channels are still
		 * open. A concurrent clear during that window would omit
		 * these streams from the rotation command sent to the relay,
		 * causing the live viewer to stay on the old (deleted) trace
		 * chunk and observe an INDEX_ERR.
		 *
		 * The session lock and reference obtained from
		 * find_locked_session are managed manually (via
		 * locked_ref::release) rather than through the locked_ref
		 * RAII wrapper. This is necessary because:
		 *
		 *  - The session list lock must NOT be held during the
		 *    consumer I/O (close_metadata) to avoid contention.
		 *
		 *  - The session lock must NOT be held while acquiring the
		 *    session list lock, as that would invert the established
		 *    lock ordering (list lock -> session lock) and deadlock
		 *    with the client thread.
		 *
		 *  - locked_ref's destructor calls session_put() which
		 *    asserts the session list lock, so it cannot be
		 *    destroyed outside the list lock scope.
		 *
		 * The sequence is:
		 *
		 *  1. Acquire list lock, find and lock the session, do
		 *     orchestrator cleanup, transfer ownership via
		 *     release(), release list lock.
		 *
		 *  2. Hash table removal and close_metadata under the
		 *     session lock only (no list lock).
		 *
		 *  3. Unlock the session, then acquire the list lock and
		 *     call session_put() (preserving list -> session order).
		 *
		 * Between session_unlock and session_put (step 3), the
		 * session object remains alive because the reference from
		 * find_locked_session (via session_get) has not yet been
		 * released.
		 *
		 * The remaining per-app cleanup (channel deletion, UST
		 * handle release, etc.) is deferred to
		 * delete_ust_app_session() in the RCU callback.
		 */
		ltt_session *recording_session = nullptr;

		{
			const auto list_lock = lttng::sessiond::lock_session_list();

			try {
				auto locked_session = ltt_session::find_locked_session(
					ua_sess->recording_session_id);

				LTTNG_ASSERT(locked_session->ust_orchestrator);

				auto& orchestrator = static_cast<lsu::domain_orchestrator&>(
					locked_session->get_ust_orchestrator());

				orchestrator.on_app_departure(app);

				recording_session = &*locked_session;
				locked_session.release();
			} catch (const lttng::sessiond::exceptions::session_not_found_error&) {
				/*
				 * Session already gone; orchestrator destroyed
				 * with it (_app_sessions cleaned up in the
				 * orchestrator destructor).
				 */
			}
		}

		/*
		 * Remove the session from the app's hash table after the
		 * orchestrator maps have been cleaned up. This ordering
		 * ensures that create_channel_subdirectories() (which looks
		 * up ua_sess via ust_app_lookup_app_session under the
		 * session lock) can find the ua_sess for any app still
		 * present in the orchestrator's per-PID maps.
		 */
		{
			const auto del_ret = cds_lfht_del(app.sessions->ht, &ua_sess->node.node);
			LTTNG_ASSERT(del_ret == 0);
		}

		if (consumer_to_close) {
			(void) close_metadata(metadata_key_to_close,
					      consumer_bitness_to_close,
					      consumer_to_close);
		}

		/*
		 * Release the recording session lock, then the reference.
		 * Unlocking before acquiring the list lock preserves the
		 * lock ordering (list lock -> session lock).
		 */
		if (recording_session) {
			session_unlock(recording_session);

			const auto list_lock = lttng::sessiond::lock_session_list();
			session_put(recording_session);
		}

		const auto pending_reclamations =
			consumer_reclaim_session_owner_id(*ua_sess, app.owner_id_n.key);

		/*
		 * Add the UST app owner ID to the set of pending reclamation
		 * IDs with the number of reclamations sent back from the
		 * consumer. The ID will be removed later once the consumer can
		 * confirm that all channels used by the UST app are not stalled
		 * because of the UST app.
		 */
		owner_id_reclamations.mark_owner_id(app.owner_id_n.key, pending_reclamations);

		app.sessions_to_teardown.emplace_back(ua_sess);
	}

	/*
	 * Remove application from notify hash table. The thread handling the
	 * notify socket could have deleted the node so ignore on error because
	 * either way it's valid. The close of that socket is handled by the
	 * apps_notify_thread.
	 */
	(void) cds_lfht_del(ust_app_ht_by_notify_sock->ht, &app.notify_sock_n.node);

	/*
	 * Ignore return value since the node might have been removed before by an
	 * add replace during app registration because the PID can be reassigned by
	 * the OS.
	 */
	if (cds_lfht_del(ust_app_ht->ht, &app.pid_n.node)) {
		DBG3("Unregister app by PID %d failed. This can happen on pid reuse", app.pid);
	}
}

/*
 * Unregister app by removing it from the global traceable app list and freeing
 * the data struct.
 *
 * The socket is already closed at this point, so there is no need to close it.
 */
void ust_app_unregister_by_socket(int sock_fd)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter ust_app_sock_iter;
	int ret;

	const lttng::urcu::read_lock_guard read_lock;

	/* Get the node reference for a call_rcu */
	lttng_ht_lookup(ust_app_ht_by_sock, (void *) ((unsigned long) sock_fd), &ust_app_sock_iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_ulong>(&ust_app_sock_iter);
	assert(node);

	auto *app = lttng::utils::container_of(node, &lsu::app::sock_n);

	DBG_FMT("Application unregistering after socket activity: app={}, socket_fd={}",
		*app,
		sock_fd);

	/* Remove application from socket hash table */
	ret = lttng_ht_del(ust_app_ht_by_sock, &ust_app_sock_iter);
	assert(!ret);

	/*
	 * The socket is closed: release its reference to the application
	 * to trigger its eventual teardown.
	 */
	ust_app_put(app);
}

/*
 * Fill events array with all events name of all registered apps.
 */
int ust_app_list_events(struct lttng_event **events)
{
	int ret, handle;
	size_t nbmem, count = 0;
	struct lttng_event *tmp_event;

	nbmem = UST_APP_EVENT_LIST_SIZE;
	tmp_event = calloc<lttng_event>(nbmem);
	if (tmp_event == nullptr) {
		PERROR("zmalloc ust app events");
		ret = -ENOMEM;
		goto error;
	}

	/* Iterate on all apps. */
	for (auto *app : lttng::urcu::lfht_iteration_adapter<lsu::app,
							     decltype(lsu::app::pid_n),
							     &lsu::app::pid_n>(*ust_app_ht->ht)) {
		struct lttng_ust_abi_tracepoint_iter uiter;

		health_code_update();

		if (!ust_app_get(*app)) {
			/* Application unregistered concurrently, skip it. */
			DBG("Could not get application reference as it is being torn down; skipping application");
			continue;
		}

		/* Prevent app teardown during use. */
		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}

		pthread_mutex_lock(&app->sock_lock);
		handle = lttng_ust_ctl_tracepoint_list(app->sock);
		if (handle < 0) {
			if (handle != -EPIPE && handle != -LTTNG_UST_ERR_EXITING) {
				ERR("UST app list events getting handle failed for app pid %d",
				    app->pid);
			}
			pthread_mutex_unlock(&app->sock_lock);
			continue;
		}

		while ((ret = lttng_ust_ctl_tracepoint_list_get(app->sock, handle, &uiter)) !=
		       -LTTNG_UST_ERR_NOENT) {
			/* Handle ustctl error. */
			if (ret < 0) {
				int release_ret;

				if (ret != -LTTNG_UST_ERR_EXITING && ret != -EPIPE) {
					ERR("UST app tp list get failed for app %d with ret %d",
					    app->sock,
					    ret);
				} else {
					DBG3("UST app tp list get failed. Application is dead");
					break;
				}

				free(tmp_event);
				release_ret = lttng_ust_ctl_release_handle(app->sock, handle);
				if (release_ret < 0 && release_ret != -LTTNG_UST_ERR_EXITING &&
				    release_ret != -EPIPE) {
					ERR("Error releasing app handle for app %d with ret %d",
					    app->sock,
					    release_ret);
				}

				pthread_mutex_unlock(&app->sock_lock);
				goto error;
			}

			health_code_update();
			if (count >= nbmem) {
				/* In case the realloc fails, we free the memory */
				struct lttng_event *new_tmp_event;
				size_t new_nbmem;

				new_nbmem = nbmem << 1;
				DBG2("Reallocating event list from %zu to %zu entries",
				     nbmem,
				     new_nbmem);
				new_tmp_event = (lttng_event *) realloc(
					tmp_event, new_nbmem * sizeof(struct lttng_event));
				if (new_tmp_event == nullptr) {
					int release_ret;

					PERROR("realloc ust app events");
					free(tmp_event);
					ret = -ENOMEM;
					release_ret =
						lttng_ust_ctl_release_handle(app->sock, handle);
					if (release_ret < 0 &&
					    release_ret != -LTTNG_UST_ERR_EXITING &&
					    release_ret != -EPIPE) {
						ERR("Error releasing app handle for app %d with ret %d",
						    app->sock,
						    release_ret);
					}

					pthread_mutex_unlock(&app->sock_lock);
					goto error;
				}
				/* Zero the new memory */
				memset(new_tmp_event + nbmem,
				       0,
				       (new_nbmem - nbmem) * sizeof(struct lttng_event));
				nbmem = new_nbmem;
				tmp_event = new_tmp_event;
			}

			memcpy(tmp_event[count].name, uiter.name, LTTNG_UST_ABI_SYM_NAME_LEN);
			tmp_event[count].loglevel = uiter.loglevel;
			tmp_event[count].type = (enum lttng_event_type) LTTNG_UST_ABI_TRACEPOINT;
			tmp_event[count].pid = app->pid;
			tmp_event[count].enabled = -1;
			count++;
		}

		ret = lttng_ust_ctl_release_handle(app->sock, handle);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("Error releasing app handle. Application died: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else if (ret == -EAGAIN) {
				WARN("Error releasing app handle. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->sock);
			} else {
				ERR("Error releasing app handle with ret %d: pid = %d, sock = %d",
				    ret,
				    app->pid,
				    app->sock);
			}
		}
	}

	ret = count;
	*events = tmp_event;

	DBG2("UST app list events done (%zu events)", count);

error:
	health_code_update();
	return ret;
}

/*
 * Fill events array with all events name of all registered apps.
 */
int ust_app_list_event_fields(struct lttng_event_field **fields)
{
	int ret, handle;
	size_t nbmem, count = 0;
	struct lttng_event_field *tmp_event;

	nbmem = UST_APP_EVENT_LIST_SIZE;
	tmp_event = calloc<lttng_event_field>(nbmem);
	if (tmp_event == nullptr) {
		PERROR("zmalloc ust app event fields");
		ret = -ENOMEM;
		goto error;
	}

	/* Iterate on all apps. */
	for (auto *app : lttng::urcu::lfht_iteration_adapter<lsu::app,
							     decltype(lsu::app::pid_n),
							     &lsu::app::pid_n>(*ust_app_ht->ht)) {
		struct lttng_ust_abi_field_iter uiter;

		health_code_update();

		if (!ust_app_get(*app)) {
			/* Application unregistered concurrently, skip it. */
			DBG("Could not get application reference as it is being torn down; skipping application");
			continue;
		}
		/* Prevent app teardown during use. */
		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			/*
			 * TODO: In time, we should notice the caller of this error by
			 * telling him that this is a version error.
			 */
			continue;
		}

		pthread_mutex_lock(&app->sock_lock);
		handle = lttng_ust_ctl_tracepoint_field_list(app->sock);
		if (handle < 0) {
			if (handle != -EPIPE && handle != -LTTNG_UST_ERR_EXITING) {
				ERR("UST app list field getting handle failed for app pid %d",
				    app->pid);
			}
			pthread_mutex_unlock(&app->sock_lock);
			continue;
		}

		while ((ret = lttng_ust_ctl_tracepoint_field_list_get(app->sock, handle, &uiter)) !=
		       -LTTNG_UST_ERR_NOENT) {
			/* Handle ustctl error. */
			if (ret < 0) {
				int release_ret;

				if (ret != -LTTNG_UST_ERR_EXITING && ret != -EPIPE) {
					ERR("UST app tp list field failed for app %d with ret %d",
					    app->sock,
					    ret);
				} else {
					DBG3("UST app tp list field failed. Application is dead");
					break;
				}

				free(tmp_event);
				release_ret = lttng_ust_ctl_release_handle(app->sock, handle);
				pthread_mutex_unlock(&app->sock_lock);
				if (release_ret < 0 && release_ret != -LTTNG_UST_ERR_EXITING &&
				    release_ret != -EPIPE) {
					ERR("Error releasing app handle for app %d with ret %d",
					    app->sock,
					    release_ret);
				}

				goto error;
			}

			health_code_update();
			if (count >= nbmem) {
				/* In case the realloc fails, we free the memory */
				struct lttng_event_field *new_tmp_event;
				size_t new_nbmem;

				new_nbmem = nbmem << 1;
				DBG2("Reallocating event field list from %zu to %zu entries",
				     nbmem,
				     new_nbmem);
				new_tmp_event = (lttng_event_field *) realloc(
					tmp_event, new_nbmem * sizeof(struct lttng_event_field));
				if (new_tmp_event == nullptr) {
					int release_ret;

					PERROR("realloc ust app event fields");
					free(tmp_event);
					ret = -ENOMEM;
					release_ret =
						lttng_ust_ctl_release_handle(app->sock, handle);
					pthread_mutex_unlock(&app->sock_lock);
					if (release_ret && release_ret != -LTTNG_UST_ERR_EXITING &&
					    release_ret != -EPIPE) {
						ERR("Error releasing app handle for app %d with ret %d",
						    app->sock,
						    release_ret);
					}

					goto error;
				}

				/* Zero the new memory */
				memset(new_tmp_event + nbmem,
				       0,
				       (new_nbmem - nbmem) * sizeof(struct lttng_event_field));
				nbmem = new_nbmem;
				tmp_event = new_tmp_event;
			}

			memcpy(tmp_event[count].field_name,
			       uiter.field_name,
			       LTTNG_UST_ABI_SYM_NAME_LEN);
			/* Mapping between these enums matches 1 to 1. */
			tmp_event[count].type = (enum lttng_event_field_type) uiter.type;
			tmp_event[count].nowrite = uiter.nowrite;

			memcpy(tmp_event[count].event.name,
			       uiter.event_name,
			       LTTNG_UST_ABI_SYM_NAME_LEN);
			tmp_event[count].event.loglevel = uiter.loglevel;
			tmp_event[count].event.type = LTTNG_EVENT_TRACEPOINT;
			tmp_event[count].event.pid = app->pid;
			tmp_event[count].event.enabled = -1;
			count++;
		}

		ret = lttng_ust_ctl_release_handle(app->sock, handle);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0 && ret != -LTTNG_UST_ERR_EXITING && ret != -EPIPE) {
			ERR("Error releasing app handle for app %d with ret %d", app->sock, ret);
		}
	}

	ret = count;
	*fields = tmp_event;

	DBG2("UST app list event fields done (%zu events)", count);

error:
	health_code_update();
	return ret;
}

/*
 * Free and clean all traceable apps of the global list.
 */
void ust_app_clean_list()
{
	int ret;
	DBG2("UST app cleaning registered apps hash table");

	/* Cleanup notify socket hash table */
	if (ust_app_ht_by_notify_sock) {
		for (auto *app :
		     lttng::urcu::lfht_iteration_adapter<lsu::app,
							 decltype(lsu::app::notify_sock_n),
							 &lsu::app::notify_sock_n>(
			     *ust_app_ht_by_notify_sock->ht)) {
			if (!ust_app_get(*app)) {
				/* Application unregistered concurrently, skip it. */
				DBG("Could not get application reference as it is being torn down; skipping application");
				continue;
			}
			/* Prevent app teardown during use. */
			const ust_app_reference app_ref(app);

			/*
			 * Assert that all notifiers are gone as all triggers
			 * are unregistered prior to this clean-up.
			 */
			LTTNG_ASSERT(lttng_ht_get_count(app->token_to_event_notifier_rule_ht) == 0);
			ust_app_notify_sock_unregister(app->notify_sock);
		}
	}

	/* Cleanup socket hash table */
	if (ust_app_ht_by_sock) {
		const lttng::urcu::read_lock_guard read_lock;

		for (auto *app : lttng::urcu::lfht_iteration_adapter<lsu::app,
								     decltype(lsu::app::sock_n),
								     &lsu::app::sock_n>(
			     *ust_app_ht_by_sock->ht)) {
			if (!ust_app_get(*app)) {
				/* Application unregistered concurrently, skip it. */
				DBG("Could not get application reference as it is being torn down; skipping application");
				continue;
			}
			/* Prevent app teardown during use. */
			const ust_app_reference app_ref(app);

			ret = cds_lfht_del(ust_app_ht_by_sock->ht, &app->sock_n.node);
			LTTNG_ASSERT(!ret);
			/*
			 * Release socket reference to the application to trigger its eventual
			 * teardown.
			 */
			ust_app_put(app);
		}
	}

	/*
	 * The application management thread, which normally processes
	 * deferred unregistration commands, has been joined by this
	 * point. Drain any commands it did not get to process, as well
	 * as those enqueued by the ust_app_put() calls above, so that
	 * applications are fully removed from the remaining hash tables
	 * before they are destroyed.
	 */
	if (the_app_unregistration_queue) {
		namespace lam = lttng::sessiond::app_management;

		while (auto cmd = the_app_unregistration_queue->try_pop()) {
			switch (cmd->type) {
			case lam::command_type::UNREGISTER_AND_DESTROY_APP:
				LTTNG_ASSERT(cmd->app);
				ust_app_unregister_and_destroy(*cmd->app);
				break;
			}
		}
	}

	/*
	 * Ensure all call_rcu callbacks (queued by ust_app_destroy
	 * during unregistration) complete before destroying the hash
	 * tables they may still reference.
	 */
	rcu_barrier();

	/* Destroy is done only when the ht is empty */
	if (ust_app_ht) {
		lttng_ht_destroy(ust_app_ht);
	}
	if (ust_app_ht_by_sock) {
		lttng_ht_destroy(ust_app_ht_by_sock);
	}
	if (ust_app_ht_by_notify_sock) {
		lttng_ht_destroy(ust_app_ht_by_notify_sock);
	}
	if (ust_app_ht_by_owner_id) {
		lttng_ht_destroy(ust_app_ht_by_owner_id);
	}
}

/*
 * Init UST app hash table.
 */
int ust_app_ht_alloc()
{
	ust_app_ht = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!ust_app_ht) {
		return -1;
	}
	ust_app_ht_by_sock = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!ust_app_ht_by_sock) {
		return -1;
	}
	ust_app_ht_by_notify_sock = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	if (!ust_app_ht_by_notify_sock) {
		return -1;
	}
	ust_app_ht_by_owner_id = lttng_ht_new(0, LTTNG_HT_TYPE_U64);
	if (!ust_app_ht_by_owner_id) {
		return -1;
	}
	return 0;
}

int ust_app_disable_event_on_apps(
	lsu::domain_orchestrator& orchestrator,
	lttng::c_string_view channel_name,
	const lttng::sessiond::config::event_rule_configuration& event_rule_config)
{
	return ust_app_session_operations::disable_event_on_apps(
		orchestrator, channel_name, event_rule_config);
}

/*
 * Determine if the ust-context 'uctx' is redundant for the ust-channel 'uchan'.
 *
 * This is used to avoid sending a context registration to UST. However, it
 * should not be used for filtering context to be added internally by the
 * session daemon.
 *
 * The rationale here is that some contexts are provided implicitly by some
 * channels.
 *
 * LTTNG_UST_ABI_CHAN_PER_CPU:
 *   LTTNG_UST_ABI_CONTEXT_CPU_ID:
 *     The CPU ID is implicitly provided in the packer header.
 */
/*
 * Config-based overload: determines whether a context is redundant
 * based on the channel configuration's buffer allocation policy.
 */
bool is_context_redundant(
	const lttng::sessiond::config::recording_channel_configuration& chan_config,
	const lttng::sessiond::config::context_configuration& ctx_config)
{
	namespace lsc = lttng::sessiond::config;

	if (chan_config.buffer_allocation_policy ==
	    lsc::recording_channel_configuration::buffer_allocation_policy_t::PER_CPU) {
		if (ctx_config.context_type == lsc::context_configuration::type::CPU_ID) {
			return true;
		}
	}

	return false;
}

static int ust_app_flush_app_session(lsu::app& app, lsu::app_session& ua_sess)
{
	int ret, retval = 0;
	struct consumer_socket *socket;

	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	DBG("Flushing app session buffers for ust app pid %d", app.pid);

	if (!app.compatible) {
		return 0;
	}

	const auto locked_ua_sess = ua_sess.lock();
	if (locked_ua_sess->deleted) {
		return 0;
	}

	health_code_update();

	/* Flushing buffers */
	socket = consumer_find_socket_by_bitness(app.abi.bits_per_long, ua_sess.consumer);

	/* Flush buffers and push metadata. */
	switch (ua_sess.buffer_type) {
	case LTTNG_BUFFER_PER_PID:
	{
		for (auto *ua_chan :
		     lttng::urcu::lfht_iteration_adapter<ust_app_channel,
							 decltype(ust_app_channel::node),
							 &ust_app_channel::node>(
			     *ua_sess.channels->ht)) {
			health_code_update();
			ret = consumer_flush_channel(socket, ua_chan->key);
			if (ret) {
				ERR("Error flushing consumer channel");
				retval = -1;
				continue;
			}
		}

		break;
	}
	case LTTNG_BUFFER_PER_UID:
	default:
		abort();
		break;
	}

	return retval;
}

/*
 * Destroy a specific UST session in apps.
 */
static int destroy_trace(std::uint64_t session_id, lsu::app *app)
{
	int ret;
	lsu::app_session *ua_sess;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;

	DBG("Destroy tracing for ust app pid %d", app->pid);

	const lttng::urcu::read_lock_guard read_lock;

	if (!app->compatible) {
		goto end;
	}

	__lookup_session_by_app(session_id, app, &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_u64>(&iter);
	if (node == nullptr) {
		/* Session is being or is deleted. */
		goto end;
	}
	ua_sess = lttng::utils::container_of(node, &lsu::app_session::node);

	health_code_update();
	destroy_app_session(app, ua_sess);

	health_code_update();

	/* Quiescent wait after stopping trace */
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_wait_quiescent(app->sock);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app wait quiescent failed. Application is dead: pid= %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app wait quiescent failed. Communication time out: pid= %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app wait quiescent failed with ret %d: pid= %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
		}
	}
end:
	health_code_update();
	return 0;
}

/*
 * Destroy app UST session.
 */
int ust_app_destroy_trace_all(std::uint64_t session_id)
{
	DBG("Destroy all UST traces");

	/* Iterate on all apps. */
	for (auto *app : lttng::urcu::lfht_iteration_adapter<lsu::app,
							     decltype(lsu::app::pid_n),
							     &lsu::app::pid_n>(*ust_app_ht->ht)) {
		if (!ust_app_get(*app)) {
			/* Application unregistered concurrently, skip it. */
			DBG("Could not get application reference as it is being torn down; skipping application");
			continue;
		}
		/* Prevent app teardown during use. */
		const ust_app_reference app_ref(app);

		(void) destroy_trace(session_id, app);
	}

	return 0;
}

/* Called with RCU read-side lock held. */
static void ust_app_synchronize_event_notifier_rules(lsu::app *app)
{
	int ret = 0;
	enum lttng_error_code ret_code;
	enum lttng_trigger_status t_status;
	struct lttng_triggers *triggers = nullptr;
	unsigned int count, i;

	ASSERT_RCU_READ_LOCKED();

	if (!ust_app_supports_notifiers(app)) {
		goto end;
	}

	/*
	 * Currrently, registering or unregistering a trigger with an
	 * event rule condition causes a full synchronization of the event
	 * notifiers.
	 *
	 * The first step attempts to add an event notifier for all registered
	 * triggers that apply to the user space tracers. Then, the
	 * application's event notifiers rules are all checked against the list
	 * of registered triggers. Any event notifier that doesn't have a
	 * matching trigger can be assumed to have been disabled.
	 *
	 * All of this is inefficient, but is put in place to get the feature
	 * rolling as it is simpler at this moment. It will be optimized Soon™
	 * to allow the state of enabled
	 * event notifiers to be synchronized in a piece-wise way.
	 */

	/* Get all triggers using uid 0 (root) */
	ret_code = notification_thread_command_list_triggers(
		the_notification_thread_handle, 0, &triggers);
	if (ret_code != LTTNG_OK) {
		goto end;
	}

	LTTNG_ASSERT(triggers);

	t_status = lttng_triggers_get_count(triggers, &count);
	if (t_status != LTTNG_TRIGGER_STATUS_OK) {
		goto end;
	}

	for (i = 0; i < count; i++) {
		const struct lttng_condition *condition;
		const struct lttng_event_rule *event_rule;
		struct lttng_trigger *trigger;
		const struct ust_app_event_notifier_rule *looked_up_event_notifier_rule;
		enum lttng_condition_status condition_status;
		uint64_t token;

		trigger = lttng_triggers_borrow_mutable_at_index(triggers, i);
		LTTNG_ASSERT(trigger);

		token = lttng_trigger_get_tracer_token(trigger);
		condition = lttng_trigger_get_const_condition(trigger);

		if (lttng_condition_get_type(condition) !=
		    LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES) {
			/* Does not apply */
			continue;
		}

		condition_status =
			lttng_condition_event_rule_matches_get_rule(condition, &event_rule);
		LTTNG_ASSERT(condition_status == LTTNG_CONDITION_STATUS_OK);

		if (lttng_event_rule_get_domain_type(event_rule) == LTTNG_DOMAIN_KERNEL) {
			/* Skip kernel related triggers. */
			continue;
		}

		/*
		 * Find or create the associated token event rule. The caller
		 * holds the RCU read lock, so this is safe to call without
		 * explicitly acquiring it here.
		 */
		looked_up_event_notifier_rule = find_ust_app_event_notifier_rule(
			app->token_to_event_notifier_rule_ht, token);
		if (!looked_up_event_notifier_rule) {
			ret = create_ust_app_event_notifier_rule(trigger, app);
			if (ret < 0) {
				goto end;
			}
		}
	}

	/* Remove all unknown event sources from the app. */
	for (auto *event_notifier_rule :
	     lttng::urcu::lfht_iteration_adapter<ust_app_event_notifier_rule,
						 decltype(ust_app_event_notifier_rule::node),
						 &ust_app_event_notifier_rule::node>(
		     *app->token_to_event_notifier_rule_ht->ht)) {
		const uint64_t app_token = event_notifier_rule->token;
		bool found = false;

		/*
		 * Check if the app event trigger still exists on the
		 * notification side.
		 */
		for (i = 0; i < count; i++) {
			uint64_t notification_thread_token;
			const struct lttng_trigger *trigger =
				lttng_triggers_get_at_index(triggers, i);

			LTTNG_ASSERT(trigger);

			notification_thread_token = lttng_trigger_get_tracer_token(trigger);

			if (notification_thread_token == app_token) {
				found = true;
				break;
			}
		}

		if (found) {
			/* Still valid. */
			continue;
		}

		/*
		 * This trigger was unregistered, disable it on the tracer's
		 * side.
		 */
		ret = cds_lfht_del(app->token_to_event_notifier_rule_ht->ht,
				   &event_notifier_rule->node.node);
		LTTNG_ASSERT(ret == 0);

		/* Callee logs errors. */
		(void) disable_ust_object(app, event_notifier_rule->obj);
		delete_ust_app_event_notifier_rule(app->sock, event_notifier_rule, app);
	}

end:
	lttng_triggers_destroy(triggers);
	return;
}

void ust_app_global_destroy(std::uint64_t session_id, lsu::app *app)
{
	lsu::app_session *ua_sess;

	ua_sess = ust_app_lookup_app_session(session_id, app);
	if (ua_sess == nullptr) {
		return;
	}
	destroy_app_session(app, ua_sess);
}

/*
 * Add all event notifiers to an application.
 *
 * Called with session lock held.
 * Called with RCU read-side lock held.
 */
void ust_app_global_update_event_notifier_rules(lsu::app *app)
{
	ASSERT_RCU_READ_LOCKED();

	DBG2("UST application global event notifier rules update: app = '%s', pid = %d",
	     app->name,
	     app->pid);

	if (!app->compatible || !ust_app_supports_notifiers(app)) {
		return;
	}

	if (app->event_notifier_group.object == nullptr) {
		WARN("UST app global update of event notifiers for app skipped since communication handle is null: app = '%s', pid = %d",
		     app->name,
		     app->pid);
		return;
	}

	ust_app_synchronize_event_notifier_rules(app);
}

void ust_app_global_update_all_event_notifier_rules()
{
	/* Iterate on all apps. */
	for (auto *app : lttng::urcu::lfht_iteration_adapter<lsu::app,
							     decltype(lsu::app::pid_n),
							     &lsu::app::pid_n>(*ust_app_ht->ht)) {
		if (!ust_app_get(*app)) {
			/* Application unregistered concurrently, skip it. */
			DBG("Could not get application reference as it is being torn down; skipping application");
			continue;
		}
		/* Prevent app teardown during use. */
		const ust_app_reference app_ref(app);

		ust_app_global_update_event_notifier_rules(app);
	}
}

/*
 * Receive registration and populate the given msg structure.
 *
 * On success return 0 else a negative value returned by the ustctl call.
 */
int ust_app_recv_registration(int sock, struct ust_register_msg *msg)
{
	int ret;
	uint32_t pid, ppid, uid, gid;

	LTTNG_ASSERT(msg);

	ret = lttng_ust_ctl_recv_reg_msg(sock,
					 &msg->type,
					 &msg->major,
					 &msg->minor,
					 &pid,
					 &ppid,
					 &uid,
					 &gid,
					 &msg->bits_per_long,
					 &msg->uint8_t_alignment,
					 &msg->uint16_t_alignment,
					 &msg->uint32_t_alignment,
					 &msg->uint64_t_alignment,
					 &msg->long_alignment,
					 &msg->byte_order,
					 msg->name);
	if (ret < 0) {
		switch (-ret) {
		case EPIPE:
		case ECONNRESET:
		case LTTNG_UST_ERR_EXITING:
			DBG3("UST app recv reg message failed. Application died");
			break;
		case LTTNG_UST_ERR_UNSUP_MAJOR:
			ERR("UST app recv reg unsupported version %d.%d. Supporting %d.%d",
			    msg->major,
			    msg->minor,
			    LTTNG_UST_ABI_MAJOR_VERSION,
			    LTTNG_UST_ABI_MINOR_VERSION);
			break;
		default:
			ERR("UST app recv reg message failed with ret %d", ret);
			break;
		}
		goto error;
	}
	msg->pid = (pid_t) pid;
	msg->ppid = (pid_t) ppid;
	msg->uid = (uid_t) uid;
	msg->gid = (gid_t) gid;

error:
	return ret;
}

/*
 * Return a ust app session object using the application object and the
 * session object descriptor has a key. If not found, NULL is returned.
 * A RCU read side lock MUST be acquired when calling this function.
 */
static lsu::app_session *find_session_by_objd(lsu::app *app, int objd)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	lsu::app_session *ua_sess = nullptr;

	LTTNG_ASSERT(app);
	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(app->ust_sessions_objd, (void *) ((unsigned long) objd), &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_ulong>(&iter);
	if (node == nullptr) {
		DBG2("UST app session find by objd %d not found", objd);
		goto error;
	}

	ua_sess = lttng::utils::container_of(node, &lsu::app_session::ust_objd_node);

error:
	return ua_sess;
}

/*
 * Return a ust app channel object using the application object and the channel
 * object descriptor has a key. If not found, NULL is returned. A RCU read side
 * lock MUST be acquired before calling this function.
 */
static struct ust_app_channel *find_channel_by_objd(lsu::app *app, int objd)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct ust_app_channel *ua_chan = nullptr;

	LTTNG_ASSERT(app);
	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(app->ust_objd, (void *) ((unsigned long) objd), &iter);
	node = lttng_ht_iter_get_node<lttng_ht_node_ulong>(&iter);
	if (node == nullptr) {
		DBG2("UST app channel find by objd %d not found", objd);
		goto error;
	}

	ua_chan = lttng::utils::container_of(node, &ust_app_channel::ust_objd_node);

error:
	return ua_chan;
}

/*
 * Reply to a register channel notification from an application on the notify
 * socket. The channel metadata is also created.
 *
 * The session UST registry lock is acquired in this function.
 *
 * On success 0 is returned else a negative value.
 */
static int handle_app_register_channel_notification(int sock,
						    int cobjd,
						    struct lttng_ust_ctl_field *raw_context_fields,
						    size_t context_field_count)
{
	int ret, ret_code = 0;
	uint32_t chan_id;
	uint64_t chan_reg_key;
	struct ust_app_channel *ua_chan;
	lsu::app_session *ua_sess;
	auto ust_ctl_context_fields =
		lttng::make_unique_wrapper<lttng_ust_ctl_field, lttng::memory::free>(
			raw_context_fields);

	const lttng::urcu::read_lock_guard read_lock_guard;

	/* Lookup application. If not found, there is a code flow error. */
	auto app = find_app_by_notify_sock(sock);
	if (!app) {
		DBG("Application socket %d is being torn down. Abort event notify", sock);
		return -1;
	}

	/* Lookup channel by UST object descriptor. */
	ua_chan = find_channel_by_objd(app->get(), cobjd);
	if (!ua_chan) {
		DBG("Application channel is being torn down. Abort event notify");
		return 0;
	}

	LTTNG_ASSERT(ua_chan->session);
	ua_sess = ua_chan->session;

	/* Get right session registry depending on the session buffer type. */

	/*
	 * HACK: ua_sess is already locked by the client thread. This is called
	 * in the context of the handling of a notification from the application.
	 */
	auto locked_ua_sess = lsu::app_session::make_locked_weak_ref(*ua_sess);
	auto locked_trace_class = get_locked_session_registry(locked_ua_sess->get_identifier());
	locked_ua_sess.release();
	if (!locked_trace_class) {
		DBG("Application session is being torn down. Abort event notify");
		return 0;
	};

	/* Depending on the buffer type, a different channel key is used. */
	if (ua_sess->buffer_type == LTTNG_BUFFER_PER_UID) {
		chan_reg_key = ua_chan->trace_class_stream_class_handle;
	} else {
		chan_reg_key = ua_chan->key;
	}

	auto& ust_reg_chan = locked_trace_class->channel(chan_reg_key);

	/* Channel id is set during the object creation. */
	chan_id = ust_reg_chan.id;

	/*
	 * The application returns the typing information of the channel's
	 * context fields. In per-PID buffering mode, this is the first and only
	 * time we get this information. It is our chance to finalize the
	 * initialiation of the channel and serialize it's layout's description
	 * to the trace's metadata.
	 *
	 * However, in per-UID buffering mode, every application will provide
	 * this information (redundantly). The first time will allow us to
	 * complete the initialization. The following times, we simply validate
	 * that all apps provide the same typing for the context fields as a
	 * sanity check.
	 */
	try {
		auto app_context_fields = lsu::create_trace_fields_from_ust_ctl_fields(
			*locked_trace_class,
			ust_ctl_context_fields.get(),
			context_field_count,
			lst::field_location::root::EVENT_RECORD_COMMON_CONTEXT,
			lsu::ctl_field_quirks::UNDERSCORE_PREFIXED_VARIANT_TAG_MAPPINGS);

		if (!ust_reg_chan.is_registered()) {
			lst::type::cuptr event_context = app_context_fields.size() ?
				lttng::make_unique<lst::structure_type>(
					0, std::move(app_context_fields)) :
				nullptr;

			ust_reg_chan.event_context(std::move(event_context));
		} else {
			/*
			 * Validate that the context fields match between
			 * registry and newcoming application.
			 */
			bool context_fields_match;
			const auto *previous_event_context = ust_reg_chan.event_context();

			if (!previous_event_context) {
				context_fields_match = app_context_fields.size() == 0;
			} else {
				const lst::structure_type app_event_context_struct(
					0, std::move(app_context_fields));

				context_fields_match = *previous_event_context ==
					app_event_context_struct;
			}

			if (!context_fields_match) {
				ERR("Registering application channel due to context field mismatch: pid = %d, sock = %d",
				    (*app)->pid,
				    (*app)->sock);
				ret_code = -EINVAL;
				goto reply;
			}
		}
	} catch (const std::exception& ex) {
		ERR("Failed to handle application context: %s", ex.what());
		ret_code = -EINVAL;
		goto reply;
	}

reply:
	DBG3("UST app replying to register channel key %" PRIu64 " with id %u, ret = %d",
	     chan_reg_key,
	     chan_id,
	     ret_code);

	ret = lttng_ust_ctl_reply_register_channel(
		sock,
		chan_id,
		ust_reg_chan.header_type_ == lst::stream_class::header_type::COMPACT ?
			LTTNG_UST_CTL_CHANNEL_HEADER_COMPACT :
			LTTNG_UST_CTL_CHANNEL_HEADER_LARGE,
		ret_code);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app reply channel failed. Application died: pid = %d, sock = %d",
			     (*app)->pid,
			     (*app)->sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app reply channel failed. Communication time out: pid = %d, sock = %d",
			     (*app)->pid,
			     (*app)->sock);
		} else {
			ERR("UST app reply channel failed with ret %d: pid = %d, sock = %d",
			    ret,
			    (*app)->pid,
			    (*app)->sock);
		}

		return ret;
	}

	/* This channel registry's registration is completed. */
	ust_reg_chan.set_as_registered();

	return ret;
}

/*
 * Add event to the UST channel registry. When the event is added to the
 * registry, the metadata is also created. Once done, this replies to the
 * application with the appropriate error code.
 *
 * The session UST registry lock is acquired in the function.
 *
 * On success 0 is returned else a negative value.
 */
static int add_event_ust_registry(int sock,
				  int sobjd,
				  int cobjd,
				  const char *name,
				  char *raw_signature,
				  size_t nr_fields,
				  struct lttng_ust_ctl_field *raw_fields,
				  int loglevel_value,
				  char *raw_model_emf_uri)
{
	int ret, ret_code;
	lsu::event_id event_id = 0;
	uint64_t chan_reg_key;
	struct ust_app_channel *ua_chan;
	lsu::app_session *ua_sess;
	const lttng::urcu::read_lock_guard rcu_lock;
	auto signature = lttng::make_unique_wrapper<char, lttng::memory::free>(raw_signature);
	auto fields =
		lttng::make_unique_wrapper<lttng_ust_ctl_field, lttng::memory::free>(raw_fields);
	auto model_emf_uri =
		lttng::make_unique_wrapper<char, lttng::memory::free>(raw_model_emf_uri);

	/* Lookup application. If not found, there is a code flow error. */
	auto app = find_app_by_notify_sock(sock);
	if (!app) {
		DBG("Application socket %d is being torn down. Abort event notify", sock);
		return -1;
	}

	/* Lookup channel by UST object descriptor. */
	ua_chan = find_channel_by_objd(app->get(), cobjd);
	if (!ua_chan) {
		DBG("Application channel is being torn down. Abort event notify");
		return 0;
	}

	LTTNG_ASSERT(ua_chan->session);
	ua_sess = ua_chan->session;

	if (ua_sess->buffer_type == LTTNG_BUFFER_PER_UID) {
		chan_reg_key = ua_chan->trace_class_stream_class_handle;
	} else {
		chan_reg_key = ua_chan->key;
	}

	{
		auto locked_registry = get_locked_session_registry(ua_sess->get_identifier());
		if (locked_registry) {
			/*
			 * From this point on, this call acquires the ownership of the signature,
			 * fields and model_emf_uri meaning any free are done inside it if needed.
			 * These three variables MUST NOT be read/write after this.
			 */
			try {
				auto& channel = locked_registry->channel(chan_reg_key);

				/* id is set on success. */
				channel.add_event(
					sobjd,
					cobjd,
					name,
					signature.get(),
					lsu::create_trace_fields_from_ust_ctl_fields(
						*locked_registry,
						fields.get(),
						nr_fields,
						lst::field_location::root::EVENT_RECORD_PAYLOAD,
						lsu::ctl_field_quirks::
							UNDERSCORE_PREFIXED_VARIANT_TAG_MAPPINGS),
					loglevel_value,
					model_emf_uri.get() ?
						nonstd::optional<std::string>(model_emf_uri.get()) :
						nonstd::nullopt,
					ua_sess->buffer_type,
					**app,
					event_id);
				ret_code = 0;
			} catch (const std::exception& ex) {
				ERR("Failed to add event `%s` to registry session: %s",
				    name,
				    ex.what());
				/* Inform the application of the error; don't return directly. */
				ret_code = -EINVAL;
			}
		} else {
			DBG("Application session is being torn down. Abort event notify");
			return 0;
		}
	}

	/*
	 * The return value is returned to ustctl so in case of an error, the
	 * application can be notified. In case of an error, it's important not to
	 * return a negative error or else the application will get closed.
	 */
	ret = lttng_ust_ctl_reply_register_event(sock, event_id, ret_code);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app reply event failed. Application died: pid = %d, sock = %d.",
			     (*app)->pid,
			     (*app)->sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app reply event failed. Communication time out: pid = %d, sock = %d",
			     (*app)->pid,
			     (*app)->sock);
		} else {
			ERR("UST app reply event failed with ret %d: pid = %d, sock = %d",
			    ret,
			    (*app)->pid,
			    (*app)->sock);
		}
		/*
		 * No need to wipe the create event since the application socket will
		 * get close on error hence cleaning up everything by itself.
		 */
		return ret;
	}

	DBG_FMT("UST registry event successfully added: name={}, id={}", name, event_id);
	return ret;
}

/*
 * Add enum to the UST session registry. Once done, this replies to the
 * application with the appropriate error code.
 *
 * The session UST registry lock is acquired within this function.
 *
 * On success 0 is returned else a negative value.
 */
static int add_enum_ust_registry(int sock,
				 int sobjd,
				 const char *name,
				 struct lttng_ust_ctl_enum_entry *raw_entries,
				 size_t nr_entries)
{
	int ret = 0;
	lsu::app_session *ua_sess;
	uint64_t enum_id = -1ULL;
	const lttng::urcu::read_lock_guard read_lock_guard;
	auto entries =
		lttng::make_unique_wrapper<struct lttng_ust_ctl_enum_entry, lttng::memory::free>(
			raw_entries);

	/* Lookup application. If not found, there is a code flow error. */
	auto app = find_app_by_notify_sock(sock);
	if (!app) {
		/* Return an error since this is not an error */
		DBG("Application socket %d is being torn down. Aborting enum registration", sock);
		return -1;
	}

	/* Lookup session by UST object descriptor. */
	ua_sess = find_session_by_objd(app->get(), sobjd);
	if (!ua_sess) {
		/* Return an error since this is not an error */
		DBG("Application session is being torn down (session not found). Aborting enum registration.");
		return 0;
	}

	auto locked_registry = get_locked_session_registry(ua_sess->get_identifier());
	if (!locked_registry) {
		DBG("Application session is being torn down (registry not found). Aborting enum registration.");
		return 0;
	}

	/*
	 * From this point on, the callee acquires the ownership of
	 * entries. The variable entries MUST NOT be read/written after
	 * call.
	 */
	int application_reply_code;
	try {
		locked_registry->create_or_find_enum(
			sobjd, name, entries.release(), nr_entries, &enum_id);
		application_reply_code = 0;
	} catch (const std::exception& ex) {
		ERR("%s: %s",
		    lttng::format(
			    "Failed to create or find enumeration provided by application: app = {}, enumeration name = {}",
			    **app,
			    name)
			    .c_str(),
		    ex.what());
		application_reply_code = -1;
	}

	/*
	 * The return value is returned to ustctl so in case of an error, the
	 * application can be notified. In case of an error, it's important not to
	 * return a negative error or else the application will get closed.
	 */
	ret = lttng_ust_ctl_reply_register_enum(sock, enum_id, application_reply_code);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app reply enum failed. Application died: pid = %d, sock = %d",
			     (*app)->pid,
			     (*app)->sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app reply enum failed. Communication time out: pid = %d, sock = %d",
			     (*app)->pid,
			     (*app)->sock);
		} else {
			ERR("UST app reply enum failed with ret %d: pid = %d, sock = %d",
			    ret,
			    (*app)->pid,
			    (*app)->sock);
		}
		/*
		 * No need to wipe the create enum since the application socket will
		 * get close on error hence cleaning up everything by itself.
		 */
		return ret;
	}

	DBG3("UST registry enum %s added successfully or already found", name);
	return 0;
}

/*
 * Handle application notification through the given notify socket.
 *
 * Return 0 on success or else a negative value.
 */
int ust_app_recv_notify(int sock)
{
	int ret;
	enum lttng_ust_ctl_notify_cmd cmd;

	DBG3("UST app receiving notify from sock %d", sock);

	ret = lttng_ust_ctl_recv_notify(sock, &cmd);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app recv notify failed. Application died: sock = %d", sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app recv notify failed. Communication time out: sock = %d", sock);
		} else {
			ERR("UST app recv notify failed with ret %d: sock = %d", ret, sock);
		}
		goto error;
	}

	switch (cmd) {
	case LTTNG_UST_CTL_NOTIFY_CMD_EVENT:
	{
		int sobjd, cobjd, loglevel_value;
		char name[LTTNG_UST_ABI_SYM_NAME_LEN], *sig, *model_emf_uri;
		size_t nr_fields;
		uint64_t tracer_token = 0;
		struct lttng_ust_ctl_field *fields;

		DBG2("UST app ustctl register event received");

		ret = lttng_ust_ctl_recv_register_event(sock,
							&sobjd,
							&cobjd,
							name,
							&loglevel_value,
							&sig,
							&nr_fields,
							&fields,
							&model_emf_uri,
							&tracer_token);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app recv event failed. Application died: sock = %d",
				     sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app recv event failed. Communication time out: sock = %d",
				     sock);
			} else {
				ERR("UST app recv event failed with ret %d: sock = %d", ret, sock);
			}
			goto error;
		}

		{
			const lttng::urcu::read_lock_guard rcu_lock;
			auto app = find_app_by_notify_sock(sock);
			if (!app) {
				DBG("Application socket %d is being torn down. Abort event notify",
				    sock);
				ret = -1;
				goto error;
			}
		}

		if ((!fields && nr_fields > 0) || (fields && nr_fields == 0)) {
			ERR("Invalid return value from lttng_ust_ctl_recv_register_event: fields = %p, nr_fields = %zu",
			    fields,
			    nr_fields);
			ret = -1;
			free(fields);
			goto error;
		}

		/*
		 * Add event to the UST registry coming from the notify socket. This
		 * call will free if needed the sig, fields and model_emf_uri. This
		 * code path loses the ownsership of these variables and transfer them
		 * to the this function.
		 */
		ret = add_event_ust_registry(sock,
					     sobjd,
					     cobjd,
					     name,
					     sig,
					     nr_fields,
					     fields,
					     loglevel_value,
					     model_emf_uri);
		if (ret < 0) {
			goto error;
		}

		break;
	}
	case LTTNG_UST_CTL_NOTIFY_CMD_CHANNEL:
	{
		int sobjd, cobjd;
		size_t field_count;
		struct lttng_ust_ctl_field *context_fields;

		DBG2("UST app ustctl register channel received");

		ret = lttng_ust_ctl_recv_register_channel(
			sock, &sobjd, &cobjd, &field_count, &context_fields);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app recv channel failed. Application died: sock = %d",
				     sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app recv channel failed. Communication time out: sock = %d",
				     sock);
			} else {
				ERR("UST app recv channel failed with ret %d: sock = %d",
				    ret,
				    sock);
			}
			goto error;
		}

		/*
		 * The fields ownership are transfered to this function call meaning
		 * that if needed it will be freed. After this, it's invalid to access
		 * fields or clean them up.
		 */
		ret = handle_app_register_channel_notification(
			sock, cobjd, context_fields, field_count);
		if (ret < 0) {
			goto error;
		}

		break;
	}
	case LTTNG_UST_CTL_NOTIFY_CMD_ENUM:
	{
		int sobjd;
		char name[LTTNG_UST_ABI_SYM_NAME_LEN];
		size_t nr_entries;
		struct lttng_ust_ctl_enum_entry *entries;

		DBG2("UST app ustctl register enum received");

		ret = lttng_ust_ctl_recv_register_enum(sock, &sobjd, name, &entries, &nr_entries);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app recv enum failed. Application died: sock = %d", sock);
			} else if (ret == -EAGAIN) {
				WARN("UST app recv enum failed. Communication time out: sock = %d",
				     sock);
			} else {
				ERR("UST app recv enum failed with ret %d: sock = %d", ret, sock);
			}
			goto error;
		}

		/* Callee assumes ownership of entries. */
		ret = add_enum_ust_registry(sock, sobjd, name, entries, nr_entries);
		if (ret < 0) {
			goto error;
		}

		break;
	}
	case LTTNG_UST_CTL_NOTIFY_CMD_KEY:
	{
		DBG2("UST app ustctl register key received");
		ret = -LTTNG_UST_ERR_NOSYS;
		goto error;
	}
	default:
		/* Should NEVER happen. */
		abort();
	}

error:
	return ret;
}

/*
 * Once the notify socket hangs up, this is called. First, it tries to find the
 * corresponding application. On failure, the call_rcu to close the socket is
 * executed. If an application is found, it tries to delete it from the notify
 * socket hash table. Whathever the result, it proceeds to the call_rcu.
 *
 * Note that an object needs to be allocated here so on ENOMEM failure, the
 * call RCU is not done but the rest of the cleanup is.
 */
void ust_app_notify_sock_unregister(int sock)
{
	int err_enomem = 0;
	struct lttng_ht_iter iter;
	struct ust_app_notify_sock_obj *obj;

	LTTNG_ASSERT(sock >= 0);

	const lttng::urcu::read_lock_guard read_lock;

	obj = zmalloc<ust_app_notify_sock_obj>();
	if (!obj) {
		/*
		 * An ENOMEM is kind of uncool. If this strikes we continue the
		 * procedure but the call_rcu will not be called. In this case, we
		 * accept the fd leak rather than possibly creating an unsynchronized
		 * state between threads.
		 *
		 * TODO: The notify object should be created once the notify socket is
		 * registered and stored independantely from the ust app object. The
		 * tricky part is to synchronize the teardown of the application and
		 * this notify object. Let's keep that in mind so we can avoid this
		 * kind of shenanigans with ENOMEM in the teardown path.
		 */
		err_enomem = 1;
	} else {
		obj->fd = sock;
	}

	DBG("UST app notify socket unregister %d", sock);

	/*
	 * Lookup application by notify socket. If this fails, this means that the
	 * hash table delete has already been done by the application
	 * unregistration process so we can safely close the notify socket in a
	 * call RCU.
	 */
	auto app = find_app_by_notify_sock(sock);
	if (!app) {
		goto close_socket;
	}

	iter.iter.node = &((*app)->notify_sock_n.node);

	/*
	 * Whatever happens here either we fail or succeed, in both cases we have
	 * to close the socket after a grace period to continue to the call RCU
	 * here. If the deletion is successful, the application is not visible
	 * anymore by other threads and is it fails it means that it was already
	 * deleted from the hash table so either way we just have to close the
	 * socket.
	 */
	(void) lttng_ht_del(ust_app_ht_by_notify_sock, &iter);

close_socket:

	/*
	 * Close socket after a grace period to avoid for the socket to be reused
	 * before the application object is freed creating potential race between
	 * threads trying to add unique in the global hash table.
	 */
	if (!err_enomem) {
		call_rcu(&obj->head, close_notify_sock_rcu);
	}
}

/*
 * Destroy a ust app data structure and free its memory.
 */
static void ust_app_destroy(lsu::app& app)
{
	ust_app_release_owner_id(app);
	call_rcu(&app.pid_n.head, delete_ust_app_rcu);
}

/*
 * Take a snapshot for a given UST session. The snapshot is sent to the given
 * output.
 *
 * Returns LTTNG_OK on success or a LTTNG_ERR error code.
 */
static int ust_app_regenerate_statedump(std::uint64_t session_id, lsu::app *app)
{
	int ret = 0;
	lsu::app_session *ua_sess;

	DBG("Regenerating the metadata for ust app pid %d", app->pid);

	const lttng::urcu::read_lock_guard read_lock;
	const auto update_health_code_on_exit =
		lttng::make_scope_exit([]() noexcept { health_code_update(); });

	ua_sess = ust_app_lookup_app_session(session_id, app);
	if (ua_sess == nullptr) {
		/* The session is in teardown process. Ignore and continue. */
		return 0;
	}

	const auto locked_ua_sess = ua_sess->lock();
	if (locked_ua_sess->deleted) {
		return 0;
	}

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_regenerate_statedump(app->sock, ua_sess->handle);
	pthread_mutex_unlock(&app->sock_lock);
	return ret;
}

/*
 * Regenerate the statedump for each app in the session.
 */
int ust_app_regenerate_statedump_all(std::uint64_t session_id)
{
	DBG("Regenerating the metadata for all UST apps");

	/* Iterate on all apps. */
	for (auto *app : lttng::urcu::lfht_iteration_adapter<lsu::app,
							     decltype(lsu::app::pid_n),
							     &lsu::app::pid_n>(*ust_app_ht->ht)) {
		if (!ust_app_get(*app)) {
			/* Application unregistered concurrently, skip it. */
			DBG("Could not get application reference as it is being torn down; skipping application");
			continue;
		}
		/* Prevent app teardown during use. */
		const ust_app_reference app_ref(app);

		if (!app->compatible) {
			continue;
		}

		(void) ust_app_regenerate_statedump(session_id, app);
	}

	return 0;
}

lsu::ctl_field_quirks lsu::app::ctl_field_quirks() const
{
	/*
	 * Application contexts are expressed as variants. LTTng-UST announces
	 * those by registering an enumeration named `..._tag`. It then registers a
	 * variant as part of the event context that contains the various possible
	 * types.
	 *
	 * Unfortunately, the names used in the enumeration and variant don't
	 * match: the enumeration names are all prefixed with an underscore while
	 * the variant type tag fields aren't.
	 *
	 * While the CTF 1.8.3 specification mentions that
	 * underscores *should* (not *must*) be removed by CTF readers. Babeltrace
	 * 1.x (and possibly others) expect a perfect match between the names used
	 * by tags and variants.
	 *
	 * When the UNDERSCORE_PREFIXED_VARIANT_TAG_MAPPINGS quirk is enabled,
	 * the variant's fields are modified to match the mappings of its tag.
	 *
	 * From ABI version >= 10.x, the variant fields and tag mapping names
	 * correctly match, making this quirk unnecessary.
	 */
	return v_major <= 9 ? lsu::ctl_field_quirks::UNDERSCORE_PREFIXED_VARIANT_TAG_MAPPINGS :
			      lsu::ctl_field_quirks::NONE;
}

static void ust_app_release(urcu_ref *ref)
{
	namespace lam = lttng::sessiond::app_management;

	auto& app = *lttng::utils::container_of(ref, &lsu::app::ref);

	the_app_unregistration_queue->send(
		lam::command(lam::command_type::UNREGISTER_AND_DESTROY_APP, app));
}

void ust_app_unregister_and_destroy(lsu::app& app)
{
	LTTNG_ASSERT(uatomic_read(&app.ref.refcount) == 0);
	ust_app_unregister(app);
	ust_app_destroy(app);
}

bool ust_app_get(lsu::app& app)
{
	return urcu_ref_get_unless_zero(&app.ref);
}

void ust_app_put(lsu::app *app)
{
	if (!app) {
		return;
	}

	urcu_ref_put(&app->ref, ust_app_release);
}

lttng_ht *ust_app_get_all()
{
	return ust_app_ht;
}
