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
#include "ust-app-channel.hpp"
#include "ust-app-event.hpp"
#include "ust-app.hpp"
#include "ust-consumer.hpp"
#include "ust-domain-orchestrator.hpp"
#include "ust-field-convert.hpp"
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
#include <exception>
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

enum owner_id_allocation_status {
	OWNER_ID_ALLOCATION_STATUS_OK,
	OWNER_ID_ALLOCATION_STATUS_FAIL,
};

struct lttng_ht *ust_app_ht;
struct lttng_ht *ust_app_ht_by_sock;
struct lttng_ht *ust_app_ht_by_notify_sock;
struct lttng_ht *ust_app_ht_by_owner_id;

namespace {
/*
 * Bundles a shared_ptr (ownership) with a locked_ref (lock) so that
 * the trace_class cannot be destroyed while the lock is held.
 *
 * Callers that need a `const locked_ref&` (e.g. push_metadata) should
 * use the locked_ref() accessor.
 */
struct owned_locked_trace_class {
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

owned_locked_trace_class get_locked_trace_class(const lsu::app_session::identifier& identifier)
{
	auto session = lsu::app_session::get_trace_class(identifier);
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
		{
			const auto protocol = app->command_socket.lock();
			ret = lttng_ust_ctl_release_object(sock, ua_event_notifier_rule->obj);
		}
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG3("UST app release event notifier failed. Application is dead: pid = %d, sock = %d",
				     app->pid,
				     app->command_socket.fd());
			} else if (ret == -EAGAIN) {
				WARN("UST app release event notifier failed. Communication time out: pid = %d, sock = %d",
				     app->pid,
				     app->command_socket.fd());
			} else {
				ERR("UST app release event notifier failed with ret %d: pid = %d, sock = %d",
				    ret,
				    app->pid,
				    app->command_socket.fd());
			}
		}

		free(ua_event_notifier_rule->obj);
	}

	lttng_trigger_put(ua_event_notifier_rule->trigger);
	call_rcu(&ua_event_notifier_rule->rcu_head, free_ust_app_event_notifier_rule_rcu);
}

int ust_app_register_done(lsu::app *app)
{
	try {
		app->command_socket.lock().register_done();
	} catch (const lsu::app_communication_error&) {
		return 0;
	} catch (const lttng::runtime_error&) {
		return -1;
	}

	return 0;
}

int ust_app_release_object(lsu::app *app, struct lttng_ust_abi_object_data *data)
{
	int ret;

	if (app) {
		const auto protocol = app->command_socket.lock();
		ret = lttng_ust_ctl_release_object(protocol.fd(), data);
	} else {
		ret = lttng_ust_ctl_release_object(-1, data);
	}
	return ret;
}

/*
 * Push metadata to consumer socket.
 *
 * RCU read-side lock must be held to guarantee existence of socket.
 * Must be called with the ust app session lock held.
 * Must be called with the trace class lock held.
 *
 * On success, return the len of metadata pushed or else a negative value.
 * Returning a -EPIPE return value means we could not send the metadata,
 * but it can be caused by recoverable errors (e.g. the application has
 * terminated concurrently).
 */
ssize_t ust_app_push_metadata(const lsu::trace_class::locked_ref& locked_trace_class,
			      struct consumer_socket *socket,
			      int send_zero_data)
{
	int ret;
	char *metadata_str = nullptr;
	size_t len, offset, new_metadata_len_sent;
	ssize_t ret_val;
	uint64_t metadata_key, metadata_version;

	LTTNG_ASSERT(locked_trace_class);
	LTTNG_ASSERT(socket);
	ASSERT_RCU_READ_LOCKED();

	metadata_key = locked_trace_class->_metadata_key;

	/*
	 * Means that no metadata was assigned to the session. This can
	 * happens if no start has been done previously.
	 */
	if (!metadata_key) {
		return 0;
	}

	offset = locked_trace_class->_metadata_len_sent;
	len = locked_trace_class->_metadata_len - locked_trace_class->_metadata_len_sent;
	new_metadata_len_sent = locked_trace_class->_metadata_len;
	metadata_version = locked_trace_class->_metadata_version;
	if (len == 0) {
		DBG3("No metadata to push for metadata key %" PRIu64,
		     locked_trace_class->_metadata_key);
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
	memcpy(metadata_str, locked_trace_class->_metadata + offset, len);

push_data:
	pthread_mutex_unlock(&locked_trace_class->_lock);
	/*
	 * We need to unlock the trace class while we push metadata to
	 * break a circular dependency between the consumerd metadata
	 * lock and the sessiond trace class lock. Indeed, pushing metadata
	 * to the consumerd awaits that it gets pushed all the way to
	 * relayd, but doing so requires grabbing the metadata lock. If
	 * a concurrent metadata request is being performed by
	 * consumerd, this can try to grab the trace class lock on the
	 * sessiond while holding the metadata lock on the consumer
	 * daemon. Those push and pull schemes are performed on two
	 * different bidirectionnal communication sockets.
	 */
	ret = consumer_push_metadata(
		socket, metadata_key, metadata_str, len, offset, metadata_version);
	pthread_mutex_lock(&locked_trace_class->_lock);
	if (ret < 0) {
		/*
		 * There is an acceptable race here between the trace class
		 * metadata key assignment and the creation on the
		 * consumer. The session daemon can concurrently push
		 * metadata for this trace class while being created on the
		 * consumer since the metadata key of the trace class is
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
		 * we're not holding the trace class lock while pushing to
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
		if (locked_trace_class->_metadata_version == metadata_version) {
			locked_trace_class->_metadata_len_sent = std::max(
				locked_trace_class->_metadata_len_sent, new_metadata_len_sent);
		}
	}
	free(metadata_str);
	return len;

end:
error:
	if (ret_val) {
		/*
		 * On error, flag the trace class that the metadata is
		 * closed. We were unable to push anything and this
		 * means that either the consumer is not responding or
		 * the metadata cache has been destroyed on the
		 * consumer.
		 */
		locked_trace_class->_metadata_closed = true;
	}
error_push:
	free(metadata_str);
	return ret_val;
}

/*
 * Delete a traceable application structure from the global list. Never call
 * this function outside of a call_rcu call.
 */
static void delete_ust_app(lsu::app *app)
{
	int ret, sock;
	bool event_notifier_write_fd_is_open;

	const auto list_lock = lttng::sessiond::lock_session_list();
	sock = app->command_socket.release_fd();

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

			delete_ust_app_event_notifier_rule(
				app->command_socket.fd(), event_notifier_rule, app);
		}
	}

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
 * Set a capture bytecode for the passed object.
 * The sequence number enforces the ordering at runtime and on reception of
 * the captured payloads.
 */
static int set_ust_capture(lsu::app *app,
			   const struct lttng_bytecode *bytecode,
			   unsigned int capture_seqnum,
			   struct lttng_ust_abi_object_data *ust_object)
{
	int ret = 0;
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

	try {
		app->command_socket.lock().set_capture(ust_bytecode, ust_object);
	} catch (const lsu::app_communication_error&) {
		goto error;
	} catch (const lttng::runtime_error&) {
		ret = -1;
		goto error;
	}

	DBG2("UST capture successfully set: object = %p", ust_object);

error:
	health_code_update();
	free(ust_bytecode);
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
	try {
		app->command_socket.lock().create_event_notifier(&event_notifier,
								 app->event_notifier_group.object,
								 &ua_event_notifier_rule->obj);
	} catch (const lsu::app_communication_error&) {
		goto error;
	} catch (const lttng::runtime_error&) {
		ret = -1;
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
		goto error;
	}

	ua_event_notifier_rule->enabled = true;

error:
	health_code_update();
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
	lta->command_socket.set_fd(sock, msg->pid);
	lttng_ht_node_init_ulong(&lta->sock_n, (unsigned long) lta->command_socket.fd());

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
	    app->command_socket.fd(),
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
	LTTNG_ASSERT(app);

	try {
		app->command_socket.lock().tracer_version(&app->version);
	} catch (const lsu::app_communication_error&) {
		return -1;
	} catch (const lttng::runtime_error&) {
		return -1;
	}

	return 0;
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
	int ret = 0;
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

	try {
		app->command_socket.lock().create_event_notifier_group(event_pipe_write_fd,
								       &event_notifier_group);
	} catch (const lsu::app_communication_error&) {
		goto error;
	} catch (const lttng::runtime_error&) {
		ret = -1;
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
		     app->command_socket.fd(),
		     app->name,
		     (int) app->pid);
		ret = 0;
		goto error_accounting;
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD:
		DBG3("Failed to setup event notifier error accounting (application is dead): app socket fd = %d, app name = '%s', app pid = %d",
		     app->command_socket.fd(),
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
	lttng_ust_ctl_release_object(app->command_socket.fd(), app->event_notifier_group.object);
	free(app->event_notifier_group.object);
	app->event_notifier_group.object = nullptr;
	return ret;
}

static void ust_app_unregister(lsu::app& app)
{
	const lttng::urcu::read_lock_guard read_lock;

	DBG_FMT("Unregistering application: "
		"app_name=`{}`, app_pid={}, app_uid={}",
		app.name,
		app.pid,
		app.uid);

	/*
	 * Snapshot all recording sessions and notify each orchestrator
	 * that this app is departing. The orchestrator owns the
	 * app_session and handles the full teardown (flush, metadata
	 * push/close, channel deletion, UST handle release).
	 *
	 * The recording session lock is held across each
	 * on_app_departure() call to ensure mutual exclusion with
	 * rotation/clear. The session list lock is acquired and
	 * released around session lookup and session_put, preserving
	 * the list lock -> session lock ordering.
	 */
	std::vector<ltt_session::ref> sessions_snapshot;
	{
		const auto list_lock = lttng::sessiond::lock_session_list();
		const auto *list = session_get_list();

		for (auto *session :
		     lttng::urcu::list_iteration_adapter<ltt_session, &ltt_session::list>(
			     list->head)) {
			if (session_get(session)) {
				sessions_snapshot.emplace_back(ltt_session::make_ref(*session));
			}
		}
	}

	unsigned int total_pending_reclamations = 0;

	for (auto& session_ref : sessions_snapshot) {
		session_lock(&*session_ref);

		if (session_ref->ust_orchestrator) {
			auto& orchestrator = static_cast<lsu::domain_orchestrator&>(
				session_ref->get_ust_orchestrator());

			try {
				total_pending_reclamations += orchestrator.on_app_departure(
					app, nonstd::optional<uint32_t>(app.owner_id_n.key));
			} catch (const std::exception& ex) {
				ERR_FMT("Failed to process app departure in UST orchestrator: session_name=`{}`, session_id={}, app={}, error='{}'",
					session_ref->name,
					session_ref->id,
					app,
					ex.what());
			}
		}

		session_unlock(&*session_ref);
	}

	/*
	 * Register the application's owner ID as pending reclamation
	 * so it is not reused until all consumer channels have
	 * acknowledged the reclamation.
	 */
	owner_id_reclamations.mark_owner_id(app.owner_id_n.key, total_pending_reclamations);

	/*
	 * Release session references under the list lock to
	 * preserve list lock -> session lock ordering.
	 */
	{
		const auto list_lock = lttng::sessiond::lock_session_list();
		sessions_snapshot.clear();
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

		{
			auto protocol = app->command_socket.lock();

			try {
				handle = protocol.tracepoint_list();
			} catch (const lsu::app_communication_error&) {
				continue;
			} catch (const lttng::runtime_error&) {
				continue;
			}

			try {
				while ((ret = protocol.tracepoint_list_get(handle, &uiter)) !=
				       -LTTNG_UST_ERR_NOENT) {
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
							tmp_event,
							new_nbmem * sizeof(struct lttng_event));
						if (new_tmp_event == nullptr) {
							PERROR("realloc ust app events");
							free(tmp_event);
							ret = -ENOMEM;
							try {
								protocol.release_handle(handle);
							} catch (
								const lsu::app_communication_error&) {
							} catch (const lttng::runtime_error&) {
							}

							goto error;
						}
						/* Zero the new memory */
						memset(new_tmp_event + nbmem,
						       0,
						       (new_nbmem - nbmem) *
							       sizeof(struct lttng_event));
						nbmem = new_nbmem;
						tmp_event = new_tmp_event;
					}

					memcpy(tmp_event[count].name,
					       uiter.name,
					       LTTNG_UST_ABI_SYM_NAME_LEN);
					tmp_event[count].loglevel = uiter.loglevel;
					tmp_event[count].type =
						(enum lttng_event_type) LTTNG_UST_ABI_TRACEPOINT;
					tmp_event[count].pid = app->pid;
					tmp_event[count].enabled = -1;
					count++;
				}
			} catch (const lsu::app_communication_error&) {
				/* App dead mid-iteration — keep events collected so far. */
			} catch (const lttng::runtime_error&) {
				free(tmp_event);
				ret = -1;
				try {
					protocol.release_handle(handle);
				} catch (const lsu::app_communication_error&) {
				} catch (const lttng::runtime_error&) {
				}

				goto error;
			}

			try {
				protocol.release_handle(handle);
			} catch (const lsu::app_communication_error&) {
			} catch (const lttng::runtime_error&) {
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

		{
			auto protocol = app->command_socket.lock();

			try {
				handle = protocol.tracepoint_field_list();
			} catch (const lsu::app_communication_error&) {
				continue;
			} catch (const lttng::runtime_error&) {
				continue;
			}

			try {
				while ((ret = protocol.tracepoint_field_list_get(handle, &uiter)) !=
				       -LTTNG_UST_ERR_NOENT) {
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
							tmp_event,
							new_nbmem *
								sizeof(struct lttng_event_field));
						if (new_tmp_event == nullptr) {
							PERROR("realloc ust app event fields");
							free(tmp_event);
							ret = -ENOMEM;
							try {
								protocol.release_handle(handle);
							} catch (
								const lsu::app_communication_error&) {
							} catch (const lttng::runtime_error&) {
							}

							goto error;
						}

						/* Zero the new memory */
						memset(new_tmp_event + nbmem,
						       0,
						       (new_nbmem - nbmem) *
							       sizeof(struct lttng_event_field));
						nbmem = new_nbmem;
						tmp_event = new_tmp_event;
					}

					memcpy(tmp_event[count].field_name,
					       uiter.field_name,
					       LTTNG_UST_ABI_SYM_NAME_LEN);
					/* Mapping between these enums matches 1 to 1. */
					tmp_event[count].type =
						(enum lttng_event_field_type) uiter.type;
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
			} catch (const lsu::app_communication_error&) {
				/* App dead mid-iteration — keep fields collected so far. */
			} catch (const lttng::runtime_error&) {
				free(tmp_event);
				ret = -1;
				try {
					protocol.release_handle(handle);
				} catch (const lsu::app_communication_error&) {
				} catch (const lttng::runtime_error&) {
				}

				goto error;
			}

			try {
				protocol.release_handle(handle);
			} catch (const lsu::app_communication_error&) {
			} catch (const lttng::runtime_error&) {
			}
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
		delete_ust_app_event_notifier_rule(
			app->command_socket.fd(), event_notifier_rule, app);
	}

end:
	lttng_triggers_destroy(triggers);
	return;
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
 * Reply to a register channel notification from an application on the notify
 * socket. The channel metadata is also created.
 *
 * The trace class lock is acquired in this function.
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

	/* Resolve channel objd via the app's registry. */
	const auto channel_entry = (*app)->objd_registry.lookup_channel(cobjd);
	if (!channel_entry) {
		DBG("Application channel is being torn down. Abort event notify");
		return 0;
	}

	auto locked_trace_class = get_locked_trace_class(channel_entry->session_id);
	if (!locked_trace_class) {
		DBG("Application session is being torn down. Abort event notify");
		return 0;
	}

	const auto tc_channel_key = channel_entry->trace_class_channel_key;
	auto& tc_channel = locked_trace_class->channel(tc_channel_key);

	/* Channel id is set during the object creation. */
	chan_id = tc_channel.id;

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

		if (!tc_channel.is_registered()) {
			lst::type::cuptr event_context = app_context_fields.size() ?
				lttng::make_unique<lst::structure_type>(
					0, std::move(app_context_fields)) :
				nullptr;

			tc_channel.event_context(std::move(event_context));
		} else {
			/*
			 * Validate that the context fields match between
			 * the trace class and newcoming application.
			 */
			bool context_fields_match;
			const auto *previous_event_context = tc_channel.event_context();

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
				    (*app)->command_socket.fd());
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
	     tc_channel_key,
	     chan_id,
	     ret_code);

	ret = lttng_ust_ctl_reply_register_channel(
		sock,
		chan_id,
		tc_channel.header_type_ == lst::stream_class::header_type::COMPACT ?
			LTTNG_UST_CTL_CHANNEL_HEADER_COMPACT :
			LTTNG_UST_CTL_CHANNEL_HEADER_LARGE,
		ret_code);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app reply channel failed. Application died: pid = %d, sock = %d",
			     (*app)->pid,
			     (*app)->command_socket.fd());
		} else if (ret == -EAGAIN) {
			WARN("UST app reply channel failed. Communication time out: pid = %d, sock = %d",
			     (*app)->pid,
			     (*app)->command_socket.fd());
		} else {
			ERR("UST app reply channel failed with ret %d: pid = %d, sock = %d",
			    ret,
			    (*app)->pid,
			    (*app)->command_socket.fd());
		}

		return ret;
	}

	/* This channel's registration is completed. */
	tc_channel.set_as_registered();

	return ret;
}

/*
 * Add event to the trace class. When the event is added to the
 * trace class, the metadata is also created. Once done, this replies to the
 * application with the appropriate error code.
 *
 * The trace class lock is acquired in the function.
 *
 * On success 0 is returned else a negative value.
 */
static int add_event_to_trace_class(int sock,
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

	/* Resolve channel objd via the app's registry. */
	const auto channel_entry = (*app)->objd_registry.lookup_channel(cobjd);
	if (!channel_entry) {
		DBG("Application channel is being torn down. Abort event notify");
		return 0;
	}

	const auto tc_channel_key = channel_entry->trace_class_channel_key;
	const auto buffer_type = (channel_entry->session_id.allocation_policy ==
				  lsu::app_session_identifier::buffer_allocation_policy::PER_UID) ?
		LTTNG_BUFFER_PER_UID :
		LTTNG_BUFFER_PER_PID;

	{
		auto locked_trace_class = get_locked_trace_class(channel_entry->session_id);
		if (locked_trace_class) {
			/*
			 * From this point on, this call acquires the ownership of the signature,
			 * fields and model_emf_uri meaning any free are done inside it if needed.
			 * These three variables MUST NOT be read/write after this.
			 */
			try {
				auto& channel = locked_trace_class->channel(tc_channel_key);

				/* id is set on success. */
				channel.add_event(
					sobjd,
					cobjd,
					name,
					signature.get(),
					lsu::create_trace_fields_from_ust_ctl_fields(
						*locked_trace_class,
						fields.get(),
						nr_fields,
						lst::field_location::root::EVENT_RECORD_PAYLOAD,
						lsu::ctl_field_quirks::
							UNDERSCORE_PREFIXED_VARIANT_TAG_MAPPINGS),
					loglevel_value,
					model_emf_uri.get() ?
						nonstd::optional<std::string>(model_emf_uri.get()) :
						nonstd::nullopt,
					buffer_type,
					**app,
					event_id);
				ret_code = 0;
			} catch (const std::exception& ex) {
				ERR("Failed to add event `%s` to trace class: %s", name, ex.what());
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
			     (*app)->command_socket.fd());
		} else if (ret == -EAGAIN) {
			WARN("UST app reply event failed. Communication time out: pid = %d, sock = %d",
			     (*app)->pid,
			     (*app)->command_socket.fd());
		} else {
			ERR("UST app reply event failed with ret %d: pid = %d, sock = %d",
			    ret,
			    (*app)->pid,
			    (*app)->command_socket.fd());
		}
		/*
		 * No need to wipe the create event since the application socket will
		 * get close on error hence cleaning up everything by itself.
		 */
		return ret;
	}

	DBG_FMT("UST trace class event successfully added: name={}, id={}", name, event_id);
	return ret;
}

/*
 * Add enum to the trace class. Once done, this replies to the
 * application with the appropriate error code.
 *
 * The trace class lock is acquired within this function.
 *
 * On success 0 is returned else a negative value.
 */
static int add_enum_to_trace_class(int sock,
				   int sobjd,
				   const char *name,
				   struct lttng_ust_ctl_enum_entry *raw_entries,
				   size_t nr_entries)
{
	int ret = 0;
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

	/* Resolve session objd via the app's registry. */
	const auto session_entry = (*app)->objd_registry.lookup_session(sobjd);
	if (!session_entry) {
		DBG("Application session is being torn down (session not found). Aborting enum registration.");
		return 0;
	}

	auto locked_trace_class = get_locked_trace_class(session_entry->session_id);
	if (!locked_trace_class) {
		DBG("Application session is being torn down (trace class not found). Aborting enum registration.");
		return 0;
	}

	/*
	 * From this point on, the callee acquires the ownership of
	 * entries. The variable entries MUST NOT be read/written after
	 * call.
	 */
	int application_reply_code;
	try {
		locked_trace_class->create_or_find_enum(
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
			     (*app)->command_socket.fd());
		} else if (ret == -EAGAIN) {
			WARN("UST app reply enum failed. Communication time out: pid = %d, sock = %d",
			     (*app)->pid,
			     (*app)->command_socket.fd());
		} else {
			ERR("UST app reply enum failed with ret %d: pid = %d, sock = %d",
			    ret,
			    (*app)->pid,
			    (*app)->command_socket.fd());
		}
		/*
		 * No need to wipe the create enum since the application socket will
		 * get close on error hence cleaning up everything by itself.
		 */
		return ret;
	}

	DBG3("UST trace class enum %s added successfully or already found", name);
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
		 * Add event to the trace class coming from the notify socket. This
		 * call will free if needed the sig, fields and model_emf_uri. This
		 * code path loses the ownsership of these variables and transfer them
		 * to the this function.
		 */
		ret = add_event_to_trace_class(sock,
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
		ret = add_enum_to_trace_class(sock, sobjd, name, entries, nr_entries);
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
