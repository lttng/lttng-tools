/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE

#include "buffer-registry.hpp"
#include "condition-internal.hpp"
#include "event-notifier-error-accounting.hpp"
#include "event.hpp"
#include "fd-limit.hpp"
#include "field.hpp"
#include "health-sessiond.hpp"
#include "lttng-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "notification-thread-commands.hpp"
#include "session.hpp"
#include "ust-app.hpp"
#include "ust-consumer.hpp"
#include "ust-field-convert.hpp"
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
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <urcu/compiler.h>
#include <vector>

namespace lsu = lttng::sessiond::ust;
namespace lst = lttng::sessiond::trace;

struct lttng_ht *ust_app_ht;
struct lttng_ht *ust_app_ht_by_sock;
struct lttng_ht *ust_app_ht_by_notify_sock;

static int ust_app_flush_app_session(ust_app& app, ust_app_session& ua_sess);

/* Next available channel key. Access under next_channel_key_lock. */
static uint64_t _next_channel_key;
static pthread_mutex_t next_channel_key_lock = PTHREAD_MUTEX_INITIALIZER;

/* Next available session ID. Access under next_session_id_lock. */
static uint64_t _next_session_id;
static pthread_mutex_t next_session_id_lock = PTHREAD_MUTEX_INITIALIZER;

namespace {

/*
 * Return the session registry according to the buffer type of the given
 * session.
 *
 * A registry per UID object MUST exists before calling this function or else
 * it LTTNG_ASSERT() if not found. RCU read side lock must be acquired.
 */
static lsu::registry_session *get_session_registry(const struct ust_app_session *ua_sess)
{
	lsu::registry_session *registry = nullptr;

	LTTNG_ASSERT(ua_sess);

	switch (ua_sess->buffer_type) {
	case LTTNG_BUFFER_PER_PID:
	{
		struct buffer_reg_pid *reg_pid = buffer_reg_pid_find(ua_sess->id);
		if (!reg_pid) {
			goto error;
		}
		registry = reg_pid->registry->reg.ust;
		break;
	}
	case LTTNG_BUFFER_PER_UID:
	{
		struct buffer_reg_uid *reg_uid =
			buffer_reg_uid_find(ua_sess->tracing_id,
					    ua_sess->bits_per_long,
					    lttng_credentials_get_uid(&ua_sess->real_credentials));
		if (!reg_uid) {
			goto error;
		}
		registry = reg_uid->registry->reg.ust;
		break;
	}
	default:
		abort();
	};

error:
	return registry;
}

lsu::registry_session::locked_ptr get_locked_session_registry(const struct ust_app_session *ua_sess)
{
	auto session = get_session_registry(ua_sess);
	if (session) {
		pthread_mutex_lock(&session->_lock);
	}

	return lsu::registry_session::locked_ptr{ session };
}
} /* namespace */

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
static uint64_t get_next_session_id()
{
	uint64_t ret;

	pthread_mutex_lock(&next_session_id_lock);
	ret = ++_next_session_id;
	pthread_mutex_unlock(&next_session_id_lock);
	return ret;
}

static void copy_channel_attr_to_ustctl(struct lttng_ust_ctl_consumer_channel_attr *attr,
					struct lttng_ust_abi_channel_attr *uattr)
{
	/* Copy event attributes since the layout is different. */
	attr->subbuf_size = uattr->subbuf_size;
	attr->num_subbuf = uattr->num_subbuf;
	attr->overwrite = uattr->overwrite;
	attr->switch_timer_interval = uattr->switch_timer_interval;
	attr->read_timer_interval = uattr->read_timer_interval;
	attr->output = (lttng_ust_abi_output) uattr->output;
	attr->blocking_timeout = uattr->u.s.blocking_timeout;
}

/*
 * Match function for the hash table lookup.
 *
 * It matches an ust app event based on three attributes which are the event
 * name, the filter bytecode and the loglevel.
 */
static int ht_match_ust_app_event(struct cds_lfht_node *node, const void *_key)
{
	struct ust_app_event *event;
	const struct ust_app_ht_key *key;

	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	event = caa_container_of(node, struct ust_app_event, node.node);
	key = (ust_app_ht_key *) _key;

	/* Match the 4 elements of the key: name, filter, loglevel, exclusions */

	/* Event name */
	if (strncmp(event->attr.name, key->name, sizeof(event->attr.name)) != 0) {
		goto no_match;
	}

	/* Event loglevel. */
	if (!loglevels_match(event->attr.loglevel_type,
			     event->attr.loglevel,
			     key->loglevel_type,
			     key->loglevel_value,
			     LTTNG_UST_ABI_LOGLEVEL_ALL)) {
		goto no_match;
	}

	/* One of the filters is NULL, fail. */
	if ((key->filter && !event->filter) || (!key->filter && event->filter)) {
		goto no_match;
	}

	if (key->filter && event->filter) {
		/* Both filters exists, check length followed by the bytecode. */
		if (event->filter->len != key->filter->len ||
		    memcmp(event->filter->data, key->filter->data, event->filter->len) != 0) {
			goto no_match;
		}
	}

	/* One of the exclusions is NULL, fail. */
	if ((key->exclusion && !event->exclusion) || (!key->exclusion && event->exclusion)) {
		goto no_match;
	}

	if (key->exclusion && event->exclusion) {
		/* Both exclusions exists, check count followed by the names. */
		if (event->exclusion->count != key->exclusion->count ||
		    memcmp(event->exclusion->names,
			   key->exclusion->names,
			   event->exclusion->count * LTTNG_UST_ABI_SYM_NAME_LEN) != 0) {
			goto no_match;
		}
	}

	/* Match. */
	return 1;

no_match:
	return 0;
}

/*
 * Unique add of an ust app event in the given ht. This uses the custom
 * ht_match_ust_app_event match function and the event name as hash.
 */
static void add_unique_ust_app_event(struct ust_app_channel *ua_chan, struct ust_app_event *event)
{
	struct cds_lfht_node *node_ptr;
	struct ust_app_ht_key key;
	struct lttng_ht *ht;

	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(ua_chan->events);
	LTTNG_ASSERT(event);

	ht = ua_chan->events;
	key.name = event->attr.name;
	key.filter = event->filter;
	key.loglevel_type = (lttng_ust_abi_loglevel_type) event->attr.loglevel_type;
	key.loglevel_value = event->attr.loglevel;
	key.exclusion = event->exclusion;

	node_ptr = cds_lfht_add_unique(ht->ht,
				       ht->hash_fct(event->node.key, lttng_ht_seed),
				       ht_match_ust_app_event,
				       &key,
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
static void delete_ust_app_ctx(int sock, struct ust_app_ctx *ua_ctx, struct ust_app *app)
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
				    ua_ctx->obj->handle,
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

	free(ua_ctx);
}

/*
 * Delete ust app event safely. RCU read lock must be held before calling
 * this function.
 */
static void delete_ust_app_event(int sock, struct ust_app_event *ua_event, struct ust_app *app)
{
	int ret;

	LTTNG_ASSERT(ua_event);
	ASSERT_RCU_READ_LOCKED();

	free(ua_event->filter);
	if (ua_event->exclusion != nullptr)
		free(ua_event->exclusion);
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
	free(ua_event);
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
	int sock, struct ust_app_event_notifier_rule *ua_event_notifier_rule, struct ust_app *app)
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
static int release_ust_app_stream(int sock, struct ust_app_stream *stream, struct ust_app *app)
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
static void delete_ust_app_stream(int sock, struct ust_app_stream *stream, struct ust_app *app)
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
	free(ua_chan);
}

/*
 * Extract the lost packet or discarded events counter when the channel is
 * being deleted and store the value in the parent channel so we can
 * access it from lttng list and at stop/destroy.
 *
 * The session list lock must be held by the caller.
 */
static void save_per_pid_lost_discarded_counters(struct ust_app_channel *ua_chan)
{
	uint64_t discarded = 0, lost = 0;
	struct ltt_session *session;
	struct ltt_ust_channel *uchan;

	if (ua_chan->attr.type != LTTNG_UST_ABI_CHAN_PER_CPU) {
		return;
	}

	lttng::urcu::read_lock_guard read_lock;
	session = session_find_by_id(ua_chan->session->tracing_id);
	if (!session || !session->ust_session) {
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
		goto end;
	}

	if (ua_chan->attr.overwrite) {
		consumer_get_lost_packets(ua_chan->session->tracing_id,
					  ua_chan->key,
					  session->ust_session->consumer,
					  &lost);
	} else {
		consumer_get_discarded_events(ua_chan->session->tracing_id,
					      ua_chan->key,
					      session->ust_session->consumer,
					      &discarded);
	}
	uchan = trace_ust_find_channel_by_name(session->ust_session->domain_global.channels,
					       ua_chan->name);
	if (!uchan) {
		ERR("Missing UST channel to store discarded counters");
		goto end;
	}

	uchan->per_pid_closed_app_discarded += discarded;
	uchan->per_pid_closed_app_lost += lost;

end:
	if (session) {
		session_put(session);
	}
}

/*
 * Delete ust app channel safely. RCU read lock must be held before calling
 * this function.
 *
 * The session list lock must be held by the caller.
 */
static void delete_ust_app_channel(int sock,
				   struct ust_app_channel *ua_chan,
				   struct ust_app *app,
				   const lsu::registry_session::locked_ptr& locked_registry)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ust_app_event *ua_event;
	struct ust_app_ctx *ua_ctx;
	struct ust_app_stream *stream, *stmp;

	LTTNG_ASSERT(ua_chan);
	ASSERT_RCU_READ_LOCKED();

	DBG3("UST app deleting channel %s", ua_chan->name);

	/* Wipe stream */
	cds_list_for_each_entry_safe (stream, stmp, &ua_chan->streams.head, list) {
		cds_list_del(&stream->list);
		delete_ust_app_stream(sock, stream, app);
	}

	/* Wipe context */
	cds_lfht_for_each_entry (ua_chan->ctx->ht, &iter.iter, ua_ctx, node.node) {
		cds_list_del(&ua_ctx->list);
		ret = lttng_ht_del(ua_chan->ctx, &iter);
		LTTNG_ASSERT(!ret);
		delete_ust_app_ctx(sock, ua_ctx, app);
	}

	/* Wipe events */
	cds_lfht_for_each_entry (ua_chan->events->ht, &iter.iter, ua_event, node.node) {
		ret = lttng_ht_del(ua_chan->events, &iter);
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

int ust_app_register_done(struct ust_app *app)
{
	int ret;

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_register_done(app->sock);
	pthread_mutex_unlock(&app->sock_lock);
	return ret;
}

int ust_app_release_object(struct ust_app *app, struct lttng_ust_abi_object_data *data)
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
ssize_t ust_app_push_metadata(const lsu::registry_session::locked_ptr& locked_registry,
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
		locked_registry->_metadata_len_sent =
			std::max(locked_registry->_metadata_len_sent, new_metadata_len_sent);
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
static int push_metadata(const lsu::registry_session::locked_ptr& locked_registry,
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

	/* Get consumer socket to use to push the metadata.*/
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
	lttng::urcu::read_lock_guard read_lock_guard;

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
	struct ust_app_session *ua_sess =
		lttng::utils::container_of(head, &ust_app_session::rcu_head);

	lttng_ht_destroy(ua_sess->channels);
	free(ua_sess);
}

/*
 * Delete ust app session safely. RCU read lock must be held before calling
 * this function.
 *
 * The session list lock must be held by the caller.
 */
static void delete_ust_app_session(int sock, struct ust_app_session *ua_sess, struct ust_app *app)
{
	int ret;
	struct lttng_ht_iter iter;
	struct ust_app_channel *ua_chan;

	LTTNG_ASSERT(ua_sess);
	ASSERT_RCU_READ_LOCKED();

	pthread_mutex_lock(&ua_sess->lock);

	LTTNG_ASSERT(!ua_sess->deleted);
	ua_sess->deleted = true;

	auto locked_registry = get_locked_session_registry(ua_sess);
	/* Registry can be null on error path during initialization. */
	if (locked_registry) {
		/* Push metadata for application before freeing the application. */
		(void) push_metadata(locked_registry, ua_sess->consumer);
	}

	cds_lfht_for_each_entry (ua_sess->channels->ht, &iter.iter, ua_chan, node.node) {
		ret = lttng_ht_del(ua_sess->channels, &iter);
		LTTNG_ASSERT(!ret);
		delete_ust_app_channel(sock, ua_chan, app, locked_registry);
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

	/* In case of per PID, the registry is kept in the session. */
	if (ua_sess->buffer_type == LTTNG_BUFFER_PER_PID) {
		struct buffer_reg_pid *reg_pid = buffer_reg_pid_find(ua_sess->id);
		if (reg_pid) {
			/*
			 * Registry can be null on error path during
			 * initialization.
			 */
			buffer_reg_pid_remove(reg_pid);
			buffer_reg_pid_destroy(reg_pid);
		}
	}

	if (ua_sess->handle != -1) {
		pthread_mutex_lock(&app->sock_lock);
		ret = lttng_ust_ctl_release_handle(sock, ua_sess->handle);
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
		iter.iter.node = &ua_sess->ust_objd_node.node;
		ret = lttng_ht_del(app->ust_sessions_objd, &iter);
		LTTNG_ASSERT(!ret);
	}

	pthread_mutex_unlock(&ua_sess->lock);

	consumer_output_put(ua_sess->consumer);

	call_rcu(&ua_sess->rcu_head, delete_ust_app_session_rcu);
}

/*
 * Delete a traceable application structure from the global list. Never call
 * this function outside of a call_rcu call.
 */
static void delete_ust_app(struct ust_app *app)
{
	int ret, sock;
	struct ust_app_session *ua_sess, *tmp_ua_sess;
	struct lttng_ht_iter iter;
	struct ust_app_event_notifier_rule *event_notifier_rule;
	bool event_notifier_write_fd_is_open;

	/*
	 * The session list lock must be held during this function to guarantee
	 * the existence of ua_sess.
	 */
	session_lock_list();
	/* Delete ust app sessions info */
	sock = app->sock;
	app->sock = -1;

	/* Wipe sessions */
	cds_list_for_each_entry_safe (ua_sess, tmp_ua_sess, &app->teardown_head, teardown_node) {
		/* Free every object in the session and the session. */
		lttng::urcu::read_lock_guard read_lock;
		delete_ust_app_session(sock, ua_sess, app);
	}

	/* Remove the event notifier rules associated with this app. */
	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (app->token_to_event_notifier_rule_ht->ht,
					 &iter.iter,
					 event_notifier_rule,
					 node.node) {
			ret = lttng_ht_del(app->token_to_event_notifier_rule_ht, &iter);
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
	free(app);
	session_unlock_list();
}

/*
 * URCU intermediate call to delete an UST app.
 */
static void delete_ust_app_rcu(struct rcu_head *head)
{
	struct lttng_ht_node_ulong *node =
		lttng::utils::container_of(head, &lttng_ht_node_ulong::head);
	struct ust_app *app = lttng::utils::container_of(node, &ust_app::pid_n);

	DBG3("Call RCU deleting app PID %d", app->pid);
	delete_ust_app(app);
}

/*
 * Delete the session from the application ht and delete the data structure by
 * freeing every object inside and releasing them.
 *
 * The session list lock must be held by the caller.
 */
static void destroy_app_session(struct ust_app *app, struct ust_app_session *ua_sess)
{
	int ret;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess);

	iter.iter.node = &ua_sess->node.node;
	ret = lttng_ht_del(app->sessions, &iter);
	if (ret) {
		/* Already scheduled for teardown. */
		goto end;
	}

	/* Once deleted, free the data structure. */
	delete_ust_app_session(app->sock, ua_sess, app);

end:
	return;
}

/*
 * Alloc new UST app session.
 */
static struct ust_app_session *alloc_ust_app_session()
{
	struct ust_app_session *ua_sess;

	/* Init most of the default value by allocating and zeroing */
	ua_sess = zmalloc<ust_app_session>();
	if (ua_sess == nullptr) {
		PERROR("malloc");
		goto error_free;
	}

	ua_sess->handle = -1;
	ua_sess->channels = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	ua_sess->metadata_attr.type = LTTNG_UST_ABI_CHAN_METADATA;
	pthread_mutex_init(&ua_sess->lock, nullptr);

	return ua_sess;

error_free:
	return nullptr;
}

/*
 * Alloc new UST app channel.
 */
static struct ust_app_channel *alloc_ust_app_channel(const char *name,
						     struct ust_app_session *ua_sess,
						     struct lttng_ust_abi_channel_attr *attr)
{
	struct ust_app_channel *ua_chan;

	/* Init most of the default value by allocating and zeroing */
	ua_chan = zmalloc<ust_app_channel>();
	if (ua_chan == nullptr) {
		PERROR("malloc");
		goto error;
	}

	/* Setup channel name */
	strncpy(ua_chan->name, name, sizeof(ua_chan->name));
	ua_chan->name[sizeof(ua_chan->name) - 1] = '\0';

	ua_chan->enabled = true;
	ua_chan->handle = -1;
	ua_chan->session = ua_sess;
	ua_chan->key = get_next_channel_key();
	ua_chan->ctx = lttng_ht_new(0, LTTNG_HT_TYPE_ULONG);
	ua_chan->events = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	lttng_ht_node_init_str(&ua_chan->node, ua_chan->name);

	CDS_INIT_LIST_HEAD(&ua_chan->streams.head);
	CDS_INIT_LIST_HEAD(&ua_chan->ctx_list);

	/* Copy attributes */
	if (attr) {
		/* Translate from lttng_ust_channel to lttng_ust_ctl_consumer_channel_attr. */
		ua_chan->attr.subbuf_size = attr->subbuf_size;
		ua_chan->attr.num_subbuf = attr->num_subbuf;
		ua_chan->attr.overwrite = attr->overwrite;
		ua_chan->attr.switch_timer_interval = attr->switch_timer_interval;
		ua_chan->attr.read_timer_interval = attr->read_timer_interval;
		ua_chan->attr.output = (lttng_ust_abi_output) attr->output;
		ua_chan->attr.blocking_timeout = attr->u.s.blocking_timeout;
	}
	/* By default, the channel is a per cpu channel. */
	ua_chan->attr.type = LTTNG_UST_ABI_CHAN_PER_CPU;

	DBG3("UST app channel %s allocated", ua_chan->name);

	return ua_chan;

error:
	return nullptr;
}

/*
 * Allocate and initialize a UST app stream.
 *
 * Return newly allocated stream pointer or NULL on error.
 */
struct ust_app_stream *ust_app_alloc_stream()
{
	struct ust_app_stream *stream = nullptr;

	stream = zmalloc<ust_app_stream>();
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
 * Alloc new UST app event.
 */
static struct ust_app_event *alloc_ust_app_event(char *name, struct lttng_ust_abi_event *attr)
{
	struct ust_app_event *ua_event;

	/* Init most of the default value by allocating and zeroing */
	ua_event = zmalloc<ust_app_event>();
	if (ua_event == nullptr) {
		PERROR("Failed to allocate ust_app_event structure");
		goto error;
	}

	ua_event->enabled = true;
	strncpy(ua_event->name, name, sizeof(ua_event->name));
	ua_event->name[sizeof(ua_event->name) - 1] = '\0';
	lttng_ht_node_init_str(&ua_event->node, ua_event->name);

	/* Copy attributes */
	if (attr) {
		memcpy(&ua_event->attr, attr, sizeof(ua_event->attr));
	}

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
static struct ust_app_ctx *alloc_ust_app_ctx(struct lttng_ust_context_attr *uctx)
{
	struct ust_app_ctx *ua_ctx;

	ua_ctx = zmalloc<ust_app_ctx>();
	if (ua_ctx == nullptr) {
		goto error;
	}

	CDS_INIT_LIST_HEAD(&ua_ctx->list);

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
	free(ua_ctx);
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
 * Find an ust_app using the sock and return it. RCU read side lock must be
 * held before calling this helper function.
 */
struct ust_app *ust_app_find_by_sock(int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(ust_app_ht_by_sock, (void *) ((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == nullptr) {
		DBG2("UST app find by sock %d not found", sock);
		goto error;
	}

	return lttng::utils::container_of(node, &ust_app::sock_n);

error:
	return nullptr;
}

/*
 * Find an ust_app using the notify sock and return it. RCU read side lock must
 * be held before calling this helper function.
 */
static struct ust_app *find_app_by_notify_sock(int sock)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(ust_app_ht_by_notify_sock, (void *) ((unsigned long) sock), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == nullptr) {
		DBG2("UST app find by notify sock %d not found", sock);
		goto error;
	}

	return lttng::utils::container_of(node, &ust_app::notify_sock_n);

error:
	return nullptr;
}

/*
 * Lookup for an ust app event based on event name, filter bytecode and the
 * event loglevel.
 *
 * Return an ust_app_event object or NULL on error.
 */
static struct ust_app_event *find_ust_app_event(struct lttng_ht *ht,
						const char *name,
						const struct lttng_bytecode *filter,
						lttng_ust_abi_loglevel_type loglevel_type,
						int loglevel_value,
						const struct lttng_event_exclusion *exclusion)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *node;
	struct ust_app_event *event = nullptr;
	struct ust_app_ht_key key;

	LTTNG_ASSERT(name);
	LTTNG_ASSERT(ht);

	/* Setup key for event lookup. */
	key.name = name;
	key.filter = filter;
	key.loglevel_type = loglevel_type;
	key.loglevel_value = loglevel_value;
	/* lttng_event_exclusion and lttng_ust_event_exclusion structures are similar */
	key.exclusion = exclusion;

	/* Lookup using the event name as hash and a custom match fct. */
	cds_lfht_lookup(ht->ht,
			ht->hash_fct((void *) name, lttng_ht_seed),
			ht_match_ust_app_event,
			&key,
			&iter.iter);
	node = lttng_ht_iter_get_node_str(&iter);
	if (node == nullptr) {
		goto end;
	}

	event = lttng::utils::container_of(node, &ust_app_event::node);

end:
	return event;
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
	node = lttng_ht_iter_get_node_u64(&iter);
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
				      struct ust_app *app)
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

	ua_ctx->handle = ua_ctx->obj->handle;

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
static int set_ust_object_filter(struct ust_app *app,
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
static int set_ust_capture(struct ust_app *app,
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
	size_t exclusion_alloc_size = sizeof(struct lttng_ust_abi_event_exclusion) +
		LTTNG_UST_ABI_SYM_NAME_LEN * exclusion->count;

	ust_exclusion = zmalloc<lttng_ust_abi_event_exclusion>(exclusion_alloc_size);
	if (!ust_exclusion) {
		PERROR("malloc");
		goto end;
	}

	LTTNG_ASSERT(sizeof(struct lttng_event_exclusion) ==
		     sizeof(struct lttng_ust_abi_event_exclusion));
	memcpy(ust_exclusion, exclusion, exclusion_alloc_size);
end:
	return ust_exclusion;
}

/*
 * Set event exclusions on the tracer.
 */
static int set_ust_object_exclusions(struct ust_app *app,
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
static int disable_ust_object(struct ust_app *app, struct lttng_ust_abi_object_data *object)
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
static int disable_ust_channel(struct ust_app *app,
			       struct ust_app_session *ua_sess,
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
static int enable_ust_channel(struct ust_app *app,
			      struct ust_app_session *ua_sess,
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
static int enable_ust_object(struct ust_app *app, struct lttng_ust_abi_object_data *ust_object)
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
static int send_channel_pid_to_ust(struct ust_app *app,
				   struct ust_app_session *ua_sess,
				   struct ust_app_channel *ua_chan)
{
	int ret;
	struct ust_app_stream *stream, *stmp;

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
		     ua_sess->tracing_id);
		/* Treat this the same way as an application that is exiting. */
		ret = -ENOTCONN;
		goto error;
	} else if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Send all streams to application. */
	cds_list_for_each_entry_safe (stream, stmp, &ua_chan->streams.head, list) {
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
			     ua_sess->tracing_id);
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
static int create_ust_event(struct ust_app *app,
			    struct ust_app_channel *ua_chan,
			    struct ust_app_event *ua_event)
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

	ua_event->handle = ua_event->obj->handle;

	DBG2("UST app event %s created successfully for pid:%d object = %p",
	     ua_event->attr.name,
	     app->pid,
	     ua_event->obj);

	health_code_update();

	/* Set filter if one is present. */
	if (ua_event->filter) {
		ret = set_ust_object_filter(app, ua_event->filter, ua_event->obj);
		if (ret < 0) {
			goto error;
		}
	}

	/* Set exclusions for the event */
	if (ua_event->exclusion) {
		ret = set_ust_object_exclusions(app, ua_event->exclusion, ua_event->obj);
		if (ret < 0) {
			goto error;
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

	event_notifier->event.instrumentation = LTTNG_UST_ABI_TRACEPOINT;
	ret = lttng_strncpy(
		event_notifier->event.name, pattern, sizeof(event_notifier->event.name));
	if (ret) {
		ERR("Failed to copy event rule pattern to notifier: pattern = '%s' ", pattern);
		goto end;
	}

	event_notifier->event.loglevel_type = ust_loglevel_type;
	event_notifier->event.loglevel = loglevel;
end:
	return ret;
}

/*
 * Create the specified event notifier against the user space tracer of a
 * given application.
 */
static int create_ust_event_notifier(struct ust_app *app,
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
		     event_rule_type == LTTNG_EVENT_RULE_TYPE_PYTHON_LOGGING);

	init_ust_event_notifier_from_event_rule(event_rule, &event_notifier);
	event_notifier.event.token = ua_event_notifier_rule->token;
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
			    event_notifier.event.name,
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error;
	}

	ua_event_notifier_rule->handle = ua_event_notifier_rule->obj->handle;

	DBG2("UST app event notifier %s created successfully: app = '%s': pid = %d, object = %p",
	     event_notifier.event.name,
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
static void shadow_copy_event(struct ust_app_event *ua_event, struct ltt_ust_event *uevent)
{
	size_t exclusion_alloc_size;

	strncpy(ua_event->name, uevent->attr.name, sizeof(ua_event->name));
	ua_event->name[sizeof(ua_event->name) - 1] = '\0';

	ua_event->enabled = uevent->enabled;

	/* Copy event attributes */
	memcpy(&ua_event->attr, &uevent->attr, sizeof(ua_event->attr));

	/* Copy filter bytecode */
	if (uevent->filter) {
		ua_event->filter = lttng_bytecode_copy(uevent->filter);
		/* Filter might be NULL here in case of ENONEM. */
	}

	/* Copy exclusion data */
	if (uevent->exclusion) {
		exclusion_alloc_size = sizeof(struct lttng_event_exclusion) +
			LTTNG_UST_ABI_SYM_NAME_LEN * uevent->exclusion->count;
		ua_event->exclusion = zmalloc<lttng_event_exclusion>(exclusion_alloc_size);
		if (ua_event->exclusion == nullptr) {
			PERROR("malloc");
		} else {
			memcpy(ua_event->exclusion, uevent->exclusion, exclusion_alloc_size);
		}
	}
}

/*
 * Copy data between an UST app channel and a LTT channel.
 */
static void shadow_copy_channel(struct ust_app_channel *ua_chan, struct ltt_ust_channel *uchan)
{
	DBG2("UST app shadow copy of channel %s started", ua_chan->name);

	strncpy(ua_chan->name, uchan->name, sizeof(ua_chan->name));
	ua_chan->name[sizeof(ua_chan->name) - 1] = '\0';

	ua_chan->tracefile_size = uchan->tracefile_size;
	ua_chan->tracefile_count = uchan->tracefile_count;

	/* Copy event attributes since the layout is different. */
	ua_chan->attr.subbuf_size = uchan->attr.subbuf_size;
	ua_chan->attr.num_subbuf = uchan->attr.num_subbuf;
	ua_chan->attr.overwrite = uchan->attr.overwrite;
	ua_chan->attr.switch_timer_interval = uchan->attr.switch_timer_interval;
	ua_chan->attr.read_timer_interval = uchan->attr.read_timer_interval;
	ua_chan->monitor_timer_interval = uchan->monitor_timer_interval;
	ua_chan->attr.output = (lttng_ust_abi_output) uchan->attr.output;
	ua_chan->attr.blocking_timeout = uchan->attr.u.s.blocking_timeout;

	/*
	 * Note that the attribute channel type is not set since the channel on the
	 * tracing registry side does not have this information.
	 */

	ua_chan->enabled = uchan->enabled;
	ua_chan->tracing_channel_id = uchan->id;

	DBG3("UST app shadow copy of channel %s done", ua_chan->name);
}

/*
 * Copy data between a UST app session and a regular LTT session.
 */
static void shadow_copy_session(struct ust_app_session *ua_sess,
				struct ltt_ust_session *usess,
				struct ust_app *app)
{
	struct tm *timeinfo;
	char datetime[16];
	int ret;
	char tmp_shm_path[PATH_MAX];

	timeinfo = localtime(&app->registration_time);
	strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);

	DBG2("Shadow copy of session handle %d", ua_sess->handle);

	ua_sess->tracing_id = usess->id;
	ua_sess->id = get_next_session_id();
	LTTNG_OPTIONAL_SET(&ua_sess->real_credentials.uid, app->uid);
	LTTNG_OPTIONAL_SET(&ua_sess->real_credentials.gid, app->gid);
	LTTNG_OPTIONAL_SET(&ua_sess->effective_credentials.uid, usess->uid);
	LTTNG_OPTIONAL_SET(&ua_sess->effective_credentials.gid, usess->gid);
	ua_sess->buffer_type = usess->buffer_type;
	ua_sess->bits_per_long = app->abi.bits_per_long;

	/* There is only one consumer object per session possible. */
	consumer_output_get(usess->consumer);
	ua_sess->consumer = usess->consumer;

	ua_sess->output_traces = usess->output_traces;
	ua_sess->live_timer_interval = usess->live_timer_interval;
	copy_channel_attr_to_ustctl(&ua_sess->metadata_attr, &usess->metadata_attr);

	switch (ua_sess->buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		ret = snprintf(ua_sess->path,
			       sizeof(ua_sess->path),
			       DEFAULT_UST_TRACE_PID_PATH "/%s-%d-%s",
			       app->name,
			       app->pid,
			       datetime);
		break;
	case LTTNG_BUFFER_PER_UID:
		ret = snprintf(ua_sess->path,
			       sizeof(ua_sess->path),
			       DEFAULT_UST_TRACE_UID_PATH,
			       lttng_credentials_get_uid(&ua_sess->real_credentials),
			       app->abi.bits_per_long);
		break;
	default:
		abort();
		goto error;
	}
	if (ret < 0) {
		PERROR("asprintf UST shadow copy session");
		abort();
		goto error;
	}

	strncpy(ua_sess->root_shm_path, usess->root_shm_path, sizeof(ua_sess->root_shm_path));
	ua_sess->root_shm_path[sizeof(ua_sess->root_shm_path) - 1] = '\0';
	strncpy(ua_sess->shm_path, usess->shm_path, sizeof(ua_sess->shm_path));
	ua_sess->shm_path[sizeof(ua_sess->shm_path) - 1] = '\0';
	if (ua_sess->shm_path[0]) {
		switch (ua_sess->buffer_type) {
		case LTTNG_BUFFER_PER_PID:
			ret = snprintf(tmp_shm_path,
				       sizeof(tmp_shm_path),
				       "/" DEFAULT_UST_TRACE_PID_PATH "/%s-%d-%s",
				       app->name,
				       app->pid,
				       datetime);
			break;
		case LTTNG_BUFFER_PER_UID:
			ret = snprintf(tmp_shm_path,
				       sizeof(tmp_shm_path),
				       "/" DEFAULT_UST_TRACE_UID_PATH,
				       app->uid,
				       app->abi.bits_per_long);
			break;
		default:
			abort();
			goto error;
		}
		if (ret < 0) {
			PERROR("sprintf UST shadow copy session");
			abort();
			goto error;
		}
		strncat(ua_sess->shm_path,
			tmp_shm_path,
			sizeof(ua_sess->shm_path) - strlen(ua_sess->shm_path) - 1);
		ua_sess->shm_path[sizeof(ua_sess->shm_path) - 1] = '\0';
	}
	return;

error:
	consumer_output_put(ua_sess->consumer);
}

/*
 * Lookup sesison wrapper.
 */
static void __lookup_session_by_app(const struct ltt_ust_session *usess,
				    struct ust_app *app,
				    struct lttng_ht_iter *iter)
{
	/* Get right UST app session from app */
	lttng_ht_lookup(app->sessions, &usess->id, iter);
}

/*
 * Return ust app session from the app session hashtable using the UST session
 * id.
 */
static struct ust_app_session *lookup_session_by_app(const struct ltt_ust_session *usess,
						     struct ust_app *app)
{
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;

	__lookup_session_by_app(usess, app, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node == nullptr) {
		goto error;
	}

	return lttng::utils::container_of(node, &ust_app_session::node);

error:
	return nullptr;
}

/*
 * Setup buffer registry per PID for the given session and application. If none
 * is found, a new one is created, added to the global registry and
 * initialized. If regp is valid, it's set with the newly created object.
 *
 * Return 0 on success or else a negative value.
 */
static int setup_buffer_reg_pid(struct ust_app_session *ua_sess,
				struct ust_app *app,
				struct buffer_reg_pid **regp)
{
	int ret = 0;
	struct buffer_reg_pid *reg_pid;

	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(app);

	lttng::urcu::read_lock_guard read_lock;

	reg_pid = buffer_reg_pid_find(ua_sess->id);
	if (!reg_pid) {
		/*
		 * This is the create channel path meaning that if there is NO
		 * registry available, we have to create one for this session.
		 */
		ret = buffer_reg_pid_create(
			ua_sess->id, &reg_pid, ua_sess->root_shm_path, ua_sess->shm_path);
		if (ret < 0) {
			goto error;
		}
	} else {
		goto end;
	}

	/* Initialize registry. */
	reg_pid->registry->reg.ust = ust_registry_session_per_pid_create(
		app,
		app->abi,
		app->version.major,
		app->version.minor,
		reg_pid->root_shm_path,
		reg_pid->shm_path,
		lttng_credentials_get_uid(&ua_sess->effective_credentials),
		lttng_credentials_get_gid(&ua_sess->effective_credentials),
		ua_sess->tracing_id);
	if (!reg_pid->registry->reg.ust) {
		/*
		 * reg_pid->registry->reg.ust is NULL upon error, so we need to
		 * destroy the buffer registry, because it is always expected
		 * that if the buffer registry can be found, its ust registry is
		 * non-NULL.
		 */
		buffer_reg_pid_destroy(reg_pid);
		goto error;
	}

	buffer_reg_pid_add(reg_pid);

	DBG3("UST app buffer registry per PID created successfully");

end:
	if (regp) {
		*regp = reg_pid;
	}
error:
	return ret;
}

/*
 * Setup buffer registry per UID for the given session and application. If none
 * is found, a new one is created, added to the global registry and
 * initialized. If regp is valid, it's set with the newly created object.
 *
 * Return 0 on success or else a negative value.
 */
static int setup_buffer_reg_uid(struct ltt_ust_session *usess,
				struct ust_app_session *ua_sess,
				struct ust_app *app,
				struct buffer_reg_uid **regp)
{
	int ret = 0;
	struct buffer_reg_uid *reg_uid;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(app);

	lttng::urcu::read_lock_guard read_lock;

	reg_uid = buffer_reg_uid_find(usess->id, app->abi.bits_per_long, app->uid);
	if (!reg_uid) {
		/*
		 * This is the create channel path meaning that if there is NO
		 * registry available, we have to create one for this session.
		 */
		ret = buffer_reg_uid_create(usess->id,
					    app->abi.bits_per_long,
					    app->uid,
					    LTTNG_DOMAIN_UST,
					    &reg_uid,
					    ua_sess->root_shm_path,
					    ua_sess->shm_path);
		if (ret < 0) {
			goto error;
		}
	} else {
		goto end;
	}

	/* Initialize registry. */
	reg_uid->registry->reg.ust = ust_registry_session_per_uid_create(app->abi,
									 app->version.major,
									 app->version.minor,
									 reg_uid->root_shm_path,
									 reg_uid->shm_path,
									 usess->uid,
									 usess->gid,
									 ua_sess->tracing_id,
									 app->uid);
	if (!reg_uid->registry->reg.ust) {
		/*
		 * reg_uid->registry->reg.ust is NULL upon error, so we need to
		 * destroy the buffer registry, because it is always expected
		 * that if the buffer registry can be found, its ust registry is
		 * non-NULL.
		 */
		buffer_reg_uid_destroy(reg_uid, nullptr);
		goto error;
	}

	/* Add node to teardown list of the session. */
	cds_list_add(&reg_uid->lnode, &usess->buffer_reg_uid_list);

	buffer_reg_uid_add(reg_uid);

	DBG3("UST app buffer registry per UID created successfully");
end:
	if (regp) {
		*regp = reg_uid;
	}
error:
	return ret;
}

/*
 * Create a session on the tracer side for the given app.
 *
 * On success, ua_sess_ptr is populated with the session pointer or else left
 * untouched. If the session was created, is_created is set to 1. On error,
 * it's left untouched. Note that ua_sess_ptr is mandatory but is_created can
 * be NULL.
 *
 * Returns 0 on success or else a negative code which is either -ENOMEM or
 * -ENOTCONN which is the default code if the lttng_ust_ctl_create_session fails.
 */
static int find_or_create_ust_app_session(struct ltt_ust_session *usess,
					  struct ust_app *app,
					  struct ust_app_session **ua_sess_ptr,
					  int *is_created)
{
	int ret, created = 0;
	struct ust_app_session *ua_sess;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess_ptr);

	health_code_update();

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == nullptr) {
		DBG2("UST app pid: %d session id %" PRIu64 " not found, creating it",
		     app->pid,
		     usess->id);
		ua_sess = alloc_ust_app_session();
		if (ua_sess == nullptr) {
			/* Only malloc can failed so something is really wrong */
			ret = -ENOMEM;
			goto error;
		}
		shadow_copy_session(ua_sess, usess, app);
		created = 1;
	}

	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		/* Init local registry. */
		ret = setup_buffer_reg_pid(ua_sess, app, nullptr);
		if (ret < 0) {
			delete_ust_app_session(-1, ua_sess, app);
			goto error;
		}
		break;
	case LTTNG_BUFFER_PER_UID:
		/* Look for a global registry. If none exists, create one. */
		ret = setup_buffer_reg_uid(usess, ua_sess, app, nullptr);
		if (ret < 0) {
			delete_ust_app_session(-1, ua_sess, app);
			goto error;
		}
		break;
	default:
		abort();
		ret = -EINVAL;
		goto error;
	}

	health_code_update();

	if (ua_sess->handle == -1) {
		pthread_mutex_lock(&app->sock_lock);
		ret = lttng_ust_ctl_create_session(app->sock);
		pthread_mutex_unlock(&app->sock_lock);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				DBG("UST app creating session failed. Application is dead: pid = %d, sock = %d",
				    app->pid,
				    app->sock);
				ret = 0;
			} else if (ret == -EAGAIN) {
				DBG("UST app creating session failed. Communication time out: pid = %d, sock = %d",
				    app->pid,
				    app->sock);
				ret = 0;
			} else {
				ERR("UST app creating session failed with ret %d: pid = %d, sock =%d",
				    ret,
				    app->pid,
				    app->sock);
			}
			delete_ust_app_session(-1, ua_sess, app);
			if (ret != -ENOMEM) {
				/*
				 * Tracer is probably gone or got an internal error so let's
				 * behave like it will soon unregister or not usable.
				 */
				ret = -ENOTCONN;
			}
			goto error;
		}

		ua_sess->handle = ret;

		/* Add ust app session to app's HT */
		lttng_ht_node_init_u64(&ua_sess->node, ua_sess->tracing_id);
		lttng_ht_add_unique_u64(app->sessions, &ua_sess->node);
		lttng_ht_node_init_ulong(&ua_sess->ust_objd_node, ua_sess->handle);
		lttng_ht_add_unique_ulong(app->ust_sessions_objd, &ua_sess->ust_objd_node);

		DBG2("UST app session created successfully with handle %d", ret);
	}

	*ua_sess_ptr = ua_sess;
	if (is_created) {
		*is_created = created;
	}

	/* Everything went well. */
	ret = 0;

error:
	health_code_update();
	return ret;
}

/*
 * Match function for a hash table lookup of ust_app_ctx.
 *
 * It matches an ust app context based on the context type and, in the case
 * of perf counters, their name.
 */
static int ht_match_ust_app_ctx(struct cds_lfht_node *node, const void *_key)
{
	struct ust_app_ctx *ctx;
	const struct lttng_ust_context_attr *key;

	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	ctx = caa_container_of(node, struct ust_app_ctx, node.node);
	key = (lttng_ust_context_attr *) _key;

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
	node = lttng_ht_iter_get_node_ulong(&iter);
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
static int create_ust_app_channel_context(struct ust_app_channel *ua_chan,
					  struct lttng_ust_context_attr *uctx,
					  struct ust_app *app)
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

	ua_ctx = alloc_ust_app_ctx(uctx);
	if (ua_ctx == nullptr) {
		/* malloc failed */
		ret = -ENOMEM;
		goto error;
	}

	lttng_ht_node_init_ulong(&ua_ctx->node, (unsigned long) ua_ctx->ctx.ctx);
	lttng_ht_add_ulong(ua_chan->ctx, &ua_ctx->node);
	cds_list_add_tail(&ua_ctx->list, &ua_chan->ctx_list);

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
static int enable_ust_app_event(struct ust_app_event *ua_event, struct ust_app *app)
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
static int disable_ust_app_event(struct ust_app_event *ua_event, struct ust_app *app)
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
static int disable_ust_app_channel(struct ust_app_session *ua_sess,
				   struct ust_app_channel *ua_chan,
				   struct ust_app *app)
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
static int enable_ust_app_channel(struct ust_app_session *ua_sess,
				  struct ltt_ust_channel *uchan,
				  struct ust_app *app)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app_channel *ua_chan;

	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(ua_sess->channels, (void *) uchan->name, &iter);
	ua_chan_node = lttng_ht_iter_get_node_str(&iter);
	if (ua_chan_node == nullptr) {
		DBG2("Unable to find channel %s in ust session id %" PRIu64,
		     uchan->name,
		     ua_sess->tracing_id);
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
static int do_consumer_create_channel(struct ltt_ust_session *usess,
				      struct ust_app_session *ua_sess,
				      struct ust_app_channel *ua_chan,
				      int bitness,
				      lsu::registry_session *registry)
{
	int ret;
	unsigned int nb_fd = 0;
	struct consumer_socket *socket;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(registry);

	lttng::urcu::read_lock_guard read_lock;
	health_code_update();

	/* Get the right consumer socket for the application. */
	socket = consumer_find_socket_by_bitness(bitness, usess->consumer);
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
		ua_sess, ua_chan, usess->consumer, socket, registry, usess->current_trace_chunk);
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
	if (usess->consumer->enabled) {
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
 * Duplicate the ust data object of the ust app stream and save it in the
 * buffer registry stream.
 *
 * Return 0 on success or else a negative value.
 */
static int duplicate_stream_object(struct buffer_reg_stream *reg_stream,
				   struct ust_app_stream *stream)
{
	int ret;

	LTTNG_ASSERT(reg_stream);
	LTTNG_ASSERT(stream);

	/* Duplicating a stream requires 2 new fds. Reserve them. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 2);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon duplicate stream");
		goto error;
	}

	/* Duplicate object for stream once the original is in the registry. */
	ret = lttng_ust_ctl_duplicate_ust_object_data(&stream->obj, reg_stream->obj.ust);
	if (ret < 0) {
		ERR("Duplicate stream obj from %p to %p failed with ret %d",
		    reg_stream->obj.ust,
		    stream->obj,
		    ret);
		lttng_fd_put(LTTNG_FD_APPS, 2);
		goto error;
	}
	stream->handle = stream->obj->handle;

error:
	return ret;
}

/*
 * Duplicate the ust data object of the ust app. channel and save it in the
 * buffer registry channel.
 *
 * Return 0 on success or else a negative value.
 */
static int duplicate_channel_object(struct buffer_reg_channel *buf_reg_chan,
				    struct ust_app_channel *ua_chan)
{
	int ret;

	LTTNG_ASSERT(buf_reg_chan);
	LTTNG_ASSERT(ua_chan);

	/* Duplicating a channel requires 1 new fd. Reserve it. */
	ret = lttng_fd_get(LTTNG_FD_APPS, 1);
	if (ret < 0) {
		ERR("Exhausted number of available FD upon duplicate channel");
		goto error_fd_get;
	}

	/* Duplicate object for stream once the original is in the registry. */
	ret = lttng_ust_ctl_duplicate_ust_object_data(&ua_chan->obj, buf_reg_chan->obj.ust);
	if (ret < 0) {
		ERR("Duplicate channel obj from %p to %p failed with ret: %d",
		    buf_reg_chan->obj.ust,
		    ua_chan->obj,
		    ret);
		goto error;
	}
	ua_chan->handle = ua_chan->obj->handle;

	return 0;

error:
	lttng_fd_put(LTTNG_FD_APPS, 1);
error_fd_get:
	return ret;
}

/*
 * For a given channel buffer registry, setup all streams of the given ust
 * application channel.
 *
 * Return 0 on success or else a negative value.
 */
static int setup_buffer_reg_streams(struct buffer_reg_channel *buf_reg_chan,
				    struct ust_app_channel *ua_chan,
				    struct ust_app *app)
{
	int ret = 0;
	struct ust_app_stream *stream, *stmp;

	LTTNG_ASSERT(buf_reg_chan);
	LTTNG_ASSERT(ua_chan);

	DBG2("UST app setup buffer registry stream");

	/* Send all streams to application. */
	cds_list_for_each_entry_safe (stream, stmp, &ua_chan->streams.head, list) {
		struct buffer_reg_stream *reg_stream;

		ret = buffer_reg_stream_create(&reg_stream);
		if (ret < 0) {
			goto error;
		}

		/*
		 * Keep original pointer and nullify it in the stream so the delete
		 * stream call does not release the object.
		 */
		reg_stream->obj.ust = stream->obj;
		stream->obj = nullptr;
		buffer_reg_stream_add(reg_stream, buf_reg_chan);

		/* We don't need the streams anymore. */
		cds_list_del(&stream->list);
		delete_ust_app_stream(-1, stream, app);
	}

error:
	return ret;
}

/*
 * Create a buffer registry channel for the given session registry and
 * application channel object. If regp pointer is valid, it's set with the
 * created object. Important, the created object is NOT added to the session
 * registry hash table.
 *
 * Return 0 on success else a negative value.
 */
static int create_buffer_reg_channel(struct buffer_reg_session *reg_sess,
				     struct ust_app_channel *ua_chan,
				     struct buffer_reg_channel **regp)
{
	int ret;
	struct buffer_reg_channel *buf_reg_chan = nullptr;

	LTTNG_ASSERT(reg_sess);
	LTTNG_ASSERT(ua_chan);

	DBG2("UST app creating buffer registry channel for %s", ua_chan->name);

	/* Create buffer registry channel. */
	ret = buffer_reg_channel_create(ua_chan->tracing_channel_id, &buf_reg_chan);
	if (ret < 0) {
		goto error_create;
	}
	LTTNG_ASSERT(buf_reg_chan);
	buf_reg_chan->consumer_key = ua_chan->key;
	buf_reg_chan->subbuf_size = ua_chan->attr.subbuf_size;
	buf_reg_chan->num_subbuf = ua_chan->attr.num_subbuf;

	/* Create and add a channel registry to session. */
	try {
		reg_sess->reg.ust->add_channel(ua_chan->tracing_channel_id);
	} catch (const std::exception& ex) {
		ERR("Failed to add a channel registry to userspace registry session: %s",
		    ex.what());
		ret = -1;
		goto error;
	}

	buffer_reg_channel_add(reg_sess, buf_reg_chan);

	if (regp) {
		*regp = buf_reg_chan;
	}

	return 0;

error:
	/* Safe because the registry channel object was not added to any HT. */
	buffer_reg_channel_destroy(buf_reg_chan, LTTNG_DOMAIN_UST);
error_create:
	return ret;
}

/*
 * Setup buffer registry channel for the given session registry and application
 * channel object. If regp pointer is valid, it's set with the created object.
 *
 * Return 0 on success else a negative value.
 */
static int setup_buffer_reg_channel(struct buffer_reg_session *reg_sess,
				    struct ust_app_channel *ua_chan,
				    struct buffer_reg_channel *buf_reg_chan,
				    struct ust_app *app)
{
	int ret;

	LTTNG_ASSERT(reg_sess);
	LTTNG_ASSERT(buf_reg_chan);
	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(ua_chan->obj);

	DBG2("UST app setup buffer registry channel for %s", ua_chan->name);

	/* Setup all streams for the registry. */
	ret = setup_buffer_reg_streams(buf_reg_chan, ua_chan, app);
	if (ret < 0) {
		goto error;
	}

	buf_reg_chan->obj.ust = ua_chan->obj;
	ua_chan->obj = nullptr;

	return 0;

error:
	buffer_reg_channel_remove(reg_sess, buf_reg_chan);
	buffer_reg_channel_destroy(buf_reg_chan, LTTNG_DOMAIN_UST);
	return ret;
}

/*
 * Send buffer registry channel to the application.
 *
 * Return 0 on success else a negative value.
 */
static int send_channel_uid_to_ust(struct buffer_reg_channel *buf_reg_chan,
				   struct ust_app *app,
				   struct ust_app_session *ua_sess,
				   struct ust_app_channel *ua_chan)
{
	int ret;
	struct buffer_reg_stream *reg_stream;

	LTTNG_ASSERT(buf_reg_chan);
	LTTNG_ASSERT(app);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);

	DBG("UST app sending buffer registry channel to ust sock %d", app->sock);

	ret = duplicate_channel_object(buf_reg_chan, ua_chan);
	if (ret < 0) {
		goto error;
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
		     ua_sess->tracing_id);
		/* Treat this the same way as an application that is exiting. */
		ret = -ENOTCONN;
		goto error;
	} else if (ret < 0) {
		goto error;
	}

	health_code_update();

	/* Send all streams to application. */
	pthread_mutex_lock(&buf_reg_chan->stream_list_lock);
	cds_list_for_each_entry (reg_stream, &buf_reg_chan->streams, lnode) {
		struct ust_app_stream stream = {};

		ret = duplicate_stream_object(reg_stream, &stream);
		if (ret < 0) {
			goto error_stream_unlock;
		}

		ret = ust_consumer_send_stream_to_ust(app, ua_chan, &stream);
		if (ret < 0) {
			if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
				ret = -ENOTCONN; /* Caused by app exiting. */
			} else if (ret == -EAGAIN) {
				/*
				 * Caused by timeout.
				 * Treat this the same way as an application
				 * that is exiting.
				 */
				WARN("Communication with application %d timed out on send_stream for stream of channel \"%s\" of session \"%" PRIu64
				     "\".",
				     app->pid,
				     ua_chan->name,
				     ua_sess->tracing_id);
				ret = -ENOTCONN;
			}
			(void) release_ust_app_stream(-1, &stream, app);
			goto error_stream_unlock;
		}

		/*
		 * The return value is not important here. This function will output an
		 * error if needed.
		 */
		(void) release_ust_app_stream(-1, &stream, app);
	}

error_stream_unlock:
	pthread_mutex_unlock(&buf_reg_chan->stream_list_lock);
error:
	return ret;
}

/*
 * Create and send to the application the created buffers with per UID buffers.
 *
 * This MUST be called with a RCU read side lock acquired.
 * The session list lock and the session's lock must be acquired.
 *
 * Return 0 on success else a negative value.
 */
static int create_channel_per_uid(struct ust_app *app,
				  struct ltt_ust_session *usess,
				  struct ust_app_session *ua_sess,
				  struct ust_app_channel *ua_chan)
{
	int ret;
	struct buffer_reg_uid *reg_uid;
	struct buffer_reg_channel *buf_reg_chan;
	struct ltt_session *session = nullptr;
	enum lttng_error_code notification_ret;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);
	ASSERT_RCU_READ_LOCKED();

	DBG("UST app creating channel %s with per UID buffers", ua_chan->name);

	reg_uid = buffer_reg_uid_find(usess->id, app->abi.bits_per_long, app->uid);
	/*
	 * The session creation handles the creation of this global registry
	 * object. If none can be find, there is a code flow problem or a
	 * teardown race.
	 */
	LTTNG_ASSERT(reg_uid);

	buf_reg_chan = buffer_reg_channel_find(ua_chan->tracing_channel_id, reg_uid);
	if (buf_reg_chan) {
		goto send_channel;
	}

	/* Create the buffer registry channel object. */
	ret = create_buffer_reg_channel(reg_uid->registry, ua_chan, &buf_reg_chan);
	if (ret < 0) {
		ERR("Error creating the UST channel \"%s\" registry instance", ua_chan->name);
		goto error;
	}

	session = session_find_by_id(ua_sess->tracing_id);
	LTTNG_ASSERT(session);
	ASSERT_LOCKED(session->lock);
	ASSERT_SESSION_LIST_LOCKED();

	/*
	 * Create the buffers on the consumer side. This call populates the
	 * ust app channel object with all streams and data object.
	 */
	ret = do_consumer_create_channel(
		usess, ua_sess, ua_chan, app->abi.bits_per_long, reg_uid->registry->reg.ust);
	if (ret < 0) {
		ERR("Error creating UST channel \"%s\" on the consumer daemon", ua_chan->name);

		/*
		 * Let's remove the previously created buffer registry channel so
		 * it's not visible anymore in the session registry.
		 */
		auto locked_registry = reg_uid->registry->reg.ust->lock();
		try {
			locked_registry->remove_channel(ua_chan->tracing_channel_id, false);
		} catch (const std::exception& ex) {
			DBG("Could not find channel for removal: %s", ex.what());
		}
		buffer_reg_channel_remove(reg_uid->registry, buf_reg_chan);
		buffer_reg_channel_destroy(buf_reg_chan, LTTNG_DOMAIN_UST);
		goto error;
	}

	/*
	 * Setup the streams and add it to the session registry.
	 */
	ret = setup_buffer_reg_channel(reg_uid->registry, ua_chan, buf_reg_chan, app);
	if (ret < 0) {
		ERR("Error setting up UST channel \"%s\"", ua_chan->name);
		goto error;
	}

	{
		auto locked_registry = reg_uid->registry->reg.ust->lock();
		auto& ust_reg_chan = locked_registry->channel(ua_chan->tracing_channel_id);

		ust_reg_chan._consumer_key = ua_chan->key;
	}

	/* Notify the notification subsystem of the channel's creation. */
	notification_ret = notification_thread_command_add_channel(
		the_notification_thread_handle,
		session->id,
		ua_chan->name,
		ua_chan->key,
		LTTNG_DOMAIN_UST,
		ua_chan->attr.subbuf_size * ua_chan->attr.num_subbuf);
	if (notification_ret != LTTNG_OK) {
		ret = -(int) notification_ret;
		ERR("Failed to add channel to notification thread");
		goto error;
	}

send_channel:
	/* Send buffers to the application. */
	ret = send_channel_uid_to_ust(buf_reg_chan, app, ua_sess, ua_chan);
	if (ret < 0) {
		if (ret != -ENOTCONN) {
			ERR("Error sending channel to application");
		}
		goto error;
	}

error:
	if (session) {
		session_put(session);
	}
	return ret;
}

/*
 * Create and send to the application the created buffers with per PID buffers.
 *
 * Called with UST app session lock held.
 * The session list lock and the session's lock must be acquired.
 *
 * Return 0 on success else a negative value.
 */
static int create_channel_per_pid(struct ust_app *app,
				  struct ltt_ust_session *usess,
				  struct ust_app_session *ua_sess,
				  struct ust_app_channel *ua_chan)
{
	int ret;
	lsu::registry_session *registry;
	enum lttng_error_code cmd_ret;
	struct ltt_session *session = nullptr;
	uint64_t chan_reg_key;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);

	DBG("UST app creating channel %s with per PID buffers", ua_chan->name);

	lttng::urcu::read_lock_guard read_lock;

	registry = get_session_registry(ua_sess);
	/* The UST app session lock is held, registry shall not be null. */
	LTTNG_ASSERT(registry);

	/* Create and add a new channel registry to session. */
	try {
		registry->add_channel(ua_chan->key);
	} catch (const std::exception& ex) {
		ERR("Error creating the UST channel \"%s\" registry instance: %s",
		    ua_chan->name,
		    ex.what());
		ret = -1;
		goto error;
	}

	session = session_find_by_id(ua_sess->tracing_id);
	LTTNG_ASSERT(session);
	ASSERT_LOCKED(session->lock);
	ASSERT_SESSION_LIST_LOCKED();

	/* Create and get channel on the consumer side. */
	ret = do_consumer_create_channel(usess, ua_sess, ua_chan, app->abi.bits_per_long, registry);
	if (ret < 0) {
		ERR("Error creating UST channel \"%s\" on the consumer daemon", ua_chan->name);
		goto error_remove_from_registry;
	}

	ret = send_channel_pid_to_ust(app, ua_sess, ua_chan);
	if (ret < 0) {
		if (ret != -ENOTCONN) {
			ERR("Error sending channel to application");
		}
		goto error_remove_from_registry;
	}

	chan_reg_key = ua_chan->key;
	{
		auto locked_registry = registry->lock();

		auto& ust_reg_chan = locked_registry->channel(chan_reg_key);
		ust_reg_chan._consumer_key = ua_chan->key;
	}

	cmd_ret = notification_thread_command_add_channel(the_notification_thread_handle,
							  session->id,
							  ua_chan->name,
							  ua_chan->key,
							  LTTNG_DOMAIN_UST,
							  ua_chan->attr.subbuf_size *
								  ua_chan->attr.num_subbuf);
	if (cmd_ret != LTTNG_OK) {
		ret = -(int) cmd_ret;
		ERR("Failed to add channel to notification thread");
		goto error_remove_from_registry;
	}

error_remove_from_registry:
	if (ret) {
		try {
			auto locked_registry = registry->lock();
			locked_registry->remove_channel(ua_chan->key, false);
		} catch (const std::exception& ex) {
			DBG("Could not find channel for removal: %s", ex.what());
		}
	}
error:
	if (session) {
		session_put(session);
	}
	return ret;
}

/*
 * From an already allocated ust app channel, create the channel buffers if
 * needed and send them to the application. This MUST be called with a RCU read
 * side lock acquired.
 *
 * Called with UST app session lock held.
 *
 * Return 0 on success or else a negative value. Returns -ENOTCONN if
 * the application exited concurrently.
 */
static int ust_app_channel_send(struct ust_app *app,
				struct ltt_ust_session *usess,
				struct ust_app_session *ua_sess,
				struct ust_app_channel *ua_chan)
{
	int ret;

	LTTNG_ASSERT(app);
	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(usess->active);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(ua_chan);
	ASSERT_RCU_READ_LOCKED();

	/* Handle buffer type before sending the channel to the application. */
	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_UID:
	{
		ret = create_channel_per_uid(app, usess, ua_sess, ua_chan);
		if (ret < 0) {
			goto error;
		}
		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		ret = create_channel_per_pid(app, usess, ua_sess, ua_chan);
		if (ret < 0) {
			goto error;
		}
		break;
	}
	default:
		abort();
		ret = -EINVAL;
		goto error;
	}

	/* Initialize ust objd object using the received handle and add it. */
	lttng_ht_node_init_ulong(&ua_chan->ust_objd_node, ua_chan->handle);
	lttng_ht_add_unique_ulong(app->ust_objd, &ua_chan->ust_objd_node);

	/* If channel is not enabled, disable it on the tracer */
	if (!ua_chan->enabled) {
		ret = disable_ust_channel(app, ua_sess, ua_chan);
		if (ret < 0) {
			goto error;
		}
	}

error:
	return ret;
}

/*
 * Create UST app channel and return it through ua_chanp if not NULL.
 *
 * Called with UST app session lock and RCU read-side lock held.
 *
 * Return 0 on success or else a negative value.
 */
static int ust_app_channel_allocate(struct ust_app_session *ua_sess,
				    struct ltt_ust_channel *uchan,
				    enum lttng_ust_abi_chan_type type,
				    struct ltt_ust_session *usess __attribute__((unused)),
				    struct ust_app_channel **ua_chanp)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app_channel *ua_chan;

	ASSERT_RCU_READ_LOCKED();

	/* Lookup channel in the ust app session */
	lttng_ht_lookup(ua_sess->channels, (void *) uchan->name, &iter);
	ua_chan_node = lttng_ht_iter_get_node_str(&iter);
	if (ua_chan_node != nullptr) {
		ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);
		goto end;
	}

	ua_chan = alloc_ust_app_channel(uchan->name, ua_sess, &uchan->attr);
	if (ua_chan == nullptr) {
		/* Only malloc can fail here */
		ret = -ENOMEM;
		goto error;
	}
	shadow_copy_channel(ua_chan, uchan);

	/* Set channel type. */
	ua_chan->attr.type = type;

	/* Only add the channel if successful on the tracer side. */
	lttng_ht_add_unique_str(ua_sess->channels, &ua_chan->node);
end:
	if (ua_chanp) {
		*ua_chanp = ua_chan;
	}

	/* Everything went well. */
	return 0;

error:
	return ret;
}

/*
 * Create UST app event and create it on the tracer side.
 *
 * Must be called with the RCU read side lock held.
 * Called with ust app session mutex held.
 */
static int create_ust_app_event(struct ust_app_channel *ua_chan,
				struct ltt_ust_event *uevent,
				struct ust_app *app)
{
	int ret = 0;
	struct ust_app_event *ua_event;

	ASSERT_RCU_READ_LOCKED();

	ua_event = alloc_ust_app_event(uevent->attr.name, &uevent->attr);
	if (ua_event == nullptr) {
		/* Only failure mode of alloc_ust_app_event(). */
		ret = -ENOMEM;
		goto end;
	}
	shadow_copy_event(ua_event, uevent);

	/* Create it on the tracer side */
	ret = create_ust_event(app, ua_chan, ua_event);
	if (ret < 0) {
		/*
		 * Not found previously means that it does not exist on the
		 * tracer. If the application reports that the event existed,
		 * it means there is a bug in the sessiond or lttng-ust
		 * (or corruption, etc.)
		 */
		if (ret == -LTTNG_UST_ERR_EXIST) {
			ERR("Tracer for application reported that an event being created already existed: "
			    "event_name = \"%s\", pid = %d, ppid = %d, uid = %d, gid = %d",
			    uevent->attr.name,
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
static int create_ust_app_event_notifier_rule(struct lttng_trigger *trigger, struct ust_app *app)
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
static int create_ust_app_metadata(struct ust_app_session *ua_sess,
				   struct ust_app *app,
				   struct consumer_output *consumer)
{
	int ret = 0;
	struct ust_app_channel *metadata;
	struct consumer_socket *socket;
	struct ltt_session *session = nullptr;

	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(app);
	LTTNG_ASSERT(consumer);
	ASSERT_RCU_READ_LOCKED();

	auto locked_registry = get_locked_session_registry(ua_sess);
	/* The UST app session is held registry shall not be null. */
	LTTNG_ASSERT(locked_registry);

	/* Metadata already exists for this registry or it was closed previously */
	if (locked_registry->_metadata_key || locked_registry->_metadata_closed) {
		ret = 0;
		goto error;
	}

	/* Allocate UST metadata */
	metadata = alloc_ust_app_channel(DEFAULT_METADATA_NAME, ua_sess, nullptr);
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

	session = session_find_by_id(ua_sess->tracing_id);
	LTTNG_ASSERT(session);
	ASSERT_LOCKED(session->lock);
	ASSERT_SESSION_LIST_LOCKED();

	/*
	 * Ask the metadata channel creation to the consumer. The metadata object
	 * will be created by the consumer and kept their. However, the stream is
	 * never added or monitored until we do a first push metadata to the
	 * consumer.
	 */
	ret = ust_consumer_ask_channel(ua_sess,
				       metadata,
				       consumer,
				       socket,
				       locked_registry.get(),
				       session->current_trace_chunk);
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
	delete_ust_app_channel(-1, metadata, app, locked_registry);
error:
	if (session) {
		session_put(session);
	}
	return ret;
}

/*
 * Return ust app pointer or NULL if not found. RCU read side lock MUST be
 * acquired before calling this function.
 */
struct ust_app *ust_app_find_by_pid(pid_t pid)
{
	struct ust_app *app = nullptr;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;

	lttng_ht_lookup(ust_app_ht, (void *) ((unsigned long) pid), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == nullptr) {
		DBG2("UST app no found with pid %d", pid);
		goto error;
	}

	DBG2("Found UST app by pid %d", pid);

	app = lttng::utils::container_of(node, &ust_app::pid_n);

error:
	return app;
}

/*
 * Allocate and init an UST app object using the registration information and
 * the command socket. This is called when the command socket connects to the
 * session daemon.
 *
 * The object is returned on success or else NULL.
 */
struct ust_app *ust_app_create(struct ust_register_msg *msg, int sock)
{
	int ret;
	struct ust_app *lta = nullptr;
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

	lta = zmalloc<ust_app>();
	if (lta == nullptr) {
		PERROR("malloc");
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

	CDS_INIT_LIST_HEAD(&lta->teardown_head);
	return lta;

error_free_pipe:
	lttng_pipe_destroy(event_notifier_event_source_pipe);
	lttng_fd_put(LTTNG_FD_APPS, 2);
error:
	return nullptr;
}

/*
 * For a given application object, add it to every hash table.
 */
void ust_app_add(struct ust_app *app)
{
	LTTNG_ASSERT(app);
	LTTNG_ASSERT(app->notify_sock >= 0);

	app->registration_time = time(nullptr);

	lttng::urcu::read_lock_guard read_lock;

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
int ust_app_version(struct ust_app *app)
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

bool ust_app_supports_notifiers(const struct ust_app *app)
{
	return app->v_major >= 9;
}

bool ust_app_supports_counters(const struct ust_app *app)
{
	return app->v_major >= 9;
}

/*
 * Setup the base event notifier group.
 *
 * Return 0 on success else a negative value either an errno code or a
 * LTTng-UST error code.
 */
int ust_app_setup_event_notifier_group(struct ust_app *app)
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

static void ust_app_unregister(ust_app& app)
{
	struct lttng_ht_iter iter;
	struct ust_app_session *ua_sess;

	lttng::urcu::read_lock_guard read_lock;

	/*
	 * For per-PID buffers, perform "push metadata" and flush all
	 * application streams before removing app from hash tables,
	 * ensuring proper behavior of data_pending check.
	 * Remove sessions so they are not visible during deletion.
	 */
	cds_lfht_for_each_entry (app.sessions->ht, &iter.iter, ua_sess, node.node) {
		const auto del_ret = lttng_ht_del(app.sessions, &iter);
		if (del_ret) {
			/* The session was already removed so scheduled for teardown. */
			continue;
		}

		if (ua_sess->buffer_type == LTTNG_BUFFER_PER_PID) {
			(void) ust_app_flush_app_session(app, *ua_sess);
		}

		/*
		 * Add session to list for teardown. This is safe since at this point we
		 * are the only one using this list.
		 */
		lttng::pthread::lock_guard ust_app_session_lock(ua_sess->lock);

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
		auto locked_registry = get_locked_session_registry(ua_sess);
		if (locked_registry) {
			/* Push metadata for application before freeing the application. */
			(void) push_metadata(locked_registry, ua_sess->consumer);

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

				/* Release lock before communication, see comments in
				 * close_metadata(). */
				locked_registry.reset();
				(void) close_metadata(
					metadata_key, consumer_bitness, ua_sess->consumer);
			} else {
				locked_registry.reset();
			}
		}

		cds_list_add(&ua_sess->teardown_node, &app.teardown_head);
	}

	/*
	 * Remove application from notify hash table. The thread handling the
	 * notify socket could have deleted the node so ignore on error because
	 * either way it's valid. The close of that socket is handled by the
	 * apps_notify_thread.
	 */
	iter.iter.node = &app.notify_sock_n.node;
	(void) lttng_ht_del(ust_app_ht_by_notify_sock, &iter);

	/*
	 * Ignore return value since the node might have been removed before by an
	 * add replace during app registration because the PID can be reassigned by
	 * the OS.
	 */
	iter.iter.node = &app.pid_n.node;
	if (lttng_ht_del(ust_app_ht, &iter)) {
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
	struct ust_app *app;
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter ust_app_sock_iter;
	int ret;

	lttng::urcu::read_lock_guard read_lock;

	/* Get the node reference for a call_rcu */
	lttng_ht_lookup(ust_app_ht_by_sock, (void *) ((unsigned long) sock_fd), &ust_app_sock_iter);
	node = lttng_ht_iter_get_node_ulong(&ust_app_sock_iter);
	assert(node);

	app = caa_container_of(node, struct ust_app, sock_n);

	DBG_FMT("Application unregistering after socket activity: pid={}, socket_fd={}",
		app->pid,
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
	struct lttng_ht_iter iter;
	struct ust_app *app;
	struct lttng_event *tmp_event;

	nbmem = UST_APP_EVENT_LIST_SIZE;
	tmp_event = calloc<lttng_event>(nbmem);
	if (tmp_event == nullptr) {
		PERROR("zmalloc ust app events");
		ret = -ENOMEM;
		goto error;
	}

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			struct lttng_ust_abi_tracepoint_iter uiter;

			health_code_update();

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

			while ((ret = lttng_ust_ctl_tracepoint_list_get(
					app->sock, handle, &uiter)) != -LTTNG_UST_ERR_NOENT) {
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
					goto rcu_error;
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
						release_ret = lttng_ust_ctl_release_handle(
							app->sock, handle);
						if (release_ret < 0 &&
						    release_ret != -LTTNG_UST_ERR_EXITING &&
						    release_ret != -EPIPE) {
							ERR("Error releasing app handle for app %d with ret %d",
							    app->sock,
							    release_ret);
						}

						pthread_mutex_unlock(&app->sock_lock);
						goto rcu_error;
					}
					/* Zero the new memory */
					memset(new_tmp_event + nbmem,
					       0,
					       (new_nbmem - nbmem) * sizeof(struct lttng_event));
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
	}

	ret = count;
	*events = tmp_event;

	DBG2("UST app list events done (%zu events)", count);

rcu_error:
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
	struct lttng_ht_iter iter;
	struct ust_app *app;
	struct lttng_event_field *tmp_event;

	nbmem = UST_APP_EVENT_LIST_SIZE;
	tmp_event = calloc<lttng_event_field>(nbmem);
	if (tmp_event == nullptr) {
		PERROR("zmalloc ust app event fields");
		ret = -ENOMEM;
		goto error;
	}

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			struct lttng_ust_abi_field_iter uiter;

			health_code_update();

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

			while ((ret = lttng_ust_ctl_tracepoint_field_list_get(
					app->sock, handle, &uiter)) != -LTTNG_UST_ERR_NOENT) {
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
					release_ret =
						lttng_ust_ctl_release_handle(app->sock, handle);
					pthread_mutex_unlock(&app->sock_lock);
					if (release_ret < 0 &&
					    release_ret != -LTTNG_UST_ERR_EXITING &&
					    release_ret != -EPIPE) {
						ERR("Error releasing app handle for app %d with ret %d",
						    app->sock,
						    release_ret);
					}

					goto rcu_error;
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
						tmp_event,
						new_nbmem * sizeof(struct lttng_event_field));
					if (new_tmp_event == nullptr) {
						int release_ret;

						PERROR("realloc ust app event fields");
						free(tmp_event);
						ret = -ENOMEM;
						release_ret = lttng_ust_ctl_release_handle(
							app->sock, handle);
						pthread_mutex_unlock(&app->sock_lock);
						if (release_ret &&
						    release_ret != -LTTNG_UST_ERR_EXITING &&
						    release_ret != -EPIPE) {
							ERR("Error releasing app handle for app %d with ret %d",
							    app->sock,
							    release_ret);
						}

						goto rcu_error;
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
				ERR("Error releasing app handle for app %d with ret %d",
				    app->sock,
				    ret);
			}
		}
	}

	ret = count;
	*fields = tmp_event;

	DBG2("UST app list event fields done (%zu events)", count);

rcu_error:
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
	struct ust_app *app;
	struct lttng_ht_iter iter;

	DBG2("UST app cleaning registered apps hash table");

	/* Cleanup notify socket hash table */
	if (ust_app_ht_by_notify_sock) {
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (
			ust_app_ht_by_notify_sock->ht, &iter.iter, app, notify_sock_n.node) {
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
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht_by_sock->ht, &iter.iter, app, sock_n.node) {
			ret = lttng_ht_del(ust_app_ht_by_sock, &iter);
			LTTNG_ASSERT(!ret);
			ust_app_put(app);
		}
	}

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
	return 0;
}

/*
 * For a specific UST session, disable the channel for all registered apps.
 */
int ust_app_disable_channel_glb(struct ltt_ust_session *usess, struct ltt_ust_channel *uchan)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;

	LTTNG_ASSERT(usess->active);
	DBG2("UST app disabling channel %s from global domain for session id %" PRIu64,
	     uchan->name,
	     usess->id);

	{
		lttng::urcu::read_lock_guard read_lock;

		/* For every registered applications */
		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			struct lttng_ht_iter uiter;
			if (!app->compatible) {
				/*
				 * TODO: In time, we should notice the caller of this error by
				 * telling him that this is a version error.
				 */
				continue;
			}
			ua_sess = lookup_session_by_app(usess, app);
			if (ua_sess == nullptr) {
				continue;
			}

			/* Get channel */
			lttng_ht_lookup(ua_sess->channels, (void *) uchan->name, &uiter);
			ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
			/* If the session if found for the app, the channel must be there */
			LTTNG_ASSERT(ua_chan_node);

			ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);
			/* The channel must not be already disabled */
			LTTNG_ASSERT(ua_chan->enabled);

			/* Disable channel onto application */
			ret = disable_ust_app_channel(ua_sess, ua_chan, app);
			if (ret < 0) {
				/* XXX: We might want to report this error at some point... */
				continue;
			}
		}
	}

	return ret;
}

/*
 * For a specific UST session, enable the channel for all registered apps.
 */
int ust_app_enable_channel_glb(struct ltt_ust_session *usess, struct ltt_ust_channel *uchan)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;
	struct ust_app_session *ua_sess;

	LTTNG_ASSERT(usess->active);
	DBG2("UST app enabling channel %s to global domain for session id %" PRIu64,
	     uchan->name,
	     usess->id);

	{
		lttng::urcu::read_lock_guard read_lock;

		/* For every registered applications */
		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			if (!app->compatible) {
				/*
				 * TODO: In time, we should notice the caller of this error by
				 * telling him that this is a version error.
				 */
				continue;
			}
			ua_sess = lookup_session_by_app(usess, app);
			if (ua_sess == nullptr) {
				continue;
			}

			/* Enable channel onto application */
			ret = enable_ust_app_channel(ua_sess, uchan, app);
			if (ret < 0) {
				/* XXX: We might want to report this error at some point... */
				continue;
			}
		}
	}

	return ret;
}

/*
 * Disable an event in a channel and for a specific session.
 */
int ust_app_disable_event_glb(struct ltt_ust_session *usess,
			      struct ltt_ust_channel *uchan,
			      struct ltt_ust_event *uevent)
{
	int ret = 0;
	struct lttng_ht_iter iter, uiter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;

	LTTNG_ASSERT(usess->active);
	DBG("UST app disabling event %s for all apps in channel "
	    "%s for session id %" PRIu64,
	    uevent->attr.name,
	    uchan->name,
	    usess->id);

	{
		lttng::urcu::read_lock_guard read_lock;

		/* For all registered applications */
		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			if (!app->compatible) {
				/*
				 * TODO: In time, we should notice the caller of this error by
				 * telling him that this is a version error.
				 */
				continue;
			}
			ua_sess = lookup_session_by_app(usess, app);
			if (ua_sess == nullptr) {
				/* Next app */
				continue;
			}

			/* Lookup channel in the ust app session */
			lttng_ht_lookup(ua_sess->channels, (void *) uchan->name, &uiter);
			ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
			if (ua_chan_node == nullptr) {
				DBG2("Channel %s not found in session id %" PRIu64
				     " for app pid %d."
				     "Skipping",
				     uchan->name,
				     usess->id,
				     app->pid);
				continue;
			}
			ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

			ua_event = find_ust_app_event(
				ua_chan->events,
				uevent->attr.name,
				uevent->filter,
				(enum lttng_ust_abi_loglevel_type) uevent->attr.loglevel_type,
				uevent->attr.loglevel,
				uevent->exclusion);
			if (ua_event == nullptr) {
				DBG2("Event %s not found in channel %s for app pid %d."
				     "Skipping",
				     uevent->attr.name,
				     uchan->name,
				     app->pid);
				continue;
			}

			ret = disable_ust_app_event(ua_event, app);
			if (ret < 0) {
				/* XXX: Report error someday... */
				continue;
			}
		}
	}

	return ret;
}

/* The ua_sess lock must be held by the caller.  */
static int ust_app_channel_create(struct ltt_ust_session *usess,
				  struct ust_app_session *ua_sess,
				  struct ltt_ust_channel *uchan,
				  struct ust_app *app,
				  struct ust_app_channel **_ua_chan)
{
	int ret = 0;
	struct ust_app_channel *ua_chan = nullptr;

	LTTNG_ASSERT(ua_sess);
	ASSERT_LOCKED(ua_sess->lock);

	if (!strncmp(uchan->name, DEFAULT_METADATA_NAME, sizeof(uchan->name))) {
		copy_channel_attr_to_ustctl(&ua_sess->metadata_attr, &uchan->attr);
		ret = 0;
	} else {
		struct ltt_ust_context *uctx = nullptr;

		/*
		 * Create channel onto application and synchronize its
		 * configuration.
		 */
		ret = ust_app_channel_allocate(
			ua_sess, uchan, LTTNG_UST_ABI_CHAN_PER_CPU, usess, &ua_chan);
		if (ret < 0) {
			goto error;
		}

		ret = ust_app_channel_send(app, usess, ua_sess, ua_chan);
		if (ret) {
			goto error;
		}

		/* Add contexts. */
		cds_list_for_each_entry (uctx, &uchan->ctx_list, list) {
			ret = create_ust_app_channel_context(ua_chan, &uctx->ctx, app);
			if (ret) {
				goto error;
			}
		}
	}

error:
	if (ret < 0) {
		switch (ret) {
		case -ENOTCONN:
			/*
			 * The application's socket is not valid. Either a bad socket
			 * or a timeout on it. We can't inform the caller that for a
			 * specific app, the session failed so lets continue here.
			 */
			ret = 0; /* Not an error. */
			break;
		case -ENOMEM:
		default:
			break;
		}
	}

	if (ret == 0 && _ua_chan) {
		/*
		 * Only return the application's channel on success. Note
		 * that the channel can still be part of the application's
		 * channel hashtable on error.
		 */
		*_ua_chan = ua_chan;
	}
	return ret;
}

/*
 * Enable event for a specific session and channel on the tracer.
 */
int ust_app_enable_event_glb(struct ltt_ust_session *usess,
			     struct ltt_ust_channel *uchan,
			     struct ltt_ust_event *uevent)
{
	int ret = 0;
	struct lttng_ht_iter iter, uiter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;
	struct ust_app_event *ua_event;

	LTTNG_ASSERT(usess->active);
	DBG("UST app enabling event %s for all apps for session id %" PRIu64,
	    uevent->attr.name,
	    usess->id);

	/*
	 * NOTE: At this point, this function is called only if the session and
	 * channel passed are already created for all apps. and enabled on the
	 * tracer also.
	 */

	{
		lttng::urcu::read_lock_guard read_lock;

		/* For all registered applications */
		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			if (!app->compatible) {
				/*
				 * TODO: In time, we should notice the caller of this error by
				 * telling him that this is a version error.
				 */
				continue;
			}
			ua_sess = lookup_session_by_app(usess, app);
			if (!ua_sess) {
				/* The application has problem or is probably dead. */
				continue;
			}

			pthread_mutex_lock(&ua_sess->lock);

			if (ua_sess->deleted) {
				pthread_mutex_unlock(&ua_sess->lock);
				continue;
			}

			/* Lookup channel in the ust app session */
			lttng_ht_lookup(ua_sess->channels, (void *) uchan->name, &uiter);
			ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
			/*
			 * It is possible that the channel cannot be found is
			 * the channel/event creation occurs concurrently with
			 * an application exit.
			 */
			if (!ua_chan_node) {
				pthread_mutex_unlock(&ua_sess->lock);
				continue;
			}

			ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

			/* Get event node */
			ua_event = find_ust_app_event(
				ua_chan->events,
				uevent->attr.name,
				uevent->filter,
				(enum lttng_ust_abi_loglevel_type) uevent->attr.loglevel_type,
				uevent->attr.loglevel,
				uevent->exclusion);
			if (ua_event == nullptr) {
				DBG3("UST app enable event %s not found for app PID %d."
				     "Skipping app",
				     uevent->attr.name,
				     app->pid);
				goto next_app;
			}

			ret = enable_ust_app_event(ua_event, app);
			if (ret < 0) {
				pthread_mutex_unlock(&ua_sess->lock);
				goto error;
			}
		next_app:
			pthread_mutex_unlock(&ua_sess->lock);
		}
	}
error:
	return ret;
}

/*
 * For a specific existing UST session and UST channel, creates the event for
 * all registered apps.
 */
int ust_app_create_event_glb(struct ltt_ust_session *usess,
			     struct ltt_ust_channel *uchan,
			     struct ltt_ust_event *uevent)
{
	int ret = 0;
	struct lttng_ht_iter iter, uiter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;

	LTTNG_ASSERT(usess->active);
	DBG("UST app creating event %s for all apps for session id %" PRIu64,
	    uevent->attr.name,
	    usess->id);

	{
		lttng::urcu::read_lock_guard read_lock;

		/* For all registered applications */
		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			if (!app->compatible) {
				/*
				 * TODO: In time, we should notice the caller of this error by
				 * telling him that this is a version error.
				 */
				continue;
			}

			ua_sess = lookup_session_by_app(usess, app);
			if (!ua_sess) {
				/* The application has problem or is probably dead. */
				continue;
			}

			pthread_mutex_lock(&ua_sess->lock);

			if (ua_sess->deleted) {
				pthread_mutex_unlock(&ua_sess->lock);
				continue;
			}

			/* Lookup channel in the ust app session */
			lttng_ht_lookup(ua_sess->channels, (void *) uchan->name, &uiter);
			ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
			/* If the channel is not found, there is a code flow error */
			LTTNG_ASSERT(ua_chan_node);

			ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

			ret = create_ust_app_event(ua_chan, uevent, app);
			pthread_mutex_unlock(&ua_sess->lock);
			if (ret < 0) {
				if (ret != -LTTNG_UST_ERR_EXIST) {
					/* Possible value at this point: -ENOMEM. If so, we stop! */
					break;
				}

				DBG2("UST app event %s already exist on app PID %d",
				     uevent->attr.name,
				     app->pid);
				continue;
			}
		}
	}

	return ret;
}

/*
 * Start tracing for a specific UST session and app.
 *
 * Called with UST app session lock held.
 *
 */
static int ust_app_start_trace(struct ltt_ust_session *usess, struct ust_app *app)
{
	int ret = 0;
	struct ust_app_session *ua_sess;

	DBG("Starting tracing for ust app pid %d", app->pid);

	lttng::urcu::read_lock_guard read_lock;

	if (!app->compatible) {
		goto end;
	}

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == nullptr) {
		/* The session is in teardown process. Ignore and continue. */
		goto end;
	}

	pthread_mutex_lock(&ua_sess->lock);

	if (ua_sess->deleted) {
		pthread_mutex_unlock(&ua_sess->lock);
		goto end;
	}

	if (ua_sess->enabled) {
		pthread_mutex_unlock(&ua_sess->lock);
		goto end;
	}

	/* Upon restart, we skip the setup, already done */
	if (ua_sess->started) {
		goto skip_setup;
	}

	health_code_update();

skip_setup:
	/* This starts the UST tracing */
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_start_session(app->sock, ua_sess->handle);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app start session failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
			pthread_mutex_unlock(&ua_sess->lock);
			goto end;
		} else if (ret == -EAGAIN) {
			WARN("UST app start session failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
			pthread_mutex_unlock(&ua_sess->lock);
			goto end;

		} else {
			ERR("UST app start session failed with ret %d: pid = %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error_unlock;
	}

	/* Indicate that the session has been started once */
	ua_sess->started = true;
	ua_sess->enabled = true;

	pthread_mutex_unlock(&ua_sess->lock);

	health_code_update();

	/* Quiescent wait after starting trace */
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_wait_quiescent(app->sock);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app wait quiescent failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app wait quiescent failed. Communication time out: pid =  %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app wait quiescent failed with ret %d: pid %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
		}
	}

end:
	health_code_update();
	return 0;

error_unlock:
	pthread_mutex_unlock(&ua_sess->lock);
	health_code_update();
	return -1;
}

/*
 * Stop tracing for a specific UST session and app.
 */
static int ust_app_stop_trace(struct ltt_ust_session *usess, struct ust_app *app)
{
	int ret = 0;
	struct ust_app_session *ua_sess;

	DBG("Stopping tracing for ust app pid %d", app->pid);

	lttng::urcu::read_lock_guard read_lock;

	if (!app->compatible) {
		goto end_no_session;
	}

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == nullptr) {
		goto end_no_session;
	}

	pthread_mutex_lock(&ua_sess->lock);

	if (ua_sess->deleted) {
		pthread_mutex_unlock(&ua_sess->lock);
		goto end_no_session;
	}

	/*
	 * If started = 0, it means that stop trace has been called for a session
	 * that was never started. It's possible since we can have a fail start
	 * from either the application manager thread or the command thread. Simply
	 * indicate that this is a stop error.
	 */
	if (!ua_sess->started) {
		goto error_rcu_unlock;
	}

	health_code_update();

	/* This inhibits UST tracing */
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_stop_session(app->sock, ua_sess->handle);
	pthread_mutex_unlock(&app->sock_lock);
	if (ret < 0) {
		if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
			DBG3("UST app stop session failed. Application is dead: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
			goto end_unlock;
		} else if (ret == -EAGAIN) {
			WARN("UST app stop session failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
			goto end_unlock;

		} else {
			ERR("UST app stop session failed with ret %d: pid = %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error_rcu_unlock;
	}

	health_code_update();
	ua_sess->enabled = false;

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

	health_code_update();

	{
		auto locked_registry = get_locked_session_registry(ua_sess);

		/* The UST app session is held registry shall not be null. */
		LTTNG_ASSERT(locked_registry);

		/* Push metadata for application before freeing the application. */
		(void) push_metadata(locked_registry, ua_sess->consumer);
	}

end_unlock:
	pthread_mutex_unlock(&ua_sess->lock);
end_no_session:
	health_code_update();
	return 0;

error_rcu_unlock:
	pthread_mutex_unlock(&ua_sess->lock);
	health_code_update();
	return -1;
}

static int ust_app_flush_app_session(ust_app& app, ust_app_session& ua_sess)
{
	int ret, retval = 0;
	struct lttng_ht_iter iter;
	struct ust_app_channel *ua_chan;
	struct consumer_socket *socket;

	DBG("Flushing app session buffers for ust app pid %d", app.pid);

	if (!app.compatible) {
		goto end_not_compatible;
	}

	pthread_mutex_lock(&ua_sess.lock);

	if (ua_sess.deleted) {
		goto end_deleted;
	}

	health_code_update();

	/* Flushing buffers */
	socket = consumer_find_socket_by_bitness(app.abi.bits_per_long, ua_sess.consumer);

	/* Flush buffers and push metadata. */
	switch (ua_sess.buffer_type) {
	case LTTNG_BUFFER_PER_PID:
	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ua_sess.channels->ht, &iter.iter, ua_chan, node.node) {
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

	health_code_update();

end_deleted:
	pthread_mutex_unlock(&ua_sess.lock);

end_not_compatible:
	health_code_update();
	return retval;
}

/*
 * Flush buffers for all applications for a specific UST session.
 * Called with UST session lock held.
 */
static int ust_app_flush_session(struct ltt_ust_session *usess)

{
	int ret = 0;

	DBG("Flushing session buffers for all ust apps");

	/* Flush buffers and push metadata. */
	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_UID:
	{
		struct buffer_reg_uid *reg;
		struct lttng_ht_iter iter;

		/* Flush all per UID buffers associated to that session. */
		cds_list_for_each_entry (reg, &usess->buffer_reg_uid_list, lnode) {
			lttng::urcu::read_lock_guard read_lock;
			lsu::registry_session *ust_session_reg;
			struct buffer_reg_channel *buf_reg_chan;
			struct consumer_socket *socket;

			/* Get consumer socket to use to push the metadata.*/
			socket = consumer_find_socket_by_bitness(reg->bits_per_long,
								 usess->consumer);
			if (!socket) {
				/* Ignore request if no consumer is found for the session. */
				continue;
			}

			cds_lfht_for_each_entry (
				reg->registry->channels->ht, &iter.iter, buf_reg_chan, node.node) {
				/*
				 * The following call will print error values so the return
				 * code is of little importance because whatever happens, we
				 * have to try them all.
				 */
				(void) consumer_flush_channel(socket, buf_reg_chan->consumer_key);
			}

			ust_session_reg = reg->registry->reg.ust;
			/* Push metadata. */
			auto locked_registry = ust_session_reg->lock();
			(void) push_metadata(locked_registry, usess->consumer);
		}

		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		struct ust_app_session *ua_sess;
		struct lttng_ht_iter iter;
		struct ust_app *app;
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			ua_sess = lookup_session_by_app(usess, app);
			if (ua_sess == nullptr) {
				continue;
			}

			(void) ust_app_flush_app_session(*app, *ua_sess);
		}

		break;
	}
	default:
		ret = -1;
		abort();
		break;
	}

	health_code_update();
	return ret;
}

static int ust_app_clear_quiescent_app_session(struct ust_app *app, struct ust_app_session *ua_sess)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app_channel *ua_chan;
	struct consumer_socket *socket;

	DBG("Clearing stream quiescent state for ust app pid %d", app->pid);

	lttng::urcu::read_lock_guard read_lock;

	if (!app->compatible) {
		goto end_not_compatible;
	}

	pthread_mutex_lock(&ua_sess->lock);

	if (ua_sess->deleted) {
		goto end_unlock;
	}

	health_code_update();

	socket = consumer_find_socket_by_bitness(app->abi.bits_per_long, ua_sess->consumer);
	if (!socket) {
		ERR("Failed to find consumer (%" PRIu32 ") socket", app->abi.bits_per_long);
		ret = -1;
		goto end_unlock;
	}

	/* Clear quiescent state. */
	switch (ua_sess->buffer_type) {
	case LTTNG_BUFFER_PER_PID:
		cds_lfht_for_each_entry (ua_sess->channels->ht, &iter.iter, ua_chan, node.node) {
			health_code_update();
			ret = consumer_clear_quiescent_channel(socket, ua_chan->key);
			if (ret) {
				ERR("Error clearing quiescent state for consumer channel");
				ret = -1;
				continue;
			}
		}
		break;
	case LTTNG_BUFFER_PER_UID:
	default:
		abort();
		ret = -1;
		break;
	}

	health_code_update();

end_unlock:
	pthread_mutex_unlock(&ua_sess->lock);

end_not_compatible:
	health_code_update();
	return ret;
}

/*
 * Clear quiescent state in each stream for all applications for a
 * specific UST session.
 * Called with UST session lock held.
 */
static int ust_app_clear_quiescent_session(struct ltt_ust_session *usess)

{
	int ret = 0;

	DBG("Clearing stream quiescent state for all ust apps");

	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_UID:
	{
		struct lttng_ht_iter iter;
		struct buffer_reg_uid *reg;

		/*
		 * Clear quiescent for all per UID buffers associated to
		 * that session.
		 */
		cds_list_for_each_entry (reg, &usess->buffer_reg_uid_list, lnode) {
			struct consumer_socket *socket;
			struct buffer_reg_channel *buf_reg_chan;
			lttng::urcu::read_lock_guard read_lock;

			/* Get associated consumer socket.*/
			socket = consumer_find_socket_by_bitness(reg->bits_per_long,
								 usess->consumer);
			if (!socket) {
				/*
				 * Ignore request if no consumer is found for
				 * the session.
				 */
				continue;
			}

			cds_lfht_for_each_entry (
				reg->registry->channels->ht, &iter.iter, buf_reg_chan, node.node) {
				/*
				 * The following call will print error values so
				 * the return code is of little importance
				 * because whatever happens, we have to try them
				 * all.
				 */
				(void) consumer_clear_quiescent_channel(socket,
									buf_reg_chan->consumer_key);
			}
		}

		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		struct ust_app_session *ua_sess;
		struct lttng_ht_iter iter;
		struct ust_app *app;
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			ua_sess = lookup_session_by_app(usess, app);
			if (ua_sess == nullptr) {
				continue;
			}
			(void) ust_app_clear_quiescent_app_session(app, ua_sess);
		}

		break;
	}
	default:
		ret = -1;
		abort();
		break;
	}

	health_code_update();
	return ret;
}

/*
 * Destroy a specific UST session in apps.
 */
static int destroy_trace(struct ltt_ust_session *usess, struct ust_app *app)
{
	int ret;
	struct ust_app_session *ua_sess;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_u64 *node;

	DBG("Destroy tracing for ust app pid %d", app->pid);

	lttng::urcu::read_lock_guard read_lock;

	if (!app->compatible) {
		goto end;
	}

	__lookup_session_by_app(usess, app, &iter);
	node = lttng_ht_iter_get_node_u64(&iter);
	if (node == nullptr) {
		/* Session is being or is deleted. */
		goto end;
	}
	ua_sess = lttng::utils::container_of(node, &ust_app_session::node);

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
 * Start tracing for the UST session.
 */
int ust_app_start_trace_all(struct ltt_ust_session *usess)
{
	struct lttng_ht_iter iter;
	struct ust_app *app;

	DBG("Starting all UST traces");

	/*
	 * Even though the start trace might fail, flag this session active so
	 * other application coming in are started by default.
	 */
	usess->active = true;

	/*
	 * In a start-stop-start use-case, we need to clear the quiescent state
	 * of each channel set by the prior stop command, thus ensuring that a
	 * following stop or destroy is sure to grab a timestamp_end near those
	 * operations, even if the packet is empty.
	 */
	(void) ust_app_clear_quiescent_session(usess);

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			ust_app_global_update(usess, app);
		}
	}

	return 0;
}

/*
 * Start tracing for the UST session.
 * Called with UST session lock held.
 */
int ust_app_stop_trace_all(struct ltt_ust_session *usess)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;

	DBG("Stopping all UST traces");

	/*
	 * Even though the stop trace might fail, flag this session inactive so
	 * other application coming in are not started by default.
	 */
	usess->active = false;

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			ret = ust_app_stop_trace(usess, app);
			if (ret < 0) {
				/* Continue to next apps even on error */
				continue;
			}
		}
	}

	(void) ust_app_flush_session(usess);

	return 0;
}

/*
 * Destroy app UST session.
 */
int ust_app_destroy_trace_all(struct ltt_ust_session *usess)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;

	DBG("Destroy all UST traces");

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			ret = destroy_trace(usess, app);
			if (ret < 0) {
				/* Continue to next apps even on error */
				continue;
			}
		}
	}

	return 0;
}

/* The ua_sess lock must be held by the caller. */
static int find_or_create_ust_app_channel(struct ltt_ust_session *usess,
					  struct ust_app_session *ua_sess,
					  struct ust_app *app,
					  struct ltt_ust_channel *uchan,
					  struct ust_app_channel **ua_chan)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;

	lttng_ht_lookup(ua_sess->channels, (void *) uchan->name, &iter);
	ua_chan_node = lttng_ht_iter_get_node_str(&iter);
	if (ua_chan_node) {
		*ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);
		goto end;
	}

	ret = ust_app_channel_create(usess, ua_sess, uchan, app, ua_chan);
	if (ret) {
		goto end;
	}
end:
	return ret;
}

static int ust_app_channel_synchronize_event(struct ust_app_channel *ua_chan,
					     struct ltt_ust_event *uevent,
					     struct ust_app *app)
{
	int ret = 0;
	struct ust_app_event *ua_event = nullptr;

	ua_event = find_ust_app_event(ua_chan->events,
				      uevent->attr.name,
				      uevent->filter,
				      (enum lttng_ust_abi_loglevel_type) uevent->attr.loglevel_type,
				      uevent->attr.loglevel,
				      uevent->exclusion);
	if (!ua_event) {
		ret = create_ust_app_event(ua_chan, uevent, app);
		if (ret < 0) {
			goto end;
		}
	} else {
		if (ua_event->enabled != uevent->enabled) {
			ret = uevent->enabled ? enable_ust_app_event(ua_event, app) :
						disable_ust_app_event(ua_event, app);
		}
	}

end:
	return ret;
}

/* Called with RCU read-side lock held. */
static void ust_app_synchronize_event_notifier_rules(struct ust_app *app)
{
	int ret = 0;
	enum lttng_error_code ret_code;
	enum lttng_trigger_status t_status;
	struct lttng_ht_iter app_trigger_iter;
	struct lttng_triggers *triggers = nullptr;
	struct ust_app_event_notifier_rule *event_notifier_rule;
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
		struct lttng_condition *condition;
		struct lttng_event_rule *event_rule;
		struct lttng_trigger *trigger;
		const struct ust_app_event_notifier_rule *looked_up_event_notifier_rule;
		enum lttng_condition_status condition_status;
		uint64_t token;

		trigger = lttng_triggers_borrow_mutable_at_index(triggers, i);
		LTTNG_ASSERT(trigger);

		token = lttng_trigger_get_tracer_token(trigger);
		condition = lttng_trigger_get_condition(trigger);

		if (lttng_condition_get_type(condition) !=
		    LTTNG_CONDITION_TYPE_EVENT_RULE_MATCHES) {
			/* Does not apply */
			continue;
		}

		condition_status = lttng_condition_event_rule_matches_borrow_rule_mutable(
			condition, &event_rule);
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

	{
		lttng::urcu::read_lock_guard read_lock;

		/* Remove all unknown event sources from the app. */
		cds_lfht_for_each_entry (app->token_to_event_notifier_rule_ht->ht,
					 &app_trigger_iter.iter,
					 event_notifier_rule,
					 node.node) {
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
			ret = lttng_ht_del(app->token_to_event_notifier_rule_ht, &app_trigger_iter);
			LTTNG_ASSERT(ret == 0);

			/* Callee logs errors. */
			(void) disable_ust_object(app, event_notifier_rule->obj);

			delete_ust_app_event_notifier_rule(app->sock, event_notifier_rule, app);
		}
	}

end:
	lttng_triggers_destroy(triggers);
	return;
}

/*
 * RCU read lock must be held by the caller.
 */
static void ust_app_synchronize_all_channels(struct ltt_ust_session *usess,
					     struct ust_app_session *ua_sess,
					     struct ust_app *app)
{
	int ret = 0;
	struct cds_lfht_iter uchan_iter;
	struct ltt_ust_channel *uchan;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(ua_sess);
	LTTNG_ASSERT(app);
	ASSERT_RCU_READ_LOCKED();

	cds_lfht_for_each_entry (usess->domain_global.channels->ht, &uchan_iter, uchan, node.node) {
		struct ust_app_channel *ua_chan;
		struct cds_lfht_iter uevent_iter;
		struct ltt_ust_event *uevent;

		/*
		 * Search for a matching ust_app_channel. If none is found,
		 * create it. Creating the channel will cause the ua_chan
		 * structure to be allocated, the channel buffers to be
		 * allocated (if necessary) and sent to the application, and
		 * all enabled contexts will be added to the channel.
		 */
		ret = find_or_create_ust_app_channel(usess, ua_sess, app, uchan, &ua_chan);
		if (ret) {
			/* Tracer is probably gone or ENOMEM. */
			goto end;
		}

		if (!ua_chan) {
			/* ua_chan will be NULL for the metadata channel */
			continue;
		}

		cds_lfht_for_each_entry (uchan->events->ht, &uevent_iter, uevent, node.node) {
			ret = ust_app_channel_synchronize_event(ua_chan, uevent, app);
			if (ret) {
				goto end;
			}
		}

		if (ua_chan->enabled != uchan->enabled) {
			ret = uchan->enabled ? enable_ust_app_channel(ua_sess, uchan, app) :
					       disable_ust_app_channel(ua_sess, ua_chan, app);
			if (ret) {
				goto end;
			}
		}
	}
end:
	return;
}

/*
 * The caller must ensure that the application is compatible and is tracked
 * by the process attribute trackers.
 */
static void ust_app_synchronize(struct ltt_ust_session *usess, struct ust_app *app)
{
	int ret = 0;
	struct ust_app_session *ua_sess = nullptr;

	/*
	 * The application's configuration should only be synchronized for
	 * active sessions.
	 */
	LTTNG_ASSERT(usess->active);

	ret = find_or_create_ust_app_session(usess, app, &ua_sess, nullptr);
	if (ret < 0) {
		/* Tracer is probably gone or ENOMEM. */
		goto end;
	}

	LTTNG_ASSERT(ua_sess);

	pthread_mutex_lock(&ua_sess->lock);
	if (ua_sess->deleted) {
		goto deleted_session;
	}

	{
		lttng::urcu::read_lock_guard read_lock;

		ust_app_synchronize_all_channels(usess, ua_sess, app);

		/*
		 * Create the metadata for the application. This returns gracefully if a
		 * metadata was already set for the session.
		 *
		 * The metadata channel must be created after the data channels as the
		 * consumer daemon assumes this ordering. When interacting with a relay
		 * daemon, the consumer will use this assumption to send the
		 * "STREAMS_SENT" message to the relay daemon.
		 */
		ret = create_ust_app_metadata(ua_sess, app, usess->consumer);
		if (ret < 0) {
			ERR("Metadata creation failed for app sock %d for session id %" PRIu64,
			    app->sock,
			    usess->id);
		}
	}

deleted_session:
	pthread_mutex_unlock(&ua_sess->lock);
end:
	return;
}

static void ust_app_global_destroy(struct ltt_ust_session *usess, struct ust_app *app)
{
	struct ust_app_session *ua_sess;

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == nullptr) {
		return;
	}
	destroy_app_session(app, ua_sess);
}

/*
 * Add channels/events from UST global domain to registered apps at sock.
 *
 * Called with session lock held.
 * Called with RCU read-side lock held.
 */
void ust_app_global_update(struct ltt_ust_session *usess, struct ust_app *app)
{
	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(usess->active);
	ASSERT_RCU_READ_LOCKED();

	DBG2("UST app global update for app sock %d for session id %" PRIu64, app->sock, usess->id);

	if (!app->compatible) {
		return;
	}
	if (trace_ust_id_tracker_lookup(LTTNG_PROCESS_ATTR_VIRTUAL_PROCESS_ID, usess, app->pid) &&
	    trace_ust_id_tracker_lookup(LTTNG_PROCESS_ATTR_VIRTUAL_USER_ID, usess, app->uid) &&
	    trace_ust_id_tracker_lookup(LTTNG_PROCESS_ATTR_VIRTUAL_GROUP_ID, usess, app->gid)) {
		/*
		 * Synchronize the application's internal tracing configuration
		 * and start tracing.
		 */
		ust_app_synchronize(usess, app);
		ust_app_start_trace(usess, app);
	} else {
		ust_app_global_destroy(usess, app);
	}
}

/*
 * Add all event notifiers to an application.
 *
 * Called with session lock held.
 * Called with RCU read-side lock held.
 */
void ust_app_global_update_event_notifier_rules(struct ust_app *app)
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

/*
 * Called with session lock held.
 */
void ust_app_global_update_all(struct ltt_ust_session *usess)
{
	struct lttng_ht_iter iter;
	struct ust_app *app;

	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			ust_app_global_update(usess, app);
		}
	}
}

void ust_app_global_update_all_event_notifier_rules()
{
	struct lttng_ht_iter iter;
	struct ust_app *app;

	lttng::urcu::read_lock_guard read_lock;
	cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		ust_app_global_update_event_notifier_rules(app);
	}
}

/*
 * Add context to a specific channel for global UST domain.
 */
int ust_app_add_ctx_channel_glb(struct ltt_ust_session *usess,
				struct ltt_ust_channel *uchan,
				struct ltt_ust_context *uctx)
{
	int ret = 0;
	struct lttng_ht_node_str *ua_chan_node;
	struct lttng_ht_iter iter, uiter;
	struct ust_app_channel *ua_chan = nullptr;
	struct ust_app_session *ua_sess;
	struct ust_app *app;

	LTTNG_ASSERT(usess->active);

	{
		lttng::urcu::read_lock_guard read_lock;
		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			if (!app->compatible) {
				/*
				 * TODO: In time, we should notice the caller of this error by
				 * telling him that this is a version error.
				 */
				continue;
			}
			ua_sess = lookup_session_by_app(usess, app);
			if (ua_sess == nullptr) {
				continue;
			}

			pthread_mutex_lock(&ua_sess->lock);

			if (ua_sess->deleted) {
				pthread_mutex_unlock(&ua_sess->lock);
				continue;
			}

			/* Lookup channel in the ust app session */
			lttng_ht_lookup(ua_sess->channels, (void *) uchan->name, &uiter);
			ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
			if (ua_chan_node == nullptr) {
				goto next_app;
			}
			ua_chan = caa_container_of(ua_chan_node, struct ust_app_channel, node);
			ret = create_ust_app_channel_context(ua_chan, &uctx->ctx, app);
			if (ret < 0) {
				goto next_app;
			}
		next_app:
			pthread_mutex_unlock(&ua_sess->lock);
		}
	}

	return ret;
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
static struct ust_app_session *find_session_by_objd(struct ust_app *app, int objd)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct ust_app_session *ua_sess = nullptr;

	LTTNG_ASSERT(app);
	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(app->ust_sessions_objd, (void *) ((unsigned long) objd), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
	if (node == nullptr) {
		DBG2("UST app session find by objd %d not found", objd);
		goto error;
	}

	ua_sess = lttng::utils::container_of(node, &ust_app_session::ust_objd_node);

error:
	return ua_sess;
}

/*
 * Return a ust app channel object using the application object and the channel
 * object descriptor has a key. If not found, NULL is returned. A RCU read side
 * lock MUST be acquired before calling this function.
 */
static struct ust_app_channel *find_channel_by_objd(struct ust_app *app, int objd)
{
	struct lttng_ht_node_ulong *node;
	struct lttng_ht_iter iter;
	struct ust_app_channel *ua_chan = nullptr;

	LTTNG_ASSERT(app);
	ASSERT_RCU_READ_LOCKED();

	lttng_ht_lookup(app->ust_objd, (void *) ((unsigned long) objd), &iter);
	node = lttng_ht_iter_get_node_ulong(&iter);
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
	struct ust_app *app;
	struct ust_app_channel *ua_chan;
	struct ust_app_session *ua_sess;
	auto ust_ctl_context_fields =
		lttng::make_unique_wrapper<lttng_ust_ctl_field, lttng::free>(raw_context_fields);

	lttng::urcu::read_lock_guard read_lock_guard;

	/* Lookup application. If not found, there is a code flow error. */
	app = find_app_by_notify_sock(sock);
	if (!app) {
		DBG("Application socket %d is being torn down. Abort event notify", sock);
		return -1;
	}

	/* Lookup channel by UST object descriptor. */
	ua_chan = find_channel_by_objd(app, cobjd);
	if (!ua_chan) {
		DBG("Application channel is being torn down. Abort event notify");
		return 0;
	}

	LTTNG_ASSERT(ua_chan->session);
	ua_sess = ua_chan->session;

	/* Get right session registry depending on the session buffer type. */
	auto locked_registry_session = get_locked_session_registry(ua_sess);
	if (!locked_registry_session) {
		DBG("Application session is being torn down. Abort event notify");
		return 0;
	};

	/* Depending on the buffer type, a different channel key is used. */
	if (ua_sess->buffer_type == LTTNG_BUFFER_PER_UID) {
		chan_reg_key = ua_chan->tracing_channel_id;
	} else {
		chan_reg_key = ua_chan->key;
	}

	auto& ust_reg_chan = locked_registry_session->channel(chan_reg_key);

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
			*locked_registry_session,
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
				    app->pid,
				    app->sock);
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
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app reply channel failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app reply channel failed with ret %d: pid = %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
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
	uint32_t event_id = 0;
	uint64_t chan_reg_key;
	struct ust_app *app;
	struct ust_app_channel *ua_chan;
	struct ust_app_session *ua_sess;
	lttng::urcu::read_lock_guard rcu_lock;
	auto signature = lttng::make_unique_wrapper<char, lttng::free>(raw_signature);
	auto fields = lttng::make_unique_wrapper<lttng_ust_ctl_field, lttng::free>(raw_fields);
	auto model_emf_uri = lttng::make_unique_wrapper<char, lttng::free>(raw_model_emf_uri);

	/* Lookup application. If not found, there is a code flow error. */
	app = find_app_by_notify_sock(sock);
	if (!app) {
		DBG("Application socket %d is being torn down. Abort event notify", sock);
		return -1;
	}

	/* Lookup channel by UST object descriptor. */
	ua_chan = find_channel_by_objd(app, cobjd);
	if (!ua_chan) {
		DBG("Application channel is being torn down. Abort event notify");
		return 0;
	}

	LTTNG_ASSERT(ua_chan->session);
	ua_sess = ua_chan->session;

	if (ua_sess->buffer_type == LTTNG_BUFFER_PER_UID) {
		chan_reg_key = ua_chan->tracing_channel_id;
	} else {
		chan_reg_key = ua_chan->key;
	}

	{
		auto locked_registry = get_locked_session_registry(ua_sess);
		if (locked_registry) {
			/*
			 * From this point on, this call acquires the ownership of the signature,
			 * fields and model_emf_uri meaning any free are done inside it if needed.
			 * These three variables MUST NOT be read/write after this.
			 */
			try {
				auto& channel = locked_registry->channel(chan_reg_key);

				/* event_id is set on success. */
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
					*app,
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
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app reply event failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app reply event failed with ret %d: pid = %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
		}
		/*
		 * No need to wipe the create event since the application socket will
		 * get close on error hence cleaning up everything by itself.
		 */
		return ret;
	}

	DBG3("UST registry event %s with id %" PRId32 " added successfully", name, event_id);
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
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	uint64_t enum_id = -1ULL;
	lttng::urcu::read_lock_guard read_lock_guard;
	auto entries = lttng::make_unique_wrapper<struct lttng_ust_ctl_enum_entry, lttng::free>(
		raw_entries);

	/* Lookup application. If not found, there is a code flow error. */
	app = find_app_by_notify_sock(sock);
	if (!app) {
		/* Return an error since this is not an error */
		DBG("Application socket %d is being torn down. Aborting enum registration", sock);
		return -1;
	}

	/* Lookup session by UST object descriptor. */
	ua_sess = find_session_by_objd(app, sobjd);
	if (!ua_sess) {
		/* Return an error since this is not an error */
		DBG("Application session is being torn down (session not found). Aborting enum registration.");
		return 0;
	}

	auto locked_registry = get_locked_session_registry(ua_sess);
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
			    *app,
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
			     app->pid,
			     app->sock);
		} else if (ret == -EAGAIN) {
			WARN("UST app reply enum failed. Communication time out: pid = %d, sock = %d",
			     app->pid,
			     app->sock);
		} else {
			ERR("UST app reply enum failed with ret %d: pid = %d, sock = %d",
			    ret,
			    app->pid,
			    app->sock);
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
							&model_emf_uri);
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
			lttng::urcu::read_lock_guard rcu_lock;
			const struct ust_app *app = find_app_by_notify_sock(sock);
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
	struct ust_app *app;
	struct ust_app_notify_sock_obj *obj;

	LTTNG_ASSERT(sock >= 0);

	lttng::urcu::read_lock_guard read_lock;

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
	app = find_app_by_notify_sock(sock);
	if (!app) {
		goto close_socket;
	}

	iter.iter.node = &app->notify_sock_n.node;

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
static void ust_app_destroy(ust_app& app)
{
	call_rcu(&app.pid_n.head, delete_ust_app_rcu);
}

/*
 * Take a snapshot for a given UST session. The snapshot is sent to the given
 * output.
 *
 * Returns LTTNG_OK on success or a LTTNG_ERR error code.
 */
enum lttng_error_code ust_app_snapshot_record(const struct ltt_ust_session *usess,
					      const struct consumer_output *output,
					      uint64_t nb_packets_per_stream)
{
	int ret = 0;
	enum lttng_error_code status = LTTNG_OK;
	struct lttng_ht_iter iter;
	struct ust_app *app;
	char *trace_path = nullptr;

	LTTNG_ASSERT(usess);
	LTTNG_ASSERT(output);

	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_UID:
	{
		struct buffer_reg_uid *reg;

		lttng::urcu::read_lock_guard read_lock;

		cds_list_for_each_entry (reg, &usess->buffer_reg_uid_list, lnode) {
			struct buffer_reg_channel *buf_reg_chan;
			struct consumer_socket *socket;
			char pathname[PATH_MAX];
			size_t consumer_path_offset = 0;

			if (!reg->registry->reg.ust->_metadata_key) {
				/* Skip since no metadata is present */
				continue;
			}

			/* Get consumer socket to use to push the metadata.*/
			socket = consumer_find_socket_by_bitness(reg->bits_per_long,
								 usess->consumer);
			if (!socket) {
				status = LTTNG_ERR_INVALID;
				goto error;
			}

			memset(pathname, 0, sizeof(pathname));
			ret = snprintf(pathname,
				       sizeof(pathname),
				       DEFAULT_UST_TRACE_UID_PATH,
				       reg->uid,
				       reg->bits_per_long);
			if (ret < 0) {
				PERROR("snprintf snapshot path");
				status = LTTNG_ERR_INVALID;
				goto error;
			}
			/* Free path allowed on previous iteration. */
			free(trace_path);
			trace_path = setup_channel_trace_path(
				usess->consumer, pathname, &consumer_path_offset);
			if (!trace_path) {
				status = LTTNG_ERR_INVALID;
				goto error;
			}
			/* Add the UST default trace dir to path. */
			cds_lfht_for_each_entry (
				reg->registry->channels->ht, &iter.iter, buf_reg_chan, node.node) {
				status =
					consumer_snapshot_channel(socket,
								  buf_reg_chan->consumer_key,
								  output,
								  0,
								  &trace_path[consumer_path_offset],
								  nb_packets_per_stream);
				if (status != LTTNG_OK) {
					goto error;
				}
			}
			status = consumer_snapshot_channel(socket,
							   reg->registry->reg.ust->_metadata_key,
							   output,
							   1,
							   &trace_path[consumer_path_offset],
							   0);
			if (status != LTTNG_OK) {
				goto error;
			}
		}

		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			struct consumer_socket *socket;
			struct lttng_ht_iter chan_iter;
			struct ust_app_channel *ua_chan;
			struct ust_app_session *ua_sess;
			lsu::registry_session *registry;
			char pathname[PATH_MAX];
			size_t consumer_path_offset = 0;

			ua_sess = lookup_session_by_app(usess, app);
			if (!ua_sess) {
				/* Session not associated with this app. */
				continue;
			}

			/* Get the right consumer socket for the application. */
			socket = consumer_find_socket_by_bitness(app->abi.bits_per_long, output);
			if (!socket) {
				status = LTTNG_ERR_INVALID;
				goto error;
			}

			/* Add the UST default trace dir to path. */
			memset(pathname, 0, sizeof(pathname));
			ret = snprintf(pathname, sizeof(pathname), "%s", ua_sess->path);
			if (ret < 0) {
				status = LTTNG_ERR_INVALID;
				PERROR("snprintf snapshot path");
				goto error;
			}
			/* Free path allowed on previous iteration. */
			free(trace_path);
			trace_path = setup_channel_trace_path(
				usess->consumer, pathname, &consumer_path_offset);
			if (!trace_path) {
				status = LTTNG_ERR_INVALID;
				goto error;
			}
			cds_lfht_for_each_entry (
				ua_sess->channels->ht, &chan_iter.iter, ua_chan, node.node) {
				status =
					consumer_snapshot_channel(socket,
								  ua_chan->key,
								  output,
								  0,
								  &trace_path[consumer_path_offset],
								  nb_packets_per_stream);
				switch (status) {
				case LTTNG_OK:
					break;
				case LTTNG_ERR_CHAN_NOT_FOUND:
					continue;
				default:
					goto error;
				}
			}

			registry = get_session_registry(ua_sess);
			if (!registry) {
				DBG("Application session is being torn down. Skip application.");
				continue;
			}
			status = consumer_snapshot_channel(socket,
							   registry->_metadata_key,
							   output,
							   1,
							   &trace_path[consumer_path_offset],
							   0);
			switch (status) {
			case LTTNG_OK:
				break;
			case LTTNG_ERR_CHAN_NOT_FOUND:
				continue;
			default:
				goto error;
			}
		}
		break;
	}
	default:
		abort();
		break;
	}

error:
	free(trace_path);
	return status;
}

/*
 * Return the size taken by one more packet per stream.
 */
uint64_t ust_app_get_size_one_more_packet_per_stream(const struct ltt_ust_session *usess,
						     uint64_t cur_nr_packets)
{
	uint64_t tot_size = 0;
	struct ust_app *app;
	struct lttng_ht_iter iter;

	LTTNG_ASSERT(usess);

	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_UID:
	{
		struct buffer_reg_uid *reg;

		cds_list_for_each_entry (reg, &usess->buffer_reg_uid_list, lnode) {
			struct buffer_reg_channel *buf_reg_chan;

			lttng::urcu::read_lock_guard read_lock;

			cds_lfht_for_each_entry (
				reg->registry->channels->ht, &iter.iter, buf_reg_chan, node.node) {
				if (cur_nr_packets >= buf_reg_chan->num_subbuf) {
					/*
					 * Don't take channel into account if we
					 * already grab all its packets.
					 */
					continue;
				}
				tot_size += buf_reg_chan->subbuf_size * buf_reg_chan->stream_count;
			}
		}
		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			struct ust_app_channel *ua_chan;
			struct ust_app_session *ua_sess;
			struct lttng_ht_iter chan_iter;

			ua_sess = lookup_session_by_app(usess, app);
			if (!ua_sess) {
				/* Session not associated with this app. */
				continue;
			}

			cds_lfht_for_each_entry (
				ua_sess->channels->ht, &chan_iter.iter, ua_chan, node.node) {
				if (cur_nr_packets >= ua_chan->attr.num_subbuf) {
					/*
					 * Don't take channel into account if we
					 * already grab all its packets.
					 */
					continue;
				}
				tot_size += ua_chan->attr.subbuf_size * ua_chan->streams.count;
			}
		}
		break;
	}
	default:
		abort();
		break;
	}

	return tot_size;
}

int ust_app_uid_get_channel_runtime_stats(uint64_t ust_session_id,
					  struct cds_list_head *buffer_reg_uid_list,
					  struct consumer_output *consumer,
					  uint64_t uchan_id,
					  int overwrite,
					  uint64_t *discarded,
					  uint64_t *lost)
{
	int ret;
	uint64_t consumer_chan_key;

	*discarded = 0;
	*lost = 0;

	ret = buffer_reg_uid_consumer_channel_key(
		buffer_reg_uid_list, uchan_id, &consumer_chan_key);
	if (ret < 0) {
		/* Not found */
		ret = 0;
		goto end;
	}

	if (overwrite) {
		ret = consumer_get_lost_packets(ust_session_id, consumer_chan_key, consumer, lost);
	} else {
		ret = consumer_get_discarded_events(
			ust_session_id, consumer_chan_key, consumer, discarded);
	}

end:
	return ret;
}

int ust_app_pid_get_channel_runtime_stats(struct ltt_ust_session *usess,
					  struct ltt_ust_channel *uchan,
					  struct consumer_output *consumer,
					  int overwrite,
					  uint64_t *discarded,
					  uint64_t *lost)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct lttng_ht_node_str *ua_chan_node;
	struct ust_app *app;
	struct ust_app_session *ua_sess;
	struct ust_app_channel *ua_chan;

	*discarded = 0;
	*lost = 0;

	/*
	 * Iterate over every registered applications. Sum counters for
	 * all applications containing requested session and channel.
	 */
	lttng::urcu::read_lock_guard read_lock;

	cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		struct lttng_ht_iter uiter;

		ua_sess = lookup_session_by_app(usess, app);
		if (ua_sess == nullptr) {
			continue;
		}

		/* Get channel */
		lttng_ht_lookup(ua_sess->channels, (void *) uchan->name, &uiter);
		ua_chan_node = lttng_ht_iter_get_node_str(&uiter);
		/* If the session is found for the app, the channel must be there */
		LTTNG_ASSERT(ua_chan_node);

		ua_chan = lttng::utils::container_of(ua_chan_node, &ust_app_channel::node);

		if (overwrite) {
			uint64_t _lost;

			ret = consumer_get_lost_packets(usess->id, ua_chan->key, consumer, &_lost);
			if (ret < 0) {
				break;
			}
			(*lost) += _lost;
		} else {
			uint64_t _discarded;

			ret = consumer_get_discarded_events(
				usess->id, ua_chan->key, consumer, &_discarded);
			if (ret < 0) {
				break;
			}
			(*discarded) += _discarded;
		}
	}

	return ret;
}

static int ust_app_regenerate_statedump(struct ltt_ust_session *usess, struct ust_app *app)
{
	int ret = 0;
	struct ust_app_session *ua_sess;

	DBG("Regenerating the metadata for ust app pid %d", app->pid);

	lttng::urcu::read_lock_guard read_lock;

	ua_sess = lookup_session_by_app(usess, app);
	if (ua_sess == nullptr) {
		/* The session is in teardown process. Ignore and continue. */
		goto end;
	}

	pthread_mutex_lock(&ua_sess->lock);

	if (ua_sess->deleted) {
		goto end_unlock;
	}

	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_regenerate_statedump(app->sock, ua_sess->handle);
	pthread_mutex_unlock(&app->sock_lock);

end_unlock:
	pthread_mutex_unlock(&ua_sess->lock);

end:
	health_code_update();
	return ret;
}

/*
 * Regenerate the statedump for each app in the session.
 */
int ust_app_regenerate_statedump_all(struct ltt_ust_session *usess)
{
	int ret = 0;
	struct lttng_ht_iter iter;
	struct ust_app *app;

	DBG("Regenerating the metadata for all UST apps");

	lttng::urcu::read_lock_guard read_lock;

	cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
		if (!app->compatible) {
			continue;
		}

		ret = ust_app_regenerate_statedump(usess, app);
		if (ret < 0) {
			/* Continue to the next app even on error */
			continue;
		}
	}

	return 0;
}

/*
 * Rotate all the channels of a session.
 *
 * Return LTTNG_OK on success or else an LTTng error code.
 */
enum lttng_error_code ust_app_rotate_session(struct ltt_session *session)
{
	int ret;
	enum lttng_error_code cmd_ret = LTTNG_OK;
	struct lttng_ht_iter iter;
	struct ltt_ust_session *usess = session->ust_session;

	LTTNG_ASSERT(usess);

	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_UID:
	{
		struct buffer_reg_uid *reg;

		cds_list_for_each_entry (reg, &usess->buffer_reg_uid_list, lnode) {
			struct buffer_reg_channel *buf_reg_chan;
			struct consumer_socket *socket;
			lttng::urcu::read_lock_guard read_lock;

			/* Get consumer socket to use to push the metadata.*/
			socket = consumer_find_socket_by_bitness(reg->bits_per_long,
								 usess->consumer);
			if (!socket) {
				cmd_ret = LTTNG_ERR_INVALID;
				goto error;
			}

			/* Rotate the data channels. */
			cds_lfht_for_each_entry (
				reg->registry->channels->ht, &iter.iter, buf_reg_chan, node.node) {
				ret = consumer_rotate_channel(socket,
							      buf_reg_chan->consumer_key,
							      usess->consumer,
							      /* is_metadata_channel */ false);
				if (ret < 0) {
					cmd_ret = LTTNG_ERR_ROTATION_FAIL_CONSUMER;
					goto error;
				}
			}

			/*
			 * The metadata channel might not be present.
			 *
			 * Consumer stream allocation can be done
			 * asynchronously and can fail on intermediary
			 * operations (i.e add context) and lead to data
			 * channels created with no metadata channel.
			 */
			if (!reg->registry->reg.ust->_metadata_key) {
				/* Skip since no metadata is present. */
				continue;
			}

			{
				auto locked_registry = reg->registry->reg.ust->lock();
				(void) push_metadata(locked_registry, usess->consumer);
			}

			ret = consumer_rotate_channel(socket,
						      reg->registry->reg.ust->_metadata_key,
						      usess->consumer,
						      /* is_metadata_channel */ true);
			if (ret < 0) {
				cmd_ret = LTTNG_ERR_ROTATION_FAIL_CONSUMER;
				goto error;
			}
		}
		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		lttng::urcu::read_lock_guard read_lock;
		ust_app *raw_app;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, raw_app, pid_n.node) {
			struct consumer_socket *socket;
			struct lttng_ht_iter chan_iter;
			struct ust_app_channel *ua_chan;
			struct ust_app_session *ua_sess;
			lsu::registry_session *registry;
			bool app_reference_taken;

			app_reference_taken = ust_app_get(*raw_app);
			if (!app_reference_taken) {
				/* Application unregistered concurrently, skip it. */
				DBG("Could not get application reference as it is being torn down; skipping application");
				continue;
			}

			ust_app_reference app(raw_app);
			raw_app = nullptr;

			ua_sess = lookup_session_by_app(usess, app.get());
			if (!ua_sess) {
				/* Session not associated with this app. */
				continue;
			}

			/* Get the right consumer socket for the application. */
			socket = consumer_find_socket_by_bitness(app->abi.bits_per_long,
								 usess->consumer);
			if (!socket) {
				cmd_ret = LTTNG_ERR_INVALID;
				goto error;
			}

			registry = get_session_registry(ua_sess);
			LTTNG_ASSERT(registry);

			/* Rotate the data channels. */
			cds_lfht_for_each_entry (
				ua_sess->channels->ht, &chan_iter.iter, ua_chan, node.node) {
				ret = consumer_rotate_channel(socket,
							      ua_chan->key,
							      ua_sess->consumer,
							      /* is_metadata_channel */ false);
				if (ret < 0) {
					cmd_ret = LTTNG_ERR_ROTATION_FAIL_CONSUMER;
					goto error;
				}
			}

			/* Rotate the metadata channel. */
			{
				auto locked_registry = registry->lock();

				(void) push_metadata(locked_registry, usess->consumer);
			}

			ret = consumer_rotate_channel(socket,
						      registry->_metadata_key,
						      ua_sess->consumer,
						      /* is_metadata_channel */ true);
			if (ret < 0) {
				cmd_ret = LTTNG_ERR_ROTATION_FAIL_CONSUMER;
				goto error;
			}
		}

		break;
	}
	default:
		abort();
		break;
	}

	cmd_ret = LTTNG_OK;

error:
	return cmd_ret;
}

enum lttng_error_code ust_app_create_channel_subdirectories(const struct ltt_ust_session *usess)
{
	enum lttng_error_code ret = LTTNG_OK;
	struct lttng_ht_iter iter;
	enum lttng_trace_chunk_status chunk_status;
	char *pathname_index;
	int fmt_ret;

	LTTNG_ASSERT(usess->current_trace_chunk);

	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_UID:
	{
		struct buffer_reg_uid *reg;
		lttng::urcu::read_lock_guard read_lock;

		cds_list_for_each_entry (reg, &usess->buffer_reg_uid_list, lnode) {
			fmt_ret = asprintf(&pathname_index,
					   DEFAULT_UST_TRACE_DIR "/" DEFAULT_UST_TRACE_UID_PATH
								 "/" DEFAULT_INDEX_DIR,
					   reg->uid,
					   reg->bits_per_long);
			if (fmt_ret < 0) {
				ERR("Failed to format channel index directory");
				ret = LTTNG_ERR_CREATE_DIR_FAIL;
				goto error;
			}

			/*
			 * Create the index subdirectory which will take care
			 * of implicitly creating the channel's path.
			 */
			chunk_status = lttng_trace_chunk_create_subdirectory(
				usess->current_trace_chunk, pathname_index);
			free(pathname_index);
			if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
				ret = LTTNG_ERR_CREATE_DIR_FAIL;
				goto error;
			}
		}
		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		struct ust_app *app;
		lttng::urcu::read_lock_guard read_lock;

		/*
		 * Create the toplevel ust/ directory in case no apps are running.
		 */
		chunk_status = lttng_trace_chunk_create_subdirectory(usess->current_trace_chunk,
								     DEFAULT_UST_TRACE_DIR);
		if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
			ret = LTTNG_ERR_CREATE_DIR_FAIL;
			goto error;
		}

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			struct ust_app_session *ua_sess;
			lsu::registry_session *registry;

			ua_sess = lookup_session_by_app(usess, app);
			if (!ua_sess) {
				/* Session not associated with this app. */
				continue;
			}

			registry = get_session_registry(ua_sess);
			if (!registry) {
				DBG("Application session is being torn down. Skip application.");
				continue;
			}

			fmt_ret = asprintf(&pathname_index,
					   DEFAULT_UST_TRACE_DIR "/%s/" DEFAULT_INDEX_DIR,
					   ua_sess->path);
			if (fmt_ret < 0) {
				ERR("Failed to format channel index directory");
				ret = LTTNG_ERR_CREATE_DIR_FAIL;
				goto error;
			}
			/*
			 * Create the index subdirectory which will take care
			 * of implicitly creating the channel's path.
			 */
			chunk_status = lttng_trace_chunk_create_subdirectory(
				usess->current_trace_chunk, pathname_index);
			free(pathname_index);
			if (chunk_status != LTTNG_TRACE_CHUNK_STATUS_OK) {
				ret = LTTNG_ERR_CREATE_DIR_FAIL;
				goto error;
			}
		}
		break;
	}
	default:
		abort();
	}

	ret = LTTNG_OK;
error:
	return ret;
}

/*
 * Clear all the channels of a session.
 *
 * Return LTTNG_OK on success or else an LTTng error code.
 */
enum lttng_error_code ust_app_clear_session(struct ltt_session *session)
{
	int ret;
	enum lttng_error_code cmd_ret = LTTNG_OK;
	struct lttng_ht_iter iter;
	struct ust_app *app;
	struct ltt_ust_session *usess = session->ust_session;

	LTTNG_ASSERT(usess);

	if (usess->active) {
		ERR("Expecting inactive session %s (%" PRIu64 ")", session->name, session->id);
		cmd_ret = LTTNG_ERR_FATAL;
		goto end;
	}

	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_UID:
	{
		struct buffer_reg_uid *reg;
		lttng::urcu::read_lock_guard read_lock;

		cds_list_for_each_entry (reg, &usess->buffer_reg_uid_list, lnode) {
			struct buffer_reg_channel *buf_reg_chan;
			struct consumer_socket *socket;

			/* Get consumer socket to use to push the metadata.*/
			socket = consumer_find_socket_by_bitness(reg->bits_per_long,
								 usess->consumer);
			if (!socket) {
				cmd_ret = LTTNG_ERR_INVALID;
				goto error_socket;
			}

			/* Clear the data channels. */
			cds_lfht_for_each_entry (
				reg->registry->channels->ht, &iter.iter, buf_reg_chan, node.node) {
				ret = consumer_clear_channel(socket, buf_reg_chan->consumer_key);
				if (ret < 0) {
					goto error;
				}
			}

			{
				auto locked_registry = reg->registry->reg.ust->lock();
				(void) push_metadata(locked_registry, usess->consumer);
			}

			/*
			 * Clear the metadata channel.
			 * Metadata channel is not cleared per se but we still need to
			 * perform a rotation operation on it behind the scene.
			 */
			ret = consumer_clear_channel(socket, reg->registry->reg.ust->_metadata_key);
			if (ret < 0) {
				goto error;
			}
		}
		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			struct consumer_socket *socket;
			struct lttng_ht_iter chan_iter;
			struct ust_app_channel *ua_chan;
			struct ust_app_session *ua_sess;
			lsu::registry_session *registry;

			ua_sess = lookup_session_by_app(usess, app);
			if (!ua_sess) {
				/* Session not associated with this app. */
				continue;
			}

			/* Get the right consumer socket for the application. */
			socket = consumer_find_socket_by_bitness(app->abi.bits_per_long,
								 usess->consumer);
			if (!socket) {
				cmd_ret = LTTNG_ERR_INVALID;
				goto error_socket;
			}

			registry = get_session_registry(ua_sess);
			if (!registry) {
				DBG("Application session is being torn down. Skip application.");
				continue;
			}

			/* Clear the data channels. */
			cds_lfht_for_each_entry (
				ua_sess->channels->ht, &chan_iter.iter, ua_chan, node.node) {
				ret = consumer_clear_channel(socket, ua_chan->key);
				if (ret < 0) {
					/* Per-PID buffer and application going away. */
					if (ret == -LTTNG_ERR_CHAN_NOT_FOUND) {
						continue;
					}
					goto error;
				}
			}

			{
				auto locked_registry = registry->lock();
				(void) push_metadata(locked_registry, usess->consumer);
			}

			/*
			 * Clear the metadata channel.
			 * Metadata channel is not cleared per se but we still need to
			 * perform rotation operation on it behind the scene.
			 */
			ret = consumer_clear_channel(socket, registry->_metadata_key);
			if (ret < 0) {
				/* Per-PID buffer and application going away. */
				if (ret == -LTTNG_ERR_CHAN_NOT_FOUND) {
					continue;
				}
				goto error;
			}
		}
		break;
	}
	default:
		abort();
		break;
	}

	cmd_ret = LTTNG_OK;
	goto end;

error:
	switch (-ret) {
	case LTTCOMM_CONSUMERD_RELAYD_CLEAR_DISALLOWED:
		cmd_ret = LTTNG_ERR_CLEAR_RELAY_DISALLOWED;
		break;
	default:
		cmd_ret = LTTNG_ERR_CLEAR_FAIL_CONSUMER;
	}

error_socket:
end:
	return cmd_ret;
}

/*
 * This function skips the metadata channel as the begin/end timestamps of a
 * metadata packet are useless.
 *
 * Moreover, opening a packet after a "clear" will cause problems for live
 * sessions as it will introduce padding that was not part of the first trace
 * chunk. The relay daemon expects the content of the metadata stream of
 * successive metadata trace chunks to be strict supersets of one another.
 *
 * For example, flushing a packet at the beginning of the metadata stream of
 * a trace chunk resulting from a "clear" session command will cause the
 * size of the metadata stream of the new trace chunk to not match the size of
 * the metadata stream of the original chunk. This will confuse the relay
 * daemon as the same "offset" in a metadata stream will no longer point
 * to the same content.
 */
enum lttng_error_code ust_app_open_packets(struct ltt_session *session)
{
	enum lttng_error_code ret = LTTNG_OK;
	struct lttng_ht_iter iter;
	struct ltt_ust_session *usess = session->ust_session;

	LTTNG_ASSERT(usess);

	switch (usess->buffer_type) {
	case LTTNG_BUFFER_PER_UID:
	{
		struct buffer_reg_uid *reg;

		cds_list_for_each_entry (reg, &usess->buffer_reg_uid_list, lnode) {
			struct buffer_reg_channel *buf_reg_chan;
			struct consumer_socket *socket;
			lttng::urcu::read_lock_guard read_lock;

			socket = consumer_find_socket_by_bitness(reg->bits_per_long,
								 usess->consumer);
			if (!socket) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}

			cds_lfht_for_each_entry (
				reg->registry->channels->ht, &iter.iter, buf_reg_chan, node.node) {
				const int open_ret = consumer_open_channel_packets(
					socket, buf_reg_chan->consumer_key);

				if (open_ret < 0) {
					ret = LTTNG_ERR_UNK;
					goto error;
				}
			}
		}
		break;
	}
	case LTTNG_BUFFER_PER_PID:
	{
		struct ust_app *app;
		lttng::urcu::read_lock_guard read_lock;

		cds_lfht_for_each_entry (ust_app_ht->ht, &iter.iter, app, pid_n.node) {
			struct consumer_socket *socket;
			struct lttng_ht_iter chan_iter;
			struct ust_app_channel *ua_chan;
			struct ust_app_session *ua_sess;
			lsu::registry_session *registry;

			ua_sess = lookup_session_by_app(usess, app);
			if (!ua_sess) {
				/* Session not associated with this app. */
				continue;
			}

			/* Get the right consumer socket for the application. */
			socket = consumer_find_socket_by_bitness(app->abi.bits_per_long,
								 usess->consumer);
			if (!socket) {
				ret = LTTNG_ERR_FATAL;
				goto error;
			}

			registry = get_session_registry(ua_sess);
			if (!registry) {
				DBG("Application session is being torn down. Skip application.");
				continue;
			}

			cds_lfht_for_each_entry (
				ua_sess->channels->ht, &chan_iter.iter, ua_chan, node.node) {
				const int open_ret =
					consumer_open_channel_packets(socket, ua_chan->key);

				if (open_ret < 0) {
					/*
					 * Per-PID buffer and application going
					 * away.
					 */
					if (open_ret == -LTTNG_ERR_CHAN_NOT_FOUND) {
						continue;
					}

					ret = LTTNG_ERR_UNK;
					goto error;
				}
			}
		}
		break;
	}
	default:
		abort();
		break;
	}

error:
	return ret;
}

lsu::ctl_field_quirks ust_app::ctl_field_quirks() const
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
	auto& app = *lttng::utils::container_of(ref, &ust_app::ref);

	ust_app_unregister(app);
	ust_app_destroy(app);
}

bool ust_app_get(ust_app& app)
{
	return urcu_ref_get_unless_zero(&app.ref);
}

void ust_app_put(struct ust_app *app)
{
	if (!app) {
		return;
	}

	urcu_ref_put(&app->ref, ust_app_release);
}
