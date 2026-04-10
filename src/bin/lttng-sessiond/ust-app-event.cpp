/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event.hpp"
#include "health-sessiond.hpp"
#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "ust-app-event.hpp"
#include "ust-app.hpp"

#include <common/bytecode/bytecode.hpp>
#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/urcu.hpp>

#include <lttng/event-rule/event-rule-internal.hpp>
#include <lttng/event-rule/event-rule.h>
#include <lttng/event-rule/user-tracepoint.h>

#include <inttypes.h>
#include <pthread.h>

namespace lsu = lttng::sessiond::ust;
namespace lsc = lttng::sessiond::config;

namespace {
/*
 * Create a liblttng-ust filter bytecode from given bytecode.
 *
 * Return allocated filter or NULL on error.
 */
struct lttng_ust_abi_filter_bytecode *
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

struct lttng_ust_abi_event_exclusion *
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
} /* anonymous namespace */

/*
 * Delete ust app event safely.
 */
void delete_ust_app_event(int sock, struct ust_app_event *ua_event, lsu::app *app)
{
	int ret;

	LTTNG_ASSERT(ua_event);

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
 * Set the filter on the tracer.
 */
int set_ust_object_filter(lsu::app *app,
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
 * Set event exclusions on the tracer.
 */
int set_ust_object_exclusions(lsu::app *app,
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
int disable_ust_object(lsu::app *app, struct lttng_ust_abi_object_data *object)
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
 * Enable the specified event on to UST tracer for the UST session.
 */
int enable_ust_object(lsu::app *app, struct lttng_ust_abi_object_data *ust_object)
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

namespace {
/*
 * Return the UST event name for an event rule. For user tracepoints, this is
 * the name pattern. For agent domain rules, this is the default UST event name
 * used by the agent tracepoint (the agent filter carries the real event name).
 */
const char *get_ust_event_name_from_rule(const struct lttng_event_rule *rule)
{
	if (lttng_event_rule_targets_agent_domain(rule)) {
		return event_get_default_agent_ust_name(lttng_event_rule_get_domain_type(rule));
	}

	const char *pattern;
	const auto status = lttng_event_rule_user_tracepoint_get_name_pattern(rule, &pattern);
	if (status != LTTNG_EVENT_RULE_STATUS_OK) {
		abort();
	}

	return pattern;
}

/*
 * Build a lttng_ust_abi_event from an event rule. Only user tracepoint
 * rules are supported.
 */
struct lttng_ust_abi_event make_ust_abi_event_from_event_rule(const struct lttng_event_rule *rule)
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
struct ust_app_event *
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

	DBG3("UST app event %s allocated",
	     get_ust_event_name_from_rule(event_config.event_rule.get()));

	return ua_event;

error:
	return nullptr;
}

/*
 * Create the specified event onto the UST tracer for a UST session.
 *
 * Should be called with session mutex held.
 */
int create_ust_event(lsu::app *app, struct ust_app_channel *ua_chan, struct ust_app_event *ua_event)
{
	int ret = 0;

	health_code_update();

	/*
	 * Build the UST ABI event structure from the event rule configuration.
	 * This is only needed for the tracer command; the per-app event does
	 * not need to retain it.
	 */
	auto ust_abi_event =
		make_ust_abi_event_from_event_rule(ua_event->event_rule_config.event_rule.get());

	/* Create UST event on tracer */
	pthread_mutex_lock(&app->sock_lock);
	ret = lttng_ust_ctl_create_event(app->sock, &ust_abi_event, ua_chan->obj, &ua_event->obj);
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
			    get_ust_event_name_from_rule(
				    ua_event->event_rule_config.event_rule.get()),
			    ret,
			    app->pid,
			    app->sock);
		}
		goto error;
	}

	ua_event->handle = ua_event->obj->header.handle;

	DBG2("UST app event %s created successfully for pid:%d object = %p",
	     get_ust_event_name_from_rule(ua_event->event_rule_config.event_rule.get()),
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

/*
 * Copy data between an UST app event and a LTT event.
 */
/*
 * Populate the per-app event's mutable fields from its associated
 * event rule configuration. The `name` field is already set by
 * `alloc_ust_app_event`, so this function only needs to copy the
 * enabled state.
 */
void shadow_copy_event(struct ust_app_event *ua_event)
{
	ua_event->enabled = ua_event->event_rule_config.is_enabled;
}

/*
 * Add a per-app event to its channel's event map. The event must not already
 * exist (keyed by its event rule configuration pointer).
 */
void add_unique_ust_app_event(struct ust_app_channel *ua_chan, struct ust_app_event *event)
{
	LTTNG_ASSERT(ua_chan);
	LTTNG_ASSERT(event);

	const auto result = ua_chan->events.emplace(&event->event_rule_config, event);
	LTTNG_ASSERT(result.second);
}
} /* anonymous namespace */

/*
 * Find a per-app event by matching its config pointer.
 *
 * Returns the matching ust_app_event or nullptr if not found.
 */
struct ust_app_event *find_ust_app_event_by_config(
	const std::unordered_map<const lsc::event_rule_configuration *, ust_app_event *>& events,
	const lsc::event_rule_configuration& event_config)
{
	const auto it = events.find(&event_config);
	return it != events.end() ? it->second : nullptr;
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
 * Create a per-app event for the given channel and register it on the
 * tracer side.
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
			    get_ust_event_name_from_rule(
				    ua_event->event_rule_config.event_rule.get()),
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
