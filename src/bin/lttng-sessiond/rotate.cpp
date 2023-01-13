/*
 * Copyright (C) 2017 Julien Desfossez <jdesfossez@efficios.com>
 * Copyright (C) 2018 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "cmd.hpp"
#include "health-sessiond.hpp"
#include "lttng-sessiond.hpp"
#include "notification-thread-commands.hpp"
#include "rotate.hpp"
#include "rotation-thread.hpp"
#include "session.hpp"
#include "utils.hpp"

#include <common/align.hpp>
#include <common/config/session-config.hpp>
#include <common/credentials.hpp>
#include <common/defaults.hpp>
#include <common/error.hpp>
#include <common/futex.hpp>
#include <common/hashtable/utils.hpp>
#include <common/kernel-ctl/kernel-ctl.hpp>
#include <common/time.hpp>
#include <common/utils.hpp>

#include <lttng/action/action-internal.hpp>
#include <lttng/condition/condition-internal.hpp>
#include <lttng/notification/channel-internal.hpp>
#include <lttng/rotate-internal.hpp>
#include <lttng/trigger/trigger.h>

#include <inttypes.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <urcu.h>
#include <urcu/list.h>
#include <urcu/rculfhash.h>

int subscribe_session_consumed_size_rotation(
	struct ltt_session *session,
	uint64_t size,
	struct notification_thread_handle *notification_thread_handle)
{
	int ret;
	enum lttng_condition_status condition_status;
	enum lttng_notification_channel_status nc_status;
	struct lttng_condition *rotate_condition = nullptr;
	struct lttng_action *notify_action = nullptr;
	const struct lttng_credentials session_creds = {
		.uid = LTTNG_OPTIONAL_INIT_VALUE(session->uid),
		.gid = LTTNG_OPTIONAL_INIT_VALUE(session->gid),
	};

	rotate_condition = lttng_condition_session_consumed_size_create();
	if (!rotate_condition) {
		ERR("Failed to create session consumed size condition object");
		ret = -1;
		goto end;
	}

	condition_status =
		lttng_condition_session_consumed_size_set_threshold(rotate_condition, size);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Could not set session consumed size condition threshold (size = %" PRIu64 ")",
		    size);
		ret = -1;
		goto end;
	}

	condition_status = lttng_condition_session_consumed_size_set_session_name(rotate_condition,
										  session->name);
	if (condition_status != LTTNG_CONDITION_STATUS_OK) {
		ERR("Could not set session consumed size condition session name (name = %s)",
		    session->name);
		ret = -1;
		goto end;
	}

	notify_action = lttng_action_notify_create();
	if (!notify_action) {
		ERR("Could not create notify action");
		ret = -1;
		goto end;
	}

	LTTNG_ASSERT(!session->rotate_trigger);
	session->rotate_trigger = lttng_trigger_create(rotate_condition, notify_action);
	if (!session->rotate_trigger) {
		ERR("Could not create size-based rotation trigger");
		ret = -1;
		goto end;
	}

	/* Ensure this trigger is not visible to external users. */
	lttng_trigger_set_hidden(session->rotate_trigger);
	lttng_trigger_set_credentials(session->rotate_trigger, &session_creds);

	nc_status =
		lttng_notification_channel_subscribe(rotate_notification_channel, rotate_condition);
	if (nc_status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		ERR("Could not subscribe to session consumed size notification");
		ret = -1;
		goto end;
	}

	ret = notification_thread_command_register_trigger(
		notification_thread_handle, session->rotate_trigger, true);
	if (ret < 0 && ret != -LTTNG_ERR_TRIGGER_EXISTS) {
		ERR("Register trigger, %s", lttng_strerror(ret));
		ret = -1;
		goto end;
	}

	ret = 0;

end:
	lttng_condition_put(rotate_condition);
	lttng_action_put(notify_action);
	if (ret) {
		lttng_trigger_put(session->rotate_trigger);
	}
	return ret;
}

int unsubscribe_session_consumed_size_rotation(
	struct ltt_session *session, struct notification_thread_handle *notification_thread_handle)
{
	int ret = 0;
	enum lttng_notification_channel_status status;

	LTTNG_ASSERT(session->rotate_trigger);
	status = lttng_notification_channel_unsubscribe(
		rotate_notification_channel,
		lttng_trigger_get_const_condition(session->rotate_trigger));
	if (status != LTTNG_NOTIFICATION_CHANNEL_STATUS_OK) {
		ERR("Session unsubscribe error: %d", (int) status);
		ret = -1;
		goto end;
	}

	ret = notification_thread_command_unregister_trigger(notification_thread_handle,
							     session->rotate_trigger);
	if (ret != LTTNG_OK) {
		ERR("Session unregister trigger error: %d", ret);
		goto end;
	}

	lttng_trigger_put(session->rotate_trigger);
	session->rotate_trigger = nullptr;

	ret = 0;
end:
	return ret;
}
