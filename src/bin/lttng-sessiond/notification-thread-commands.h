/*
 * Copyright (C) 2017 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef NOTIFICATION_THREAD_COMMANDS_H
#define NOTIFICATION_THREAD_COMMANDS_H

#include <lttng/domain.h>
#include <lttng/lttng-error.h>
#include <urcu/rculfhash.h>
#include "notification-thread.h"
#include <common/waiter.h>

struct notification_thread_data;
struct lttng_trigger;

enum notification_thread_command_type {
	NOTIFICATION_COMMAND_TYPE_REGISTER_TRIGGER,
	NOTIFICATION_COMMAND_TYPE_UNREGISTER_TRIGGER,
	NOTIFICATION_COMMAND_TYPE_ADD_CHANNEL,
	NOTIFICATION_COMMAND_TYPE_REMOVE_CHANNEL,
	NOTIFICATION_COMMAND_TYPE_QUIT,
};

struct channel_key {
	uint64_t key;
	enum lttng_domain_type domain;
};

struct channel_info {
	struct channel_key key;
	char *session_name;
	uid_t uid;
	gid_t gid;
	char *channel_name;
	uint64_t capacity;
	struct cds_lfht_node channels_ht_node;
};

struct notification_thread_command {
	struct cds_list_head cmd_list_node;

	enum notification_thread_command_type type;
	union {
		/* Register/Unregister trigger. */
		struct lttng_trigger *trigger;
		/* Add channel. */
		struct channel_info add_channel;
		/* Remove channel. */
		struct {
			uint64_t key;
			enum lttng_domain_type domain;
		} remove_channel;
	} parameters;

	/* lttng_waiter on which to wait for command reply (optional). */
	struct lttng_waiter reply_waiter;
	enum lttng_error_code reply_code;
};

enum lttng_error_code notification_thread_command_register_trigger(
		struct notification_thread_handle *handle,
		struct lttng_trigger *trigger);

enum lttng_error_code notification_thread_command_unregister_trigger(
		struct notification_thread_handle *handle,
		struct lttng_trigger *trigger);

enum lttng_error_code notification_thread_command_add_channel(
		struct notification_thread_handle *handle,
		char *session_name, uid_t uid, gid_t gid,
		char *channel_name, uint64_t key,
		enum lttng_domain_type domain, uint64_t capacity);

enum lttng_error_code notification_thread_command_remove_channel(
		struct notification_thread_handle *handle,
		uint64_t key, enum lttng_domain_type domain);

void notification_thread_command_quit(
		struct notification_thread_handle *handle);

#endif /* NOTIFICATION_THREAD_COMMANDS_H */
