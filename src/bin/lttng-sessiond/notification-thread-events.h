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

#ifndef NOTIFICATION_THREAD_EVENTS_H
#define NOTIFICATION_THREAD_EVENTS_H

#include <lttng/domain.h>
#include "notification-thread.h"

/**
 * Event handling function shall only return an error if
 * the thread should be stopped.
 */
int handle_notification_thread_command(
		struct notification_thread_handle *handle,
		struct notification_thread_state *state);

int handle_notification_thread_client_connect(
		struct notification_thread_state *state);

int handle_notification_thread_client_disconnect(
		int client_fd,
		struct notification_thread_state *state);

int handle_notification_thread_client_disconnect_all(
		struct notification_thread_state *state);

int handle_notification_thread_trigger_unregister_all(
		struct notification_thread_state *state);

int handle_notification_thread_client_in(
		struct notification_thread_state *state,
		int socket);

int handle_notification_thread_client_out(
		struct notification_thread_state *state,
		int socket);

int handle_notification_thread_channel_sample(
		struct notification_thread_state *state, int pipe,
		enum lttng_domain_type domain);

#endif /* NOTIFICATION_THREAD_EVENTS_H */
