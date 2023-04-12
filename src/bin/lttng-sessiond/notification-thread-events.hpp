/*
 * Copyright (C) 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef NOTIFICATION_THREAD_EVENTS_H
#define NOTIFICATION_THREAD_EVENTS_H

#include "notification-thread.hpp"

#include <lttng/domain.h>

/**
 * Event handling function shall only return an error if
 * the thread should be stopped.
 */
int handle_notification_thread_command(struct notification_thread_handle *handle,
				       struct notification_thread_state *state);

int handle_notification_thread_client_connect(struct notification_thread_state *state);

int handle_notification_thread_client_disconnect(int client_fd,
						 struct notification_thread_state *state);

int handle_notification_thread_client_disconnect_all(struct notification_thread_state *state);

int handle_notification_thread_trigger_unregister_all(struct notification_thread_state *state);

int handle_notification_thread_tracer_event_source_died(struct notification_thread_state *state,
							int tracer_event_source_fd);

int handle_notification_thread_client_in(struct notification_thread_state *state, int socket);

int handle_notification_thread_client_out(struct notification_thread_state *state, int socket);

int handle_notification_thread_channel_sample(struct notification_thread_state *state,
					      int pipe,
					      enum lttng_domain_type domain);

int handle_notification_thread_event_notification(struct notification_thread_state *state,
						  int pipe,
						  enum lttng_domain_type domain);

#endif /* NOTIFICATION_THREAD_EVENTS_H */
