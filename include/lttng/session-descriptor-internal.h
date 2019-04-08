/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_SESSION_DESCRIPTOR_INTERNAL_H
#define LTTNG_SESSION_DESCRIPTOR_INTERNAL_H

#include <lttng/session-descriptor.h>
#include <lttng/lttng-error.h>
#include <common/uri.h>
#include <common/dynamic-buffer.h>
#include <common/buffer-view.h>
#include <stdbool.h>

/* Note that these enums are used as part of the lttnctl protocol. */
enum lttng_session_descriptor_type {
	LTTNG_SESSION_DESCRIPTOR_TYPE_UNKNOWN = -1,
	/*
	 * The output type determines whether this is a no-output, local,
	 * or networked tracing session.
	 */
	LTTNG_SESSION_DESCRIPTOR_TYPE_REGULAR = 1,
	LTTNG_SESSION_DESCRIPTOR_TYPE_SNAPSHOT = 2,
	LTTNG_SESSION_DESCRIPTOR_TYPE_LIVE = 3,
};

enum lttng_session_descriptor_output_type {
	LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NONE = 0,
	LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_LOCAL = 1,
	LTTNG_SESSION_DESCRIPTOR_OUTPUT_TYPE_NETWORK = 2,
};

LTTNG_HIDDEN
ssize_t lttng_session_descriptor_create_from_buffer(
		const struct lttng_buffer_view *view,
		struct lttng_session_descriptor **descriptor);

LTTNG_HIDDEN
int lttng_session_descriptor_serialize(
		const struct lttng_session_descriptor *descriptor,
		struct lttng_dynamic_buffer *buffer);

LTTNG_HIDDEN
enum lttng_session_descriptor_type
lttng_session_descriptor_get_type(
		const struct lttng_session_descriptor *descriptor);

LTTNG_HIDDEN
enum lttng_session_descriptor_output_type
lttng_session_descriptor_get_output_type(
		const struct lttng_session_descriptor *descriptor);

LTTNG_HIDDEN
void lttng_session_descriptor_get_local_output_uri(
		const struct lttng_session_descriptor *descriptor,
		struct lttng_uri *local_uri);

LTTNG_HIDDEN
void lttng_session_descriptor_get_network_output_uris(
		const struct lttng_session_descriptor *descriptor,
		struct lttng_uri *control,
		struct lttng_uri *data);

LTTNG_HIDDEN
unsigned long long
lttng_session_descriptor_live_get_timer_interval(
		const struct lttng_session_descriptor *descriptor);

LTTNG_HIDDEN
enum lttng_session_descriptor_status
lttng_session_descriptor_get_session_name(
		const struct lttng_session_descriptor *descriptor,
		const char **name);

LTTNG_HIDDEN
int lttng_session_descriptor_set_session_name(
		struct lttng_session_descriptor *descriptor,
		const char *name);

LTTNG_HIDDEN
bool lttng_session_descriptor_is_output_destination_initialized(
		const struct lttng_session_descriptor *descriptor);

LTTNG_HIDDEN
bool lttng_session_descriptor_has_output_directory(
		const struct lttng_session_descriptor *descriptor);

LTTNG_HIDDEN
enum lttng_error_code lttng_session_descriptor_set_default_output(
		struct lttng_session_descriptor *descriptor,
		time_t *session_creation_time,
		const char *absolute_home_path);

LTTNG_HIDDEN
int lttng_session_descriptor_assign(
		struct lttng_session_descriptor *dst_descriptor,
		const struct lttng_session_descriptor *src_descriptor);

#endif /* LTTNG_SESSION_DESCRIPTOR_INTERNAL_H */
