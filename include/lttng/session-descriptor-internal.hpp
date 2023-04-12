/*
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_SESSION_DESCRIPTOR_INTERNAL_H
#define LTTNG_SESSION_DESCRIPTOR_INTERNAL_H

#include <common/buffer-view.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/uri.hpp>

#include <lttng/lttng-error.h>
#include <lttng/session-descriptor.h>

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

ssize_t lttng_session_descriptor_create_from_buffer(const struct lttng_buffer_view *view,
						    struct lttng_session_descriptor **descriptor);

int lttng_session_descriptor_serialize(const struct lttng_session_descriptor *descriptor,
				       struct lttng_dynamic_buffer *buffer);

enum lttng_session_descriptor_type
lttng_session_descriptor_get_type(const struct lttng_session_descriptor *descriptor);

enum lttng_session_descriptor_output_type
lttng_session_descriptor_get_output_type(const struct lttng_session_descriptor *descriptor);

void lttng_session_descriptor_get_local_output_uri(
	const struct lttng_session_descriptor *descriptor, struct lttng_uri *local_uri);

void lttng_session_descriptor_get_network_output_uris(
	const struct lttng_session_descriptor *descriptor,
	struct lttng_uri *control,
	struct lttng_uri *data);

unsigned long long
lttng_session_descriptor_live_get_timer_interval(const struct lttng_session_descriptor *descriptor);

int lttng_session_descriptor_set_session_name(struct lttng_session_descriptor *descriptor,
					      const char *name);

bool lttng_session_descriptor_is_output_destination_initialized(
	const struct lttng_session_descriptor *descriptor);

bool lttng_session_descriptor_has_output_directory(
	const struct lttng_session_descriptor *descriptor);

enum lttng_error_code
lttng_session_descriptor_set_default_output(struct lttng_session_descriptor *descriptor,
					    time_t *session_creation_time,
					    const char *absolute_home_path);

int lttng_session_descriptor_assign(struct lttng_session_descriptor *dst_descriptor,
				    const struct lttng_session_descriptor *src_descriptor);

#endif /* LTTNG_SESSION_DESCRIPTOR_INTERNAL_H */
