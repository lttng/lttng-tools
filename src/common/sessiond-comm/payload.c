/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include "payload.h"

LTTNG_HIDDEN
void lttng_payload_init(struct lttng_payload *payload)
{
	assert(payload);
	lttng_dynamic_buffer_init(&payload->buffer);
	lttng_dynamic_array_init(&payload->_fds, sizeof(int), NULL);
}

LTTNG_HIDDEN
void lttng_payload_reset(struct lttng_payload *payload)
{
	if (!payload) {
		return;
	}

	lttng_dynamic_buffer_reset(&payload->buffer);
	lttng_dynamic_array_reset(&payload->_fds);
}

LTTNG_HIDDEN
int lttng_payload_push_fd(struct lttng_payload *payload, int fd)
{
	int ret;

	if (!payload) {
		ret = -1;
		goto end;
	}

	ret = lttng_dynamic_array_add_element(&payload->_fds, &fd);
end:
	return ret;
}
