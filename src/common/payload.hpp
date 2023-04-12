/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_PAYLOAD_H
#define LTTNG_PAYLOAD_H

#include <common/dynamic-array.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/fd-handle.hpp>

/*
 * An lttng_payload encompasses the 'data' (bytes) and any passed file
 * descriptors as part of a message between liblttng-ctl and the session
 * daemon.
 */
struct lttng_payload {
	struct lttng_dynamic_buffer buffer;
	/* private */
	struct lttng_dynamic_pointer_array _fd_handles;
};

/*
 * Initialize a payload. This performs no allocation and is meant
 * to be used instead of zero-ing the payload structure.
 */
void lttng_payload_init(struct lttng_payload *payload);

/* Copy a payload. */
int lttng_payload_copy(const struct lttng_payload *src_payload, struct lttng_payload *dst_payload);

/* Release any memory and references held by the payload. */
void lttng_payload_reset(struct lttng_payload *payload);

/*
 * Empty the contents of a payload, releasing all references held.
 * This should be used to put a payload in a re-usable state.
 *
 * lttng_payload_reset must still be called on an lttng_payload to
 * free all allocated memory.
 */
void lttng_payload_clear(struct lttng_payload *payload);

/**
 * Add an fd to the payload.
 * The payload acquires a reference to the fd_handle.
 *
 * @payload	Payload instance
 * @fd_handle	File descriptor handle to add to the payload
 *
 * Returns 0 on success, -1 on allocation error.
 */
int lttng_payload_push_fd_handle(struct lttng_payload *payload, struct fd_handle *fd_handle);

#endif /* LTTNG_PAYLOAD_H */
