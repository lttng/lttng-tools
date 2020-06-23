/*
 * Copyright (C) 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_PAYLOAD_H
#define LTTNG_PAYLOAD_H

#include <common/dynamic-buffer.h>
#include <common/dynamic-array.h>

/*
 * An lttng_payload encompasses the 'data' (bytes) and any passed file
 * descriptors as part of a message between liblttng-ctl and the session
 * daemon.
 */
struct lttng_payload {
	struct lttng_dynamic_buffer buffer;
	/* private */
	struct lttng_dynamic_array _fds;
};

/*
 * Initialize a payload. This performs no allocation and is meant
 * to be used instead of zero-ing the payload structure.
 */
LTTNG_HIDDEN
void lttng_payload_init(struct lttng_payload *payload);

/* Release any memory used by the payload. */
LTTNG_HIDDEN
void lttng_payload_reset(struct lttng_payload *payload);

/**
 * Add an fd to the payload.
 * No ownership of the file descriptor is assumed by the payload.
 *
 * @payload	Payload instance
 * @fd		File descriptor to add to the payload
 *
 * Returns 0 on success, -1 on allocation error.
 */
LTTNG_HIDDEN
int lttng_payload_push_fd(struct lttng_payload *payload, int fd);

#endif /* LTTNG_PAYLOAD_H */
