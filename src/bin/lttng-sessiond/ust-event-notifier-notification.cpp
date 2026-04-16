/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-event-notifier-notification.hpp"

#include <common/error.hpp>
#include <common/readwrite.hpp>

#include <lttng/ust-ctl.h>

namespace lttng {
namespace sessiond {
namespace ust {

nonstd::optional<event_notifier_notification_header>
read_event_notifier_notification_header(int pipe_fd)
{
	struct lttng_ust_abi_event_notifier_notification raw_header;

	/*
	 * The monitoring pipe only holds messages smaller than PIPE_BUF,
	 * ensuring that read/write of tracer notifications are atomic.
	 */
	const auto read_ret = lttng_read(pipe_fd, &raw_header, sizeof(raw_header));
	if (read_ret != sizeof(raw_header)) {
		PERROR("Failed to read from event source notification pipe: fd = %d, size to read = %zu, ret = %zd",
		       pipe_fd,
		       sizeof(raw_header),
		       read_ret);
		return nonstd::nullopt;
	}

	return event_notifier_notification_header{ raw_header.token, raw_header.capture_buf_size };
}

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */
