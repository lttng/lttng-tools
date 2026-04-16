/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_EVENT_NOTIFIER_NOTIFICATION_HPP
#define LTTNG_SESSIOND_UST_EVENT_NOTIFIER_NOTIFICATION_HPP

#include <vendor/optional.hpp>

#include <cstddef>
#include <cstdint>

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * Fields extracted from the fixed-size UST event notifier notification
 * header that tracers write at the head of every notification on the
 * monitoring pipe.
 */
struct event_notifier_notification_header {
	uint64_t token;
	std::size_t capture_buf_size;
};

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * Read the fixed UST event notifier notification header from
 * `pipe_fd` and return the fields relevant to the notification
 * thread. On read error or short read, returns nullopt (the error is
 * logged by the implementation).
 *
 * Any capture payload that follows the header is left on the pipe
 * for the caller to drain.
 */
nonstd::optional<event_notifier_notification_header>
read_event_notifier_notification_header(int pipe_fd);

#else /* HAVE_LIBLTTNG_UST_CTL */

/*
 * The session daemon cannot process UST event notifier notifications
 * in this configuration; the notification pipe for UST applications
 * is never created, so the helper should never be reached.
 */
inline nonstd::optional<event_notifier_notification_header>
read_event_notifier_notification_header(int pipe_fd __attribute__((unused)))
{
	std::abort();
	return nonstd::nullopt;
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_EVENT_NOTIFIER_NOTIFICATION_HPP */
