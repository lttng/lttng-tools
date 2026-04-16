/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_ABI_FILENAMES_HPP
#define LTTNG_SESSIOND_UST_ABI_FILENAMES_HPP

#include <common/string-utils/c-string-view.hpp>

namespace lttng {
namespace sessiond {
namespace ust {

#ifdef HAVE_LIBLTTNG_UST_CTL

/*
 * Return the filename of the unix socket on which the session daemon
 * listens for application registrations. The filename embeds the
 * oldest UST ABI major version that the daemon is able to speak; that
 * value lives in <lttng/ust-ctl.h> and is only accessible when the
 * daemon is built with UST support.
 */
lttng::c_string_view app_sock_filename() noexcept;

/*
 * Return the filename of the wait shared-memory object used to notify
 * applications that the session daemon is available. Same ABI-version
 * coupling as app_sock_filename().
 */
lttng::c_string_view app_wait_shm_filename() noexcept;

#else /* HAVE_LIBLTTNG_UST_CTL */

/*
 * The session daemon cannot serve UST applications in this
 * configuration, so the filenames — whose values come from
 * <lttng/ust-ctl.h> — are returned as empty views. Callers that build
 * on them to create a communication endpoint must handle the
 * empty-view case, or avoid the code path altogether.
 */
inline lttng::c_string_view app_sock_filename() noexcept
{
	return "";
}

inline lttng::c_string_view app_wait_shm_filename() noexcept
{
	return "";
}

#endif /* HAVE_LIBLTTNG_UST_CTL */

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_ABI_FILENAMES_HPP */
