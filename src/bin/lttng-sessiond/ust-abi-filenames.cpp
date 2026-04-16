/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-abi-filenames.hpp"

#include <lttng/ust-ctl.h>

namespace lttng {
namespace sessiond {
namespace ust {

lttng::c_string_view app_sock_filename() noexcept
{
	return LTTNG_UST_SOCK_FILENAME;
}

lttng::c_string_view app_wait_shm_filename() noexcept
{
	return LTTNG_UST_WAIT_FILENAME;
}

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */
