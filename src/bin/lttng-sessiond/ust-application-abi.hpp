/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APPLICATION_ABI_HPP
#define LTTNG_SESSIOND_UST_APPLICATION_ABI_HPP

#include <cstdint>

namespace lttng {
namespace sessiond {
namespace ust {

enum class application_abi : std::uint8_t {
	ABI_32 = 32,
	ABI_64 = 64,
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_APPLICATION_ABI_HPP */
