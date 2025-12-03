/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CONSUMER_RECLAIM_HPP
#define LTTNG_CONSUMER_RECLAIM_HPP

#include <cstdint>

namespace lttng {
namespace consumer {
struct memory_reclaim_result {
	std::uint64_t bytes_reclaimed = 0;
	std::uint64_t pending_bytes_to_reclaim = 0;
};
} /* namespace consumer */
} /* namespace lttng */

#endif /* LTTNG_CONSUMER_RECLAIM_HPP */