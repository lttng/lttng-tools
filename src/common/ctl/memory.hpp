/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_CTL_MEMORY_HPP
#define LTTNG_COMMON_CTL_MEMORY_HPP

#include <common/meta-helpers.hpp>

#include <lttng/lttng.h>

#include <memory>
#include <vector>

namespace lttng {

using event_rule_uptr = std::unique_ptr<
	lttng_event_rule,
	lttng::memory::create_deleter_class<lttng_event_rule, lttng_event_rule_destroy>>;

using kernel_location_uptr =
	std::unique_ptr<lttng_kernel_probe_location,
			lttng::memory::create_deleter_class<lttng_kernel_probe_location,
							    lttng_kernel_probe_location_destroy>>;

using notification_uptr = std::unique_ptr<
	lttng_notification,
	lttng::memory::create_deleter_class<lttng_notification, lttng_notification_destroy>>;

using data_stream_info_sets_cuptr =
	std::unique_ptr<const lttng_data_stream_info_sets,
			lttng::memory::create_deleter_class<const lttng_data_stream_info_sets,
							    lttng_data_stream_info_sets_destroy>>;

} /* namespace lttng */

#endif /* LTTNG_COMMON_CTL_MEMORY_HPP */
