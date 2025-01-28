/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_CTL_UTILS_H
#define LTTNG_SESSIOND_CTL_UTILS_H

#include <common/make-unique-wrapper.hpp>

#include <lttng/lttng.h>

namespace lttng {
namespace ctl {
/*
 * The 'session_descriptor' alias, based on unique_ptr, manages lttng_session_descriptor resources
 * with automatic cleanup.
 */
using session_descriptor = std::unique_ptr<
	lttng_session_descriptor,
	lttng::memory::create_deleter_class<lttng_session_descriptor,
					    lttng_session_descriptor_destroy>::deleter>;

/*
 * The 'trigger' alias, based on unique_ptr, manages lttng_trigger resources
 * with automatic cleanup.
 */
using trigger = std::unique_ptr<
	lttng_trigger,
	lttng::memory::create_deleter_class<lttng_trigger, lttng_trigger_destroy>::deleter>;

} /* namespace ctl */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_CTL_UTILS_H */
