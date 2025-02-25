/*
 * SPDX-FileCopyrightText: 2025 Kienan Stewart <kstewart@efficios.com>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <common/make-unique-wrapper.hpp>

#include <string>

namespace lttng {
namespace tracepoints {
namespace details {
/*
 * Helper function to unload dlopened tracepoint provider.
 *
 * Doesn't need to be called directly by public users.
 */
void tracepoints_unload(void *tracepoint);
} /* namespace details */
} /* namespace tracepoints */
} /* namespace lttng */

/*
 * Returns a unique pointer reference to the loaded tracepoint provider, if any.
 *
 * The return value is owned by the caller. When the object is destroyed, the
 * library will be unloaded.
 */
std::unique_ptr<void,
		lttng::memory::create_deleter_class<
			void,
			lttng::tracepoints::details::tracepoints_unload>::deleter>
tracepoints_load(const char *basename);
