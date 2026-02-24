/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_LTTNG_CHANNEL_FROM_CONFIG_HPP
#define LTTNG_SESSIOND_LTTNG_CHANNEL_FROM_CONFIG_HPP

#include <common/ctl/memory.hpp>

namespace lttng {
namespace sessiond {
namespace config {
class recording_channel_configuration;
} /* namespace config */

/*
 * Build a legacy lttng_channel from a recording_channel_configuration.
 *
 * This conversion is a transitional bridge: the legacy ltt_kernel_channel
 * struct still carries a lttng_channel pointer that downstream code reads
 * from (channel listing, consumer channel send, etc.). Once those readers
 * are migrated to read from the configuration objects directly, this
 * conversion will be eliminated.
 *
 * Populates all fields from the configuration, including extended
 * attributes. Runtime statistics (discarded_events, lost_packets)
 * are not set.
 */
lttng::ctl::lttng_channel_uptr
make_lttng_channel(const config::recording_channel_configuration& channel_config);

} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_LTTNG_CHANNEL_FROM_CONFIG_HPP */
