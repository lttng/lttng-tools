/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_MODULES_MAP_CHANNEL_HPP
#define LTTNG_SESSIOND_MODULES_MAP_CHANNEL_HPP

#include "key-registry.hpp"
#include "map-channel.hpp"
#include "modules-map-group.hpp"

#include <common/file-descriptor.hpp>

#include <cstdint>
#include <map>

namespace lttng {
namespace sessiond {

namespace config {
class map_channel_configuration;
} /* namespace config */

namespace modules {

/*
 * Kernel-domain map channel. Owns exactly one `modules::map_group`
 * (one tracer-side counter per recording session) sitting alongside
 * the base `map_channel`'s shared group and registry.
 */
class map_channel final : public sessiond::map::map_channel {
public:
	map_channel(const config::map_channel_configuration& configuration,
		    sessiond::map::key_registry::uptr registry,
		    modules::map_group kernel_group);

	~map_channel() override = default;
	map_channel(const map_channel&) = delete;
	map_channel(map_channel&&) = delete;
	map_channel& operator=(const map_channel&) = delete;
	map_channel& operator=(map_channel&&) = delete;

	modules::map_group& kernel_group() noexcept;
	const modules::map_group& kernel_group() const noexcept;

	void for_each_group(const group_visitor& visitor) const override;

	struct rule_record {
		/* The (&event_rule, &incr_map_value_action) pair identifying the rule. */
		sessiond::map::event_rule_action_key key;
		/* The kernel counter-event fd; closed when the record is erased. */
		lttng::file_descriptor event_fd;
	};

	/*
	 * Records of the counter-event rules registered against this channel,
	 * keyed by user token. Tokens are allocated monotonically by
	 * `allocate_user_token()`, so an in-order traversal visits the rules in
	 * registration order.
	 *
	 * Owned by the channel for each rule's registered lifetime; populated
	 * and cleared by the modules orchestrator, the sole accessor.
	 */
	std::map<std::uint64_t, rule_record> _rules;

private:
	void _clear_tracer_groups() override;

	modules::map_group _kernel_group;
};

} /* namespace modules */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_MODULES_MAP_CHANNEL_HPP */
