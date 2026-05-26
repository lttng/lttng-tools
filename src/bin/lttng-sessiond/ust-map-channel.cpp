/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "bin/lttng-sessiond/channel-configuration.hpp"
#include "map-channel-configuration.hpp"
#include "ust-app.hpp"
#include "ust-map-channel.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/scope-exit.hpp>

#include <utility>

namespace lttng {
namespace sessiond {
namespace ust {

map_channel::app_attachment::app_attachment(
	ust::map_group::app_handle counter_attachment,
	app_objd_registry::registration_token objd_token) noexcept :
	_counter_attachment(std::move(counter_attachment)), _objd_token(std::move(objd_token))
{
}

map_channel::map_channel(const config::map_channel_configuration& configuration,
			 sessiond::map::key_registry::uptr registry) :
	sessiond::map::map_channel(configuration, std::move(registry))
{
}

ust::map_group& map_channel::add_uid_group(uid_t uid, application_abi abi)
{
	LTTNG_ASSERT(configuration().buffer_ownership == config::ownership_model_t::PER_UID);

	const uid_abi_key key{ uid, abi };

	const auto existing = _per_uid_groups.find(key);
	if (existing != _per_uid_groups.end()) {
		return *existing->second;
	}

	auto group =
		lttng::make_unique<ust::map_group>(map_group::create_from_config(configuration()));
	auto& group_ref = *group;
	_per_uid_groups.emplace(key, std::move(group));

	return group_ref;
}

void map_channel::remove_uid_group(uid_t uid, application_abi abi)
{
	LTTNG_ASSERT(configuration().buffer_ownership == config::ownership_model_t::PER_UID);

	const auto erased = _per_uid_groups.erase(uid_abi_key{ uid, abi });
	LTTNG_ASSERT(erased == 1);
}

void map_channel::for_each_uid_group(const uid_group_visitor& visitor) const
{
	LTTNG_ASSERT(configuration().buffer_ownership == config::ownership_model_t::PER_UID);

	for (const auto& entry : _per_uid_groups) {
		visitor(entry.first.first, entry.first.second, *entry.second);
	}
}

ust::map_group& map_channel::add_app_group(const ust::app& app)
{
	LTTNG_ASSERT(configuration().buffer_ownership == config::ownership_model_t::PER_PID);
	LTTNG_ASSERT(_per_app_groups.find(&app) == _per_app_groups.end());

	auto group =
		lttng::make_unique<ust::map_group>(map_group::create_from_config(configuration()));
	auto& group_ref = *group;
	_per_app_groups.emplace(&app, std::move(group));

	return group_ref;
}

void map_channel::remove_app_group(const ust::app& app)
{
	LTTNG_ASSERT(configuration().buffer_ownership == config::ownership_model_t::PER_PID);

	const auto it = _per_app_groups.find(&app);
	if (it == _per_app_groups.end()) {
		/*
		 * Attach may have failed (and been logged + skipped) when
		 * the app first synchronized with this channel; the
		 * orchestrator still calls remove on departure for every
		 * known channel, so a missing entry is a normal outcome.
		 */
		return;
	}

	using policy_t = config::map_channel_configuration::dead_group_policy_t;

	switch (configuration().dead_group_policy) {
	case policy_t::DROP:
		break;
	case policy_t::SUM_INTO_SHARED:
	{
		/*
		 * The shared group operates on flat indices. INDEX-keyed
		 * channels have no string registry; the drain over such a
		 * channel is currently unreachable (no UST consumer of
		 * INDEX-keyed map channels).
		 */
		LTTNG_ASSERT(has_registry());

		auto& dying_group = *it->second;
		registry().for_each([&](lttng::c_string_view /* key */, std::uint64_t index) {
			const auto element = dying_group.aggregate_element(index);
			shared().increment(index, element.value);
		});
		break;
	}
	}

	_per_app_groups.erase(it);
}

void map_channel::for_each_app_group(const app_group_visitor& visitor) const
{
	LTTNG_ASSERT(configuration().buffer_ownership == config::ownership_model_t::PER_PID);

	for (const auto& entry : _per_app_groups) {
		visitor(*entry.first, *entry.second);
	}
}

map_channel::app_attachment map_channel::attach_to_app(ust::app& app, int session_parent_handle)
{
	using ownership_t = config::ownership_model_t;

	switch (configuration().buffer_ownership) {
	case ownership_t::PER_UID:
	{
		auto& group = add_uid_group(app.uid,
					    app.abi.bits_per_long == 32 ? application_abi::ABI_32 :
									  application_abi::ABI_64);

		auto counter_attachment = group.attach_to_app(app, session_parent_handle);
		auto objd_token = app.objd_registry.register_map_channel_objd(
			counter_attachment.master_objd(),
			app_objd_registry::map_channel_entry{ registry_observer() });

		return app_attachment(std::move(counter_attachment), std::move(objd_token));
	}
	case ownership_t::PER_PID:
	{
		auto& group = add_app_group(app);
		/*
		 * Per-PID groups are exclusive to their app: roll back the
		 * insertion if a subsequent step throws so the channel does
		 * not retain an orphaned local counter. Per-UID groups are
		 * shared across apps and intentionally outlive an
		 * individual attachment failure, so they have no
		 * equivalent rollback.
		 */
		auto group_rollback = lttng::make_scope_exit([&]() noexcept {
			try {
				remove_app_group(app);
			} catch (const std::exception& ex) {
				ERR_FMT("Failed to roll back per-PID map group after failed app attachment: "
					"map_name=`{}`, app={}, error=`{}`",
					configuration().name,
					app,
					ex.what());
			}
		});

		auto counter_attachment = group.attach_to_app(app, session_parent_handle);
		auto objd_token = app.objd_registry.register_map_channel_objd(
			counter_attachment.master_objd(),
			app_objd_registry::map_channel_entry{ registry_observer() });

		group_rollback.disarm();
		return app_attachment(std::move(counter_attachment), std::move(objd_token));
	}
	case ownership_t::SYSTEM:
		/* SYSTEM is kernel-only; unreachable for a user space channel. */
		break;
	}

	abort();
}

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */
