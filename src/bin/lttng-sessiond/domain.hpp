/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_DOMAIN_HPP
#define LTTNG_SESSIOND_DOMAIN_HPP

#include "process-attribute-tracker.hpp"
#include "recording-channel-configuration.hpp"

#include <common/container-wrapper.hpp>
#include <common/domain.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/make-unique.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <lttng/domain.h>

#include <vendor/optional.hpp>

#include <memory>
#include <string>
#include <unordered_map>

namespace lttng {
namespace sessiond {

#define LTTNG_THROW_CHANNEL_NOT_FOUND_BY_NAME_ERROR(channel_name)                \
	throw lttng::sessiond::exceptions::channel_not_found_error(channel_name, \
								   LTTNG_SOURCE_LOCATION())

namespace exceptions {
/*
 * @class channel_not_found_error
 * @brief Represents a channel-not-found error and provides the name of the channel looked-up
 * for use by error-reporting code.
 */
class channel_not_found_error : public lttng::runtime_error {
public:
	explicit channel_not_found_error(std::string channel_name,
					 const lttng::source_location& source_location);

	const std::string channel_name;
};
} /* namespace exceptions */

namespace details {
/* Create a tracker if domain is kernel-only. */
template <typename TrackerType>
nonstd::optional<TrackerType> make_kernel_tracker(lttng::domain_class domain_class)
{
	if (domain_class == lttng::domain_class::KERNEL_SPACE) {
		return TrackerType();
	}

	return nonstd::nullopt;
}

/* Create a tracker if domain is kernel or user space. */
template <typename TrackerType>
nonstd::optional<TrackerType> make_kernel_or_user_space_tracker(lttng::domain_class domain_class)
{
	if (domain_class == lttng::domain_class::KERNEL_SPACE ||
	    domain_class == lttng::domain_class::USER_SPACE) {
		return TrackerType();
	}

	return nonstd::nullopt;
}
} /* namespace details */

/*
 * A domain holds the channel configurations for a specific tracing domain
 * (kernel, user space, agent, etc.) within a recording session.
 *
 * Process attribute trackers are domain-specific:
 * - Kernel domain: all 6 trackers (pid, vpid, uid, vuid, gid, vgid)
 * - User space domain: 3 virtual trackers (vpid, vuid, vgid)
 * - Agent domains: no trackers (use agent_domain class instead)
 */
class domain final {
public:
	explicit domain(lttng::domain_class domain_class) :
		domain_class_(domain_class),
		_process_id_tracker(
			details::make_kernel_tracker<process_id_tracker_t>(domain_class)),
		_virtual_process_id_tracker(
			details::make_kernel_or_user_space_tracker<virtual_process_id_tracker_t>(
				domain_class)),
		_user_id_tracker(details::make_kernel_tracker<user_id_tracker_t>(domain_class)),
		_virtual_user_id_tracker(
			details::make_kernel_or_user_space_tracker<virtual_user_id_tracker_t>(
				domain_class)),
		_group_id_tracker(details::make_kernel_tracker<group_id_tracker_t>(domain_class)),
		_virtual_group_id_tracker(
			details::make_kernel_or_user_space_tracker<virtual_group_id_tracker_t>(
				domain_class))
	{
	}

	~domain() = default;
	domain(domain&& other) noexcept :
		domain_class_(other.domain_class_),
		_channels(std::move(other._channels)),
		_process_id_tracker(std::move(other._process_id_tracker)),
		_virtual_process_id_tracker(std::move(other._virtual_process_id_tracker)),
		_user_id_tracker(std::move(other._user_id_tracker)),
		_virtual_user_id_tracker(std::move(other._virtual_user_id_tracker)),
		_group_id_tracker(std::move(other._group_id_tracker)),
		_virtual_group_id_tracker(std::move(other._virtual_group_id_tracker))
	{
	}

	domain(const domain&) = delete;
	domain& operator=(const domain&) = delete;
	domain& operator=(domain&&) = delete;

	/* Add a channel to the domain by constructing it in place. */
	template <typename... Args>
	recording_channel_configuration& add_channel(Args&&...args)
	{
		auto new_channel = lttng::make_unique<recording_channel_configuration>(
			std::forward<Args>(args)...);

		const auto& name = new_channel->name;
		auto result = _channels.emplace(name, std::move(new_channel));
		if (!result.second) {
			LTTNG_THROW_ERROR(lttng::format(
				"Failed to add channel to domain, name already in use: channel_name=`{}`",
				name));
		}

		return *(result.first->second);
	}

	/* Lookup by name. */
	recording_channel_configuration& get_channel(const lttng::c_string_view& name)
	{
		const auto it = _channels.find(name.data());
		if (it == _channels.end()) {
			LTTNG_THROW_CHANNEL_NOT_FOUND_BY_NAME_ERROR(name);
		}

		return *(it->second);
	}

	const recording_channel_configuration& get_channel(const lttng::c_string_view& name) const
	{
		/* NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) */
		return const_cast<domain *>(this)->get_channel(name);
	}

	using recording_channels_view = lttng::utils::dereferenced_mapped_values_view<
		std::unordered_map<std::string, recording_channel_configuration::uptr>,
		recording_channel_configuration>;
	using const_recording_channels_view = lttng::utils::dereferenced_mapped_values_view<
		const std::unordered_map<std::string, recording_channel_configuration::uptr>,
		const recording_channel_configuration>;

	recording_channels_view recording_channels() noexcept
	{
		return recording_channels_view(_channels);
	}

	const_recording_channels_view recording_channels() const noexcept
	{
		return const_recording_channels_view(_channels);
	}

	/*
	 * Process attribute tracker accessors.
	 *
	 * Kernel-only trackers (process_id, user_id, group_id) assert if accessed
	 * on a non-kernel domain.
	 *
	 * Virtual trackers (virtual_process_id, virtual_user_id, virtual_group_id)
	 * are available for both kernel and user space domains.
	 */

	/* Kernel-only: real process ID tracker. */
	process_id_tracker_t& process_id_tracker()
	{
		LTTNG_ASSERT(domain_class_ == lttng::domain_class::KERNEL_SPACE);
		return *_process_id_tracker;
	}

	const process_id_tracker_t& process_id_tracker() const
	{
		LTTNG_ASSERT(domain_class_ == lttng::domain_class::KERNEL_SPACE);
		return *_process_id_tracker;
	}

	/* Kernel and user space: virtual process ID tracker. */
	virtual_process_id_tracker_t& virtual_process_id_tracker()
	{
		LTTNG_ASSERT(_virtual_process_id_tracker);
		return *_virtual_process_id_tracker;
	}

	const virtual_process_id_tracker_t& virtual_process_id_tracker() const
	{
		LTTNG_ASSERT(_virtual_process_id_tracker);
		return *_virtual_process_id_tracker;
	}

	/* Kernel-only: real user ID tracker. */
	user_id_tracker_t& user_id_tracker()
	{
		LTTNG_ASSERT(domain_class_ == lttng::domain_class::KERNEL_SPACE);
		return *_user_id_tracker;
	}

	const user_id_tracker_t& user_id_tracker() const
	{
		LTTNG_ASSERT(domain_class_ == lttng::domain_class::KERNEL_SPACE);
		return *_user_id_tracker;
	}

	/* Kernel and user space: virtual user ID tracker. */
	virtual_user_id_tracker_t& virtual_user_id_tracker()
	{
		LTTNG_ASSERT(_virtual_user_id_tracker);
		return *_virtual_user_id_tracker;
	}

	const virtual_user_id_tracker_t& virtual_user_id_tracker() const
	{
		LTTNG_ASSERT(_virtual_user_id_tracker);
		return *_virtual_user_id_tracker;
	}

	/* Kernel-only: real group ID tracker. */
	group_id_tracker_t& group_id_tracker()
	{
		LTTNG_ASSERT(domain_class_ == lttng::domain_class::KERNEL_SPACE);
		return *_group_id_tracker;
	}

	const group_id_tracker_t& group_id_tracker() const
	{
		LTTNG_ASSERT(domain_class_ == lttng::domain_class::KERNEL_SPACE);
		return *_group_id_tracker;
	}

	/* Kernel and user space: virtual group ID tracker. */
	virtual_group_id_tracker_t& virtual_group_id_tracker()
	{
		LTTNG_ASSERT(_virtual_group_id_tracker);
		return *_virtual_group_id_tracker;
	}

	const virtual_group_id_tracker_t& virtual_group_id_tracker() const
	{
		LTTNG_ASSERT(_virtual_group_id_tracker);
		return *_virtual_group_id_tracker;
	}

	const lttng::domain_class domain_class_;

private:
	std::unordered_map<std::string, recording_channel_configuration::uptr> _channels;

	/* Process attribute trackers (populated based on domain_class_). */
	nonstd::optional<process_id_tracker_t> _process_id_tracker;
	nonstd::optional<virtual_process_id_tracker_t> _virtual_process_id_tracker;
	nonstd::optional<user_id_tracker_t> _user_id_tracker;
	nonstd::optional<virtual_user_id_tracker_t> _virtual_user_id_tracker;
	nonstd::optional<group_id_tracker_t> _group_id_tracker;
	nonstd::optional<virtual_group_id_tracker_t> _virtual_group_id_tracker;
};
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_DOMAIN_HPP */
