/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_DOMAIN_HPP
#define LTTNG_SESSIOND_DOMAIN_HPP

#include "recording-channel-configuration.hpp"

#include <common/container-wrapper.hpp>
#include <common/domain.hpp>
#include <common/exception.hpp>
#include <common/format.hpp>
#include <common/make-unique.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <lttng/domain.h>

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

/*
 * A domain holds the channel configurations for a specific tracing domain
 * (kernel, user space, agent, etc.) within a recording session.
 */
class domain final {
public:
	explicit domain(lttng::domain_class domain_class, bool single_channel_mode = false) :
		domain_class_(domain_class), _single_channel_mode(single_channel_mode)
	{
	}

	~domain() = default;
	domain(domain&& other) noexcept :
		domain_class_(other.domain_class_),
		_single_channel_mode(other._single_channel_mode),
		_channels(std::move(other._channels))
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

		if (_single_channel_mode && !_channels.empty()) {
			LTTNG_THROW_ERROR(lttng::format(
				"Single-channel domain already has a channel: existing_name=`{}`, new_name=`{}`",
				_channels.begin()->second->name,
				new_channel->name));
		}

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

	/* Direct access for single-channel domains. */
	recording_channel_configuration& get_channel()
	{
		LTTNG_ASSERT(_single_channel_mode && _channels.size() == 1);
		return *_channels.begin()->second;
	}

	const recording_channel_configuration& get_channel() const
	{
		LTTNG_ASSERT(_single_channel_mode && _channels.size() == 1);
		return *_channels.begin()->second;
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

	const lttng::domain_class domain_class_;

private:
	const bool _single_channel_mode;
	std::unordered_map<std::string, recording_channel_configuration::uptr> _channels;
};
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_DOMAIN_HPP */
