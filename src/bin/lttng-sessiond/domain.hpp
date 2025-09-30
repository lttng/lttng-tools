/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_DOMAIN_HPP
#define LTTNG_SESSIOND_DOMAIN_HPP

#include "recording-channel-configuration.hpp"

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
 * A channel configuration represents the configuration of a recording session's
 * channel at a given point in time. It belongs to a single recording session.
 */
class domain {
public:
	explicit domain(lttng::domain_class domain_class) : domain_class_(domain_class)
	{
	}

	virtual ~domain() = default;

	domain(const domain&) = delete;
	domain(domain&&) = delete;
	domain& operator=(const domain&) = delete;
	domain& operator=(domain&&) = delete;

	/* Add a channel to the domain by constructing it in place. */
	template <typename... Args>
	recording_channel_configuration& add_channel(Args&&...args)
	{
		return _add_channel(lttng::make_unique<recording_channel_configuration>(
			std::forward<Args>(args)...));
	}

	/* Lookup by name, get non-const reference. */
	virtual recording_channel_configuration& get_channel(const lttng::c_string_view& name) = 0;

	/* Lookup by name, get const reference. */
	const recording_channel_configuration& get_channel(const lttng::c_string_view& name) const
	{
		/* NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) */
		return const_cast<domain *>(this)->get_channel(name);
	}

	const lttng::domain_class domain_class_;

private:
	virtual recording_channel_configuration&
	_add_channel(recording_channel_configuration::uptr new_channel) = 0;
};

class multi_channel_domain : public domain {
	using channels_t = std::unordered_map<std::string, recording_channel_configuration::uptr>;

public:
	explicit multi_channel_domain(domain_class domain_class) : domain(domain_class)
	{
	}

	~multi_channel_domain() override = default;
	multi_channel_domain(multi_channel_domain&& other) noexcept :
		domain(other.domain_class_), channels(std::move(other.channels))
	{
	}

	multi_channel_domain(const multi_channel_domain&) = delete;
	multi_channel_domain& operator=(const multi_channel_domain&) = delete;
	multi_channel_domain& operator=(multi_channel_domain&&) = delete;

	/* Lookup by name, get non-const reference. */
	recording_channel_configuration& get_channel(const lttng::c_string_view& name) override
	{
		const auto it = channels.find(name.data());
		if (it == channels.end()) {
			LTTNG_THROW_CHANNEL_NOT_FOUND_BY_NAME_ERROR(name);
		}

		return *(it->second);
	}

	/* Iterate over channels (non-const) */
	channels_t::iterator begin()
	{
		return channels.begin();
	}

	channels_t::iterator end()
	{
		return channels.end();
	}

	/* Iterate over channels (const) */
	channels_t::const_iterator begin() const
	{
		return channels.begin();
	}

	channels_t::const_iterator end() const
	{
		return channels.end();
	}

private:
	recording_channel_configuration&
	_add_channel(recording_channel_configuration::uptr new_channel) override
	{
		const auto& name = new_channel->name;

		auto result = channels.emplace(name, std::move(new_channel));
		if (!result.second) {
			throw std::runtime_error(fmt::format(
				"Failed to add channel to domain, name already in use: channel_name=`{}`",
				name));
		}

		return *(result.first->second);
	}

	channels_t channels;
};
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_DOMAIN_HPP */
