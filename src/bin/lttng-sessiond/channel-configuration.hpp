/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_CHANNEL_CONFIGURATION_HPP
#define LTTNG_SESSIOND_CHANNEL_CONFIGURATION_HPP

#include <common/format.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <string>

namespace lttng {
namespace sessiond {
namespace config {

/*
 * Ownership model for a channel's buffers. Shared across channel kinds
 * (recording, map) that can be owned per-process or per-user.
 */
enum class ownership_model_t {
	PER_PID,
	PER_UID,
};

/*
 * Base class for channel configurations. Holds the buffer parameters common to
 * both metadata and event recording channels — the fields needed to create a
 * channel against the tracer (kernel or user space) and the consumer daemon.
 */
class channel_configuration {
public:
	using timer_period_us = std::uint64_t;

	enum class channel_type_t {
		DATA,
		METADATA,
	};

	enum class buffer_full_policy_t {
		DISCARD_EVENT,
		OVERWRITE_OLDEST_PACKET,
	};

	enum class buffer_consumption_backend_t {
		MMAP,
		SPLICE,
	};

	channel_configuration(std::string name_,
			      buffer_full_policy_t buffer_full_policy_,
			      buffer_consumption_backend_t buffer_consumption_backend_,
			      std::uint64_t subbuffer_size_bytes_,
			      unsigned int subbuffer_count_,
			      const nonstd::optional<timer_period_us>& switch_timer_period_us_,
			      const nonstd::optional<timer_period_us>& read_timer_period_us_) :
		name(std::move(name_)),
		buffer_full_policy(buffer_full_policy_),
		buffer_consumption_backend(buffer_consumption_backend_),
		subbuffer_size_bytes(subbuffer_size_bytes_),
		subbuffer_count(subbuffer_count_),
		switch_timer_period_us(switch_timer_period_us_),
		read_timer_period_us(read_timer_period_us_)
	{
	}

	channel_configuration(const channel_configuration&) = default;
	channel_configuration(channel_configuration&&) = default;
	channel_configuration& operator=(const channel_configuration&) = delete;
	channel_configuration& operator=(channel_configuration&&) = delete;

	virtual channel_type_t channel_type() const noexcept = 0;

	const std::string name;
	const buffer_full_policy_t buffer_full_policy;
	const buffer_consumption_backend_t buffer_consumption_backend;
	const std::uint64_t subbuffer_size_bytes;
	const unsigned int subbuffer_count;
	const nonstd::optional<timer_period_us> switch_timer_period_us;
	const nonstd::optional<timer_period_us> read_timer_period_us;

protected:
	~channel_configuration() = default;
};

/*
 * A metadata channel configuration holds only the buffer parameters needed to
 * create the metadata channel against the tracer. Unlike event recording
 * channels, metadata channels carry no event rules, contexts, or trace file
 * limits.
 *
 * This class is trivially copyable and movable.
 */
class metadata_channel_configuration final : public channel_configuration {
public:
	metadata_channel_configuration(
		std::string name_,
		buffer_full_policy_t buffer_full_policy_,
		buffer_consumption_backend_t buffer_consumption_backend_,
		std::uint64_t subbuffer_size_bytes_,
		unsigned int subbuffer_count_,
		const nonstd::optional<timer_period_us>& switch_timer_period_us_,
		const nonstd::optional<timer_period_us>& read_timer_period_us_) :
		channel_configuration(std::move(name_),
				      buffer_full_policy_,
				      buffer_consumption_backend_,
				      subbuffer_size_bytes_,
				      subbuffer_count_,
				      switch_timer_period_us_,
				      read_timer_period_us_)
	{
	}

	~metadata_channel_configuration() = default;
	metadata_channel_configuration(const metadata_channel_configuration&) = default;
	metadata_channel_configuration(metadata_channel_configuration&&) = default;
	metadata_channel_configuration& operator=(const metadata_channel_configuration&) = delete;
	metadata_channel_configuration& operator=(metadata_channel_configuration&&) = delete;

	channel_type_t channel_type() const noexcept override
	{
		return channel_type_t::METADATA;
	}
};

} /* namespace config */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Specialize fmt::formatter for buffer_full_policy_t.
 *
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::config::channel_configuration::buffer_full_policy_t>
	: formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::config::channel_configuration::buffer_full_policy_t policy,
	       FormatContextType& ctx) const
	{
		auto name = "UNKNOWN";

		switch (policy) {
		case lttng::sessiond::config::channel_configuration::buffer_full_policy_t::
			DISCARD_EVENT:
			name = "DISCARD_EVENT";
			break;
		case lttng::sessiond::config::channel_configuration::buffer_full_policy_t::
			OVERWRITE_OLDEST_PACKET:
			name = "OVERWRITE_OLDEST_PACKET";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng::sessiond::config::channel_configuration::buffer_consumption_backend_t>
	: formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::config::channel_configuration::buffer_consumption_backend_t backend,
	       FormatContextType& ctx) const
	{
		auto name = "UNKNOWN";

		switch (backend) {
		case lttng::sessiond::config::channel_configuration::buffer_consumption_backend_t::
			MMAP:
			name = "MMAP";
			break;
		case lttng::sessiond::config::channel_configuration::buffer_consumption_backend_t::
			SPLICE:
			name = "SPLICE";
			break;
		}

		return format_to(ctx.out(), name);
	}
};

template <>
struct formatter<lttng::sessiond::config::ownership_model_t> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(lttng::sessiond::config::ownership_model_t model, FormatContextType& ctx) const
	{
		auto name = "unknown";

		switch (model) {
		case lttng::sessiond::config::ownership_model_t::PER_PID:
			name = "per-pid";
			break;
		case lttng::sessiond::config::ownership_model_t::PER_UID:
			name = "per-uid";
			break;
		}

		return format_to(ctx.out(), name);
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_CHANNEL_CONFIGURATION_HPP */
