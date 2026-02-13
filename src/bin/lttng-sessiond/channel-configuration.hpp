/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_CHANNEL_CONFIGURATION_HPP
#define LTTNG_SESSIOND_CHANNEL_CONFIGURATION_HPP

#include <vendor/optional.hpp>

#include <cstdint>
#include <string>

namespace lttng {
namespace sessiond {
namespace config {

/*
 * Base class for channel configurations. Holds the buffer parameters common to
 * both metadata and event recording channels — the fields needed to create a
 * channel against the tracer (kernel or user space) and the consumer daemon.
 */
class channel_configuration {
public:
	using timer_period_us = std::uint64_t;

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
};

} /* namespace config */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_CHANNEL_CONFIGURATION_HPP */
