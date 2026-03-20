/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-stream-group.hpp"

#include <utility>

namespace ls = lttng::sessiond;
namespace lsu = lttng::sessiond::ust;

lsu::stream_group::stream_group(uint64_t consumer_key,
				ust_object_data channel_object,
				const ls::config::recording_channel_configuration& configuration,
				lsu::trace_class& trace_class,
				lsu::stream_class& stream_class) :
	ls::stream_group<ust_object_data>(consumer_key),
	_channel_object(std::move(channel_object)),
	_configuration(configuration),
	_trace_class(trace_class),
	_stream_class(stream_class)
{
}

const ls::config::recording_channel_configuration& lsu::stream_group::configuration() const noexcept
{
	return _configuration;
}

lsu::trace_class& lsu::stream_group::get_trace_class() const noexcept
{
	return _trace_class;
}

lsu::stream_class& lsu::stream_group::get_stream_class() const noexcept
{
	return _stream_class;
}

const lsu::ust_object_data& lsu::stream_group::channel_object() const noexcept
{
	return _channel_object;
}

lsu::ust_object_data& lsu::stream_group::channel_object() noexcept
{
	return _channel_object;
}

lsu::ust_object_data lsu::stream_group::duplicate_channel_object() const
{
	return _channel_object.duplicate();
}

bool lsu::stream_group::is_sent_to_consumer() const noexcept
{
	return _sent_to_consumer;
}

void lsu::stream_group::mark_sent_to_consumer() noexcept
{
	_sent_to_consumer = true;
}
