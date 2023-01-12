/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "stream-class.hpp"
#include "trace-class.hpp"

namespace lst = lttng::sessiond::trace;

lttng::sessiond::trace::stream_class::stream_class(unsigned int in_id,
		enum header_type in_header_type,
		nonstd::optional<std::string> in_default_clock_class_name) :
	id{in_id},
	header_type_{in_header_type},
	default_clock_class_name{std::move(in_default_clock_class_name)}
{
}

void lst::stream_class::accept(trace_class_visitor& visitor) const
{
	visitor.visit(*this);
	_accept_on_event_classes(visitor);
}

const lttng::sessiond::trace::type *lst::stream_class::packet_context() const
{
	return _packet_context.get();
}

const lttng::sessiond::trace::type *lst::stream_class::event_header() const
{
	return _event_header.get();
}

const lttng::sessiond::trace::type *lst::stream_class::event_context() const
{
	return _event_context.get();
}
