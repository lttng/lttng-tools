/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "stream-class.hpp"
#include "trace-class.hpp"

namespace lst = lttng::sessiond::trace;

lttng::sessiond::trace::stream_class::stream_class(
		unsigned int in_id, enum header_type in_header_type) :
	id{in_id}, header_type{in_header_type}
{
}

void lst::stream_class::accept(trace_class_visitor& visitor) const
{
	visitor.visit(*this);
	_accept_on_event_classes(visitor);
}

const lttng::sessiond::trace::type& lst::stream_class::get_context() const
{
	LTTNG_ASSERT(_context);
	return *_context;
}
