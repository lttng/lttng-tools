/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "trace-class.hpp"

namespace lst = lttng::sessiond::trace;

lttng::sessiond::trace::trace_class::trace_class(const struct abi& in_abi,
						 const lttng_uuid& in_trace_uuid) :
	abi(in_abi), uuid(in_trace_uuid)
{
}

void lttng::sessiond::trace::trace_class::accept(trace_class_visitor& trace_class_visitor) const
{
	trace_class_visitor.visit(*this);
	_accept_on_clock_classes(trace_class_visitor);
	_accept_on_stream_classes(trace_class_visitor);
}

void lst::trace_class_environment_visitor::visit(const environment_field<std::string>& field)
{
	visit(environment_field<const char *>(field.name, field.value.c_str()));
}
