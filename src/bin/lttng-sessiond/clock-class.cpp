/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "clock-class.hpp"
#include "trace-class.hpp"

lttng::sessiond::trace::clock_class::clock_class(std::string in_name,
						 std::string in_description,
						 nonstd::optional<lttng_uuid> in_uuid,
						 scycles_t in_offset,
						 cycles_t in_frequency) :
	name{ std::move(in_name) },
	description{ std::move(in_description) },
	uuid{ std::move(in_uuid) },
	offset{ in_offset },
	frequency{ in_frequency }
{
}

void lttng::sessiond::trace::clock_class::accept(trace_class_visitor& visitor) const
{
	visitor.visit(*this);
}
