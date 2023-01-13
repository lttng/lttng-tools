/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-class.hpp"
#include "trace-class.hpp"

namespace lst = lttng::sessiond::trace;

lst::event_class::event_class(unsigned int in_id,
			      unsigned int in_stream_class_id,
			      int in_log_level,
			      std::string in_name,
			      nonstd::optional<std::string> in_model_emf_uri,
			      lttng::sessiond::trace::type::cuptr in_payload) :
	id{ in_id },
	stream_class_id{ in_stream_class_id },
	log_level{ in_log_level },
	name{ std::move(in_name) },
	model_emf_uri{ std::move(in_model_emf_uri) },
	payload{ std::move(in_payload) }
{
}

void lst::event_class::accept(lst::trace_class_visitor& visitor) const
{
	visitor.visit(*this);
}
