/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_EVENT_CLASS_H
#define LTTNG_EVENT_CLASS_H

#include "field.hpp"

#include <common/uuid.hpp>

#include <vendor/optional.hpp>

#include <string>

namespace lttng {
namespace sessiond {
namespace trace {

class trace_class_visitor;

class event_class {
public:
	event_class(const event_class&) = delete;
	event_class(event_class&&) = delete;
	event_class& operator=(event_class&&) = delete;
	event_class& operator=(const event_class&) = delete;
	virtual ~event_class() = default;

	virtual void accept(trace_class_visitor& visitor) const;

	const unsigned int id;
	const unsigned int stream_class_id;
	const int log_level;
	const std::string name;
	const nonstd::optional<std::string> model_emf_uri;
	const lttng::sessiond::trace::type::cuptr payload;

protected:
	event_class(unsigned int id,
		    unsigned int stream_class_id,
		    int log_level,
		    std::string name,
		    nonstd::optional<std::string> model_emf_uri,
		    lttng::sessiond::trace::type::cuptr payload);
};

} /* namespace trace */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_EVENT_CLASS_H */
