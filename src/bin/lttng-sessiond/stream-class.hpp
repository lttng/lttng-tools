/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_STREAM_CLASS_H
#define LTTNG_STREAM_CLASS_H

#include "field.hpp"

#include <vendor/optional.hpp>

#include <vector>

namespace lttng {
namespace sessiond {
namespace trace {

class trace_class_visitor;

class stream_class {
public:
	enum class header_type { COMPACT, LARGE };

	/*
	 * Derived classes must implement _accept_on_event_classes()
	 * to continue the traversal to the stream class' event classes.
	 */
	void accept(trace_class_visitor& visitor) const;
	virtual ~stream_class() = default;
	stream_class(const stream_class&) = delete;
	stream_class(stream_class&&) = delete;
	stream_class& operator=(stream_class&&) = delete;
	stream_class& operator=(const stream_class&) = delete;

	virtual const type *packet_context() const;
	virtual const type *event_header() const;
	virtual const type *event_context() const;

	const unsigned int id;
	/*
	 * header_type is suffixed with '_' to work-around a bug in older
	 * GCCs (before 6) that do not recognize hidden/shadowed enumeration as valid
	 * nested-name-specifiers.
	 */
	const header_type header_type_;
	const nonstd::optional<std::string> default_clock_class_name;

protected:
	stream_class(unsigned int id,
		     enum header_type header_type,
		     nonstd::optional<std::string> default_clock_class_name = nonstd::nullopt);
	virtual void _accept_on_event_classes(trace_class_visitor& trace_class_visitor) const = 0;

	lttng::sessiond::trace::type::cuptr _packet_context;
	lttng::sessiond::trace::type::cuptr _event_header;
	lttng::sessiond::trace::type::cuptr _event_context;
};

} /* namespace trace */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_STREAM_CLASS_H */
