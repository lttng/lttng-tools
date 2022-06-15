/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_STREAM_CLASS_H
#define LTTNG_STREAM_CLASS_H

#include "field.hpp"

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

	virtual const lttng::sessiond::trace::type& get_context() const;

	const unsigned int id;
	/*
	 * header_type is suffixed with '_' to work-around a bug in older
	 * GCCs (before 6) that do not recognize hidden/shadowed enumeration as valid
	 * nested-name-specifiers.
	 */
	const header_type header_type_;

protected:
	stream_class(unsigned int id, enum header_type header_type);
	virtual void _accept_on_event_classes(trace_class_visitor& trace_class_visitor) const = 0;

	lttng::sessiond::trace::type::cuptr _context;
};

} /* namespace trace */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_STREAM_CLASS_H */
