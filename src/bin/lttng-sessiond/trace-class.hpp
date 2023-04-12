/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_TRACE_CLASS_H
#define LTTNG_TRACE_CLASS_H

#include "field.hpp"

#include <common/uuid.hpp>

namespace lttng {
namespace sessiond {
namespace trace {

class clock_class;
class stream_class;
class event_class;
class trace_class_visitor;
class trace_class_environment_visitor;

struct abi {
	unsigned int bits_per_long;
	unsigned int long_alignment;
	unsigned int uint8_t_alignment;
	unsigned int uint16_t_alignment;
	unsigned int uint32_t_alignment;
	unsigned int uint64_t_alignment;
	enum byte_order byte_order;
};

template <class ValueType>
class environment_field {
public:
	environment_field(const char *in_name, const ValueType& in_value) :
		name(in_name), value(in_value)
	{
	}

	const char *const name;
	const ValueType& value;
};

class trace_class {
public:
	virtual ~trace_class() = default;
	trace_class(const trace_class&) = delete;
	trace_class(trace_class&&) = delete;
	trace_class& operator=(trace_class&&) = delete;
	trace_class& operator=(const trace_class&) = delete;

	/*
	 * Derived classes must implement the _accept_on_*()
	 * to continue the traversal to the trace class' children.
	 */
	virtual void accept(trace_class_visitor& trace_class_visitor) const;
	virtual void accept(trace_class_environment_visitor& environment_visitor) const = 0;
	virtual const lttng::sessiond::trace::type *packet_header() const noexcept = 0;

	const struct abi abi;
	const lttng_uuid uuid;

protected:
	trace_class(const struct abi& abi, const lttng_uuid& trace_uuid);
	virtual void _accept_on_clock_classes(trace_class_visitor& trace_class_visitor) const = 0;
	virtual void _accept_on_stream_classes(trace_class_visitor& trace_class_visitor) const = 0;
};

class trace_class_environment_visitor {
public:
	trace_class_environment_visitor() = default;
	virtual ~trace_class_environment_visitor() = default;
	trace_class_environment_visitor(const trace_class_environment_visitor&) = delete;
	trace_class_environment_visitor(trace_class_environment_visitor&&) = delete;
	trace_class_environment_visitor& operator=(trace_class_environment_visitor&&) = delete;
	trace_class_environment_visitor& operator=(const trace_class_environment_visitor&) = delete;

	virtual void visit(const environment_field<int64_t>& field) = 0;
	virtual void visit(const environment_field<const char *>& field) = 0;
	virtual void visit(const environment_field<std::string>& field);
};

class trace_class_visitor {
public:
	using cuptr = std::unique_ptr<trace_class_visitor>;

	trace_class_visitor() = default;
	virtual ~trace_class_visitor() = default;
	trace_class_visitor(const trace_class_visitor&) = delete;
	trace_class_visitor(trace_class_visitor&&) = delete;
	trace_class_visitor& operator=(trace_class_visitor&&) = delete;
	trace_class_visitor& operator=(const trace_class_visitor&) = delete;

	virtual void visit(const lttng::sessiond::trace::trace_class& trace_class) = 0;
	virtual void visit(const lttng::sessiond::trace::clock_class& clock_class) = 0;
	virtual void visit(const lttng::sessiond::trace::stream_class& stream_class) = 0;
	virtual void visit(const lttng::sessiond::trace::event_class& event_class) = 0;
};

} /* namespace trace */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_TRACE_CLASS_H */
