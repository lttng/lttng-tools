/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_TRACE_CLASS_H
#define LTTNG_TRACE_CLASS_H

#include <common/uuid.hpp>

namespace lttng {
namespace sessiond {
namespace trace {

class clock_class;
class stream_class;
class event_class;
class trace_class_visitor;

enum class byte_order {
	BIG_ENDIAN_,
	LITTLE_ENDIAN_,
};

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

	const char * const name;
	const ValueType& value;
};

class trace_class {
public:
	/*
	 * Derived classes must implement the _accept_on_*()
	 * to continue the traversal to the trace class' children.
	 */
	virtual void accept(trace_class_visitor& trace_class_visitor) const;

	virtual ~trace_class() = default;

	const struct abi abi;
	const lttng_uuid uuid;

protected:
	trace_class(const struct abi& abi, const lttng_uuid& trace_uuid);
	virtual void _accept_on_clock_classes(trace_class_visitor& trace_class_visitor) const = 0;
	virtual void _visit_environment(trace_class_visitor& trace_class_visitor) const = 0;
	virtual void _accept_on_stream_classes(trace_class_visitor& trace_class_visitor) const = 0;
};

class trace_class_visitor {
public:
	using cuptr = std::unique_ptr<trace_class_visitor>;

	virtual ~trace_class_visitor() = default;

	/* trace class visitor interface. */
	virtual void visit(const lttng::sessiond::trace::trace_class& trace_class) = 0;

	/* clock class visitor interface. */
	virtual void visit(const lttng::sessiond::trace::clock_class& clock_class) = 0;

	/* environment visitor interface. */
	virtual void environment_begin() = 0;
	virtual void visit(const environment_field<int64_t>& field) = 0;
	virtual void visit(const environment_field<const char *>& field) = 0;
	void visit(const environment_field<std::string>& field);
	virtual void environment_end() = 0;

	/* stream class visitor interface. */
	virtual void visit(const lttng::sessiond::trace::stream_class& stream_class) = 0;

	/* event class visitor interface. */
	virtual void visit(const lttng::sessiond::trace::event_class& event_class) = 0;
};

} /* namespace trace */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_TRACE_CLASS_H */
