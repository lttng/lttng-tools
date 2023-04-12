/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_TSDL_TRACE_CLASS_VISITOR_H
#define LTTNG_TSDL_TRACE_CLASS_VISITOR_H

#include "event-class.hpp"
#include "stream-class.hpp"
#include "trace-class.hpp"

#include <vendor/optional.hpp>

#include <functional>
#include <unordered_map>

namespace lttng {
namespace sessiond {
namespace tsdl {

using append_metadata_fragment_function = std::function<void(const std::string& fragment)>;

namespace details {
/*
 * Register types to be overriden. For example, a TSDL-safe copy of a type can
 * be added to be overriden whenever the original type is encountered.
 *
 * Note that this class assumes no ownership of the original types. It assumes
 * that the original types live as long as the original trace.
 */
class type_overrider {
public:
	type_overrider() = default;

	void publish(const lttng::sessiond::trace::type& original,
		     lttng::sessiond::trace::type::cuptr new_type_override);
	const lttng::sessiond::trace::type&
	type(const lttng::sessiond::trace::type& original) const noexcept;

private:
	std::unordered_map<const lttng::sessiond::trace::type *, lttng::sessiond::trace::type::cuptr>
		_overriden_types;
};
} /* namespace details. */

/*
 * TSDL-producing trace class visitor.
 *
 * An instance of this class must not be used on multiple trace class instances.
 * The `append_metadata` callback is automatically invoked when a coherent
 * fragment of TSDL is available.
 */
class trace_class_visitor : public lttng::sessiond::trace::trace_class_visitor {
public:
	trace_class_visitor(const lttng::sessiond::trace::abi& trace_abi,
			    append_metadata_fragment_function append_metadata);

	virtual void visit(const lttng::sessiond::trace::trace_class& trace_class) override final;
	virtual void visit(const lttng::sessiond::trace::clock_class& clock_class) override final;
	virtual void visit(const lttng::sessiond::trace::stream_class& stream_class) override final;
	virtual void visit(const lttng::sessiond::trace::event_class& event_class) override final;

private:
	/* Coherent (parseable) fragments must be appended. */
	void append_metadata_fragment(const std::string& fragment) const;
	const lttng::sessiond::trace::type&
	_lookup_field_type(const lttng::sessiond::trace::field_location& field_location) const;

	const lttng::sessiond::trace::abi& _trace_abi;
	const append_metadata_fragment_function _append_metadata_fragment;
	details::type_overrider _sanitized_types_overrides;

	/*
	 * Current visit context.
	 *
	 * The members of a trace class hierarchy do not provide back-references
	 * up the hierarchy (e.g. stream class to its parent trace class).
	 *
	 * This context allows the visitor to evaluate a "field location".
	 *
	 * _current_trace_class is set the first time a trace class is visited and
	 * remains valid until the destruction of this object.
	 *
	 * _current_stream_class and _current_event_class are set only in the
	 * context of the visit of a stream class and of its event class(es).
	 */
	const lttng::sessiond::trace::trace_class *_current_trace_class = nullptr;
	const lttng::sessiond::trace::stream_class *_current_stream_class = nullptr;
	const lttng::sessiond::trace::event_class *_current_event_class = nullptr;
};

} /* namespace tsdl */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_TSDL_TRACE_CLASS_VISITOR_H */
