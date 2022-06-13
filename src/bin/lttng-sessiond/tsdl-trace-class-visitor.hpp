/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_TSDL_TRACE_CLASS_VISITOR_H
#define LTTNG_TSDL_TRACE_CLASS_VISITOR_H

#include "trace-class.hpp"
#include "stream-class.hpp"
#include "event-class.hpp"

#include <vendor/optional.hpp>

#include <functional>

namespace lttng {
namespace sessiond {
namespace tsdl {

using append_metadata_fragment_function = std::function<void(const std::string& fragment)>;

class trace_class_visitor : public lttng::sessiond::trace::trace_class_visitor {
public:
	trace_class_visitor(const lttng::sessiond::trace::abi& trace_abi,
			append_metadata_fragment_function append_metadata);

	/* trace class visitor interface. */
	virtual void visit(const lttng::sessiond::trace::trace_class& trace_class) override final;

	/* clock class visitor interface. */
	virtual void visit(const lttng::sessiond::trace::clock_class& clock_class) override final;

	/* environment visitor interface. */
	virtual void environment_begin() override final;
	virtual void visit(const lttng::sessiond::trace::environment_field<int64_t>& field) override final;
	virtual void visit(const lttng::sessiond::trace::environment_field<const char *>& field) override final;
	virtual void environment_end() override final;

	/* stream class visitor interface. */
	virtual void visit(const lttng::sessiond::trace::stream_class& stream_class) override final;

	/* event class visitor interface. */
	virtual void visit(const lttng::sessiond::trace::event_class& event_class) override final;

private:
	/* Coherent (parseable) fragments must be appended. */
	void append_metadata_fragment(const std::string& fragment) const;

	const lttng::sessiond::trace::abi& _trace_abi;
	const append_metadata_fragment_function _append_metadata_fragment;
	std::string _environment;
};

} /* namespace tsdl */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_TSDL_TRACE_CLASS_VISITOR_H */
