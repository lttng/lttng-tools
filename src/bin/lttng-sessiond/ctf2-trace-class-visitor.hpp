/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CTF2_TRACE_CLASS_VISITOR_H
#define LTTNG_CTF2_TRACE_CLASS_VISITOR_H

#include "event-class.hpp"
#include "stream-class.hpp"
#include "trace-class.hpp"

#include <vendor/nlohmann/json.hpp>
#include <vendor/optional.hpp>

#include <functional>

namespace lttng {
namespace sessiond {
namespace ctf2 {

using append_metadata_fragment_function = std::function<void(const std::string& fragment)>;

class trace_class_visitor final : public lttng::sessiond::trace::trace_class_visitor {
public:
	explicit trace_class_visitor(append_metadata_fragment_function append_metadata);

	void visit(const lttng::sessiond::trace::trace_class& trace_class) override;
	void visit(const lttng::sessiond::trace::clock_class& clock_class) override;
	void visit(const lttng::sessiond::trace::stream_class& stream_class) override;
	void visit(const lttng::sessiond::trace::event_class& event_class) override;

private:
	void _append_metadata_fragment(const char *const type, nlohmann::json&& extra_json) const;

	const append_metadata_fragment_function _append_metadata_fragment_func;
};

} /* namespace ctf2 */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_CTF2_TRACE_CLASS_VISITOR_H */
