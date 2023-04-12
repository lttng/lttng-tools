/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_REGISTRY_EVENT_H
#define LTTNG_UST_REGISTRY_EVENT_H

#include "event-class.hpp"
#include "field.hpp"

#include <common/format.hpp>
#include <common/hashtable/hashtable.hpp>

#include <vendor/optional.hpp>

#include <typeinfo>

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * Event registered from a UST tracer sent to the session daemon. This is
 * indexed and matched by <event_name/signature>.
 */
class registry_event : public lttng::sessiond::trace::event_class {
public:
	registry_event(unsigned int id,
		       unsigned int stream_class_id,
		       int session_objd,
		       int channel_objd,
		       std::string name,
		       std::string signature,
		       std::vector<lttng::sessiond::trace::field::cuptr> fields,
		       int loglevel_value,
		       nonstd::optional<std::string> model_emf_uri);
	~registry_event() override = default;
	registry_event(const registry_event&) = delete;
	registry_event(registry_event&&) = delete;
	registry_event& operator=(registry_event&&) = delete;
	registry_event& operator=(const registry_event&) = delete;

	/* Both objd are set by the tracer. */
	const int session_objd;
	const int channel_objd;
	const std::string signature;

	/*
	 * Flag for this channel if the metadata was dumped once during
	 * registration.
	 */
	bool _metadata_dumped;

	/*
	 * Node in the ust-registry hash table. The event name is used to
	 * initialize the node and the event_name/signature for the match function.
	 */
	struct cds_lfht_node _node;
	struct rcu_head _head;
};

void registry_event_destroy(registry_event *event);

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::sessiond::ust::registry_event> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator
	format(const lttng::sessiond::ust::registry_event& event, FormatContextType& ctx)
	{
		return format_to(
			ctx.out(),
			"{{ name = `{}`, signature = `{}`, id = {}, session objd = {}, channel objd = {} }}",
			event.name,
			event.signature,
			event.id,
			event.session_objd,
			event.channel_objd);
	}
};
} /* namespace fmt */

#endif /* LTTNG_UST_REGISTRY_EVENT_H */
