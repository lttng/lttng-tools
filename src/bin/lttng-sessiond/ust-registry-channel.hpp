/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_REGISTRY_CHANNEL_H
#define LTTNG_UST_REGISTRY_CHANNEL_H

#include "stream-class.hpp"

#include <common/hashtable/hashtable.hpp>

#include <lttng/lttng.h>

#include <urcu.h>
#include <functional>

struct ust_app;

namespace lttng {
namespace sessiond {
namespace ust {

class registry_event;

class registry_channel : public lttng::sessiond::trace::stream_class {
public:
	using registered_listener_fn = std::function<void(const registry_channel&)>;
	using event_added_listener_fn = std::function<void(const registry_channel&, const registry_event &)>;

	registry_channel(uint32_t channel_id,
			registered_listener_fn channel_registered_listener,
			event_added_listener_fn new_event_listener);
	void add_event(int session_objd,
			int channel_objd,
			std::string name,
			std::string signature,
			std::vector<lttng::sessiond::trace::field::cuptr> event_fields,
			int loglevel_value,
			nonstd::optional<std::string> model_emf_uri,
			lttng_buffer_type buffer_type,
			const ust_app& app,
			uint32_t& out_event_id);
	virtual ~registry_channel();

	virtual const lttng::sessiond::trace::type& get_context() const override final;
	void set_context(lttng::sessiond::trace::type::cuptr context);

	/* Channel was registered to at least one application. */
	bool is_registered() const;
	void set_as_registered();

	uint64_t _key;
	uint64_t _consumer_key;

	/*
	 * Hash table containing events sent by the UST tracer. MUST be accessed
	 * with a RCU read side lock acquired.
	 */
	struct lttng_ht *_events;
	struct lttng_ht_node_u64 _node;
	/* For delayed reclaim */
	struct rcu_head _rcu_head;
	/* Once this value reaches UINT32_MAX, no more id can be allocated. */
	uint32_t _next_event_id;

private:
	virtual void _accept_on_event_classes(
			lttng::sessiond::trace::trace_class_visitor& trace_class_visitor) const override final;

	registered_listener_fn _is_registered_listener;
	event_added_listener_fn _event_added_listener;
	/* Indicates if this channel registry has already been registered. */
	bool _is_registered;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_UST_REGISTRY_CHANNEL_H */