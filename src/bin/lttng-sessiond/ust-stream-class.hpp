/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_UST_STREAM_CLASS_H
#define LTTNG_UST_STREAM_CLASS_H

#include "stream-class.hpp"
#include "trace-class.hpp"

#include <common/hashtable/hashtable.hpp>

#include <lttng/lttng.h>

#include <functional>
#include <urcu.h>

struct ust_app;

namespace lttng {
namespace sessiond {
namespace ust {

class event_class;

using event_id = uint32_t;

class stream_class : public lttng::sessiond::trace::stream_class {
public:
	using registered_listener_fn = std::function<void(const stream_class&)>;
	using event_added_listener_fn =
		std::function<void(const stream_class&, const event_class&)>;

	stream_class(
		uint32_t channel_id,
		lttng::sessiond::config::recording_channel_configuration::buffer_allocation_policy_t
			buffer_allocation_policy,
		const lttng::sessiond::trace::abi& trace_abi,
		std::string default_clock_class_name,
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
		       event_id& out_event_id);
	~stream_class() override;
	stream_class(const stream_class&) = delete;
	stream_class(stream_class&&) = delete;
	stream_class& operator=(stream_class&&) = delete;
	stream_class& operator=(const stream_class&) = delete;

	const lttng::sessiond::trace::type *event_context() const final;
	void event_context(lttng::sessiond::trace::type::cuptr context);

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
	event_id _next_event_id;

private:
	void _accept_on_event_classes(
		lttng::sessiond::trace::trace_class_visitor& trace_class_visitor) const final;

	registered_listener_fn _is_registered_listener;
	event_added_listener_fn _event_added_listener;
	/* Indicates if this channel registry has already been registered. */
	bool _is_registered;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_UST_STREAM_CLASS_H */
