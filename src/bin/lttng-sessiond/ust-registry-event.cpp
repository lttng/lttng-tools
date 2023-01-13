/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-registry-event.hpp"

#include <common/make-unique.hpp>

#include <urcu/rculfhash.h>

namespace lst = lttng::sessiond::trace;
namespace lsu = lttng::sessiond::ust;

lsu::registry_event::registry_event(unsigned int in_id,
				    unsigned int in_stream_class_id,
				    int in_session_objd,
				    int in_channel_objd,
				    std::string in_name,
				    std::string in_signature,
				    std::vector<lttng::sessiond::trace::field::cuptr> in_fields,
				    int in_loglevel_value,
				    nonstd::optional<std::string> in_model_emf_uri) :
	lst::event_class(in_id,
			 in_stream_class_id,
			 in_loglevel_value,
			 std::move(in_name),
			 std::move(in_model_emf_uri),
			 lttng::make_unique<lst::structure_type>(0, std::move(in_fields))),
	session_objd{ in_session_objd },
	channel_objd{ in_channel_objd },
	signature{ std::move(in_signature) },
	_metadata_dumped{ false }
{
	cds_lfht_node_init(&_node);
	_head = {};
}

/*
 * Free event data structure. This does NOT delete it from any hash table. It's
 * safe to pass a NULL pointer. This should be called inside a call RCU if the
 * event is previously deleted from a rcu hash table.
 */
void lsu::registry_event_destroy(lsu::registry_event *event)
{
	delete event;
}
