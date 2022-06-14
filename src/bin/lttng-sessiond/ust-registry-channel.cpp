/*
 * Copyright (C) 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-registry-channel.hpp"
#include "ust-app.hpp"
#include "ust-registry-event.hpp"

#include <common/error.hpp>
#include <common/exception.hpp>
#include <common/hashtable/utils.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/urcu.hpp>

namespace lst = lttng::sessiond::trace;
namespace lsu = lttng::sessiond::ust;

namespace {
bool is_max_event_id(uint32_t id)
{
	return id == UINT32_MAX;
}

unsigned long ht_hash_event(const void *_key, unsigned long seed)
{
	uint64_t hashed_key;
	const lttng::sessiond::ust::registry_event *key =
			(lttng::sessiond::ust::registry_event *) _key;

	LTTNG_ASSERT(key);

	hashed_key = (uint64_t) hash_key_str(key->name.c_str(), seed);

	return hash_key_u64(&hashed_key, seed);
}

/*
 * Hash table match function for event in the registry.
 */
int ht_match_event(struct cds_lfht_node *node, const void *_key)
{
	const lttng::sessiond::ust::registry_event *key;
	lttng::sessiond::ust::registry_event *event;

	LTTNG_ASSERT(node);
	LTTNG_ASSERT(_key);

	event = lttng::utils::container_of(node, &lttng::sessiond::ust::registry_event::_node);
	key = (lttng::sessiond::ust::registry_event *) _key;

	/* It has to be a perfect match. First, compare the event names. */
	if (event->name != key->name) {
		goto no_match;
	}

	/* Compare log levels. */
	if (event->log_level != key->log_level) {
		goto no_match;
	}

	/* Compare the arrays of fields. */
	if (*event->payload != *key->payload) {
		goto no_match;
	}

	/* Compare model URI. */
	if (event->model_emf_uri != key->model_emf_uri) {
		goto no_match;
	}

	/* Match */
	return 1;

no_match:
	return 0;
}
}; /* namespace */

lsu::registry_channel::registry_channel(unsigned int channel_id,
		lsu::registry_channel::registered_listener_fn channel_registered_listener,
		lsu::registry_channel::event_added_listener_fn event_added_listener) :
	lst::stream_class(channel_id, lst::stream_class::header_type::LARGE),
	_key{-1ULL},
	_consumer_key{-1ULL},
	_metadata_dumped{false},
	_next_event_id{0},
	_is_registered_listener{channel_registered_listener},
	_event_added_listener{event_added_listener},
	_is_registered{false}
{
	_events = lttng_ht_new(0, LTTNG_HT_TYPE_STRING);
	if (!_events) {
		LTTNG_THROW_POSIX("Failed to allocate urcu events hash table", ENOMEM);
	}

	/* Set custom match function. */
	_events->match_fct = ht_match_event;
	_events->hash_fct = ht_hash_event;
}

void lsu::registry_channel::add_event(
		int session_objd,
		int channel_objd,
		std::string name,
		std::string signature,
		std::vector<lst::field::cuptr> event_fields,
		int loglevel_value,
		nonstd::optional<std::string> model_emf_uri,
		lttng_buffer_type buffer_type,
		const ust_app& app,
		uint32_t& out_event_id)
{
	uint32_t event_id;
	struct cds_lfht_node *nptr;
	lttng::urcu::read_lock_guard read_lock_guard;

	/*
	 * This should not happen but since it comes from the UST tracer, an
	 * external party, don't assert and simply validate values.
	 */
	if (session_objd < 0) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
				"Invalid session object descriptor provided by application: session descriptor = {}, app = {}",
				session_objd, app));
	}

	if (channel_objd < 0) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
				"Invalid channel object descriptor provided by application: channel descriptor = {}, app = {}",
				channel_objd, app));
	}

	/* Check if we've reached the maximum possible id. */
	if (is_max_event_id(_next_event_id)) {
		LTTNG_THROW_ERROR(fmt::format(
				"Failed to allocate new event id (id would overflow): app = {}",
				app));
	}

	auto event = lttng::make_unique_wrapper<lsu::registry_event, registry_event_destroy>(
			new lsu::registry_event(_next_event_id, id, session_objd, channel_objd,
					std::move(name), std::move(signature),
					std::move(event_fields), loglevel_value,
					std::move(model_emf_uri)));

	DBG3("%s", fmt::format("UST registry creating event: event = {}", *event).c_str());

	/*
	 * This is an add unique with a custom match function for event. The node
	 * are matched using the event name and signature.
	 */
	nptr = cds_lfht_add_unique(_events->ht, _events->hash_fct(event.get(), lttng_ht_seed),
			_events->match_fct, event.get(), &event->_node);
	if (nptr != &event->_node) {
		if (buffer_type == LTTNG_BUFFER_PER_UID) {
			/*
			 * This is normal, we just have to send the event id of the
			 * returned node.
			 */
			const auto existing_event = lttng::utils::container_of(
					nptr, &lttng::sessiond::ust::registry_event::_node);
			event_id = existing_event->id;
		} else {
			LTTNG_THROW_INVALID_ARGUMENT_ERROR(fmt::format(
					"UST registry create event add unique failed for event: event = {}",
					*event));
		}
	} else {
		const auto& event_ref = *event;

		/* Ownership transferred to _events hash table. */
		event.release();

		/* Request next event id if the node was successfully added. */
		event_id = event_ref.id;

		/*
		 * Only increment the next id here since we don't want to waste an ID when the event
		 * matches an existing one.
		 */
		_next_event_id++;
		_event_added_listener(*this, event_ref);
	}

	out_event_id = event_id;
}

lsu::registry_channel::~registry_channel()
{
	lttng_ht_destroy(_events);
}

const lttng::sessiond::trace::type& lsu::registry_channel::get_context() const
{
	LTTNG_ASSERT(_is_registered);
	return lst::stream_class::get_context();
}

void lsu::registry_channel::set_context(lttng::sessiond::trace::type::cuptr context)
{
	/* Must only be set once, on the first channel registration provided by an application. */
	LTTNG_ASSERT(!_context);
	_context = std::move(context);
}

bool lsu::registry_channel::is_registered() const
{
	return _is_registered;
}

void lsu::registry_channel::set_as_registered()
{
	if (!_is_registered) {
		_is_registered = true;
		_is_registered_listener(*this);
	}
}

void lsu::registry_channel::_accept_on_event_classes(
		lttng::sessiond::trace::trace_class_visitor& visitor) const
{
	std::vector<const lttng::sessiond::ust::registry_event *> sorted_event_classes;

	{
		lttng::urcu::read_lock_guard read_lock_guard;
		struct lttng_ht_iter iter;
		const lttng::sessiond::ust::registry_event *event;

		DIAGNOSTIC_PUSH
		DIAGNOSTIC_IGNORE_INVALID_OFFSETOF
		cds_lfht_for_each_entry(_events->ht, &iter.iter, event, _node) {
			sorted_event_classes.emplace_back(event);
		}
		DIAGNOSTIC_POP
	}

	std::sort(sorted_event_classes.begin(), sorted_event_classes.end(),
			[](const lttng::sessiond::ust::registry_event *a,
					const lttng::sessiond::ust::registry_event *b) {
				return a->id < b->id;
			});

	for (const auto event : sorted_event_classes) {
		event->accept(visitor);
	}
}
