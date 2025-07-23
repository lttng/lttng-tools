/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "common/hashtable/hashtable.hpp"

#include <common/consumer/consumer-channel.hpp>
#include <common/consumer/consumer.hpp>
#include <common/exception.hpp>
#include <common/macros.hpp>

lttng::consumer::stream_set::stream_set(
	const lttng_consumer_channel& channel,
	const nonstd::optional<lttng::consumer::stream_set::filter>& filter_) :
	_channel(channel), _filter(filter_)
{
}

lttng::consumer::stream_set::iterator lttng::consumer::stream_set::begin() const noexcept
{
	return lttng::consumer::stream_set::iterator(_channel, false, _filter);
}

lttng::consumer::stream_set::iterator lttng::consumer::stream_set::end() const noexcept
{
	return lttng::consumer::stream_set::iterator(_channel, true);
}

lttng::consumer::stream_set::iterator::iterator(
	const lttng_consumer_channel& channel,
	bool at_end,
	const nonstd::optional<lttng::consumer::stream_set::filter>& filter_) :
	_channel(channel), _at_end(at_end), _filter(filter_)
{
	if (_at_end) {
		return;
	}

	if (!_filter || *_filter == lttng::consumer::stream_set::filter::PUBLISHED) {
		lttng_ht_lookup(the_consumer_data.stream_per_chan_id_ht,
				&channel.key,
				&_position.published.stream_iterator);
		const auto node = lttng_ht_iter_get_node<lttng_ht_node_u64>(
			&_position.published.stream_iterator);
		if (node) {
			/* Pointing to first published stream. */
			return;
		} else if (_filter) {
			/* Only published streams requested and there are none. */
			_at_end = true;
			return;
		}
	}

	/* No published streams, switch to unpublished streams. */
	if (!_filter || *_filter == lttng::consumer::stream_set::filter::UNPUBLISHED) {
		_phase = lttng::consumer::stream_set::iterator::_phase_t::
			ITERATING_ON_UNPUBLISHED_STREAMS;
		if (cds_list_empty(&_channel.streams.head)) {
			_position.unpublished.next_stream_node = nullptr;
			_at_end = true;
			return;
		}

		/* Point to the first unpublished stream. */
		_position.unpublished.current_stream_node = _channel.streams.head.next;
		_position.unpublished.next_stream_node =
			_position.unpublished.current_stream_node->next;
	}
}

lttng::consumer::stream_set::iterator& lttng::consumer::stream_set::iterator::operator++()
{
	switch (_phase) {
	case lttng::consumer::stream_set::iterator::_phase_t::ITERATING_ON_PUBLISHED_STREAMS:
	{
		cds_lfht_next_duplicate(the_consumer_data.stream_per_chan_id_ht->ht,
					the_consumer_data.stream_per_chan_id_ht->match_fct,
					&_channel.key,
					&_position.published.stream_iterator.iter);

		const auto node = lttng_ht_iter_get_node<lttng_ht_node_u64>(
			&_position.published.stream_iterator);
		if (!node) {
			/* No more published streams, switch to unpublished streams. */
			_phase = lttng::consumer::stream_set::iterator::_phase_t::
				ITERATING_ON_UNPUBLISHED_STREAMS;
			if (cds_list_empty(&_channel.streams.head) ||
			    (_filter &&
			     _filter == lttng::consumer::stream_set::filter::PUBLISHED)) {
				_at_end = true;
			} else {
				_position.unpublished.current_stream_node =
					_channel.streams.head.next;
			}
		}

		break;
	}
	case lttng::consumer::stream_set::iterator::_phase_t::ITERATING_ON_UNPUBLISHED_STREAMS:
	{
		if (_position.unpublished.next_stream_node == &_channel.streams.head) {
			/* Reached the end of the unpublished streams. */
			_at_end = true;
			break;
		}

		_position.unpublished.current_stream_node = _position.unpublished.next_stream_node;
		_position.unpublished.next_stream_node =
			_position.unpublished.current_stream_node->next;
		break;
	}
	default:
		std::abort();
	}

	return *this;
}

bool lttng::consumer::stream_set::iterator::operator==(const iterator& other) const noexcept
{
	if (_at_end != other._at_end) {
		return false;
	}

	/* If both iterators are at the end, they are equal regardless of other state. */
	if (_at_end && other._at_end) {
		return true;
	}

	if (_phase != other._phase) {
		return false;
	}

	switch (_phase) {
	case lttng::consumer::stream_set::iterator::_phase_t::ITERATING_ON_PUBLISHED_STREAMS:
		return lttng_ht_iter_get_node<lttng_ht_node_u64>(
			       &_position.published.stream_iterator) ==
			lttng_ht_iter_get_node<lttng_ht_node_u64>(
				&other._position.published.stream_iterator);
	case lttng::consumer::stream_set::iterator::_phase_t::ITERATING_ON_UNPUBLISHED_STREAMS:
		return _position.unpublished.current_stream_node ==
			other._position.unpublished.current_stream_node;
	}

	std::abort();
}

bool lttng::consumer::stream_set::iterator::operator!=(const iterator& other) const noexcept
{
	return !(*this == other);
}

lttng_consumer_stream& lttng::consumer::stream_set::iterator::operator*() const
{
	if (_at_end) {
		LTTNG_THROW_OUT_OF_RANGE(
			"Attempt to use operator* on stream_set iterator at the end position");
	}

	switch (_phase) {
	case lttng::consumer::stream_set::iterator::_phase_t::ITERATING_ON_PUBLISHED_STREAMS:
	{
		const auto node_wrapper = lttng_ht_iter_get_node<lttng_ht_node_u64>(
			&_position.published.stream_iterator);
		return *lttng::utils::container_of(node_wrapper,
						   &lttng_consumer_stream::node_channel_id);
	}
	case lttng::consumer::stream_set::iterator::_phase_t::ITERATING_ON_UNPUBLISHED_STREAMS:
	{
		return *lttng::utils::container_of(_position.unpublished.current_stream_node,
						   &lttng_consumer_stream::send_node);
	}
	}

	std::abort();
}

lttng::consumer::stream_set lttng_consumer_channel::get_streams(
	const nonstd::optional<lttng::consumer::stream_set::filter>& filter)
{
	ASSERT_LOCKED(the_consumer_data.lock);
	ASSERT_LOCKED(lock);
	return lttng::consumer::stream_set(*this, filter);
}
