/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CONSUMERD_CHANNEL_HPP
#define LTTNG_CONSUMERD_CHANNEL_HPP

#include <common/scope-exit.hpp>
#include <common/urcu.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <iterator>

struct lttng_consumer_channel;
struct lttng_consumer_stream;

namespace lttng {
namespace consumer {
class stream_set {
	friend lttng_consumer_channel;

public:
	enum class filter : std::uint8_t {
		PUBLISHED,
		UNPUBLISHED,
	};

	class iterator;

	iterator begin() const noexcept;
	iterator end() const noexcept;

	class iterator : public std::iterator<std::forward_iterator_tag, lttng_consumer_stream> {
		friend stream_set;

	public:
		iterator(const iterator& other) = delete;
		iterator(iterator&& /* other */) = default;
		~iterator() = default;
		iterator& operator=(const iterator&) = delete;
		iterator& operator=(iterator&&) noexcept = delete;

		iterator& operator++();
		bool operator==(const iterator& other) const noexcept;
		bool operator!=(const iterator& other) const noexcept;
		lttng_consumer_stream& operator*() const;

	private:
		explicit iterator(const lttng_consumer_channel& channel,
				  bool is_end = false,
				  const nonstd::optional<lttng::consumer::stream_set::filter>&
					  filter = nonstd::nullopt);

		const lttng_consumer_channel& _channel;

		/*
		 * The phase of the iterator determines whether we are iterating
		 * on published or unpublished streams.
		 */
		enum class _phase_t : std::uint8_t {
			ITERATING_ON_PUBLISHED_STREAMS,
			ITERATING_ON_UNPUBLISHED_STREAMS,
		} _phase = _phase_t::ITERATING_ON_PUBLISHED_STREAMS;

		union {
			struct {
				lttng_ht_iter stream_iterator;
			} published;
			struct {
				const cds_list_head *current_stream_node;
				/*
				 * Used to maintain iterator validity when the current position is
				 * deleted during iteration.
				 */
				const cds_list_head *next_stream_node;
			} unpublished;
		} _position;

		bool _at_end;
		nonstd::optional<filter> _filter;
	};

private:
	explicit stream_set(const lttng_consumer_channel& channel,
			    const nonstd::optional<filter>& filter = nonstd::nullopt);

	const lttng_consumer_channel& _channel;
	lttng::urcu::scoped_rcu_read_lock _rcu_lock;
	nonstd::optional<filter> _filter;
};
} /* namespace consumer */
} /* namespace lttng */

#endif /* LTTNG_CONSUMERD_CHANNEL_HPP */
