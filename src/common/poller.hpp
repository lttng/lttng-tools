/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_POLLER_H
#define LTTNG_POLLER_H

#include <common/exception.hpp>
#include <common/file-descriptor.hpp>
#include <common/format.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/epoll.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace lttng {
class poller {
public:
	enum class event_type : std::uint8_t {
		NONE = 0,
		READABLE = 1 << 0,
		WRITABLE = 1 << 1,
		ERROR = 1 << 2,
		CLOSED = 1 << 3,
	};

	enum class timeout_type {
		NO_WAIT,
		WAIT_FOREVER,
	};

	using timeout_ms = std::chrono::milliseconds;

	using event_callback = std::function<void(event_type)>;

	poller();
	~poller() = default;

	poller(const poller&) = delete;
	poller& operator=(const poller&) = delete;
	poller(poller&&) = delete;
	poller& operator=(poller&&) = delete;

	void add(const lttng::file_descriptor& fd, event_type events, event_callback cb);
	void modify(const lttng::file_descriptor& fd, event_type events);
	void remove(const lttng::file_descriptor& fd);

	void poll(timeout_type timeout) const;
	void poll(timeout_ms timeout) const;

private:
	void _epoll(int timeout_ms) const;

	lttng::file_descriptor _epoll_fd;
	std::unordered_map<int, event_callback> _event_callbacks;
	mutable std::vector<::epoll_event> _event_set;
};

inline poller::event_type operator|(poller::event_type a, poller::event_type b)
{
	return static_cast<poller::event_type>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b));
}

inline poller::event_type& operator|=(poller::event_type& a, poller::event_type b)
{
	a = a | b;
	return a;
}

inline poller::event_type operator&(poller::event_type a, poller::event_type b)
{
	return static_cast<poller::event_type>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b));
}
} /* namespace lttng */

/*
 * Specialize fmt::formatter for poller::event_type.
 *
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<lttng::poller::event_type> : formatter<std::string> {
	/* Format function to convert enum to string. */
	template <typename FormatContextType>
	typename FormatContextType::iterator format(lttng::poller::event_type event_set,
						    FormatContextType& ctx) const
	{
		std::string expression;
		using event_type = lttng::poller::event_type;
		if (event_set == event_type::NONE) {
			expression = "NONE";
		} else {
			bool first = true;

			if ((event_set & event_type::READABLE) == event_type::READABLE) {
				expression += "READABLE";
				first = false;
			}

			if ((event_set & event_type::WRITABLE) == event_type::WRITABLE) {
				if (!first) {
					expression += " | ";
				}

				expression += "WRITABLE";
				first = false;
			}

			if ((event_set & event_type::ERROR) == event_type::ERROR) {
				if (!first) {
					expression += " | ";
				}

				expression += "ERROR";
				first = false;
			}

			if ((event_set & event_type::CLOSED) == event_type::CLOSED) {
				if (!first) {
					expression += " | ";
				}

				expression += "CLOSED";
			}
		}
		/* Write the string representation to the format context output iterator. */
		return format_to(ctx.out(), expression);
	}
};
} /* namespace fmt */

#endif /* LTTNG_POLLER_H */