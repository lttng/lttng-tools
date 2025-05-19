/*
 * SPDX-License-Identifier: LGPL-2.0-only
 *
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 */

#include <common/error.hpp>
#include <common/poller.hpp>

namespace {

std::uint32_t to_epoll_events(lttng::poller::event_type events)
{
	std::uint32_t epoll_events = 0;

	if ((events & lttng::poller::event_type::READABLE) == lttng::poller::event_type::READABLE) {
		epoll_events |= EPOLLIN;
	}

	if ((events & lttng::poller::event_type::WRITABLE) == lttng::poller::event_type::WRITABLE) {
		epoll_events |= EPOLLOUT;
	}

	if ((events & lttng::poller::event_type::ERROR) == lttng::poller::event_type::ERROR) {
		epoll_events |= EPOLLERR;
	}

	if ((events & lttng::poller::event_type::CLOSED) == lttng::poller::event_type::CLOSED) {
		epoll_events |= EPOLLHUP;
	}

	return epoll_events;
}

lttng::poller::event_type from_epoll_events(std::uint32_t epoll_events)
{
	lttng::poller::event_type events = lttng::poller::event_type::NONE;

	if (epoll_events & EPOLLIN) {
		events = events | lttng::poller::event_type::READABLE;
	}

	if (epoll_events & EPOLLOUT) {
		events = events | lttng::poller::event_type::WRITABLE;
	}

	if (epoll_events & EPOLLERR) {
		events = events | lttng::poller::event_type::ERROR;
	}

	if (epoll_events & EPOLLHUP) {
		events = events | lttng::poller::event_type::CLOSED;
	}

	return events;
}
} /* namespace */

lttng::poller::poller() :
	_epoll_fd([]() {
		const auto epoll_fd = ::epoll_create1(::EPOLL_CLOEXEC);

		if (epoll_fd < 0) {
			LTTNG_THROW_POSIX("Failed to create epoll fd", errno);
		}

		return epoll_fd;
	}())
{
}

void lttng::poller::add(const lttng::file_descriptor& new_fd, event_type events, event_callback cb)
{
	DBG_FMT("Adding fd to poller set: fd={}, events='{}'", new_fd.fd(), events);

	epoll_event ev{};
	ev.events = to_epoll_events(events);
	ev.data.fd = new_fd.fd();

	if (::epoll_ctl(_epoll_fd.fd(), EPOLL_CTL_ADD, new_fd.fd(), &ev) == -1) {
		LTTNG_THROW_POSIX(lttng::format("Failed to add fd to epoll: epoll_fd={}, fd={}",
						_epoll_fd.fd(),
						new_fd.fd()),
				  errno);
	}

	_event_callbacks[new_fd.fd()] = std::move(cb);
	_event_set.resize(_event_callbacks.size());
}

void lttng::poller::modify(const lttng::file_descriptor& fd_to_modify, event_type events)
{
	DBG_FMT("Modifying fd events in poller set: fd={}, events='{}'", fd_to_modify.fd(), events);

	epoll_event ev{};
	ev.events = to_epoll_events(events);
	ev.data.fd = fd_to_modify.fd();

	if (::epoll_ctl(_epoll_fd.fd(), EPOLL_CTL_MOD, fd_to_modify.fd(), &ev) == -1) {
		LTTNG_THROW_POSIX(lttng::format("Failed to modify epoll fd: epoll_fd={}, fd={}",
						_epoll_fd.fd(),
						fd_to_modify.fd()),
				  errno);
	}
}

void lttng::poller::remove(const lttng::file_descriptor& fd_to_remove)
{
	DBG_FMT("Removing fd from poller set: fd={}", fd_to_remove.fd());

	if (epoll_ctl(_epoll_fd.fd(), EPOLL_CTL_DEL, fd_to_remove.fd(), nullptr)) {
		LTTNG_THROW_POSIX(
			lttng::format("Failed to delete fd from epoll fd: epoll_fd={}, fd={}",
				      _epoll_fd.fd(),
				      fd_to_remove.fd()),
			errno);
	}

	_event_callbacks.erase(fd_to_remove.fd());
	_event_set.resize(_event_callbacks.size());
}

void lttng::poller::poll(timeout_type timeout) const
{
	switch (timeout) {
	case timeout_type::NO_WAIT:
		_epoll(0);
		break;
	case timeout_type::WAIT_FOREVER:
		_epoll(-1);
		break;
	default:
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(lttng::format(
			"Invalid poller timeout type: {}",
			static_cast<std::underlying_type<timeout_type>::type>(timeout)));
	}
}

void lttng::poller::poll(timeout_ms timeout) const
{
	if (timeout.count() <= 0) {
		LTTNG_THROW_INVALID_ARGUMENT_ERROR(
			lttng::format("Invalid poller timeout value: {}", timeout.count()));
	}

	_epoll(static_cast<int>(timeout.count()));
}

void lttng::poller::_epoll(int timeout) const
{
	if (_event_set.empty()) {
		if (timeout != 0) {
			WARN_FMT("Poller has no file descriptors to poll, "
				 "ignoring timeout: timeout_ms={}",
				 timeout);
		}

		return;
	}

	while (true) {
		const auto wait_ret =
			::epoll_wait(_epoll_fd.fd(), _event_set.data(), _event_set.size(), timeout);
		if (wait_ret == -1) {
			if (errno == EINTR) {
				continue;
			}

			LTTNG_THROW_POSIX("Failed to collect new poll events using epoll_wait",
					  errno);
		}

		unsigned int event_count = wait_ret;
		for (const auto& event : _event_set) {
			if (event_count == 0) {
				break;
			}

			DBG_FMT("Poller handling file descriptor event: fd={}, events='{}'",
				event.data.fd,
				from_epoll_events(event.events));

			if (event.events == 0) {
				continue;
			}

			const auto callback_it = _event_callbacks.find(event.data.fd);
			if (callback_it == _event_callbacks.end()) {
				LTTNG_THROW_OUT_OF_RANGE(
					lttng::format(""
						      "No callback registered for fd: fd={}",
						      event.data.fd));
			}

			callback_it->second(from_epoll_events(event.events));
			event_count--;
		}

		break;
	}
}