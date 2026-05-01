/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "ust-app-command-socket.hpp"

namespace lsu = lttng::sessiond::ust;

lsu::app_command_socket::app_command_socket() = default;

void lsu::app_command_socket::set_fd(int fd, pid_t pid) noexcept
{
	_fd.emplace(fd);
	_pid = pid;
}

int lsu::app_command_socket::fd() const noexcept
{
	return _fd ? _fd->fd() : -1;
}

lsu::app_command_socket::protocol_guard lsu::app_command_socket::lock()
{
	return protocol_guard(*this);
}

lsu::app_command_socket::protocol_guard::protocol_guard(app_command_socket& socket) :
	_socket(&socket), _lock(socket._lock)
{
}

lsu::app_command_socket::protocol_guard::protocol_guard(protocol_guard&& other) noexcept :
	_socket(other._socket), _lock(std::move(other._lock))
{
}

int lsu::app_command_socket::protocol_guard::fd() const noexcept
{
	return _socket->fd();
}
