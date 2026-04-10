/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APP_COMMAND_SOCKET_HPP
#define LTTNG_SESSIOND_UST_APP_COMMAND_SOCKET_HPP

#include <mutex>

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * Wraps the socket used for session daemon to tracer application communication
 * along with the mutex that serializes access to the tracer command protocol.
 *
 * The socket is used to send commands to the UST tracer through the
 * liblttng-ust-ctl interface. Since the protocol is not multiplexed,
 * all commands must be serialized. The protocol_guard inner class
 * provides RAII-based mutex management and access to the socket fd.
 */
class app_command_socket final {
public:
	/*
	 * RAII guard that serializes access to the tracer command protocol.
	 * Holds the command socket's mutex for its lifetime, providing
	 * access to the underlying socket fd for use with lttng_ust_ctl_*
	 * functions.
	 */
	class protocol_guard final {
	public:
		protocol_guard(const protocol_guard&) = delete;
		protocol_guard& operator=(const protocol_guard&) = delete;
		protocol_guard(protocol_guard&&) noexcept;
		protocol_guard& operator=(protocol_guard&&) = delete;
		~protocol_guard() = default;

		/*
		 * Returns the socket file descriptor for use with
		 * lttng_ust_ctl_* functions.
		 */
		int fd() const noexcept;

	private:
		friend class app_command_socket;
		explicit protocol_guard(app_command_socket& socket);

		app_command_socket *_socket;
		std::unique_lock<std::mutex> _lock;
	};

	app_command_socket();
	~app_command_socket() = default;

	app_command_socket(const app_command_socket&) = delete;
	app_command_socket& operator=(const app_command_socket&) = delete;
	app_command_socket(app_command_socket&&) = delete;
	app_command_socket& operator=(app_command_socket&&) = delete;

	/*
	 * Set the file descriptor. Called once during application registration.
	 */
	void set_fd(int fd) noexcept;

	/*
	 * Returns the socket fd value without acquiring the lock.
	 * Use for logging, hash table keying, and other non-protocol uses.
	 */
	int fd() const noexcept;

	/*
	 * Extracts the file descriptor, setting the internal value to -1.
	 * Used during application teardown to transfer fd ownership to the
	 * teardown path.
	 */
	int release_fd() noexcept;

	/*
	 * Acquires the protocol mutex and returns a guard that provides
	 * access to the socket fd for use with lttng_ust_ctl_* functions.
	 */
	protocol_guard lock();

private:
	int _fd = -1;
	mutable std::mutex _lock;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_APP_COMMAND_SOCKET_HPP */
