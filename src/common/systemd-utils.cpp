/*
 * SPDX-FileCopyrightText: 2005-2007 Florian octo Forster
 * SPDX-FileCopyrightText: 2025 Michael Jeanson <mjeanson@efficios.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include "systemd-utils.hpp"

#ifdef __linux__

#include <common/compat/getenv.hpp>
#include <common/file-descriptor.hpp>
#include <common/string-utils/c-string-view.hpp>

#include <sys/socket.h>
#include <sys/un.h>

namespace lttng {
namespace systemd {

namespace {

/* Return a valid NOTIFY_SOCKET path or an empty c_string_view. */
lttng::c_string_view get_notify_socket_path()
{
	const lttng::c_string_view notify_socket_path = lttng_secure_getenv("NOTIFY_SOCKET");
	if (!notify_socket_path) {
		DBG_FMT("NOTIFY_SOCKET environment variable not set; no systemd notification will be sent");
		return {};
	}

	if ((notify_socket_path.len() < 2) ||
	    ((notify_socket_path[0] != '@') && (notify_socket_path[0] != '/'))) {
		ERR_FMT("Invalid notification socket NOTIFY_SOCKET=`{}`: path must be absolute",
			notify_socket_path);
		return {};
	}

	DBG_FMT("Using systemd notification socket: path=`{}`", notify_socket_path);
	return notify_socket_path;
}

/* Send a notification message to systemd over the NOTIFY_SOCKET. */
void notify(lttng::c_string_view notify_socket_path, lttng::c_string_view message)
{
	if (!notify_socket_path || !message) {
		return;
	}

	DBG_FMT("Sending systemd notification: socket_path=`{}`, message=`{}`",
		notify_socket_path,
		message);

	const int raw_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (raw_fd < 0) {
		PERROR("Failed to create UNIX socket for systemd notification");
		return;
	}

	const lttng::file_descriptor fd(raw_fd);

	struct sockaddr_un su = {};
	su.sun_family = AF_UNIX;

	/* Check for truncation before copying. */
	if (notify_socket_path.len() >= sizeof(su.sun_path)) {
		ERR_FMT("Systemd notification socket path is too long and would be truncated: path=`{}`, max_length={}",
			notify_socket_path,
			sizeof(su.sun_path) - 1);
		return;
	}

	size_t su_size;
	if (notify_socket_path[0] != '@') {
		/* Regular UNIX socket. */
		strncpy(su.sun_path, notify_socket_path.data(), sizeof(su.sun_path));
		su_size = sizeof(su);
	} else {
		/*
		 * Linux abstract namespace socket: specify address as "\0foo", i.e.
		 * start with a null byte. Since null bytes have no special meaning in
		 * that case, we have to set su_size correctly to cover only the bytes
		 * that are part of the address.
		 */
		strncpy(su.sun_path, notify_socket_path.data(), sizeof(su.sun_path));
		su.sun_path[0] = '\0';
		su_size = sizeof(sa_family_t) + notify_socket_path.len();
	}

	const auto send_ret = sendto(fd.fd(),
				     message.data(),
				     message.len(),
				     MSG_NOSIGNAL,
				     reinterpret_cast<const sockaddr *>(&su),
				     static_cast<socklen_t>(su_size));
	if (send_ret < 0) {
		PERROR_FMT("Failed to send systemd notification: socket_path=`{}`, message={:?}",
			   notify_socket_path,
			   message.data());
	}
}

} /* namespace */

void notify_ready()
{
	/*
	 * If NOTIFY_SOCKET doesn't contain a valid socket path, we are not
	 * running under systemd, do nothing.
	 */
	const auto notify_socket_path = get_notify_socket_path();
	if (!notify_socket_path) {
		return;
	}

	DBG_FMT("Systemd detected, signaling readiness");
	notify(notify_socket_path, "READY=1\n");
}

void notify_stopping()
{
	/*
	 * If NOTIFY_SOCKET doesn't contain a valid socket path, we are not
	 * running under systemd, do nothing.
	 */
	const auto notify_socket_path = get_notify_socket_path();
	if (!notify_socket_path) {
		return;
	}

	DBG_FMT("Systemd detected, signaling stopping");
	notify(notify_socket_path, "STOPPING=1\n");
}

} /* namespace systemd */
} /* namespace lttng */

#else /* __linux__ */

namespace lttng {
namespace systemd {

void notify_ready()
{
}

void notify_stopping()
{
}

} /* namespace systemd */
} /* namespace lttng */

#endif /* __linux__ */
