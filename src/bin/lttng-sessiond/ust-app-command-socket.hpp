/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APP_COMMAND_SOCKET_HPP
#define LTTNG_SESSIOND_UST_APP_COMMAND_SOCKET_HPP

#include <common/exception.hpp>

#include <mutex>
#include <sys/types.h>

struct lttng_ust_abi_object_data;
struct lttng_ust_abi_event;
struct lttng_ust_abi_event_notifier;
struct lttng_ust_abi_event_exclusion;
struct lttng_ust_abi_filter_bytecode;
struct lttng_ust_abi_capture_bytecode;
struct lttng_ust_abi_tracepoint_iter;
struct lttng_ust_abi_field_iter;
struct lttng_ust_abi_tracer_version;
struct lttng_ust_context_attr;

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * Thrown when a tracer command fails due to the application being dead
 * or a communication timeout.
 *
 * Callers catching this exception can safely skip the application and
 * continue with others.
 */
class app_communication_error : public lttng::communication_error {
public:
	using lttng::communication_error::communication_error;
};

/*
 * Wraps the socket used for session daemon to tracer application communication
 * along with the mutex that serializes access to the tracer command protocol.
 *
 * The socket is used to send commands to the UST tracer through the
 * liblttng-ust-ctl interface. Since the protocol is not multiplexed,
 * all commands must be serialized. The protocol_guard inner class
 * provides RAII-based mutex management and typed protocol methods.
 */
class app_command_socket final {
public:
	/*
	 * RAII guard that serializes access to the tracer command protocol.
	 * Holds the command socket's mutex for its lifetime, providing
	 * typed methods for each tracer control command.
	 *
	 * Protocol methods throw `app_communication_error` when the
	 * application is dead or a communication timeout occurs.
	 * Unexpected errors throw `lttng::runtime_error`.
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
		 * lttng_ust_ctl_* functions not yet wrapped by protocol
		 * methods.
		 */
		int fd() const noexcept;

		/* Session management. */
		int create_session();
		void start_session(int handle);
		void stop_session(int handle);
		void wait_quiescent();
		void register_done();
		void regenerate_statedump(int handle);

		/* Object lifecycle. */
		void release_object(lttng_ust_abi_object_data *object);
		void release_handle(int handle);

		/* Event management. */
		void create_event(lttng_ust_abi_event *event,
				  lttng_ust_abi_object_data *channel_data,
				  lttng_ust_abi_object_data **event_data);
		void enable(lttng_ust_abi_object_data *object);
		void disable(lttng_ust_abi_object_data *object);
		void set_filter(lttng_ust_abi_filter_bytecode *bytecode,
				lttng_ust_abi_object_data *object);
		void set_exclusion(lttng_ust_abi_event_exclusion *exclusion,
				   lttng_ust_abi_object_data *object);

		/* Context management. */
		void add_context(lttng_ust_context_attr *ctx,
				 lttng_ust_abi_object_data *channel_data,
				 lttng_ust_abi_object_data **context_data);

		/* Channel and stream transport. */
		void send_channel_to_ust(int session_handle,
					 lttng_ust_abi_object_data *channel_data);
		void send_stream_to_ust(lttng_ust_abi_object_data *channel_data,
					lttng_ust_abi_object_data *stream_data);

		/* Event notifier management. */
		void create_event_notifier_group(int pipe_fd, lttng_ust_abi_object_data **out);
		void create_event_notifier(lttng_ust_abi_event_notifier *notifier,
					   lttng_ust_abi_object_data *group,
					   lttng_ust_abi_object_data **out);
		void set_capture(lttng_ust_abi_capture_bytecode *bytecode,
				 lttng_ust_abi_object_data *object);

		/* Counter management (event notifier error accounting). */
		void send_counter_data_to_ust(int parent_handle,
					      lttng_ust_abi_object_data *counter_data);
		void send_counter_cpu_data_to_ust(lttng_ust_abi_object_data *counter_data,
						  lttng_ust_abi_object_data *counter_cpu_data);

		/* Tracer introspection. */
		void tracer_version(lttng_ust_abi_tracer_version *version);
		int tracepoint_list();
		int tracepoint_list_get(int handle, lttng_ust_abi_tracepoint_iter *iter);
		int tracepoint_field_list();
		int tracepoint_field_list_get(int handle, lttng_ust_abi_field_iter *iter);

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
	 * Set the file descriptor and application pid. Called once during
	 * application registration.
	 */
	void set_fd(int fd, pid_t pid) noexcept;

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
	 * typed protocol methods.
	 */
	protocol_guard lock();

private:
	int _fd = -1;
	pid_t _pid = -1;
	mutable std::mutex _lock;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_APP_COMMAND_SOCKET_HPP */
