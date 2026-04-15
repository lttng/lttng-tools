/*
 * SPDX-FileCopyrightText: 2024 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng-ust-ctl.hpp"
#include "lttng-ust-error.hpp"
#include "ust-app-command-socket.hpp"

#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/format.hpp>

namespace lsu = lttng::sessiond::ust;

#define LTTNG_THROW_APP_COMMUNICATION_ERROR(msg) \
	throw lsu::app_communication_error((msg), LTTNG_SOURCE_LOCATION())

namespace {
/*
 * Classify the return value of a lttng_ust_ctl_* function and throw an
 * appropriate exception on error.
 *
 * - Success (ret >= 0): returns immediately.
 * - App dead (-EPIPE, -LTTNG_UST_ERR_EXITING): throws app_communication_error.
 * - Timeout (-EAGAIN): throws app_communication_error.
 * - Other error: throws lttng::runtime_error.
 */
void throw_on_ust_ctl_error(int ret, const char *operation, pid_t pid, int sock_fd)
{
	if (ret >= 0) {
		return;
	}

	if (ret == -EPIPE || ret == -LTTNG_UST_ERR_EXITING) {
		LTTNG_THROW_APP_COMMUNICATION_ERROR(
			lttng::format("UST app {} failed: application is dead: pid={}, sock={}",
				      operation,
				      pid,
				      sock_fd));
	}

	if (ret == -EAGAIN) {
		LTTNG_THROW_APP_COMMUNICATION_ERROR(
			lttng::format("UST app {} failed: communication timeout: pid={}, sock={}",
				      operation,
				      pid,
				      sock_fd));
	}

	LTTNG_THROW_ERROR(lttng::format(
		"UST app {} failed with ret {}: pid={}, sock={}", operation, ret, pid, sock_fd));
}
} /* anonymous namespace */

/* Session management. */

int lsu::app_command_socket::protocol_guard::create_session()
{
	const auto ret = lttng_ust_ctl_create_session(_socket->_fd);

	throw_on_ust_ctl_error(ret, "create session", _socket->_pid, _socket->_fd);
	return ret;
}

void lsu::app_command_socket::protocol_guard::start_session(int handle)
{
	const auto ret = lttng_ust_ctl_start_session(_socket->_fd, handle);

	throw_on_ust_ctl_error(ret, "start session", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::stop_session(int handle)
{
	const auto ret = lttng_ust_ctl_stop_session(_socket->_fd, handle);

	throw_on_ust_ctl_error(ret, "stop session", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::wait_quiescent()
{
	const auto ret = lttng_ust_ctl_wait_quiescent(_socket->_fd);

	throw_on_ust_ctl_error(ret, "wait quiescent", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::register_done()
{
	const auto ret = lttng_ust_ctl_register_done(_socket->_fd);

	throw_on_ust_ctl_error(ret, "register done", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::regenerate_statedump(int handle)
{
	const auto ret = lttng_ust_ctl_regenerate_statedump(_socket->_fd, handle);

	throw_on_ust_ctl_error(ret, "regenerate statedump", _socket->_pid, _socket->_fd);
}

/* Object lifecycle. */

void lsu::app_command_socket::protocol_guard::release_object(lttng_ust_abi_object_data *object)
{
	const auto ret = lttng_ust_ctl_release_object(_socket->_fd, object);

	throw_on_ust_ctl_error(ret, "release object", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::release_handle(int handle)
{
	const auto ret = lttng_ust_ctl_release_handle(_socket->_fd, handle);

	throw_on_ust_ctl_error(ret, "release handle", _socket->_pid, _socket->_fd);
}

/* Event management. */

void lsu::app_command_socket::protocol_guard::create_event(lttng_ust_abi_event *event,
							   lttng_ust_abi_object_data *channel_data,
							   lttng_ust_abi_object_data **event_data)
{
	const auto ret = lttng_ust_ctl_create_event(_socket->_fd, event, channel_data, event_data);

	throw_on_ust_ctl_error(ret, "create event", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::enable(lttng_ust_abi_object_data *object)
{
	const auto ret = lttng_ust_ctl_enable(_socket->_fd, object);

	throw_on_ust_ctl_error(ret, "enable", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::disable(lttng_ust_abi_object_data *object)
{
	const auto ret = lttng_ust_ctl_disable(_socket->_fd, object);

	throw_on_ust_ctl_error(ret, "disable", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::set_filter(lttng_ust_abi_filter_bytecode *bytecode,
							 lttng_ust_abi_object_data *object)
{
	const auto ret = lttng_ust_ctl_set_filter(_socket->_fd, bytecode, object);

	throw_on_ust_ctl_error(ret, "set filter", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::set_exclusion(
	lttng_ust_abi_event_exclusion *exclusion, lttng_ust_abi_object_data *object)
{
	const auto ret = lttng_ust_ctl_set_exclusion(_socket->_fd, exclusion, object);

	throw_on_ust_ctl_error(ret, "set exclusion", _socket->_pid, _socket->_fd);
}

/* Context management. */

void lsu::app_command_socket::protocol_guard::add_context(lttng_ust_context_attr *ctx,
							  lttng_ust_abi_object_data *channel_data,
							  lttng_ust_abi_object_data **context_data)
{
	const auto ret = lttng_ust_ctl_add_context(_socket->_fd, ctx, channel_data, context_data);

	throw_on_ust_ctl_error(ret, "add context", _socket->_pid, _socket->_fd);
}

/* Channel and stream transport. */

void lsu::app_command_socket::protocol_guard::send_channel_to_ust(
	int session_handle, lttng_ust_abi_object_data *channel_data)
{
	const auto ret =
		lttng_ust_ctl_send_channel_to_ust(_socket->_fd, session_handle, channel_data);

	throw_on_ust_ctl_error(ret, "send channel to UST", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::send_stream_to_ust(
	lttng_ust_abi_object_data *channel_data, lttng_ust_abi_object_data *stream_data)
{
	const auto ret = lttng_ust_ctl_send_stream_to_ust(_socket->_fd, channel_data, stream_data);

	throw_on_ust_ctl_error(ret, "send stream to UST", _socket->_pid, _socket->_fd);
}

/* Event notifier management. */

void lsu::app_command_socket::protocol_guard::create_event_notifier_group(
	int pipe_fd, lttng_ust_abi_object_data **out)
{
	const auto ret = lttng_ust_ctl_create_event_notifier_group(_socket->_fd, pipe_fd, out);

	throw_on_ust_ctl_error(ret, "create event notifier group", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::create_event_notifier(
	lttng_ust_abi_event_notifier *notifier,
	lttng_ust_abi_object_data *group,
	lttng_ust_abi_object_data **out)
{
	const auto ret = lttng_ust_ctl_create_event_notifier(_socket->_fd, notifier, group, out);

	throw_on_ust_ctl_error(ret, "create event notifier", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::set_capture(lttng_ust_abi_capture_bytecode *bytecode,
							  lttng_ust_abi_object_data *object)
{
	const auto ret = lttng_ust_ctl_set_capture(_socket->_fd, bytecode, object);

	throw_on_ust_ctl_error(ret, "set capture", _socket->_pid, _socket->_fd);
}

/* Counter management (event notifier error accounting). */

void lsu::app_command_socket::protocol_guard::send_counter_data_to_ust(
	int parent_handle, lttng_ust_abi_object_data *counter_data)
{
	const auto ret =
		lttng_ust_ctl_send_counter_data_to_ust(_socket->_fd, parent_handle, counter_data);

	throw_on_ust_ctl_error(ret, "send counter data to UST", _socket->_pid, _socket->_fd);
}

void lsu::app_command_socket::protocol_guard::send_counter_cpu_data_to_ust(
	lttng_ust_abi_object_data *counter_data, lttng_ust_abi_object_data *counter_cpu_data)
{
	const auto ret = lttng_ust_ctl_send_counter_cpu_data_to_ust(
		_socket->_fd, counter_data, counter_cpu_data);

	throw_on_ust_ctl_error(ret, "send counter CPU data to UST", _socket->_pid, _socket->_fd);
}

/* Tracer introspection. */

void lsu::app_command_socket::protocol_guard::tracer_version(lttng_ust_abi_tracer_version *version)
{
	const auto ret = lttng_ust_ctl_tracer_version(_socket->_fd, version);

	throw_on_ust_ctl_error(ret, "tracer version", _socket->_pid, _socket->_fd);
}

int lsu::app_command_socket::protocol_guard::tracepoint_list()
{
	const auto ret = lttng_ust_ctl_tracepoint_list(_socket->_fd);

	throw_on_ust_ctl_error(ret, "tracepoint list", _socket->_pid, _socket->_fd);
	return ret;
}

/*
 * Returns the underlying lttng_ust_ctl return value so the caller can
 * detect the end-of-iteration sentinel (-LTTNG_UST_ERR_NOENT).
 */
int lsu::app_command_socket::protocol_guard::tracepoint_list_get(
	int handle, lttng_ust_abi_tracepoint_iter *iter)
{
	const auto ret = lttng_ust_ctl_tracepoint_list_get(_socket->_fd, handle, iter);

	if (ret == -LTTNG_UST_ERR_NOENT) {
		return ret;
	}

	throw_on_ust_ctl_error(ret, "tracepoint list get", _socket->_pid, _socket->_fd);
	return ret;
}

int lsu::app_command_socket::protocol_guard::tracepoint_field_list()
{
	const auto ret = lttng_ust_ctl_tracepoint_field_list(_socket->_fd);

	throw_on_ust_ctl_error(ret, "tracepoint field list", _socket->_pid, _socket->_fd);
	return ret;
}

/*
 * Returns the underlying lttng_ust_ctl return value so the caller can
 * detect the end-of-iteration sentinel (-LTTNG_UST_ERR_NOENT).
 */
int lsu::app_command_socket::protocol_guard::tracepoint_field_list_get(
	int handle, lttng_ust_abi_field_iter *iter)
{
	const auto ret = lttng_ust_ctl_tracepoint_field_list_get(_socket->_fd, handle, iter);

	if (ret == -LTTNG_UST_ERR_NOENT) {
		return ret;
	}

	throw_on_ust_ctl_error(ret, "tracepoint field list get", _socket->_pid, _socket->_fd);
	return ret;
}
