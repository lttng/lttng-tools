/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "pending-memory-reclamation-request.hpp"

#include <common/error.hpp>

namespace ls = lttng::sessiond;

/*
 * Represents an in-flight memory reclamation request that is waiting for
 * one or more consumer daemons to complete processing pending sub-buffers.
 *
 * Each consumer daemon involved in the reclamation will send a completion
 * notification when all its streams have finished reclaiming. When all
 * consumers have completed, the completion callback is invoked.
 */
class ls::pending_memory_reclamation_request {
	friend class pending_memory_reclamation_registry;

public:
	using token_t = std::uint64_t;
	/* Completion callback signature: bool parameter indicates success (true) or failure
	 * (false). */
	using completion_callback_t = std::function<void(bool)>;
	/* Cancellation callback signature (no parameters). */
	using cancellation_callback_t = std::function<void()>;

	pending_memory_reclamation_request(const pending_memory_reclamation_request&) = delete;
	pending_memory_reclamation_request&
	operator=(const pending_memory_reclamation_request&) = delete;
	pending_memory_reclamation_request(pending_memory_reclamation_request&&) = delete;
	pending_memory_reclamation_request&
	operator=(pending_memory_reclamation_request&&) = delete;
	~pending_memory_reclamation_request() = default;

	token_t token() const noexcept;

	ltt_session& session() noexcept;

	const std::string& channel_name() const noexcept;

private:
	/*
	 * Constructor - creates a request with completion disallowed.
	 * Consumer completions can arrive and be counted, but the completion
	 * callback will not be invoked until allow_completion() is called.
	 */
	pending_memory_reclamation_request(token_t token,
					   ltt_session& session,
					   std::string channel_name,
					   unsigned int expected_consumer_count,
					   completion_callback_t on_complete,
					   cancellation_callback_t on_cancel) :
		_token(token),
		_session([&session]() -> ltt_session::ref {
			session_get(&session);
			return ltt_session::make_ref(session);
		}()),
		_channel_name(std::move(channel_name)),
		_on_complete(std::move(on_complete)),
		_on_cancel(std::move(on_cancel)),
		_expected_consumer_count(expected_consumer_count)
	{
	}

	/*
	 * Allow the request to complete.
	 * Returns true if all consumers have already completed (request is done).
	 */
	bool allow_completion() noexcept;

	/*
	 * Called when a consumer daemon completes its part of the reclamation.
	 * Returns true if completion is allowed and all consumers have completed.
	 * If success is false, the overall request is marked as failed.
	 */
	bool consumer_completed(bool success) noexcept;

	/*
	 * Check if the request is complete (completion allowed and all consumers done).
	 */
	bool _has_completed() const noexcept;

	/*
	 * Invoke the completion callback and remove the channel from the
	 * session's pending reclaim set. Should only be called when all
	 * consumers have completed.
	 */
	void invoke_completion_callback();

	/* Invoke the cancellation callback, if set. */
	void invoke_cancellation_callback();

	const token_t _token;
	const ltt_session::ref _session;
	const std::string _channel_name;
	const completion_callback_t _on_complete;
	const cancellation_callback_t _on_cancel;
	const unsigned int _expected_consumer_count;

	unsigned int _completed_consumer_count = 0;
	bool _completion_allowed = false;
	bool _any_failed = false;
};

ls::pending_memory_reclamation_registry ls::the_pending_memory_reclamation_registry;

void ls::pending_memory_reclamation_request::invoke_completion_callback()
{
	session_lock(&*_session);
	_session->remove_pending_reclamation(_channel_name);
	session_unlock(&*_session);

	if (_on_complete) {
		_on_complete(!_any_failed);
	}
}

void ls::pending_memory_reclamation_request::invoke_cancellation_callback()
{
	ASSERT_LOCKED(_session->_lock);
	_session->remove_pending_reclamation(_channel_name);

	if (_on_cancel) {
		_on_cancel();
	}
}

ls::pending_memory_reclamation_request::token_t
ls::pending_memory_reclamation_request::token() const noexcept
{
	return _token;
}

ltt_session& ls::pending_memory_reclamation_request::session() noexcept
{
	return *_session;
}

const std::string& ls::pending_memory_reclamation_request::channel_name() const noexcept
{
	return _channel_name;
}

bool ls::pending_memory_reclamation_request::allow_completion() noexcept
{
	DBG_FMT("Allowing completion for memory reclaim request: token={}, completed={}, expected={}",
		_token,
		_completed_consumer_count,
		_expected_consumer_count);

	_completion_allowed = true;
	return _has_completed();
}

bool ls::pending_memory_reclamation_request::consumer_completed(bool success) noexcept
{
	++_completed_consumer_count;
	if (!success) {
		_any_failed = true;
	}

	DBG_FMT("Consumer completed for memory reclaim request: token={}, success={}, completed={}, expected={}, allowed={}, any_failed={}",
		_token,
		success,
		_completed_consumer_count,
		_expected_consumer_count,
		_completion_allowed,
		_any_failed);

	return _has_completed();
}

bool ls::pending_memory_reclamation_request::_has_completed() const noexcept
{
	return _completion_allowed && _completed_consumer_count >= _expected_consumer_count;
}

/* pending_memory_reclaim_registry implementation */

ls::pending_memory_reclamation_registry::token_t
ls::pending_memory_reclamation_registry::create_request(
	ltt_session& session,
	lttng::c_string_view channel_name,
	unsigned int consumer_count,
	pending_memory_reclamation_request::completion_callback_t on_complete,
	pending_memory_reclamation_request::cancellation_callback_t on_cancel)
{
	ASSERT_LOCKED(session._lock);
	const std::lock_guard<std::mutex> lock(_lock);

	const auto token = _next_token++;

	session.add_pending_reclamation(channel_name);

	auto remove_pending_reclaim_on_failure =
		lttng::make_scope_exit([&session, &channel_name]() noexcept {
			session.remove_pending_reclamation(channel_name);
		});

	/*
	 * The constructor of pending_memory_reclaim_request is private so
	 * we need to use 'new' here as make_unique cannot access it.
	 */
	auto request = std::unique_ptr<pending_memory_reclamation_request>(
		new pending_memory_reclamation_request(token,
						       session,
						       channel_name,
						       consumer_count,
						       std::move(on_complete),
						       std::move(on_cancel)));

	_pending_requests.emplace(token, std::move(request));

	DBG_FMT("Created pending memory reclaim request (completion disallowed): token={}, consumer_count={}",
		token,
		consumer_count);

	remove_pending_reclaim_on_failure.disarm();
	return token;
}

void ls::pending_memory_reclamation_registry::allow_completion(token_t token)
{
	std::unique_ptr<pending_memory_reclamation_request> completed_request;

	{
		const std::lock_guard<std::mutex> lock(_lock);

		const auto it = _pending_requests.find(token);
		if (it == _pending_requests.end()) {
			DBG_FMT("Attempted to allow completion for unknown memory reclaim request: token={}",
				token);
			return;
		}

		/*
		 * Allow completion and check if all consumers have already completed
		 * (race condition where consumers completed before we allowed it).
		 */
		if (it->second->allow_completion()) {
			DBG_FMT("All consumers already completed for memory reclaim request, completing now: token={}",
				token);
			completed_request = std::move(it->second);
			_pending_requests.erase(it);
		}
	}

	/*
	 * Invoke callback outside the lock to avoid potential deadlocks
	 * if the callback tries to access the registry.
	 */
	if (completed_request) {
		completed_request->invoke_completion_callback();
	}
}

void ls::pending_memory_reclamation_registry::consumer_completed(token_t token, bool success)
{
	std::unique_ptr<pending_memory_reclamation_request> completed_request;

	{
		const std::lock_guard<std::mutex> lock(_lock);

		const auto it = _pending_requests.find(token);
		if (it == _pending_requests.end()) {
			WARN_FMT(
				"Received completion for unknown memory reclaim request: token={}, success={}",
				token,
				success);
			return;
		}

		if (it->second->consumer_completed(success)) {
			DBG_FMT("All consumers completed for memory reclaim request: token={}",
				token);
			completed_request = std::move(it->second);
			_pending_requests.erase(it);
		} else {
			DBG_FMT("Consumer completed for memory reclaim request, waiting for more: token={}, success={}",
				token,
				success);
		}
	}

	/*
	 * Invoke callback outside the lock to avoid potential deadlocks
	 * if the callback tries to access the registry.
	 */
	if (completed_request) {
		completed_request->invoke_completion_callback();
	}
}

void ls::pending_memory_reclamation_registry::cancel_request(token_t token)
{
	std::unique_ptr<pending_memory_reclamation_request> cancelled_request;

	{
		const std::lock_guard<std::mutex> lock(_lock);

		const auto it = _pending_requests.find(token);
		if (it == _pending_requests.end()) {
			DBG_FMT("Attempted to cancel unknown memory reclaim request: token={}",
				token);
			return;
		}

		DBG_FMT("Cancelling pending memory reclaim request: token={}", token);
		cancelled_request = std::move(it->second);
		_pending_requests.erase(it);
	}

	/* Invoke cancellation callback outside the lock. */
	if (cancelled_request) {
		cancelled_request->invoke_cancellation_callback();
	}
}
