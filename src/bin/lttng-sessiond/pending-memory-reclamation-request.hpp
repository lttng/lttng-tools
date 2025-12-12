/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_PENDING_MEMORY_RECLAMATION_REQUEST_HPP
#define LTTNG_SESSIOND_PENDING_MEMORY_RECLAMATION_REQUEST_HPP

#include "session.hpp"

#include <common/make-unique.hpp>

#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace lttng {
namespace sessiond {

class pending_memory_reclamation_request;

/*
 * Registry of pending memory reclamation requests.
 *
 * Thread-safe: all operations are protected by an internal mutex.
 */
class pending_memory_reclamation_registry {
public:
	using token_t = std::uint64_t;
	/* Completion callback signature: bool parameter indicates success (true) or failure
	 * (false). */
	using completion_callback_t = std::function<void(bool)>;
	/* Cancellation callback signature (no parameters). */
	using cancellation_callback_t = std::function<void()>;

	pending_memory_reclamation_registry() = default;
	~pending_memory_reclamation_registry() = default;

	pending_memory_reclamation_registry(const pending_memory_reclamation_registry&) = delete;
	pending_memory_reclamation_registry&
	operator=(const pending_memory_reclamation_registry&) = delete;
	pending_memory_reclamation_registry(pending_memory_reclamation_registry&&) = delete;
	pending_memory_reclamation_registry&
	operator=(pending_memory_reclamation_registry&&) = delete;

	/*
	 * Create and register a new memory reclamation request.
	 *
	 * The request is created with completion disallowed. Consumer daemons
	 * may send completion notifications at any time after this call, but
	 * the completion callback will not be invoked until allow_completion()
	 * is called.
	 *
	 * @param session        Recording session.
	 * @param channel_name   Name of the channel being reclaimed.
	 * @param consumer_count Number of consumers that will send completion
	 *                       notifications.
	 * @param on_complete    Callback invoked when reclamation completes.
	 * @param on_cancel      Optional callback invoked if the request is cancelled.
	 * @return               Token for the request (pass to consumer daemons).
	 */
	token_t create_request(ltt_session& session,
			       lttng::c_string_view channel_name,
			       unsigned int consumer_count,
			       completion_callback_t on_complete,
			       cancellation_callback_t on_cancel = nullptr);

	/*
	 * Allow completion for a pending request.
	 *
	 * This must be called after create_request() and after the initial
	 * response has been sent to the client. This prevents a race condition
	 * where:
	 *   1. Request is created and consumers are contacted
	 *   2. Consumer completes immediately and sends notification
	 *   3. Completion callback tries to send final status
	 *   4. Initial response hasn't been sent yet (wrong message order)
	 *
	 * By allowing completion only after the initial response is sent, we
	 * ensure completion messages are always sent in the correct order.
	 *
	 * If all consumers have already completed, the completion callback is
	 * invoked immediately.
	 *
	 * @param token Token from create_request().
	 */
	void allow_completion(token_t token);

	/*
	 * Called when a consumer daemon sends a completion notification.
	 *
	 * If completion is allowed and this was the last consumer, the
	 * completion callback is invoked and the request is removed.
	 *
	 * If completion is not yet allowed, the completion is recorded and
	 * will be checked when allow_completion() is called.
	 *
	 * If any consumer reports failure (success=false), the final completion
	 * callback will be invoked with success=false even if other consumers
	 * succeed.
	 */
	void consumer_completed(token_t token, bool success);

	/*
	 * Cancel a specific pending memory reclamation request.
	 *
	 * The cancellation callback is invoked if set.
	 */
	void cancel_request(token_t token);

private:
	std::mutex _lock;
	token_t _next_token = 1;
	std::unordered_map<token_t, std::unique_ptr<pending_memory_reclamation_request>>
		_pending_requests;
};

/* Global registry instance. */
extern pending_memory_reclamation_registry the_pending_memory_reclamation_registry;

} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_PENDING_MEMORY_RECLAMATION_REQUEST_HPP */
