/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_CONSUMER_PENDING_MEMORY_RECLAMATION_TRACKER_H
#define LTTNG_CONSUMER_PENDING_MEMORY_RECLAMATION_TRACKER_H

#include <common/scheduler.hpp>

#include <vendor/optional.hpp>

#include <cstdint>
#include <mutex>
#include <unordered_map>

struct lttng_consumer_stream;
struct protected_socket;

namespace lttng {
namespace consumerd {

/*
 * Tracks pending memory reclamation operations to send a completion notification
 * to the session daemon when all streams have completed their pending reclamation
 * during user-initiated reclamation requests.
 *
 * All operations are protected by an internal mutex.
 */
class pending_memory_reclamation_tracker {
public:
	pending_memory_reclamation_tracker() = default;
	~pending_memory_reclamation_tracker() = default;

	pending_memory_reclamation_tracker(const pending_memory_reclamation_tracker&) = delete;
	pending_memory_reclamation_tracker&
	operator=(const pending_memory_reclamation_tracker&) = delete;
	pending_memory_reclamation_tracker(pending_memory_reclamation_tracker&&) = delete;
	pending_memory_reclamation_tracker&
	operator=(pending_memory_reclamation_tracker&&) = delete;

	/*
	 * Set the error socket used to send completion notifications.
	 * Must be called before any stream registration.
	 */
	void set_error_socket(protected_socket& error_socket) noexcept;

	/*
	 * Set the scheduler used to reschedule suspended timer tasks.
	 * Must be called before any channel timer suspension.
	 */
	void set_scheduler(lttng::scheduling::scheduler& scheduler) noexcept;

	/*
	 * Register a stream as having pending reclamation for a given token.
	 * Increments the pending stream count for that token.
	 */
	void register_stream(std::uint64_t memory_reclaim_request_token);

	/*
	 * Called when a stream completes its pending reclamation.
	 * Decrements the pending stream count for the token.
	 *
	 * If the count reaches zero, sends a completion notification to the
	 * session daemon via the error socket and resumes any suspended task.
	 */
	void stream_completed(const lttng_consumer_stream& stream,
			      std::uint64_t memory_reclaim_request_token);

	/*
	 * Send a completion notification if no streams are pending for the given token.
	 *
	 * This is used when a memory reclamation request completes immediately
	 * (no pending bytes to reclaim). Since no streams are registered with the
	 * tracker, we send the completion notification directly.
	 *
	 * If streams are pending for the token, this is a no-op since completion
	 * will be sent when the last stream completes.
	 */
	void complete_if_no_pending_streams(std::uint64_t memory_reclaim_request_token);

private:
	void _send_completion_notification(std::uint64_t memory_reclaim_request_token);

	std::mutex _lock;
	/*
	 * Map from memory reclaim request token to number of streams still pending for that token.
	 */
	std::unordered_map<std::uint64_t, unsigned long> _pending_stream_counts;
	protected_socket *_error_socket = nullptr;
	lttng::scheduling::scheduler *_scheduler = nullptr;
};

extern pending_memory_reclamation_tracker the_pending_memory_reclamation_tracker;

} /* namespace consumerd */
} /* namespace lttng */

#endif /* LTTNG_CONSUMER_PENDING_MEMORY_RECLAMATION_TRACKER_H */
