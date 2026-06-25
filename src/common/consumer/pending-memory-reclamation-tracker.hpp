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
#include <functional>
#include <mutex>
#include <unordered_map>
#include <vector>

struct lttng_consumer_channel;
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
	 * Begin tracking a reclamation request for the given token.
	 *
	 * This must be called once, before any channel or stream is registered
	 * for the token. It holds a reference on the request that is only
	 * released by end_request(), which guarantees that the request can not
	 * be considered complete (and its suspended timers resumed) while the
	 * caller is still registering the channels and streams it touches.
	 */
	void begin_request(std::uint64_t memory_reclaim_request_token);

	/*
	 * Register a channel whose memory reclaim timer task was suspended for
	 * the duration of the request identified by the token. Every channel
	 * registered this way has its timer task resumed when the request
	 * completes, whether the request completes immediately or
	 * asynchronously as its streams are consumed.
	 */
	void register_suspended_channel(std::uint64_t memory_reclaim_request_token,
					lttng_consumer_channel& channel);

	/*
	 * Register a stream as having pending reclamation for a given token.
	 * Increments the pending stream count for that token.
	 */
	void register_stream(std::uint64_t memory_reclaim_request_token);

	/*
	 * Called when a stream completes its pending reclamation. Decrements
	 * the pending stream count for the token.
	 *
	 * If the count reaches zero, sends a completion notification to the
	 * session daemon via the error socket and resumes the timer tasks of
	 * all the channels suspended for that token.
	 */
	void stream_completed(std::uint64_t memory_reclaim_request_token);

	/*
	 * Release the reference held by begin_request(), signalling that the
	 * caller is done registering channels and streams for the token.
	 *
	 * If no streams are still pending at this point (the request reclaimed
	 * everything synchronously), the completion notification is sent and
	 * the suspended timer tasks are resumed immediately. Otherwise,
	 * completion happens when the last pending stream completes.
	 */
	void end_request(std::uint64_t memory_reclaim_request_token);

	/*
	 * Abort the request identified by the token without sending a
	 * completion notification. Used on an error path, after
	 * begin_request(), when the request could not be issued. The suspended
	 * timer tasks are resumed (best-effort) so that automatic reclamation
	 * keeps running, and the request's tracking state is dropped.
	 */
	void abort_request(std::uint64_t memory_reclaim_request_token) noexcept;

	/*
	 * Stop tracking a channel that is being torn down, removing it from any
	 * in-flight request's set of suspended channels so that its timer task
	 * is not resumed through a dangling pointer.
	 */
	void channel_removed(const lttng_consumer_channel& channel);

private:
	void _send_completion_notification(std::uint64_t memory_reclaim_request_token);
	void _decrement_and_maybe_complete(std::uint64_t memory_reclaim_request_token);
	void _resume_suspended_channels(std::uint64_t memory_reclaim_request_token);
	void _resume_channel_timer(lttng_consumer_channel& channel);

	std::mutex _lock;
	/*
	 * Map from memory reclaim request token to number of streams still
	 * pending for that token.
	 */
	std::unordered_map<std::uint64_t, unsigned long> _pending_stream_counts;
	/*
	 * Map from memory reclaim request token to the channels whose timer task was
	 * suspended for the duration of that request.
	 */
	std::unordered_map<std::uint64_t,
			   std::vector<std::reference_wrapper<lttng_consumer_channel>>>
		_suspended_channels_per_token;
	protected_socket *_error_socket = nullptr;
	lttng::scheduling::scheduler *_scheduler = nullptr;
};

extern pending_memory_reclamation_tracker the_pending_memory_reclamation_tracker;

} /* namespace consumerd */
} /* namespace lttng */

#endif /* LTTNG_CONSUMER_PENDING_MEMORY_RECLAMATION_TRACKER_H */
