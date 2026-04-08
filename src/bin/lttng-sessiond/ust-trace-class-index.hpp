/*
 * SPDX-FileCopyrightText: 2026 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_TRACE_CLASS_INDEX_HPP
#define LTTNG_SESSIOND_UST_TRACE_CLASS_INDEX_HPP

#include <cstdint>
#include <memory>
#include <mutex>
#include <sys/types.h>
#include <unordered_map>

namespace lttng {
namespace sessiond {
namespace ust {

class trace_class;

/*
 * Thread-safe index for looking up trace_class objects without holding
 * the session list lock or any session lock.
 *
 * This index exists for two reasons:
 *
 * 1. Deadlock avoidance: the consumer management thread handles
 *    metadata pull requests from the consumer daemon. During live
 *    tracing, the consumer's live timer triggers metadata pulls while
 *    the command thread may simultaneously push metadata to the
 *    consumer. The push blocks until the consumer processes it, but
 *    the consumer may be blocked waiting for its metadata pull request
 *    to be served. If the consumer management thread needed the
 *    session list lock to resolve the trace class, and the command
 *    thread held that lock during the push, a circular dependency
 *    would form (see commit c585821bc78955b3d).
 *
 * 2. Per-PID key space: in per-PID buffer mode, the consumer
 *    identifies the trace class by an app_session_id
 *    (app_session::app_session_id) which is a sessiond-internal
 *    identifier with no relation to ltt_session::id. There is no way
 *    to derive an ltt_session from this value alone.
 *
 * Lookup keys match what the consumer daemon includes in
 * lttcomm_metadata_request_msg:
 *   - Per-UID: (recording_session_id, abi_bitness, app_uid)
 *   - Per-PID: (app_session_id)
 *
 * The find methods return a shared_ptr so that the trace class remains
 * alive for the duration of the caller's use, even if the orchestrator
 * concurrently destroys it (e.g. during session teardown).
 *
 * The orchestrator registers trace classes when they are created and
 * unregisters them before destruction.
 */
class trace_class_index {
public:
	trace_class_index() = default;
	~trace_class_index() = default;

	trace_class_index(const trace_class_index&) = delete;
	trace_class_index(trace_class_index&&) = delete;
	trace_class_index& operator=(const trace_class_index&) = delete;
	trace_class_index& operator=(trace_class_index&&) = delete;

	/*
	 * Register a per-UID trace class. The key is the triplet
	 * (recording_session_id, abi_bitness, app_uid) that the consumer
	 * daemon includes in metadata request messages.
	 */
	void add_per_uid(std::uint64_t recording_session_id,
			 std::uint32_t abi_bitness,
			 uid_t app_uid,
			 const std::shared_ptr<trace_class>& tc);

	void remove_per_uid(std::uint64_t recording_session_id,
			    std::uint32_t abi_bitness,
			    uid_t app_uid);

	/*
	 * Look up a per-UID trace class. Returns an empty shared_ptr if
	 * not found.
	 */
	std::shared_ptr<trace_class> find_per_uid(std::uint64_t recording_session_id,
						  std::uint32_t abi_bitness,
						  uid_t app_uid) const;

	/*
	 * Register a per-PID trace class. The key is the
	 * app_session::app_session_id, which the consumer daemon
	 * includes in metadata request messages as session_id_per_pid.
	 */
	void add_per_pid(std::uint64_t app_session_id, const std::shared_ptr<trace_class>& tc);

	void remove_per_pid(std::uint64_t app_session_id);

	/*
	 * Look up a per-PID trace class. Returns an empty shared_ptr if
	 * not found.
	 */
	std::shared_ptr<trace_class> find_per_pid(std::uint64_t app_session_id) const;

private:
	struct _per_uid_key {
		std::uint64_t recording_session_id;
		std::uint32_t abi_bitness;
		uid_t app_uid;

		bool operator==(const _per_uid_key& other) const noexcept
		{
			return recording_session_id == other.recording_session_id &&
				abi_bitness == other.abi_bitness && app_uid == other.app_uid;
		}
	};

	struct _per_uid_key_hasher {
		std::size_t operator()(const _per_uid_key& key) const noexcept
		{
			/*
			 * Golden-ratio hash combining (boost::hash_combine
			 * inspired).
			 */
			constexpr auto golden_ratio = sizeof(std::size_t) == 8 ?
				std::size_t(0x9e3779b97f4a7c15) :
				std::size_t(0x9e3779b9);

			auto seed = std::hash<std::uint64_t>{}(key.recording_session_id);
			seed ^= std::hash<std::uint32_t>{}(key.abi_bitness) + golden_ratio +
				(seed << 6) + (seed >> 2);
			seed ^= std::hash<uid_t>{}(key.app_uid) + golden_ratio + (seed << 6) +
				(seed >> 2);
			return seed;
		}
	};

	mutable std::mutex _mutex;

	std::unordered_map<_per_uid_key, std::shared_ptr<trace_class>, _per_uid_key_hasher>
		_per_uid_map;
	std::unordered_map<std::uint64_t, std::shared_ptr<trace_class>> _per_pid_map;
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_TRACE_CLASS_INDEX_HPP */
