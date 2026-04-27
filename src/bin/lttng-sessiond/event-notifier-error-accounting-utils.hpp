/*
 * SPDX-FileCopyrightText: 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UTILS_HPP
#define LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UTILS_HPP

#include "event-notifier-error-accounting.hpp"

#include <common/index-allocator.hpp>

#include <lttng/trigger/trigger.h>

#include <vendor/optional.hpp>

#include <cstdint>
#include <memory>
#include <mutex>
#include <sys/types.h>
#include <unordered_map>

namespace lttng {
namespace sessiond {
namespace event_notifier_error_accounting {

/*
 * Tracks the per-domain (UST or kernel) mapping from event-notifier
 * tracer tokens to error-counter indices, and owns the underlying
 * pool of indices.
 *
 * All public methods serialize on an internal mutex.
 */
class tracer_token_index_table {
public:
	explicit tracer_token_index_table(std::uint64_t index_count);
	~tracer_token_index_table() = default;

	tracer_token_index_table(const tracer_token_index_table&) = delete;
	tracer_token_index_table& operator=(const tracer_token_index_table&) = delete;
	tracer_token_index_table(tracer_token_index_table&&) = delete;
	tracer_token_index_table& operator=(tracer_token_index_table&&) = delete;

	/*
	 * Look up the index allocated for `tracer_token`. Returns
	 * nullopt when no index has been allocated for this token.
	 */
	nonstd::optional<std::uint64_t> lookup(std::uint64_t tracer_token) const;

	/*
	 * Allocate and register an index for `tracer_token`. Returns
	 * nullopt when the index pool is exhausted.
	 *
	 * Throws lttng::runtime_error on internal allocator failure.
	 */
	nonstd::optional<std::uint64_t> allocate(std::uint64_t tracer_token);

	/*
	 * Release the index registered for `tracer_token`. Returns
	 * false if no index was registered for this token; the caller
	 * is expected to log details.
	 */
	bool release(std::uint64_t tracer_token);

	std::uint64_t index_count() const noexcept
	{
		return _index_count;
	}

private:
	struct index_allocator_deleter {
		void operator()(lttng_index_allocator *allocator) const noexcept
		{
			lttng_index_allocator_destroy(allocator);
		}
	};

	using index_allocator_uptr =
		std::unique_ptr<lttng_index_allocator, index_allocator_deleter>;

	mutable std::mutex _lock;
	index_allocator_uptr _index_allocator;
	std::unordered_map<std::uint64_t, std::uint64_t> _token_to_index;
	std::uint64_t _index_count;
};

} /* namespace event_notifier_error_accounting */
} /* namespace sessiond */
} /* namespace lttng */

/*
 * The UST-side of the accounting subsystem accesses the UST index
 * table to look up indices on the count/clear paths. The dispatcher
 * owns the table; this is the shared handle.
 */
extern nonstd::optional<lttng::sessiond::event_notifier_error_accounting::tracer_token_index_table>
	ust_index_table;

void get_trigger_info_for_log(const struct lttng_trigger *trigger,
			      const char **trigger_name,
			      uid_t *trigger_owner_uid);

const char *error_accounting_status_str(enum event_notifier_error_accounting_status status);

#endif /* LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UTILS_HPP */
