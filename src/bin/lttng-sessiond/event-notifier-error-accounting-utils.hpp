/*
 * SPDX-FileCopyrightText: 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UTILS_HPP
#define LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UTILS_HPP

#include "event-notifier-error-accounting.hpp"

#include <common/format.hpp>

#include <lttng/trigger/trigger.h>

#include <vendor/optional.hpp>

#include <cstdint>
#include <mutex>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

namespace lttng {
namespace sessiond {
namespace event_notifier_error_accounting {

/*
 * Tracks the per-domain (UST or kernel) mapping from event-notifier
 * tracer tokens to error-counter indices, and owns the underlying
 * pool of indices.
 *
 * Indices are drawn from [0, index_count[: a high-water mark grows on
 * each fresh allocation, and a free-list of released indices is
 * preferentially reused before bumping the high-water mark again.
 *
 * All public methods serialize on an internal mutex.
 */
class tracer_token_index_table {
public:
	explicit tracer_token_index_table(std::uint64_t index_count) : _index_count(index_count)
	{
	}

	~tracer_token_index_table();

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
	mutable std::mutex _lock;
	std::unordered_map<std::uint64_t, std::uint64_t> _token_to_index;
	std::vector<std::uint64_t> _unused_indices;
	std::uint64_t _high_water = 0;
	const std::uint64_t _index_count;
};

} /* namespace event_notifier_error_accounting */
} /* namespace sessiond */
} /* namespace lttng */

const char *error_accounting_status_str(enum event_notifier_error_accounting_status status);

/*
 * Due to a bug in g++ < 7.1, this specialization must be enclosed in the fmt namespace,
 * see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=56480.
 */
namespace fmt {
template <>
struct formatter<event_notifier_error_accounting_status> : formatter<std::string> {
	template <typename FormatContextType>
	typename FormatContextType::iterator format(event_notifier_error_accounting_status status,
						    FormatContextType& ctx) const
	{
		return format_to(ctx.out(), error_accounting_status_str(status));
	}
};
} /* namespace fmt */

#endif /* LTTNG_SESSIOND_EVENT_NOTIFIER_ERROR_ACCOUNTING_UTILS_HPP */
