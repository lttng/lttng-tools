/*
 * SPDX-FileCopyrightText: 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "event-notifier-error-accounting-utils.hpp"

#include <common/error.hpp>

#include <lttng/trigger/trigger-internal.hpp>

namespace lttng {
namespace sessiond {
namespace event_notifier_error_accounting {

tracer_token_index_table::~tracer_token_index_table()
{
	if (!_token_to_index.empty()) {
		WARN_FMT(
			"Destroying tracer token index table with indices still in use: in_use_count={}, index_count={}",
			_token_to_index.size(),
			_index_count);
	}
}

nonstd::optional<std::uint64_t> tracer_token_index_table::lookup(std::uint64_t tracer_token) const
{
	const std::lock_guard<std::mutex> guard(_lock);

	const auto it = _token_to_index.find(tracer_token);
	if (it == _token_to_index.end()) {
		return nonstd::nullopt;
	}

	return it->second;
}

nonstd::optional<std::uint64_t> tracer_token_index_table::allocate(std::uint64_t tracer_token)
{
	const std::lock_guard<std::mutex> guard(_lock);

	std::uint64_t index;
	if (!_unused_indices.empty()) {
		index = _unused_indices.back();
		_unused_indices.pop_back();
	} else if (_high_water < _index_count) {
		index = _high_water++;
	} else {
		return nonstd::nullopt;
	}

	_token_to_index.emplace(tracer_token, index);
	return index;
}

bool tracer_token_index_table::release(std::uint64_t tracer_token)
{
	const std::lock_guard<std::mutex> guard(_lock);

	const auto it = _token_to_index.find(tracer_token);
	if (it == _token_to_index.end()) {
		return false;
	}

	_unused_indices.push_back(it->second);
	_token_to_index.erase(it);
	return true;
}

} /* namespace event_notifier_error_accounting */
} /* namespace sessiond */
} /* namespace lttng */

const char *error_accounting_status_str(enum event_notifier_error_accounting_status status)
{
	switch (status) {
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_OK:
		return "OK";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_ERR:
		return "ERROR";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOT_FOUND:
		return "NOT_FOUND";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NOMEM:
		return "NOMEM";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_NO_INDEX_AVAILABLE:
		return "NO_INDEX_AVAILABLE";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_APP_DEAD:
		return "APP_DEAD";
	case EVENT_NOTIFIER_ERROR_ACCOUNTING_STATUS_UNSUPPORTED:
		return "UNSUPPORTED";
	default:
		abort();
	}
}
