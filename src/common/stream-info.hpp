/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_COMMON_STREAM_INFO_HPP
#define LTTNG_COMMON_STREAM_INFO_HPP

#include <common/payload-view.hpp>
#include <common/payload.hpp>

#include <lttng/stream-info.h>

#include <vendor/optional.hpp>

#include <memory>
#include <vector>

struct lttng_data_stream_info {
	nonstd::optional<std::uint32_t> cpu_id;
	std::uint64_t memory_usage;
	std::uint64_t max_memory_usage;
};

struct lttng_data_stream_info_set {
	enum lttng_app_bitness bitness;
	union {
		pid_t pid;
		uid_t uid;
	} owner;
	/* true for per-PID, false for per-UID */
	bool is_per_pid;

	std::vector<lttng_data_stream_info> streams;
};

struct lttng_data_stream_info_sets {
	using uptr = std::unique_ptr<lttng_data_stream_info_sets>;

	std::vector<lttng_data_stream_info_set> sets;

	void serialize(lttng_payload& payload);
	static std::pair<ssize_t, lttng_data_stream_info_sets::uptr>
	create_from_payload(lttng_payload_view& view);
};

#endif /* LTTNG_COMMON_STREAM_INFO_HPP */
