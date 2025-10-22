/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <common/binary-view.hpp>
#include <common/dynamic-buffer.hpp>
#include <common/error.hpp>
#include <common/macros.hpp>
#include <common/make-unique.hpp>
#include <common/payload-view.hpp>
#include <common/payload.hpp>
#include <common/stream-info.hpp>

#include <lttng/lttng-error.h>

#include <bin/lttng-sessiond/commands/get-channel-memory-usage.hpp>
#include <stdlib.h>
#include <string.h>

enum lttng_data_stream_info_status
lttng_data_stream_info_get_cpu_id(const struct lttng_data_stream_info *stream_info,
				  unsigned int *cpu_id)
{
	if (!stream_info || !cpu_id) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	if (!stream_info->cpu_id.has_value()) {
		return LTTNG_DATA_STREAM_INFO_STATUS_NONE;
	}

	*cpu_id = (stream_info->cpu_id).value();
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

enum lttng_data_stream_info_status
lttng_data_stream_info_get_memory_usage(const struct lttng_data_stream_info *stream_info,
					uint64_t *value)
{
	if (!stream_info || !value) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	*value = stream_info->memory_usage;
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

enum lttng_data_stream_info_status
lttng_data_stream_info_get_max_memory_usage(const struct lttng_data_stream_info *stream_info,
					    uint64_t *value)
{
	if (!stream_info || !value) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	*value = stream_info->max_memory_usage;
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_count(const struct lttng_data_stream_info_set *set,
				     unsigned int *count)
{
	if (!set || !count) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	*count = set->streams.size();
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_at_index(const struct lttng_data_stream_info_set *set,
					unsigned int index,
					const struct lttng_data_stream_info **stream_info)
{
	if (!set || !stream_info) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	if (index >= set->streams.size()) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	*stream_info = &set->streams[index];
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_uid(const struct lttng_data_stream_info_set *set, uid_t *uid)
{
	if (!set || !uid) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	if (set->is_per_pid) {
		return LTTNG_DATA_STREAM_INFO_STATUS_NONE;
	}

	*uid = set->owner.uid;
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_app_bitness(const struct lttng_data_stream_info_set *set,
					   enum lttng_app_bitness *bitness)
{
	if (!set || !bitness) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	*bitness = set->bitness;
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_pid(const struct lttng_data_stream_info_set *set, pid_t *pid)
{
	if (!set || !pid) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	if (!set->is_per_pid) {
		return LTTNG_DATA_STREAM_INFO_STATUS_NONE;
	}

	*pid = set->owner.pid;
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

enum lttng_data_stream_info_status
lttng_data_stream_info_sets_get_count(const struct lttng_data_stream_info_sets *sets,
				      unsigned int *count)
{
	if (!sets || !count) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	*count = sets->sets.size();
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

enum lttng_data_stream_info_status
lttng_data_stream_info_sets_get_at_index(const struct lttng_data_stream_info_sets *sets,
					 unsigned int index,
					 const struct lttng_data_stream_info_set **set)
{
	if (!sets || !set) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	if (index >= sets->sets.size()) {
		return LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER;
	}

	*set = &sets->sets[index];
	return LTTNG_DATA_STREAM_INFO_STATUS_OK;
}

void lttng_data_stream_info_sets_destroy(const struct lttng_data_stream_info_sets *sets)
{
	delete sets;
}

/* Serialization functions */
void lttng_data_stream_info_sets::serialize(lttng_payload& payload)
{
	int ret;

	/* Serialize the number of sets */
	const std::uint32_t set_count = sets.size();
	ret = lttng_dynamic_buffer_append(&payload.buffer, &set_count, sizeof(set_count));
	if (ret) {
		LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
			"Failed to append set count to payload", sizeof(set_count));
	}

	/* Serialize each set */
	for (const auto& set : sets) {
		/* Serialize set metadata */
		const std::uint8_t bitness = static_cast<std::uint8_t>(set.bitness);
		ret = lttng_dynamic_buffer_append(&payload.buffer, &bitness, sizeof(bitness));
		if (ret) {
			LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
				"Failed to append set bitness to payload", sizeof(bitness));
		}

		const std::uint8_t is_per_pid = set.is_per_pid ? 1 : 0;
		ret = lttng_dynamic_buffer_append(&payload.buffer, &is_per_pid, sizeof(is_per_pid));
		if (ret) {
			LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
				"Failed to append is_per_pid to payload", sizeof(is_per_pid));
		}

		if (set.is_per_pid) {
			const std::uint64_t pid = set.owner.pid;

			ret = lttng_dynamic_buffer_append(&payload.buffer, &pid, sizeof(pid));
			if (ret) {
				LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
					"Failed to append owner pid to payload", sizeof(pid));
			}
		} else {
			const std::uint64_t uid = set.owner.uid;

			ret = lttng_dynamic_buffer_append(&payload.buffer, &uid, sizeof(uid));
			if (ret) {
				LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
					"Failed to append owner uid to payload", sizeof(uid));
			}
		}

		/* Serialize stream count */
		const std::uint32_t stream_count = set.streams.size();
		ret = lttng_dynamic_buffer_append(
			&payload.buffer, &stream_count, sizeof(stream_count));
		if (ret) {
			LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
				"Failed to append stream count to payload", sizeof(stream_count));
		}

		/* Serialize each stream */
		for (const auto& stream : set.streams) {
			const std::uint8_t has_cpu_id = stream.cpu_id.has_value() ? 1 : 0;

			ret = lttng_dynamic_buffer_append(
				&payload.buffer, &has_cpu_id, sizeof(has_cpu_id));
			if (ret) {
				LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
					"Failed to append has_cpu_id to payload",
					sizeof(has_cpu_id));
			}

			if (stream.cpu_id.has_value()) {
				const std::uint32_t cpu_id = stream.cpu_id.value();

				ret = lttng_dynamic_buffer_append(
					&payload.buffer, &cpu_id, sizeof(cpu_id));
				if (ret) {
					LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
						"Failed to append cpu_id to payload",
						sizeof(cpu_id));
				}
			}

			const std::uint64_t memory_usage = stream.memory_usage;
			ret = lttng_dynamic_buffer_append(
				&payload.buffer, &memory_usage, sizeof(memory_usage));
			if (ret) {
				LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
					"Failed to append memory_usage to payload",
					sizeof(memory_usage));
			}

			const std::uint64_t max_memory_usage = stream.max_memory_usage;
			ret = lttng_dynamic_buffer_append(
				&payload.buffer, &max_memory_usage, sizeof(max_memory_usage));
			if (ret) {
				LTTNG_THROW_ALLOCATION_FAILURE_WITH_SIZE_ERROR(
					"Failed to append max_memory_usage to payload",
					sizeof(max_memory_usage));
			}
		}
	}
}

std::pair<ssize_t, lttng_data_stream_info_sets::uptr>
lttng_data_stream_info_sets::create_from_payload(lttng_payload_view& view)
{
	ssize_t offset = 0;
	auto sets = lttng::make_unique<lttng_data_stream_info_sets>();

	/* Read set count */
	const lttng::binary_view<uint32_t> set_count_view(view.buffer.data + offset,
							  view.buffer.size);
	const auto set_count = set_count_view.value();
	offset += sizeof(set_count);

	sets->sets.reserve(set_count);

	/* Deserialize each set */
	for (unsigned int set_idx = 0; set_idx < set_count; set_idx++) {
		lttng_data_stream_info_set set;

		const lttng::binary_view<std::uint8_t> bitness_view(view.buffer.data + offset,
								    view.buffer.size - offset);
		const auto bitness = bitness_view.value();
		offset += sizeof(bitness);

		const lttng::binary_view<std::uint8_t> is_per_pid_view(view.buffer.data + offset,
								       view.buffer.size - offset);
		const auto is_per_pid = is_per_pid_view.value();
		offset += sizeof(is_per_pid);

		/* Read owner info */
		if (is_per_pid) {
			const lttng::binary_view<std::uint64_t> pid_view(view.buffer.data + offset,
									 view.buffer.size - offset);
			const auto pid = pid_view.value();
			offset += sizeof(pid);

			set.owner.pid = pid;
		} else {
			const lttng::binary_view<std::uint64_t> uid_view(view.buffer.data + offset,
									 view.buffer.size - offset);
			const auto uid = uid_view.value();
			offset += sizeof(uid);

			set.owner.uid = uid;
		}

		const lttng::binary_view<std::uint32_t> stream_count_view(
			view.buffer.data + offset, view.buffer.size - offset);
		const auto stream_count = stream_count_view.value();
		offset += sizeof(stream_count);

		set.bitness = static_cast<enum lttng_app_bitness>(bitness);
		set.is_per_pid = is_per_pid != 0;
		set.streams.reserve(stream_count);

		/* Deserialize each stream */
		for (unsigned int stream_idx = 0; stream_idx < stream_count; stream_idx++) {
			lttng_data_stream_info stream;

			const lttng::binary_view<std::uint8_t> has_cpu_id_view(
				view.buffer.data + offset, view.buffer.size - offset);
			const auto has_cpu_id = has_cpu_id_view.value();
			offset += sizeof(has_cpu_id);

			if (has_cpu_id) {
				const lttng::binary_view<std::uint32_t> cpu_id_view(
					view.buffer.data + offset, view.buffer.size - offset);
				const auto cpu_id = cpu_id_view.value();
				offset += sizeof(cpu_id);
				stream.cpu_id = cpu_id;
			}

			const lttng::binary_view<std::uint64_t> memory_usage_view(
				view.buffer.data + offset, view.buffer.size - offset);
			const auto memory_usage = memory_usage_view.value();
			offset += sizeof(memory_usage);

			stream.memory_usage = memory_usage;

			const lttng::binary_view<std::uint64_t> max_memory_usage_view(
				view.buffer.data + offset, view.buffer.size - offset);
			const auto max_memory_usage = max_memory_usage_view.value();
			offset += sizeof(max_memory_usage);

			stream.max_memory_usage = max_memory_usage;

			set.streams.emplace_back(stream);
		}

		sets->sets.emplace_back(std::move(set));
	}

	return { offset, std::move(sets) };
}
