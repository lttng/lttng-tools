/*
 * SPDX-FileCopyrightText: 2025 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_STREAM_INFO_H
#define LTTNG_STREAM_INFO_H

#include <lttng/domain.h>
#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_data_stream_info;

enum lttng_app_bitness {
	LTTNG_APP_BITNESS_32 = 0,
	LTTNG_APP_BITNESS_64 = 1,
};

enum lttng_data_stream_info_status {
	LTTNG_DATA_STREAM_INFO_STATUS_OK = 0,
	LTTNG_DATA_STREAM_INFO_STATUS_NONE = 1,
	LTTNG_DATA_STREAM_INFO_STATUS_ERROR = -1,
	LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER = -2,
};

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_get_cpu_id(const struct lttng_data_stream_info *stream_info,
				  unsigned int *cpu_id);

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_get_memory_usage(const struct lttng_data_stream_info *stream_info,
					uint64_t *value);

struct lttng_data_stream_info_set;

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_count(const struct lttng_data_stream_info_set *set,
				     unsigned int *count);

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_at_index(const struct lttng_data_stream_info_set *set,
					unsigned int index,
					const struct lttng_data_stream_info **stream_info);

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_uid(const struct lttng_data_stream_info_set *set, uid_t *uid);

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_app_bitness(const struct lttng_data_stream_info_set *set,
					   enum lttng_app_bitness *bitness);

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_pid(const struct lttng_data_stream_info_set *set, pid_t *pid);

struct lttng_data_stream_info_sets;

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_sets_get_count(const struct lttng_data_stream_info_sets *sets,
				      unsigned int *count);

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_sets_get_at_index(const struct lttng_data_stream_info_sets *sets,
					 unsigned int index,
					 const struct lttng_data_stream_info_set **set);

extern LTTNG_EXPORT void
lttng_data_stream_info_sets_destroy(const struct lttng_data_stream_info_sets *sets);

enum lttng_channel_get_data_stream_info_sets_status {
	LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK = 0,
	LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_ERROR = -1,
	LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_INVALID_PARAMETER = -2,
	LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_UNSUPPORTED_DOMAIN = -3,
};

extern LTTNG_EXPORT enum lttng_channel_get_data_stream_info_sets_status
lttng_channel_get_data_stream_info_sets(const char *session_name,
					const char *channel_name,
					enum lttng_domain_type domain,
					const struct lttng_data_stream_info_sets **sets);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_STREAM_INFO_H */
