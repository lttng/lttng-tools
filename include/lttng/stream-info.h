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

/*!
@addtogroup api_channel_ds_info
@{
*/

/*!
@struct lttng_data_stream_info

@brief
    Data stream info (opaque type).
*/
struct lttng_data_stream_info;

/*!
@brief
    Bitness of an instrumented application.
*/
enum lttng_app_bitness {
	/// 32-bit.
	LTTNG_APP_BITNESS_32 = 0,

	/// 64-bit.
	LTTNG_APP_BITNESS_64 = 1,
};

/*!
@brief
    Return type for data stream info functions.

Error status enumerators have a negative value.
*/
enum lttng_data_stream_info_status {
	/// Success.
	LTTNG_DATA_STREAM_INFO_STATUS_OK = 0,

	/// Information not available.
	LTTNG_DATA_STREAM_INFO_STATUS_NONE = 1,

	/// Other error.
	LTTNG_DATA_STREAM_INFO_STATUS_ERROR = -1,

	/// Unsatisfied precondition.
	LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER = -2,
};

/*!
@brief
    Sets \lt_p{*cpu_id} to the CPU ID of the data stream info
    \lt_p{stream_info}.

When a channel uses a
\ref api-channel-per-cpu-buf "per-CPU" buffer ownership model,
each data stream of the channel is bound to a specific CPU and
therefore has a CPU ID. Otherwise, the CPU ID isn't set and this
function returns #LTTNG_DATA_STREAM_INFO_STATUS_NONE.

@param[in] stream_info
    Data stream information from which to get the CPU ID.
@param[out] cpu_id
    <strong>On success</strong>, this function sets \lt_p{*cpu_id} to
    the ID of the CPU to which the data stream of \lt_p{stream_info}
    is bound.

@retval #LTTNG_DATA_STREAM_INFO_STATUS_OK
    Success.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_NONE
    The data stream of \lt_p{stream_info} isn't bound to a CPU.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{stream_info}
    @lt_pre_not_null{cpu_id}
*/
extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_get_cpu_id(const struct lttng_data_stream_info *stream_info,
				  unsigned int *cpu_id);

/*!
@brief
    Sets \lt_p{*value} to the current memory usage (bytes) of
    the data stream info \lt_p{stream_info}.

@param[in] stream_info
    Data stream information object from which to get the memory usage.
@param[out] value
    <strong>On success</strong>, this function sets \lt_p{*value} to the
    current memory usage (bytes) of \lt_p{stream_info}.

@retval #LTTNG_DATA_STREAM_INFO_STATUS_OK
    Success.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{stream_info}
    @lt_pre_not_null{value}
*/
extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_get_memory_usage(const struct lttng_data_stream_info *stream_info,
					uint64_t *value);

extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_get_max_memory_usage(const struct lttng_data_stream_info *stream_info,
					    uint64_t *value);

/*!
@struct lttng_data_stream_info_set

@brief
    Data stream info set (opaque type).
*/
struct lttng_data_stream_info_set;

/*!
@brief
    Sets \lt_p{*count} to the number of data stream infos in the
    data stream info set \lt_p{set}.

@param[in] set
    Set of data stream info of which to get the count.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count} to the
    number of data stream infos in \lt_p{set}.

@retval #LTTNG_DATA_STREAM_INFO_STATUS_OK
    Success.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    @lt_pre_not_null{count}

@sa lttng_data_stream_info_set_get_at_index() --
    Get a data stream info from a data stream info set by index.
*/
extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_count(const struct lttng_data_stream_info_set *set,
				     unsigned int *count);

/*!
@brief
    Sets \lt_p{*stream_info} to the data stream info at the index
    \lt_p{index} in the data stream info set \lt_p{set}.

@param[in] set
    Data stream info set from which to get the data stream info
    at the index \lt_p{index}.
@param[in] index
    Index of the data stream info to get from \lt_p{set}.
@param[out] stream_info
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*stream_info}
    to the data stream info at the index \lt_p{index} in \lt_p{set}.

    \lt_p{*stream_info} remains valid as long as \lt_p{set} exists.
    @endparblock

@retval #LTTNG_DATA_STREAM_INFO_STATUS_OK
    Success.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    - \lt_p{index} is less than the number of data stream infos
      in \lt_p{set} (as given by
      lttng_data_stream_info_set_get_count()).
    @lt_pre_not_null{stream_info}
*/
extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_at_index(const struct lttng_data_stream_info_set *set,
					unsigned int index,
					const struct lttng_data_stream_info **stream_info);

/*!
@brief
    Sets \lt_p{*uid} to the Unix user ID of the owner of the data
    streams of the data stream info set \lt_p{set}.

If \lt_p{set} represents
\ref api-channel-per-proc-buf "per-process" data streams, then the
owner is a process and this function returns
#LTTNG_DATA_STREAM_INFO_STATUS_NONE.

@param[in] set
    Data stream info set of which to get the ID of
    the owning Unix user.
@param[out] uid
    <strong>On success</strong>, this function sets \lt_p{*uid} to the
    ID of the Unix user owning the data streams of \lt_p{set}.

@retval #LTTNG_DATA_STREAM_INFO_STATUS_OK
    Success.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_NONE
    \lt_p{set} isn't owned by a Unix user.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    @lt_pre_not_null{uid}
*/
extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_uid(const struct lttng_data_stream_info_set *set, uid_t *uid);

/*!
@brief
    Sets \lt_p{*bitness} to the application bitness of the data
    streams of the data stream set \lt_p{set}.

@param[in] set
    Data stream set for which to get the application bitness.
@param[out] bitness
    <strong>On success</strong>, this function sets \lt_p{*bitness} to
    the application bitness of the data streams of \lt_p{set}.

@retval #LTTNG_DATA_STREAM_INFO_STATUS_OK
    Success.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    @lt_pre_not_null{bitness}
*/
extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_app_bitness(const struct lttng_data_stream_info_set *set,
					   enum lttng_app_bitness *bitness);

/*!
@brief
    Sets \lt_p{*pid} to the process ID of the owner of the data
    streams of the data stream info set \lt_p{set}.

If \lt_p{set} represents
\ref api-channel-per-user-buf "per-user" data streams, then the
owner is a Unix user and this function returns
#LTTNG_DATA_STREAM_INFO_STATUS_NONE.

@param[in] set
    Data stream info set of which to get the ID of the owning process.
@param[out] pid
    <strong>On success</strong>, this function sets \lt_p{*pid} to the
    ID of the owning process of the data streams of \lt_p{set}.

@retval #LTTNG_DATA_STREAM_INFO_STATUS_OK
    Success.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_NONE
    \lt_p{set} isn't owned by a process.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{set}
    @lt_pre_not_null{pid}
*/
extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_set_get_pid(const struct lttng_data_stream_info_set *set, pid_t *pid);

/*!
@struct lttng_data_stream_info_sets

@brief
    Set of data stream info sets (opaque type).
*/
struct lttng_data_stream_info_sets;

/*!
@brief
    Sets \lt_p{*count} to the number of data stream info sets in the
    set of data stream info sets \lt_p{sets}.

@param[in] sets
    Set of data stream info sets of which to get the count.
@param[out] count
    <strong>On success</strong>, this function sets \lt_p{*count} to the
    number of data stream info sets in \lt_p{sets}.

@retval #LTTNG_DATA_STREAM_INFO_STATUS_OK
    Success.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{sets}
    @lt_pre_not_null{count}

@sa lttng_data_stream_info_sets_get_at_index() --
    Get a data stream info set from a set of data stream info sets
    by index.
*/
extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_sets_get_count(const struct lttng_data_stream_info_sets *sets,
				      unsigned int *count);

/*!
@brief
    Sets \lt_p{*set} to the data stream info set at the
    index \lt_p{index} in the set of data stream info sets \lt_p{sets}.

@param[in] sets
    Set of data stream info sets from which to get the data stream info
    set at the index \lt_p{index}.
@param[in] index
    Index of the data stream info set to get from \lt_p{sets}.
@param[out] set
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*set}
    to the data stream info set at the index \lt_p{index}
    in \lt_p{sets}.

    \lt_p{*set} remains valid as long as \lt_p{sets} exists.
    @endparblock

@retval #LTTNG_DATA_STREAM_INFO_STATUS_OK
    Success.
@retval #LTTNG_DATA_STREAM_INFO_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.

@pre
    @lt_pre_not_null{sets}
    - \lt_p{index} is less than the number of data stream info sets
      in \lt_p{sets} (as given by
      lttng_data_stream_info_sets_get_count()).
    @lt_pre_not_null{set}
*/
extern LTTNG_EXPORT enum lttng_data_stream_info_status
lttng_data_stream_info_sets_get_at_index(const struct lttng_data_stream_info_sets *sets,
					 unsigned int index,
					 const struct lttng_data_stream_info_set **set);

/*!
@brief
    Destroys the set of data stream info sets \lt_p{sets}.

@param[in] sets
    @parblock
    Set of data stream info sets to destroy.

    May be \c NULL.
    @endparblock
*/
extern LTTNG_EXPORT void
lttng_data_stream_info_sets_destroy(const struct lttng_data_stream_info_sets *sets);

/// @}

/*!
@brief
    Return type of lttng_channel_get_data_stream_info_sets().

@ingroup api_channel

Error status enumerators have a negative value.
*/
enum lttng_channel_get_data_stream_info_sets_status {
	/// Success.
	LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK = 0,

	/// Other error.
	LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_ERROR = -1,

	/// Unsatisfied precondition.
	LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_INVALID_PARAMETER = -2,
	LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_UNSUPPORTED_DOMAIN = -3,
};

/*!
@brief
    Retrieves data stream info sets for the channel named
    \lt_p{channel_name} in the recording session named
    \lt_p{session_name} and tracing domain \lt_p{domain}.

@ingroup api_channel

Only user space domains are supported. The content and availability of
memory usage information may vary depending on tracer support.

@param[in] session_name
    Name of the recording session which contains the targeted channel.
@param[in] channel_name
    Name of the channel for which to get data stream info sets.
@param[in] domain
    Tracing domain of the targeted channel for which to get data stream
    info sets.
@param[out] sets
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*sets} to a
    the data stream information sets for the targeted channel.

    Destroy \lt_p{*sets} with lttng_data_stream_info_sets_destroy().
    @endparblock

@retval #LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_OK
    Success.
@retval #LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_INVALID_PARAMETER
    Unsatisfied precondition.
@retval #LTTNG_CHANNEL_GET_DATA_STREAM_INFO_SETS_STATUS_ERROR
    Other error.

@pre
    @lt_pre_conn
    @lt_pre_not_null{session_name}
    @lt_pre_sess_exists{session_name}
    @lt_pre_not_null{channel_name}
    - \lt_p{domain} is one of #LTTNG_DOMAIN_UST, #LTTNG_DOMAIN_JUL,
      #LTTNG_DOMAIN_LOG4J, #LTTNG_DOMAIN_LOG4J2,
      or #LTTNG_DOMAIN_PYTHON.
    @lt_pre_not_null{sets}
*/
extern LTTNG_EXPORT enum lttng_channel_get_data_stream_info_sets_status
lttng_channel_get_data_stream_info_sets(const char *session_name,
					const char *channel_name,
					enum lttng_domain_type domain,
					const struct lttng_data_stream_info_sets **sets);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_STREAM_INFO_H */
