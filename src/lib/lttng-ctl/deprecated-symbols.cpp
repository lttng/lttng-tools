/*
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <lttng/lttng-export.h>

#include <stddef.h>

/*
 * These are symbols that were erroneously exposed and have since been removed.
 */

LTTNG_EXPORT size_t default_channel_subbuf_size;
LTTNG_EXPORT size_t default_kernel_channel_subbuf_size;
LTTNG_EXPORT size_t default_metadata_subbuf_size;
LTTNG_EXPORT size_t default_ust_pid_channel_subbuf_size;
LTTNG_EXPORT size_t default_ust_uid_channel_subbuf_size;

#ifdef __cplusplus
extern "C" {
#endif

LTTNG_EXPORT extern const char *const config_element_perf;
LTTNG_EXPORT extern const char *const config_element_pid_tracker;
LTTNG_EXPORT extern const char *const config_element_target_pid;
LTTNG_EXPORT extern const char *const config_element_targets;
LTTNG_EXPORT extern const char *const config_element_trackers;

const char *const config_element_perf = nullptr;
const char *const config_element_pid_tracker = nullptr;
const char *const config_element_target_pid = nullptr;
const char *const config_element_targets = nullptr;
const char *const config_element_trackers = nullptr;

struct log_time {
	char str[19];
};

LTTNG_EXPORT thread_local struct log_time error_log_time = {};

#ifdef __cplusplus
}
#endif
