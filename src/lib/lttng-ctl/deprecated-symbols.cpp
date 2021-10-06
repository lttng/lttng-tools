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

LTTNG_EXPORT const char *config_element_pid_tracker = nullptr;
LTTNG_EXPORT const char *config_element_target_pid = nullptr;
LTTNG_EXPORT const char *config_element_targets = nullptr;
LTTNG_EXPORT const char *config_element_trackers = nullptr;
