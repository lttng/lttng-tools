/*
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stddef.h>

/*
 * These are symbols that were erroneously exposed and have since been removed.
 */

size_t default_channel_subbuf_size;
size_t default_kernel_channel_subbuf_size;
size_t default_metadata_subbuf_size;
size_t default_ust_pid_channel_subbuf_size;
size_t default_ust_uid_channel_subbuf_size;

const char * const config_element_pid_tracker;
const char * const config_element_target_pid;
const char * const config_element_targets;
const char * const config_element_trackers;
