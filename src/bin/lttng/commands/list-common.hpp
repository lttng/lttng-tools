/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2020 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_LIST_COMMON_HPP
#define LTTNG_LIST_COMMON_HPP

#include "../command.hpp"

#include <common/tracker.hpp>
#include <common/utils.hpp>

#include <lttng/lttng.h>
#include <lttng/tracker.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

/*
 * Get command line from /proc for a specific pid.
 *
 * On success, return an allocated string pointer to the proc cmdline.
 * On error, return NULL.
 */
static inline char *get_cmdline_by_pid(pid_t pid)
{
	int ret;
	FILE *fp = nullptr;
	char *cmdline = nullptr;
	/* Can't go bigger than /proc/LTTNG_MAX_PID/cmdline */
	char path[sizeof("/proc//cmdline") + sizeof(LTTNG_MAX_PID_STR) - 1];

	snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
	fp = fopen(path, "r");
	if (fp == nullptr) {
		goto end;
	}

	/* Caller must free() *cmdline */
	cmdline = zmalloc<char>(PATH_MAX);
	if (!cmdline) {
		PERROR("malloc cmdline");
		goto end;
	}

	ret = fread(cmdline, 1, PATH_MAX, fp);
	if (ret < 0) {
		PERROR("fread proc list");
	}

end:
	if (fp) {
		fclose(fp);
	}
	return cmdline;
}

/*
 * Handle the status returned by lttng_process_attr_tracker_handle operations.
 *
 * Returns CMD_SUCCESS if the status indicates success or a benign condition,
 * CMD_ERROR otherwise. Logs appropriate error messages for failure cases.
 */
static inline int handle_process_attr_status(enum lttng_process_attr process_attr,
					     enum lttng_process_attr_tracker_handle_status status,
					     const char *session_name)
{
	int ret = CMD_SUCCESS;

	switch (status) {
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_INVALID_TRACKING_POLICY:
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_OK:
		/* Carry on. */
		break;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_COMMUNICATION_ERROR:
		ERR("Communication error occurred while fetching %s tracker",
		    lttng_process_attr_to_string(process_attr));
		ret = CMD_ERROR;
		break;
	case LTTNG_PROCESS_ATTR_TRACKER_HANDLE_STATUS_SESSION_DOES_NOT_EXIST:
		ERR("Failed to get the inclusion set of the %s tracker: session `%s` no longer exists",
		    lttng_process_attr_to_string(process_attr),
		    session_name);
		ret = CMD_ERROR;
		break;
	default:
		ERR("Unknown error occurred while fetching the inclusion set of the %s tracker",
		    lttng_process_attr_to_string(process_attr));
		ret = CMD_ERROR;
		break;
	}

	return ret;
}

#endif /* LTTNG_LIST_COMMON_HPP */
