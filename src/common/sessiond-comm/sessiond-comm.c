/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <common/defaults.h>
#include <common/error.h>

#include "sessiond-comm.h"

/*
 * Human readable error message.
 */
static const char *lttcomm_readable_code[] = {
	[ LTTCOMM_ERR_INDEX(LTTCOMM_OK) ] = "Success",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_ERR) ] = "Unknown error",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UND) ] = "Undefined command",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NOT_IMPLEMENTED) ] = "Not implemented",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UNKNOWN_DOMAIN) ] = "Unknown tracing domain",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_SESSION) ] = "No session found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_LIST_FAIL) ] = "Unable to list traceable apps",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_APPS) ] = "No traceable apps found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_SESS_NOT_FOUND) ] = "Session name not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_TRACE) ] = "No trace found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_FATAL) ] = "Fatal error of the session daemon",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CREATE_DIR_FAIL) ] = "Create directory failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_START_FAIL) ] = "Start trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_STOP_FAIL) ] = "Stop trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_TRACEABLE) ] = "App is not traceable",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_SELECT_SESS) ] = "A session MUST be selected",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_EXIST_SESS) ] = "Session name already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_CONNECT_FAIL) ] = "Unable to connect to Unix socket",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_APP_NOT_FOUND) ] = "Application not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_EPERM) ] = "Permission denied",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_NA) ] = "Kernel tracer not available",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_VERSION) ] = "Kernel tracer version is not compatible",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_EVENT_EXIST) ] = "Kernel event already exists",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_SESS_FAIL) ] = "Kernel create session failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CHAN_EXIST) ] = "Kernel channel already exists",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CHAN_FAIL) ] = "Kernel create channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CHAN_NOT_FOUND) ] = "Kernel channel not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CHAN_DISABLE_FAIL) ] = "Disable kernel channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CHAN_ENABLE_FAIL) ] = "Enable kernel channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CONTEXT_FAIL) ] = "Add kernel context failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_ENABLE_FAIL) ] = "Enable kernel event failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_DISABLE_FAIL) ] = "Disable kernel event failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_META_FAIL) ] = "Opening metadata failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_START_FAIL) ] = "Starting kernel trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_STOP_FAIL) ] = "Stoping kernel trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_CONSUMER_FAIL) ] = "Kernel consumer start failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_STREAM_FAIL) ] = "Kernel create stream failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_DIR_FAIL) ] = "Kernel trace directory creation failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_DIR_EXIST) ] = "Kernel trace directory already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_NO_SESSION) ] = "No kernel session found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_LIST_FAIL) ] = "Listing kernel events failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CALIBRATE_FAIL) ] = "UST calibration failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_VERSION) ] = "UST tracer version is not compatible",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_SESS_FAIL) ] = "UST create session failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_FAIL) ] = "UST create channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_EXIST) ] = "UST channel already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_NOT_FOUND) ] = "UST channel not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_DISABLE_FAIL) ] = "Disable UST channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CHAN_ENABLE_FAIL) ] = "Enable UST channel failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONTEXT_FAIL) ] = "Add UST context failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_ENABLE_FAIL) ] = "Enable UST event failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_DISABLE_FAIL) ] = "Disable UST event failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_META_FAIL) ] = "Opening metadata failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_START_FAIL) ] = "Starting UST trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_STOP_FAIL) ] = "Stoping UST trace failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONSUMER64_FAIL) ] = "64-bit UST consumer start failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONSUMER32_FAIL) ] = "32-bit UST consumer start failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_STREAM_FAIL) ] = "UST create stream failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_DIR_FAIL) ] = "UST trace directory creation failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_DIR_EXIST) ] = "UST trace directory already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_NO_SESSION) ] = "No UST session found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_LIST_FAIL) ] = "Listing UST events failed",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_EVENT_EXIST) ] = "UST event already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_EVENT_NOT_FOUND)] = "UST event not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONTEXT_EXIST)] = "UST context already exist",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_UST_CONTEXT_INVAL)] = "UST invalid context",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NEED_ROOT_SESSIOND) ] = "Tracing the kernel requires a root lttng-sessiond daemon and \"tracing\" group user membership",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_TRACE_ALREADY_STARTED) ] = "Tracing already started",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_TRACE_ALREADY_STOPPED) ] = "Tracing already stopped",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_KERN_EVENT_ENOSYS) ] = "Kernel event type not supported",

	[ LTTCOMM_ERR_INDEX(CONSUMERD_COMMAND_SOCK_READY) ] = "consumerd command socket ready",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SUCCESS_RECV_FD) ] = "consumerd success on receiving fds",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_ERROR_RECV_FD) ] = "consumerd error on receiving fds",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_ERROR_RECV_CMD) ] = "consumerd error on receiving command",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_POLL_ERROR) ] = "consumerd error in polling thread",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_POLL_NVAL) ] = "consumerd polling on closed fd",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_POLL_HUP) ] = "consumerd all fd hung up",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_EXIT_SUCCESS) ] = "consumerd exiting normally",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_EXIT_FAILURE) ] = "consumerd exiting on error",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_OUTFD_ERROR) ] = "consumerd error opening the tracefile",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SPLICE_EBADF) ] = "consumerd splice EBADF",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SPLICE_EINVAL) ] = "consumerd splice EINVAL",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SPLICE_ENOMEM) ] = "consumerd splice ENOMEM",
	[ LTTCOMM_ERR_INDEX(CONSUMERD_SPLICE_ESPIPE) ] = "consumerd splice ESPIPE",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_EVENT) ] = "Event not found",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_INVALID) ] = "Invalid parameter",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_USTCONSUMERD) ] = "No UST consumer detected",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_NO_KERNCONSUMERD) ] = "No kernel consumer detected",
	[ LTTCOMM_ERR_INDEX(LTTCOMM_EVENT_EXIST_LOGLEVEL) ] = "Event already enabled with different loglevel",
};

/*
 * Return ptr to string representing a human readable error code from the
 * lttcomm_return_code enum.
 *
 * These code MUST be negative in other to treat that as an error value.
 */
const char *lttcomm_get_readable_code(enum lttcomm_return_code code)
{
	int tmp_code = -code;

	if (tmp_code >= LTTCOMM_OK && tmp_code < LTTCOMM_NR) {
		return lttcomm_readable_code[LTTCOMM_ERR_INDEX(tmp_code)];
	}

	return "Unknown error code";
}
