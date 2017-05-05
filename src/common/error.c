/*
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <lttng/lttng-error.h>
#include <common/common.h>
#include <common/compat/getenv.h>

#include "error.h"

#define ERROR_INDEX(code) (code - LTTNG_OK)

/*
 * lttng_opt_abort_on_error: unset: -1, disabled: 0, enabled: 1.
 * Controlled by the LTTNG_ABORT_ON_ERROR environment variable.
 */
static int lttng_opt_abort_on_error = -1;

/* TLS variable that contains the time of one single log entry. */
DEFINE_URCU_TLS(struct log_time, error_log_time);

LTTNG_HIDDEN
const char *log_add_time(void)
{
	int ret;
	struct tm tm, *res;
	struct timespec tp;
	time_t now;

	ret = lttng_clock_gettime(CLOCK_REALTIME, &tp);
	if (ret < 0) {
		goto error;
	}
	now = (time_t) tp.tv_sec;

	res = localtime_r(&now, &tm);
	if (!res) {
		goto error;
	}

	/* Format time in the TLS variable. */
	ret = snprintf(URCU_TLS(error_log_time).str, sizeof(URCU_TLS(error_log_time).str),
			"%02d:%02d:%02d.%06ld",
			tm.tm_hour, tm.tm_min, tm.tm_sec, tp.tv_nsec);
	if (ret < 0) {
		goto error;
	}

	return URCU_TLS(error_log_time).str;

error:
	/* Return an empty string on error so logging is not affected. */
	return "";
}

/*
 * Human readable error message.
 */
static const char *error_string_array[] = {
	/* LTTNG_OK code MUST be at the top for the ERROR_INDEX macro to work */
	[ ERROR_INDEX(LTTNG_OK) ] = "Success",
	[ ERROR_INDEX(LTTNG_ERR_UNK) ] = "Unknown error",
	[ ERROR_INDEX(LTTNG_ERR_UND) ] = "Undefined command",
	[ ERROR_INDEX(LTTNG_ERR_UNKNOWN_DOMAIN) ] = "Unknown tracing domain",
	[ ERROR_INDEX(LTTNG_ERR_NO_SESSION) ] = "No session found",
	[ ERROR_INDEX(LTTNG_ERR_CREATE_DIR_FAIL) ] = "Create directory failed",
	[ ERROR_INDEX(LTTNG_ERR_SESSION_FAIL) ] = "Create session failed",
	[ ERROR_INDEX(LTTNG_ERR_SESS_NOT_FOUND) ] = "Session name not found",
	[ ERROR_INDEX(LTTNG_ERR_FATAL) ] = "Fatal error of the session daemon",
	[ ERROR_INDEX(LTTNG_ERR_SELECT_SESS) ] = "A session MUST be selected",
	[ ERROR_INDEX(LTTNG_ERR_EXIST_SESS) ] = "Session name already exists",
	[ ERROR_INDEX(LTTNG_ERR_NO_EVENT) ] = "Event not found",
	[ ERROR_INDEX(LTTNG_ERR_CONNECT_FAIL) ] = "Unable to connect to Unix socket",
	[ ERROR_INDEX(LTTNG_ERR_EPERM) ] = "Permission denied",
	[ ERROR_INDEX(LTTNG_ERR_KERN_NA) ] = "Kernel tracer not available",
	[ ERROR_INDEX(LTTNG_ERR_KERN_VERSION) ] = "Kernel tracer version is not compatible",
	[ ERROR_INDEX(LTTNG_ERR_KERN_EVENT_EXIST) ] = "Kernel event already exists",
	[ ERROR_INDEX(LTTNG_ERR_KERN_SESS_FAIL) ] = "Kernel create session failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_CHAN_EXIST) ] = "Kernel channel already exists",
	[ ERROR_INDEX(LTTNG_ERR_KERN_CHAN_FAIL) ] = "Kernel create channel failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_CHAN_NOT_FOUND) ] = "Kernel channel not found",
	[ ERROR_INDEX(LTTNG_ERR_KERN_CHAN_DISABLE_FAIL) ] = "Disable kernel channel failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_CHAN_ENABLE_FAIL) ] = "Enable kernel channel failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_CONTEXT_FAIL) ] = "Add kernel context failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_ENABLE_FAIL) ] = "Enable kernel event failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_DISABLE_FAIL) ] = "Disable kernel event failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_META_FAIL) ] = "Opening metadata failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_START_FAIL) ] = "Starting kernel trace failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_STOP_FAIL) ] = "Stopping kernel trace failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_CONSUMER_FAIL) ] = "Kernel consumer start failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_STREAM_FAIL) ] = "Kernel create stream failed",
	[ ERROR_INDEX(LTTNG_ERR_KERN_LIST_FAIL) ] = "Listing kernel events failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_CALIBRATE_FAIL) ] = "UST calibration failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_SESS_FAIL) ] = "UST create session failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_CHAN_FAIL) ] = "UST create channel failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_CHAN_EXIST) ] = "UST channel already exist",
	[ ERROR_INDEX(LTTNG_ERR_UST_CHAN_NOT_FOUND) ] = "UST channel not found",
	[ ERROR_INDEX(LTTNG_ERR_UST_CHAN_DISABLE_FAIL) ] = "Disable UST channel failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_CHAN_ENABLE_FAIL) ] = "Enable UST channel failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_ENABLE_FAIL) ] = "Enable UST event failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_DISABLE_FAIL) ] = "Disable UST event failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_META_FAIL) ] = "Opening metadata failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_START_FAIL) ] = "Starting UST trace failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_STOP_FAIL) ] = "Stopping UST trace failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_CONSUMER64_FAIL) ] = "64-bit UST consumer start failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_CONSUMER32_FAIL) ] = "32-bit UST consumer start failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_STREAM_FAIL) ] = "UST create stream failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_LIST_FAIL) ] = "Listing UST events failed",
	[ ERROR_INDEX(LTTNG_ERR_UST_EVENT_EXIST) ] = "UST event already exist",
	[ ERROR_INDEX(LTTNG_ERR_UST_EVENT_NOT_FOUND)] = "UST event not found",
	[ ERROR_INDEX(LTTNG_ERR_UST_CONTEXT_EXIST)] = "UST context already exist",
	[ ERROR_INDEX(LTTNG_ERR_UST_CONTEXT_INVAL)] = "UST invalid context",
	[ ERROR_INDEX(LTTNG_ERR_NEED_ROOT_SESSIOND) ] = "Tracing the kernel requires a root lttng-sessiond daemon, as well as \"tracing\" group membership or root user ID for the lttng client.",
	[ ERROR_INDEX(LTTNG_ERR_NO_UST) ] = "LTTng-UST tracer is not supported. Please rebuild lttng-tools with lttng-ust support enabled.",
	[ ERROR_INDEX(LTTNG_ERR_TRACE_ALREADY_STARTED) ] = "Tracing has already been started once",
	[ ERROR_INDEX(LTTNG_ERR_TRACE_ALREADY_STOPPED) ] = "Tracing has already been stopped",
	[ ERROR_INDEX(LTTNG_ERR_KERN_EVENT_ENOSYS) ] = "Kernel event type not supported",
	[ ERROR_INDEX(LTTNG_ERR_NEED_CHANNEL_NAME) ] = "Non-default channel exists within session: channel name needs to be specified with '-c name'",
	[ ERROR_INDEX(LTTNG_ERR_INVALID) ] = "Invalid parameter",
	[ ERROR_INDEX(LTTNG_ERR_NO_USTCONSUMERD) ] = "No UST consumer detected",
	[ ERROR_INDEX(LTTNG_ERR_NO_KERNCONSUMERD) ] = "No kernel consumer detected",
	[ ERROR_INDEX(LTTNG_ERR_EVENT_EXIST_LOGLEVEL) ] = "Event already enabled with different loglevel",
	[ ERROR_INDEX(LTTNG_ERR_URL_DATA_MISS) ] = "Missing data path URL",
	[ ERROR_INDEX(LTTNG_ERR_URL_CTRL_MISS) ] = "Missing control path URL",
	[ ERROR_INDEX(LTTNG_ERR_ENABLE_CONSUMER_FAIL) ] = "Enabling consumer failed",
	[ ERROR_INDEX(LTTNG_ERR_RELAYD_CONNECT_FAIL) ] = "Unable to connect to lttng-relayd",
	[ ERROR_INDEX(LTTNG_ERR_RELAYD_VERSION_FAIL) ] = "Relay daemon not compatible",
	[ ERROR_INDEX(LTTNG_ERR_FILTER_INVAL) ] = "Invalid filter bytecode",
	[ ERROR_INDEX(LTTNG_ERR_FILTER_NOMEM) ] = "Not enough memory for filter bytecode",
	[ ERROR_INDEX(LTTNG_ERR_FILTER_EXIST) ] = "Filter already exist",
	[ ERROR_INDEX(LTTNG_ERR_NO_CONSUMER) ] = "Consumer not found for tracing session",
	[ ERROR_INDEX(LTTNG_ERR_NO_SESSIOND) ] = "No session daemon is available",
	[ ERROR_INDEX(LTTNG_ERR_SESSION_STARTED) ] = "Session is running",
	[ ERROR_INDEX(LTTNG_ERR_NOT_SUPPORTED) ] = "Operation not supported",
	[ ERROR_INDEX(LTTNG_ERR_UST_EVENT_ENABLED) ] = "UST event already enabled",
	[ ERROR_INDEX(LTTNG_ERR_SET_URL) ] = "Error setting URL",
	[ ERROR_INDEX(LTTNG_ERR_URL_EXIST) ] = "URL already exists",
	[ ERROR_INDEX(LTTNG_ERR_BUFFER_NOT_SUPPORTED)] = "Buffer type not supported",
	[ ERROR_INDEX(LTTNG_ERR_BUFFER_TYPE_MISMATCH)] = "Buffer type mismatch for session",
	[ ERROR_INDEX(LTTNG_ERR_NOMEM)] = "Not enough memory",
	[ ERROR_INDEX(LTTNG_ERR_SNAPSHOT_OUTPUT_EXIST) ] = "Snapshot output already exists",
	[ ERROR_INDEX(LTTNG_ERR_START_SESSION_ONCE) ] = "Session needs to be started once",
	[ ERROR_INDEX(LTTNG_ERR_SNAPSHOT_FAIL) ] = "Snapshot record failed",
	[ ERROR_INDEX(LTTNG_ERR_CHAN_EXIST) ] = "Channel already exists",
	[ ERROR_INDEX(LTTNG_ERR_SNAPSHOT_NODATA) ] = "No data available in snapshot",
	[ ERROR_INDEX(LTTNG_ERR_NO_CHANNEL) ] = "No channel found in the session",
	[ ERROR_INDEX(LTTNG_ERR_SESSION_INVALID_CHAR) ] = "Invalid character found in session name",
	[ ERROR_INDEX(LTTNG_ERR_SAVE_FILE_EXIST) ] = "Session file already exists",
	[ ERROR_INDEX(LTTNG_ERR_SAVE_IO_FAIL) ] = "IO error while writing session configuration",
	[ ERROR_INDEX(LTTNG_ERR_LOAD_INVALID_CONFIG) ] = "Invalid session configuration",
	[ ERROR_INDEX(LTTNG_ERR_LOAD_IO_FAIL) ] = "IO error while reading a session configuration",
	[ ERROR_INDEX(LTTNG_ERR_LOAD_SESSION_NOENT) ] = "Session file not found",
	[ ERROR_INDEX(LTTNG_ERR_MAX_SIZE_INVALID) ] = "Snapshot max size is invalid",
	[ ERROR_INDEX(LTTNG_ERR_MI_OUTPUT_TYPE) ] = "Invalid MI output format",
	[ ERROR_INDEX(LTTNG_ERR_MI_IO_FAIL) ] = "IO error while writing MI output",
	[ ERROR_INDEX(LTTNG_ERR_MI_NOT_IMPLEMENTED) ] = "Mi feature not implemented",
	[ ERROR_INDEX(LTTNG_ERR_INVALID_EVENT_NAME) ] = "Invalid event name",
	[ ERROR_INDEX(LTTNG_ERR_INVALID_CHANNEL_NAME) ] = "Invalid channel name",
	[ ERROR_INDEX(LTTNG_ERR_PID_TRACKED) ] = "PID already tracked",
	[ ERROR_INDEX(LTTNG_ERR_PID_NOT_TRACKED) ] = "PID not tracked",
	[ ERROR_INDEX(LTTNG_ERR_INVALID_CHANNEL_DOMAIN) ] = "Invalid channel domain",
	[ ERROR_INDEX(LTTNG_ERR_OVERFLOW) ] = "Overflow occurred",
	[ ERROR_INDEX(LTTNG_ERR_SESSION_NOT_STARTED) ] = "Session not started",
	[ ERROR_INDEX(LTTNG_ERR_LIVE_SESSION) ] = "Live sessions are not supported",
	[ ERROR_INDEX(LTTNG_ERR_PER_PID_SESSION) ] = "Per-PID tracing sessions are not supported",
	[ ERROR_INDEX(LTTNG_ERR_KERN_CONTEXT_UNAVAILABLE) ] = "Context unavailable on this kernel",
	[ ERROR_INDEX(LTTNG_ERR_REGEN_STATEDUMP_FAIL) ] = "Failed to regenerate the state dump",
	[ ERROR_INDEX(LTTNG_ERR_REGEN_STATEDUMP_NOMEM) ] = "Failed to regenerate the state dump, not enough memory",
	[ ERROR_INDEX(LTTNG_ERR_NOT_SNAPSHOT_SESSION) ] = "Snapshot command can't be applied to a non-snapshot session",
	[ ERROR_INDEX(LTTNG_ERR_INVALID_TRIGGER) ] = "Invalid trigger",
	[ ERROR_INDEX(LTTNG_ERR_TRIGGER_EXISTS) ] = "Trigger already registered",
	[ ERROR_INDEX(LTTNG_ERR_TRIGGER_NOT_FOUND) ] = "Trigger not found",
	[ ERROR_INDEX(LTTNG_ERR_COMMAND_CANCELLED) ] = "Command cancelled",

	/* Last element */
	[ ERROR_INDEX(LTTNG_ERR_NR) ] = "Unknown error code"
};

/*
 * Return ptr to string representing a human readable error code from the
 * lttng_error_code enum.
 *
 * These code MUST be negative in other to treat that as an error value.
 */
LTTNG_HIDDEN
const char *error_get_str(int32_t code)
{
	code = -code;

	if (code < LTTNG_OK || code > LTTNG_ERR_NR) {
		code = LTTNG_ERR_NR;
	}

	return error_string_array[ERROR_INDEX(code)];
}

LTTNG_HIDDEN
void lttng_abort_on_error(void)
{
	if (lttng_opt_abort_on_error < 0) {
		/* Use lttng_secure_getenv() to query its state. */
		const char *value;

		value = lttng_secure_getenv("LTTNG_ABORT_ON_ERROR");
		if (value && !strcmp(value, "1")) {
			lttng_opt_abort_on_error = 1;
		} else {
			lttng_opt_abort_on_error = 0;
		}
	}
	if (lttng_opt_abort_on_error > 0) {
		abort();
	}
}
