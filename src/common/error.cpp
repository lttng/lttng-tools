/*
 * Copyright (C) 2012 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#define _LGPL_SOURCE
#include "error.hpp"

#include <common/common.hpp>
#include <common/compat/errno.hpp>
#include <common/compat/getenv.hpp>
#include <common/thread.hpp>

#include <lttng/lttng-error.h>

#include <inttypes.h>
#include <iostream>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

namespace {
/*
 * lttng_opt_abort_on_error: unset: -1, disabled: 0, enabled: 1.
 * Controlled by the LTTNG_ABORT_ON_ERROR environment variable.
 */
int lttng_opt_abort_on_error = -1;

/* TLS variable that contains the time of one single log entry. */
thread_local struct log_time error_log_time;
} /* namespace */

thread_local const char *logger_thread_name;

const char *log_add_time()
{
	int ret;
	struct tm tm, *res;
	struct timespec tp;
	time_t now;
	const int errsv = errno;

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
	ret = snprintf(error_log_time.str,
		       sizeof(error_log_time.str),
		       "%02d:%02d:%02d.%09ld",
		       tm.tm_hour,
		       tm.tm_min,
		       tm.tm_sec,
		       tp.tv_nsec);
	if (ret < 0) {
		goto error;
	}

	errno = errsv;
	return error_log_time.str;

error:
	/* Return an empty string on error so logging is not affected. */
	errno = errsv;
	return "";
}

void logger_set_thread_name(const char *name, bool set_pthread_name)
{
	int ret;

	LTTNG_ASSERT(name);
	logger_thread_name = name;

	if (set_pthread_name) {
		ret = lttng_thread_setname(name);
		if (ret && ret != -ENOSYS) {
			/* Don't fail as this is not essential. */
			DBG("Failed to set pthread name attribute");
		}
	}
}

/*
 * Human readable error message.
 */
static const char *lttng_error_code_str(lttng_error_code code)
{
	switch (code) {
	case LTTNG_OK:
		return "Success";
	case LTTNG_ERR_UNK:
		return "Unknown error";
	case LTTNG_ERR_UND:
		return "Undefined command";
	case LTTNG_ERR_UNKNOWN_DOMAIN:
		return "Unknown tracing domain";
	case LTTNG_ERR_NO_SESSION:
		return "No session found";
	case LTTNG_ERR_CREATE_DIR_FAIL:
		return "Create directory failed";
	case LTTNG_ERR_SESSION_FAIL:
		return "Create session failed";
	case LTTNG_ERR_SESS_NOT_FOUND:
		return "Session name not found";
	case LTTNG_ERR_FATAL:
		return "Fatal error of the session daemon";
	case LTTNG_ERR_SELECT_SESS:
		return "A session MUST be selected";
	case LTTNG_ERR_EXIST_SESS:
		return "Session name already exists";
	case LTTNG_ERR_NO_EVENT:
		return "Event not found";
	case LTTNG_ERR_CONNECT_FAIL:
		return "Unable to connect to Unix socket";
	case LTTNG_ERR_EPERM:
		return "Permission denied";
	case LTTNG_ERR_KERN_NA:
		return "Kernel tracer not available";
	case LTTNG_ERR_KERN_VERSION:
		return "Kernel tracer version is not compatible";
	case LTTNG_ERR_KERN_EVENT_EXIST:
		return "Kernel event already exists";
	case LTTNG_ERR_KERN_SESS_FAIL:
		return "Kernel create session failed";
	case LTTNG_ERR_KERN_CHAN_EXIST:
		return "Kernel channel already exists";
	case LTTNG_ERR_KERN_CHAN_FAIL:
		return "Kernel create channel failed";
	case LTTNG_ERR_KERN_CHAN_NOT_FOUND:
		return "Kernel channel not found";
	case LTTNG_ERR_KERN_CHAN_DISABLE_FAIL:
		return "Disable kernel channel failed";
	case LTTNG_ERR_KERN_CHAN_ENABLE_FAIL:
		return "Enable kernel channel failed";
	case LTTNG_ERR_KERN_CONTEXT_FAIL:
		return "Add kernel context failed";
	case LTTNG_ERR_KERN_ENABLE_FAIL:
		return "Enable kernel event failed";
	case LTTNG_ERR_KERN_DISABLE_FAIL:
		return "Disable kernel event failed";
	case LTTNG_ERR_KERN_META_FAIL:
		return "Opening metadata failed";
	case LTTNG_ERR_KERN_START_FAIL:
		return "Starting kernel trace failed";
	case LTTNG_ERR_KERN_STOP_FAIL:
		return "Stopping kernel trace failed";
	case LTTNG_ERR_KERN_CONSUMER_FAIL:
		return "Kernel consumer start failed";
	case LTTNG_ERR_KERN_STREAM_FAIL:
		return "Kernel create stream failed";
	case LTTNG_ERR_KERN_LIST_FAIL:
		return "Listing kernel events failed";
	case LTTNG_ERR_UST_CALIBRATE_FAIL:
		return "UST calibration failed";
	case LTTNG_ERR_UST_SESS_FAIL:
		return "UST create session failed";
	case LTTNG_ERR_UST_CHAN_FAIL:
		return "UST create channel failed";
	case LTTNG_ERR_UST_CHAN_EXIST:
		return "UST channel already exist";
	case LTTNG_ERR_UST_CHAN_NOT_FOUND:
		return "UST channel not found";
	case LTTNG_ERR_UST_CHAN_DISABLE_FAIL:
		return "Disable UST channel failed";
	case LTTNG_ERR_UST_CHAN_ENABLE_FAIL:
		return "Enable UST channel failed";
	case LTTNG_ERR_UST_ENABLE_FAIL:
		return "Enable UST event failed";
	case LTTNG_ERR_UST_DISABLE_FAIL:
		return "Disable UST event failed";
	case LTTNG_ERR_UST_META_FAIL:
		return "Opening metadata failed";
	case LTTNG_ERR_UST_START_FAIL:
		return "Starting UST trace failed";
	case LTTNG_ERR_UST_STOP_FAIL:
		return "Stopping UST trace failed";
	case LTTNG_ERR_UST_CONSUMER64_FAIL:
		return "64-bit UST consumer start failed";
	case LTTNG_ERR_UST_CONSUMER32_FAIL:
		return "32-bit UST consumer start failed";
	case LTTNG_ERR_UST_STREAM_FAIL:
		return "UST create stream failed";
	case LTTNG_ERR_UST_LIST_FAIL:
		return "Listing UST events failed";
	case LTTNG_ERR_UST_EVENT_EXIST:
		return "UST event already exist";
	case LTTNG_ERR_UST_EVENT_NOT_FOUND:
		return "UST event not found";
	case LTTNG_ERR_UST_CONTEXT_EXIST:
		return "UST context already exist";
	case LTTNG_ERR_UST_CONTEXT_INVAL:
		return "UST invalid context";
	case LTTNG_ERR_NEED_ROOT_SESSIOND:
		return "Tracing the kernel requires a root lttng-sessiond daemon, as well as \"tracing\" group membership or root user ID for the lttng client";
	case LTTNG_ERR_NO_UST:
		return "LTTng-UST tracer is not supported. Please rebuild lttng-tools with lttng-ust support enabled";
	case LTTNG_ERR_TRACE_ALREADY_STARTED:
		return "Tracing has already been started once";
	case LTTNG_ERR_TRACE_ALREADY_STOPPED:
		return "Tracing has already been stopped";
	case LTTNG_ERR_KERN_EVENT_ENOSYS:
		return "Kernel event type not supported";
	case LTTNG_ERR_NEED_CHANNEL_NAME:
		return "Non-default channel exists within session: channel name needs to be specified with '-c name'";
	case LTTNG_ERR_INVALID:
		return "Invalid parameter";
	case LTTNG_ERR_NO_USTCONSUMERD:
		return "No UST consumer detected";
	case LTTNG_ERR_NO_KERNCONSUMERD:
		return "No kernel consumer detected";
	case LTTNG_ERR_EVENT_EXIST_LOGLEVEL:
		return "Event already enabled with different loglevel";
	case LTTNG_ERR_URL_DATA_MISS:
		return "Missing data path URL";
	case LTTNG_ERR_URL_CTRL_MISS:
		return "Missing control path URL";
	case LTTNG_ERR_ENABLE_CONSUMER_FAIL:
		return "Enabling consumer failed";
	case LTTNG_ERR_RELAYD_CONNECT_FAIL:
		return "Unable to connect to lttng-relayd";
	case LTTNG_ERR_RELAYD_VERSION_FAIL:
		return "Relay daemon not compatible";
	case LTTNG_ERR_FILTER_INVAL:
		return "Invalid filter bytecode";
	case LTTNG_ERR_FILTER_NOMEM:
		return "Not enough memory for filter bytecode";
	case LTTNG_ERR_FILTER_EXIST:
		return "Filter already exist";
	case LTTNG_ERR_NO_CONSUMER:
		return "Consumer not found for recording session";
	case LTTNG_ERR_EXCLUSION_INVAL:
		return "Invalid event exclusion data";
	case LTTNG_ERR_EXCLUSION_NOMEM:
		return "Lack of memory while processing event exclusions";
	case LTTNG_ERR_NO_SESSIOND:
		return "No session daemon is available";
	case LTTNG_ERR_SESSION_STARTED:
		return "Session is running";
	case LTTNG_ERR_NOT_SUPPORTED:
		return "Operation not supported";
	case LTTNG_ERR_UST_EVENT_ENABLED:
		return "UST event already enabled";
	case LTTNG_ERR_SET_URL:
		return "Error setting URL";
	case LTTNG_ERR_URL_EXIST:
		return "URL already exists";
	case LTTNG_ERR_BUFFER_NOT_SUPPORTED:
		return "Buffer type not supported";
	case LTTNG_ERR_BUFFER_TYPE_MISMATCH:
		return "Buffer type mismatch for session";
	case LTTNG_ERR_NOMEM:
		return "Not enough memory";
	case LTTNG_ERR_SNAPSHOT_OUTPUT_EXIST:
		return "Snapshot output already exists";
	case LTTNG_ERR_START_SESSION_ONCE:
		return "Session needs to be started once";
	case LTTNG_ERR_SNAPSHOT_FAIL:
		return "Snapshot record failed";
	case LTTNG_ERR_NO_STREAM:
		return "Index without stream on relay";
	case LTTNG_ERR_CHAN_EXIST:
		return "Channel already exists";
	case LTTNG_ERR_SNAPSHOT_NODATA:
		return "No data available in snapshot";
	case LTTNG_ERR_NO_CHANNEL:
		return "No channel found in the session";
	case LTTNG_ERR_SESSION_INVALID_CHAR:
		return "Invalid character found in session name";
	case LTTNG_ERR_SAVE_FILE_EXIST:
		return "Session file already exists";
	case LTTNG_ERR_SAVE_IO_FAIL:
		return "IO error while writing session configuration";
	case LTTNG_ERR_LOAD_INVALID_CONFIG:
		return "Invalid session configuration";
	case LTTNG_ERR_LOAD_IO_FAIL:
		return "IO error while reading a session configuration";
	case LTTNG_ERR_LOAD_SESSION_NOENT:
		return "Session file not found";
	case LTTNG_ERR_MAX_SIZE_INVALID:
		return "Snapshot max size is invalid";
	case LTTNG_ERR_MI_OUTPUT_TYPE:
		return "Invalid MI output format";
	case LTTNG_ERR_MI_IO_FAIL:
		return "IO error while writing MI output";
	case LTTNG_ERR_MI_NOT_IMPLEMENTED:
		return "Mi feature not implemented";
	case LTTNG_ERR_INVALID_EVENT_NAME:
		return "Invalid event name";
	case LTTNG_ERR_INVALID_CHANNEL_NAME:
		return "Invalid channel name";
	case LTTNG_ERR_PROCESS_ATTR_EXISTS:
		return "Process attribute is already tracked";
	case LTTNG_ERR_PROCESS_ATTR_MISSING:
		return "Process attribute was not tracked";
	case LTTNG_ERR_INVALID_CHANNEL_DOMAIN:
		return "Invalid channel domain";
	case LTTNG_ERR_OVERFLOW:
		return "Overflow occurred";
	case LTTNG_ERR_SESSION_NOT_STARTED:
		return "Session not started";
	case LTTNG_ERR_LIVE_SESSION:
		return "Live sessions are not supported";
	case LTTNG_ERR_PER_PID_SESSION:
		return "Per-PID recording sessions are not supported";
	case LTTNG_ERR_KERN_CONTEXT_UNAVAILABLE:
		return "Context unavailable on this kernel";
	case LTTNG_ERR_REGEN_STATEDUMP_FAIL:
		return "Failed to regenerate the state dump";
	case LTTNG_ERR_REGEN_STATEDUMP_NOMEM:
		return "Failed to regenerate the state dump, not enough memory";
	case LTTNG_ERR_NOT_SNAPSHOT_SESSION:
		return "Snapshot command can't be applied to a non-snapshot session";
	case LTTNG_ERR_INVALID_TRIGGER:
		return "Invalid trigger";
	case LTTNG_ERR_TRIGGER_EXISTS:
		return "Trigger already registered";
	case LTTNG_ERR_TRIGGER_NOT_FOUND:
		return "Trigger not found";
	case LTTNG_ERR_COMMAND_CANCELLED:
		return "Command cancelled";
	case LTTNG_ERR_ROTATION_PENDING:
		return "Rotation already pending for this session";
	case LTTNG_ERR_ROTATION_NOT_AVAILABLE:
		return "Rotation feature not available for this session's creation mode";
	case LTTNG_ERR_ROTATION_SCHEDULE_SET:
		return "A session rotation schedule of this type is already set on the session";
	case LTTNG_ERR_ROTATION_SCHEDULE_NOT_SET:
		return "No session rotation schedule of this type is set on the session";
	case LTTNG_ERR_ROTATION_MULTIPLE_AFTER_STOP:
		return "Session was already rotated once since it became inactive";
	case LTTNG_ERR_ROTATION_WRONG_VERSION:
		return "Session rotation is not supported by this kernel tracer version";
	case LTTNG_ERR_NO_SESSION_OUTPUT:
		return "Session has no output";
	case LTTNG_ERR_ROTATION_NOT_AVAILABLE_RELAY:
		return "Rotation feature not available on the relay";
	case LTTNG_ERR_AGENT_TRACING_DISABLED:
		return "Session daemon agent tracing is disabled";
	case LTTNG_ERR_PROBE_LOCATION_INVAL:
		return "Invalid userspace probe location";
	case LTTNG_ERR_ELF_PARSING:
		return "ELF parsing error";
	case LTTNG_ERR_SDT_PROBE_SEMAPHORE:
		return "SDT probe guarded by a semaphore";
	case LTTNG_ERR_ROTATION_FAIL_CONSUMER:
		return "Rotation failure on consumer";
	case LTTNG_ERR_ROTATE_RENAME_FAIL_CONSUMER:
		return "Rotation rename failure on consumer";
	case LTTNG_ERR_ROTATION_PENDING_LOCAL_FAIL_CONSUMER:
		return "Rotation pending check (local) failure on consumer";
	case LTTNG_ERR_ROTATION_PENDING_RELAY_FAIL_CONSUMER:
		return "Rotation pending check (relay) failure on consumer";
	case LTTNG_ERR_MKDIR_FAIL_CONSUMER:
		return "Directory creation failure on consumer";
	case LTTNG_ERR_CHAN_NOT_FOUND:
		return "Channel not found";
	case LTTNG_ERR_SNAPSHOT_UNSUPPORTED:
		return "Session configuration does not allow the use of snapshots";
	case LTTNG_ERR_SESSION_NOT_EXIST:
		return "Recording session does not exist";
	case LTTNG_ERR_CREATE_TRACE_CHUNK_FAIL_CONSUMER:
		return "Trace chunk creation failed on consumer";
	case LTTNG_ERR_CLOSE_TRACE_CHUNK_FAIL_CONSUMER:
		return "Trace chunk close failed on consumer";
	case LTTNG_ERR_TRACE_CHUNK_EXISTS_FAIL_CONSUMER:
		return "Failed to query consumer for trace chunk existence";
	case LTTNG_ERR_INVALID_PROTOCOL:
		return "Protocol error occurred";
	case LTTNG_ERR_FILE_CREATION_ERROR:
		return "Failed to create file";
	case LTTNG_ERR_TIMER_STOP_ERROR:
		return "Failed to stop a timer";
	case LTTNG_ERR_ROTATION_NOT_AVAILABLE_KERNEL:
		return "Rotation feature not supported by the kernel tracer";
	case LTTNG_ERR_CLEAR_RELAY_DISALLOWED:
		return "Relayd daemon peer does not allow sessions to be cleared";
	case LTTNG_ERR_CLEAR_NOT_AVAILABLE_RELAY:
		return "Clearing a session is not supported by the relay daemon";
	case LTTNG_ERR_CLEAR_FAIL_CONSUMER:
		return "Consumer failed to clear the session";
	case LTTNG_ERR_ROTATION_AFTER_STOP_CLEAR:
		return "Session was already cleared since it became inactive";
	case LTTNG_ERR_USER_NOT_FOUND:
		return "User not found";
	case LTTNG_ERR_GROUP_NOT_FOUND:
		return "Group not found";
	case LTTNG_ERR_UNSUPPORTED_DOMAIN:
		return "Unsupported domain used";
	case LTTNG_ERR_PROCESS_ATTR_TRACKER_INVALID_TRACKING_POLICY:
		return "Operation does not apply to the process attribute tracker's tracking policy";
	case LTTNG_ERR_EVENT_NOTIFIER_GROUP_NOTIFICATION_FD:
		return "Failed to create an event notifier group notification file descriptor";
	case LTTNG_ERR_INVALID_CAPTURE_EXPRESSION:
		return "Invalid capture expression";
	case LTTNG_ERR_EVENT_NOTIFIER_REGISTRATION:
		return "Failed to create event notifier";
	case LTTNG_ERR_EVENT_NOTIFIER_ERROR_ACCOUNTING:
		return "Failed to initialize event notifier error accounting";
	case LTTNG_ERR_EVENT_NOTIFIER_ERROR_ACCOUNTING_FULL:
		return "No index available in event notifier error accounting";
	case LTTNG_ERR_INVALID_ERROR_QUERY_TARGET:
		return "Invalid error query target.";
	case LTTNG_ERR_BUFFER_FLUSH_FAILED:
		return "Failed to flush stream buffer";
	case LTTNG_ERR_NR:
		abort();
	}

	abort();
};

/*
 * Return ptr to string representing a human readable error code from the
 * lttng_error_code enum.
 *
 * These code MUST be negative in other to treat that as an error value.
 */
const char *error_get_str(int32_t code)
{
	code = -code;

	if (code < LTTNG_OK || code >= LTTNG_ERR_NR) {
		code = LTTNG_ERR_UNK;
	}

	return lttng_error_code_str((lttng_error_code) code);
}

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

[[noreturn]] void
lttng::logging::details::die_formatting_exception(const char *format,
						  const std::exception& formatting_exception)
{
	std::cerr << "Error occurred while formatting logging message: msg=`" << format
		  << "`: " << formatting_exception.what();
	abort();
}
