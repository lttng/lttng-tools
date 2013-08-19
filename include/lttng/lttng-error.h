/*
 * lttng-error.h
 *
 * Linux Trace Toolkit Control Library Error Header File
 *
 * The following values are all the possible errors the lttng command line
 * client can quit with.
 *
 * Copyright (C) 2012 - David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_ERROR_H
#define LTTNG_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LTTNG_DEPRECATED
#if defined (__GNUC__) \
	&& ((__GNUC_MAJOR__ == 4) && (__GNUC_MINOR__ >= 5)  \
			|| __GNUC_MAJOR__ >= 5)
#define LTTNG_DEPRECATED(msg) __attribute__((deprecated(msg)))
#else
#define LTTNG_DEPRECATED(msg) __attribute__((deprecated))
#endif /* defined __GNUC__ */
#endif /* LTTNG_DEPRECATED */

enum lttng_error_code {
	LTTNG_OK                         = 10,  /* Ok */
	LTTNG_ERR_UNK                    = 11,  /* Unknown Error */
	LTTNG_ERR_UND                    = 12,  /* Undefine command */
	LTTNG_ERR_SESSION_STARTED        = 13,  /* Session is running */
	LTTNG_ERR_UNKNOWN_DOMAIN         = 14,  /* Tracing domain not known */
	LTTNG_ERR_NOT_SUPPORTED          = 15,  /* Operation not supported */
	LTTNG_ERR_NO_SESSION             = 16,  /* No session found */
	LTTNG_ERR_CREATE_DIR_FAIL        = 17,  /* Create directory fail */
	LTTNG_ERR_SESSION_FAIL           = 18,  /* Create session fail */
	LTTNG_ERR_NO_SESSIOND            = 19,  /* No session daemon available */
	LTTNG_ERR_SET_URL                = 20,  /* Error setting URL */
	LTTNG_ERR_URL_EXIST              = 21,  /* URL already exists. */
	LTTNG_ERR_BUFFER_NOT_SUPPORTED   = 22,  /* Buffer type not supported. */
	LTTNG_ERR_SESS_NOT_FOUND         = 23,  /* Session by name not found */
	LTTNG_ERR_BUFFER_TYPE_MISMATCH   = 24,  /* Buffer type mismatched. */
	LTTNG_ERR_FATAL                  = 25,  /* Fatal error */
	LTTNG_ERR_NOMEM                  = 26,  /* Not enough memory. */
	LTTNG_ERR_SELECT_SESS            = 27,  /* Must select a session */
	LTTNG_ERR_EXIST_SESS             = 28,  /* Session name already exist */
	LTTNG_ERR_NO_EVENT               = 29,  /* No event found */
	LTTNG_ERR_CONNECT_FAIL           = 30,  /* Unable to connect to unix socket */
	LTTNG_ERR_SNAPSHOT_OUTPUT_EXIST  = 31,  /* Snapshot output already exists */
	LTTNG_ERR_EPERM                  = 32,  /* Permission denied */
	LTTNG_ERR_KERN_NA                = 33,  /* Kernel tracer unavalable */
	LTTNG_ERR_KERN_VERSION           = 34,  /* Kernel tracer not compatible */
	LTTNG_ERR_KERN_EVENT_EXIST       = 35,  /* Kernel event already exists */
	LTTNG_ERR_KERN_SESS_FAIL         = 36,  /* Kernel create session failed */
	LTTNG_ERR_KERN_CHAN_EXIST        = 37,  /* Kernel channel already exists */
	LTTNG_ERR_KERN_CHAN_FAIL         = 38,  /* Kernel create channel failed */
	LTTNG_ERR_KERN_CHAN_NOT_FOUND    = 39,  /* Kernel channel not found */
	LTTNG_ERR_KERN_CHAN_DISABLE_FAIL = 40,  /* Kernel disable channel failed */
	LTTNG_ERR_KERN_CHAN_ENABLE_FAIL  = 41,  /* Kernel enable channel failed */
	LTTNG_ERR_KERN_CONTEXT_FAIL      = 42,  /* Kernel add context failed */
	LTTNG_ERR_KERN_ENABLE_FAIL       = 43,  /* Kernel enable event failed */
	LTTNG_ERR_KERN_DISABLE_FAIL      = 44,  /* Kernel disable event failed */
	LTTNG_ERR_KERN_META_FAIL         = 45,  /* Kernel open metadata failed */
	LTTNG_ERR_KERN_START_FAIL        = 46,  /* Kernel start trace failed */
	LTTNG_ERR_KERN_STOP_FAIL         = 47,  /* Kernel stop trace failed */
	LTTNG_ERR_KERN_CONSUMER_FAIL     = 48,  /* Kernel consumer start failed */
	LTTNG_ERR_KERN_STREAM_FAIL       = 49,  /* Kernel create stream failed */
	LTTNG_ERR_START_SESSION_ONCE     = 50,  /* Session needs to be started once. */
	LTTNG_ERR_SNAPSHOT_FAIL          = 51,  /* Snapshot record failed. */
	LTTNG_ERR_NO_STREAM              = 52,  /* Index without stream on relay. */
	LTTNG_ERR_KERN_LIST_FAIL         = 53,  /* Kernel listing events failed */
	LTTNG_ERR_UST_CALIBRATE_FAIL     = 54,  /* UST calibration failed */
	LTTNG_ERR_UST_EVENT_ENABLED      = 55,  /* UST event already enabled. */
	LTTNG_ERR_UST_SESS_FAIL          = 56,  /* UST create session failed */
	LTTNG_ERR_UST_CHAN_EXIST         = 57,  /* UST channel already exist */
	LTTNG_ERR_UST_CHAN_FAIL          = 58,  /* UST create channel failed */
	LTTNG_ERR_UST_CHAN_NOT_FOUND     = 59,  /* UST channel not found */
	LTTNG_ERR_UST_CHAN_DISABLE_FAIL  = 60,  /* UST disable channel failed */
	LTTNG_ERR_UST_CHAN_ENABLE_FAIL   = 61,  /* UST enable channel failed */
	/* 62 */
	LTTNG_ERR_UST_ENABLE_FAIL        = 63,  /* UST enable event failed */
	LTTNG_ERR_UST_DISABLE_FAIL       = 64,  /* UST disable event failed */
	LTTNG_ERR_UST_META_FAIL          = 65,  /* UST open metadata failed */
	LTTNG_ERR_UST_START_FAIL         = 66,  /* UST start trace failed */
	LTTNG_ERR_UST_STOP_FAIL          = 67,  /* UST stop trace failed */
	LTTNG_ERR_UST_CONSUMER64_FAIL    = 68,  /* 64-bit UST consumer start failed */
	LTTNG_ERR_UST_CONSUMER32_FAIL    = 69,  /* 32-bit UST consumer start failed */
	LTTNG_ERR_UST_STREAM_FAIL        = 70,  /* UST create stream failed */
	/* 71 */
	/* 72 */
	/* 73 */
	LTTNG_ERR_UST_LIST_FAIL          = 74,  /* UST listing events failed */
	LTTNG_ERR_UST_EVENT_EXIST        = 75,  /* UST event exist */
	LTTNG_ERR_UST_EVENT_NOT_FOUND    = 76,  /* UST event not found */
	LTTNG_ERR_UST_CONTEXT_EXIST      = 77,  /* UST context exist */
	LTTNG_ERR_UST_CONTEXT_INVAL      = 78,  /* UST context invalid */
	LTTNG_ERR_NEED_ROOT_SESSIOND     = 79,  /* root sessiond is needed */
	LTTNG_ERR_TRACE_ALREADY_STARTED  = 80,  /* Tracing already started */
	LTTNG_ERR_TRACE_ALREADY_STOPPED  = 81,  /* Tracing already stopped */
	LTTNG_ERR_KERN_EVENT_ENOSYS      = 82,  /* Kernel event type not supported */
	LTTNG_ERR_NEED_CHANNEL_NAME      = 83,	/* Non-default channel exists within session: channel name needs to be specified with '-c name' */
	LTTNG_ERR_NO_UST                 = 84,  /* LTTng-UST tracer is not supported. Please rebuild lttng-tools with lttng-ust support enabled. */
	/* 85 */
	/* 86 */
	/* 87 */
	/* 88 */
	/* 89 */
	/* 90 */
	/* 91 */
	/* 92 */
	/* 93 */
	/* 94 */
	/* 95 */
	/* 96 */
	LTTNG_ERR_INVALID                = 97,  /* Invalid parameter */
	LTTNG_ERR_NO_USTCONSUMERD        = 98,  /* No UST consumer detected */
	LTTNG_ERR_NO_KERNCONSUMERD       = 99,  /* No Kernel consumer detected */
	LTTNG_ERR_EVENT_EXIST_LOGLEVEL   = 100, /* Event enabled with different loglevel */
	LTTNG_ERR_URL_DATA_MISS          = 101, /* Missing network data URL */
	LTTNG_ERR_URL_CTRL_MISS          = 102, /* Missing network control URL */
	LTTNG_ERR_ENABLE_CONSUMER_FAIL   = 103, /* Enabling consumer failed */
	LTTNG_ERR_RELAYD_CONNECT_FAIL    = 104, /* lttng-relayd create session failed */
	LTTNG_ERR_RELAYD_VERSION_FAIL    = 105, /* lttng-relayd not compatible */
	LTTNG_ERR_FILTER_INVAL           = 106, /* Invalid filter bytecode */
	LTTNG_ERR_FILTER_NOMEM           = 107, /* Lack of memory for filter bytecode */
	LTTNG_ERR_FILTER_EXIST           = 108, /* Filter already exist */
	LTTNG_ERR_NO_CONSUMER            = 109, /* No consumer exist for the session */

	/* MUST be last element */
	LTTNG_ERR_NR,                           /* Last element */
};

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_ERROR_H */
