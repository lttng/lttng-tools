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
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _DEFAULTS_H
#define _DEFAULTS_H

#include <config.h>

/* Default unix group name for tracing. */
#define DEFAULT_TRACING_GROUP                   "tracing"

/*
 * This value is defined in the CTF specification (see
 * git://git.efficios.com/ctf.git in the file
 * common-trace-format-specification.txt.
 */
#define DEFAULT_METADATA_NAME                   "metadata"

/* Environment variable to set session daemon binary path. */
#define DEFAULT_SESSIOND_PATH_ENV               "LTTNG_SESSIOND_PATH"

/* Default trace output directory name */
#define DEFAULT_TRACE_DIR_NAME                  "lttng-traces"

/* Default size of a hash table */
#define DEFAULT_HT_SIZE                         4

/* Default session daemon paths */
#define DEFAULT_HOME_DIR						"/tmp"
#define DEFAULT_UST_SOCK_DIR                    DEFAULT_HOME_DIR "/ust-app-socks"
#define DEFAULT_GLOBAL_APPS_PIPE                DEFAULT_UST_SOCK_DIR "/global"
#define DEFAULT_TRACE_OUTPUT                    DEFAULT_HOME_DIR "/lttng"

/* Default directory where the trace are written in per domain */
#define DEFAULT_KERNEL_TRACE_DIR                "/kernel"
#define DEFAULT_UST_TRACE_DIR                   "/ust"

/* Subpath for per PID or UID sessions. */
#define DEFAULT_UST_TRACE_PID_PATH               "/pid"
#define DEFAULT_UST_TRACE_UID_PATH               "/uid/%d/%u-bit"

/*
 * Default session name for the lttng command line. This default value will
 * get the date and time appended (%Y%m%d-%H%M%S) to it.
 */
#define DEFAULT_SESSION_NAME                    "auto"

/* Default consumer paths */
#define DEFAULT_CONSUMERD_RUNDIR                "%s"

/* Kernel consumer path */
#define DEFAULT_KCONSUMERD_PATH                 DEFAULT_CONSUMERD_RUNDIR "/kconsumerd"
#define DEFAULT_KCONSUMERD_CMD_SOCK_PATH        DEFAULT_KCONSUMERD_PATH "/command"
#define DEFAULT_KCONSUMERD_ERR_SOCK_PATH        DEFAULT_KCONSUMERD_PATH "/error"

/* UST 64-bit consumer path */
#define DEFAULT_USTCONSUMERD64_PATH             DEFAULT_CONSUMERD_RUNDIR "/ustconsumerd64"
#define DEFAULT_USTCONSUMERD64_CMD_SOCK_PATH    DEFAULT_USTCONSUMERD64_PATH "/command"
#define DEFAULT_USTCONSUMERD64_ERR_SOCK_PATH    DEFAULT_USTCONSUMERD64_PATH "/error"

/* UST 32-bit consumer path */
#define DEFAULT_USTCONSUMERD32_PATH             DEFAULT_CONSUMERD_RUNDIR "/ustconsumerd32"
#define DEFAULT_USTCONSUMERD32_CMD_SOCK_PATH    DEFAULT_USTCONSUMERD32_PATH "/command"
#define DEFAULT_USTCONSUMERD32_ERR_SOCK_PATH    DEFAULT_USTCONSUMERD32_PATH "/error"

/* Default lttng run directory */
#define DEFAULT_LTTNG_HOME_ENV_VAR              "LTTNG_HOME"
#define DEFAULT_LTTNG_FALLBACK_HOME_ENV_VAR	"HOME"
#define DEFAULT_LTTNG_RUNDIR                    CONFIG_LTTNG_SYSTEM_RUNDIR
#define DEFAULT_LTTNG_HOME_RUNDIR               "%s/.lttng"
#define DEFAULT_LTTNG_SESSIOND_PIDFILE          "lttng-sessiond.pid"

/* Default unix socket path */
#define DEFAULT_GLOBAL_CLIENT_UNIX_SOCK         DEFAULT_LTTNG_RUNDIR "/client-lttng-sessiond"
#define DEFAULT_HOME_CLIENT_UNIX_SOCK           DEFAULT_LTTNG_HOME_RUNDIR "/client-lttng-sessiond"
#define DEFAULT_GLOBAL_HEALTH_UNIX_SOCK         DEFAULT_LTTNG_RUNDIR "/health.sock"
#define DEFAULT_HOME_HEALTH_UNIX_SOCK           DEFAULT_LTTNG_HOME_RUNDIR "/health.sock"

#define DEFAULT_GLOBAL_APPS_UNIX_SOCK \
	DEFAULT_LTTNG_RUNDIR "/" LTTNG_UST_SOCK_FILENAME
#define DEFAULT_HOME_APPS_UNIX_SOCK \
	DEFAULT_LTTNG_HOME_RUNDIR "/" LTTNG_UST_SOCK_FILENAME
#define DEFAULT_GLOBAL_APPS_WAIT_SHM_PATH \
	"/" LTTNG_UST_WAIT_FILENAME
#define DEFAULT_HOME_APPS_WAIT_SHM_PATH \
	DEFAULT_GLOBAL_APPS_WAIT_SHM_PATH "-%d"

/*
 * Value taken from the hard limit allowed by the kernel when using setrlimit
 * with RLIMIT_NOFILE on an Intel i7 CPU and Linux 3.0.3.
 */
#define DEFAULT_POLL_SIZE 65535

/*
 * Format is %s_%d respectively channel name and CPU number. Eigth bytes
 * are added here to add space for the CPU number. I guess 2^8 CPUs is more
 * than enough. We might end up with quantum computing in a cell phone when
 * reaching this limit.
 */
#define DEFAULT_STREAM_NAME_LEN        LTTNG_SYMBOL_NAME_LEN + 8

/* Default channel attributes */
#define DEFAULT_CHANNEL_NAME            "channel0"
#define DEFAULT_CHANNEL_OVERWRITE       0
#define DEFAULT_CHANNEL_TRACEFILE_SIZE  0
#define DEFAULT_CHANNEL_TRACEFILE_COUNT 0

/* Must always be a power of 2 */
#define _DEFAULT_CHANNEL_SUBBUF_SIZE	4096    /* bytes */
/* Must always be a power of 2 */
#define _DEFAULT_CHANNEL_SUBBUF_NUM		4
#define _DEFAULT_CHANNEL_SWITCH_TIMER	0       /* usec */
#define _DEFAULT_CHANNEL_LIVE_TIMER	0       /* usec */
#define _DEFAULT_CHANNEL_READ_TIMER		200000  /* usec */
#define _DEFAULT_CHANNEL_OUTPUT			LTTNG_EVENT_MMAP

/* Metadata channel defaults. */
#define DEFAULT_METADATA_SUBBUF_SIZE    4096
#define DEFAULT_METADATA_SUBBUF_NUM     2
#define DEFAULT_METADATA_CACHE_SIZE     4096
#define DEFAULT_METADATA_SWITCH_TIMER	_DEFAULT_CHANNEL_SWITCH_TIMER
#define DEFAULT_METADATA_READ_TIMER		0
#define DEFAULT_METADATA_OUTPUT			_DEFAULT_CHANNEL_OUTPUT

/* Kernel has different defaults */

/* DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE must always be a power of 2 */
#define DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE		262144    /* bytes */
/*
 * DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM must always be a power of 2.
 * Update help manually if override.
 */
#define DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM		_DEFAULT_CHANNEL_SUBBUF_NUM
/* See lttng-kernel.h enum lttng_kernel_output for channel output */
#define DEFAULT_KERNEL_CHANNEL_OUTPUT			LTTNG_EVENT_SPLICE
#define DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER		_DEFAULT_CHANNEL_SWITCH_TIMER
#define DEFAULT_KERNEL_CHANNEL_READ_TIMER		_DEFAULT_CHANNEL_READ_TIMER
#define DEFAULT_KERNEL_CHANNEL_LIVE_TIMER		_DEFAULT_CHANNEL_LIVE_TIMER

/* User space defaults */

/* Must be a power of 2 */
#define DEFAULT_UST_PID_CHANNEL_SUBBUF_SIZE		_DEFAULT_CHANNEL_SUBBUF_SIZE
#define DEFAULT_UST_UID_CHANNEL_SUBBUF_SIZE		131072  /* bytes */
/* Must be a power of 2. Update help manuall if override. */
#define DEFAULT_UST_PID_CHANNEL_SUBBUF_NUM		_DEFAULT_CHANNEL_SUBBUF_NUM
#define DEFAULT_UST_UID_CHANNEL_SUBBUF_NUM		_DEFAULT_CHANNEL_SUBBUF_NUM
/* See lttng-ust.h enum lttng_ust_output */
#define DEFAULT_UST_PID_CHANNEL_OUTPUT			_DEFAULT_CHANNEL_OUTPUT
#define DEFAULT_UST_UID_CHANNEL_OUTPUT			_DEFAULT_CHANNEL_OUTPUT
/* Timers in usec. */
#define DEFAULT_UST_PID_CHANNEL_SWITCH_TIMER	_DEFAULT_CHANNEL_SWITCH_TIMER
#define DEFAULT_UST_UID_CHANNEL_SWITCH_TIMER	_DEFAULT_CHANNEL_SWITCH_TIMER
#define DEFAULT_UST_PID_CHANNEL_LIVE_TIMER	_DEFAULT_CHANNEL_LIVE_TIMER
#define DEFAULT_UST_UID_CHANNEL_LIVE_TIMER	_DEFAULT_CHANNEL_LIVE_TIMER

#define DEFAULT_UST_PID_CHANNEL_READ_TIMER      0  /* usec */
#define DEFAULT_UST_UID_CHANNEL_READ_TIMER      0  /* usec */

/*
 * Default timeout value for the sem_timedwait() call. Blocking forever is not
 * wanted so a timeout is used to control the data flow and not freeze the
 * session daemon.
 */
#define DEFAULT_SEM_WAIT_TIMEOUT            30    /* in seconds */

/* Default network ports for trace streaming support */
#define DEFAULT_NETWORK_CONTROL_PORT        5342
#define DEFAULT_NETWORK_DATA_PORT           5343

/*
 * If a thread stalls for this amount of time, it will be considered bogus (bad
 * health).
 */
#define DEFAULT_HEALTH_CHECK_DELTA_S        20
#define DEFAULT_HEALTH_CHECK_DELTA_NS       0

/*
 * Wait period before retrying the lttng_data_pending command in the lttng
 * stop command of liblttng-ctl.
 */
#define DEFAULT_DATA_AVAILABILITY_WAIT_TIME 200000  /* usec */

/*
 * Wait period before retrying the lttng_consumer_flushed_cache when
 * the consumer receives metadata.
 */
#define DEFAULT_METADATA_AVAILABILITY_WAIT_TIME 200000  /* usec */

/*
 * The usual value for the maximum TCP SYN retries time and TCP FIN timeout is
 * 180 and 60 seconds on most Linux system and the default value since kernel
 * 2.2 thus using the highest value. See tcp(7) for more details.
 */
#define DEFAULT_INET_TCP_TIMEOUT			180	/* sec */

/*
 * Default receiving and sending timeout for an application socket.
 */
#define DEFAULT_APP_SOCKET_RW_TIMEOUT       5  /* sec */
#define DEFAULT_APP_SOCKET_TIMEOUT_ENV      "LTTNG_APP_SOCKET_TIMEOUT"

#define DEFAULT_UST_STREAM_FD_NUM			2 /* Number of fd per UST stream. */

#define DEFAULT_SNAPSHOT_NAME				"snapshot"
#define DEFAULT_SNAPSHOT_MAX_SIZE			0 /* Unlimited. */

/* Suffix of an index file. */
#define DEFAULT_INDEX_FILE_SUFFIX			".idx"
#define DEFAULT_INDEX_DIR					"index"

extern size_t default_channel_subbuf_size;
extern size_t default_metadata_subbuf_size;
extern size_t default_ust_pid_channel_subbuf_size;
extern size_t default_ust_uid_channel_subbuf_size;
extern size_t default_kernel_channel_subbuf_size;

/*
 * Returns the default subbuf size.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
static inline
size_t default_get_channel_subbuf_size(void)
{
	return default_channel_subbuf_size;
}

/*
 * Returns the default metadata subbuf size.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
static inline
size_t default_get_metadata_subbuf_size(void)
{
	return default_metadata_subbuf_size;
}

/*
 * Returns the default subbuf size for the kernel domain.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
static inline
size_t default_get_kernel_channel_subbuf_size(void)
{
	return default_kernel_channel_subbuf_size;
}

/*
 * Returns the default subbuf size for the UST domain per PID.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
static inline
size_t default_get_ust_pid_channel_subbuf_size(void)
{
	return default_ust_pid_channel_subbuf_size;
}

/*
 * Returns the default subbuf size for the UST domain per UID.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
static inline
size_t default_get_ust_uid_channel_subbuf_size(void)
{
	return default_ust_uid_channel_subbuf_size;
}

#endif /* _DEFAULTS_H */
