/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2011 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * SPDX-FileCopyrightText: 2015 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _DEFAULTS_H
#define _DEFAULTS_H

#include <common/macros.hpp>

#include <pthread.h>

/* Default unix group name for tracing. */
#define DEFAULT_TRACING_GROUP "tracing"

/*
 * This value is defined in the CTF specification (see
 * https://git.efficios.com/ctf.git in the file
 * common-trace-format-specification.txt.
 */
#define DEFAULT_METADATA_NAME "metadata"

/* Environment variable to set session daemon binary path. */
#define DEFAULT_SESSIOND_PATH_ENV "LTTNG_SESSIOND_PATH"

/* Environment variable to set man pager binary path. */
#define DEFAULT_MAN_BIN_PATH_ENV "LTTNG_MAN_BIN_PATH"

/* Environment variable to set man manpath. */
#define DEFAULT_MANPATH "LTTNG_MANPATH"

/* Default man pager binary path. */
#define DEFAULT_MAN_BIN_PATH "/usr/bin/man"

/* Default trace output directory name */
#define DEFAULT_TRACE_DIR_NAME "lttng-traces"

/* Default size of a hash table */
#define DEFAULT_HT_SIZE 4

/* Default session daemon paths */
#define DEFAULT_HOME_DIR     "/tmp"
#define DEFAULT_UST_SOCK_DIR DEFAULT_HOME_DIR "/ust-app-socks"
#define DEFAULT_TRACE_OUTPUT DEFAULT_HOME_DIR "/lttng"

/* Default directory where the trace are written in per domain */
#define DEFAULT_KERNEL_TRACE_DIR "kernel"
#define DEFAULT_UST_TRACE_DIR	 "ust"

/* Subpath for per PID or UID sessions. */
#define DEFAULT_UST_TRACE_PID_PATH "pid"
#define DEFAULT_UST_TRACE_UID_PATH "uid/%d/%u-bit"

/*
 * Default session name for the lttng command line. This default value will
 * get the date and time appended (%Y%m%d-%H%M%S) to it.
 */
#define DEFAULT_SESSION_NAME "auto"

/* Default consumer paths */
#define DEFAULT_CONSUMERD_FILE "lttng-consumerd"

/* Default consumer paths */
#define DEFAULT_CONSUMERD_RUNDIR "%s"

/* Kernel consumer path */
#define DEFAULT_KCONSUMERD_PATH		 DEFAULT_CONSUMERD_RUNDIR "/kconsumerd"
#define DEFAULT_KCONSUMERD_CMD_SOCK_PATH DEFAULT_KCONSUMERD_PATH "/command"
#define DEFAULT_KCONSUMERD_ERR_SOCK_PATH DEFAULT_KCONSUMERD_PATH "/error"

/* UST 64-bit consumer path */
#define DEFAULT_USTCONSUMERD64_PATH	     DEFAULT_CONSUMERD_RUNDIR "/ustconsumerd64"
#define DEFAULT_USTCONSUMERD64_CMD_SOCK_PATH DEFAULT_USTCONSUMERD64_PATH "/command"
#define DEFAULT_USTCONSUMERD64_ERR_SOCK_PATH DEFAULT_USTCONSUMERD64_PATH "/error"

/* UST 32-bit consumer path */
#define DEFAULT_USTCONSUMERD32_PATH	     DEFAULT_CONSUMERD_RUNDIR "/ustconsumerd32"
#define DEFAULT_USTCONSUMERD32_CMD_SOCK_PATH DEFAULT_USTCONSUMERD32_PATH "/command"
#define DEFAULT_USTCONSUMERD32_ERR_SOCK_PATH DEFAULT_USTCONSUMERD32_PATH "/error"

/* Relayd path */
#define DEFAULT_RELAYD_RUNDIR		 "%s"
#define DEFAULT_RELAYD_PATH		 DEFAULT_RELAYD_RUNDIR "/relayd"
#define DEFAULT_RELAYD_CONTROL_PORT_PATH DEFAULT_LTTNG_EXPLICIT_RUNDIR "/control.port"
#define DEFAULT_RELAYD_DATA_PORT_PATH	 DEFAULT_LTTNG_EXPLICIT_RUNDIR "/data.port"
#define DEFAULT_RELAYD_LIVE_PORT_PATH	 DEFAULT_LTTNG_EXPLICIT_RUNDIR "/live.port"

#define DEFAULT_RELAYD_MIN_FD_POOL_SIZE 100
/*
 * The file descriptor pool size needs a reserve buffer to accommodates the
 * indirect use of short-lived file descriptors. For instance, glibc will
 * create a socket (and thus, use an fd) during calls to gethostname() or
 * when querying the user's group. Other calls also probably make use of
 * short-lived FDs.
 *
 * The theoritical maximal reserve corresponds to the number of threads as,
 * in the worst case, they could all be making such calls.
 *
 * This value must be less than DEFAULT_RELAYD_MIN_FD_POOL_SIZE.
 */
#define DEFAULT_RELAYD_FD_POOL_SIZE_RESERVE 10

/* Default lttng run directory */
#define DEFAULT_LTTNG_HOME_ENV_VAR	      "LTTNG_HOME"
#define DEFAULT_LTTNG_FALLBACK_HOME_ENV_VAR   "HOME"
#define DEFAULT_LTTNG_UST_CTL_PATH_ENV_VAR    "LTTNG_UST_CTL_PATH"
#define DEFAULT_LTTNG_UST_APP_PATH_ENV_VAR    "LTTNG_UST_APP_PATH"
#define DEFAULT_LTTNG_RUNDIR_ENV_VAR	      "LTTNG_RUNDIR"
#define DEFAULT_LTTNG_RUNDIR		      CONFIG_LTTNG_SYSTEM_RUNDIR
#define DEFAULT_LTTNG_EXPLICIT_RUNDIR	      "%s"
#define DEFAULT_LTTNG_HOME_RUNDIR	      "%s/.lttng"
#define DEFAULT_LTTNG_SESSIOND_PIDFILE	      "lttng-sessiond.pid"
#define DEFAULT_LTTNG_SESSIOND_AGENTPORT_FILE "agent.port"
#define DEFAULT_LTTNG_SESSIOND_LOCKFILE	      "lttng-sessiond.lck"

/* Default probes list */
#define DEFAULT_LTTNG_KMOD_PROBES "LTTNG_KMOD_PROBES"

/* Default extra probes list */
#define DEFAULT_LTTNG_EXTRA_KMOD_PROBES "LTTNG_EXTRA_KMOD_PROBES"

/* Default unix socket path */
#define DEFAULT_CLIENT_UNIX_SOCK DEFAULT_LTTNG_EXPLICIT_RUNDIR "/client-lttng-sessiond"
#define DEFAULT_HEALTH_UNIX_SOCK DEFAULT_LTTNG_EXPLICIT_RUNDIR "/sessiond-health"
#define DEFAULT_NOTIFICATION_CHANNEL_UNIX_SOCK \
	DEFAULT_LTTNG_EXPLICIT_RUNDIR "/sessiond-notification"

/* Default consumer health unix socket path */
#define DEFAULT_USTCONSUMER32_HEALTH_UNIX_SOCK \
	DEFAULT_LTTNG_EXPLICIT_RUNDIR "/ustconsumerd32/health"
#define DEFAULT_USTCONSUMER64_HEALTH_UNIX_SOCK \
	DEFAULT_LTTNG_EXPLICIT_RUNDIR "/ustconsumerd64/health"
#define DEFAULT_KCONSUMER_HEALTH_UNIX_SOCK DEFAULT_LTTNG_EXPLICIT_RUNDIR "/kconsumerd/health"

/* Default relay health unix socket path */
#define DEFAULT_RELAY_HEALTH_UNIX_SOCK DEFAULT_LTTNG_EXPLICIT_RUNDIR "/relayd/health-%d"

/* Default daemon configuration file path */
#define DEFAULT_SYSTEM_CONFIGPATH     \
	CONFIG_LTTNG_SYSTEM_CONFIGDIR \
	"/lttng"

#define DEFAULT_DAEMON_CONFIG_FILE	 "lttng.conf"
#define DEFAULT_DAEMON_HOME_CONFIGPATH	 DEFAULT_LTTNG_HOME_RUNDIR "/" DEFAULT_DAEMON_CONFIG_FILE
#define DEFAULT_DAEMON_SYSTEM_CONFIGPATH DEFAULT_SYSTEM_CONFIGPATH "/" DEFAULT_DAEMON_CONFIG_FILE
#define DEFAULT_DAEMON_CONFIGPATH	 DEFAULT_LTTNG_EXPLICIT_RUNDIR "/" DEFAULT_DAEMON_CONFIG_FILE

/* Default session configuration file path */
#define DEFAULT_SESSION_PATH "sessions"
/* Auto load session in that directory. */
#define DEFAULT_SESSION_CONFIG_AUTOLOAD	      "auto"
#define DEFAULT_SESSION_HOME_CONFIGPATH	      DEFAULT_LTTNG_HOME_RUNDIR "/" DEFAULT_SESSION_PATH
#define DEFAULT_SESSION_SYSTEM_CONFIGPATH     DEFAULT_SYSTEM_CONFIGPATH "/" DEFAULT_SESSION_PATH
#define DEFAULT_SESSION_CONFIGPATH	      DEFAULT_LTTNG_EXPLICIT_RUNDIR "/" DEFAULT_SESSION_PATH
#define DEFAULT_SESSION_CONFIG_FILE_EXTENSION ".lttng"
#define DEFAULT_SESSION_CONFIG_XSD_FILENAME   "session.xsd"
#define DEFAULT_SESSION_CONFIG_XSD_PATH	      CONFIG_LTTNG_SYSTEM_DATADIR "/xml/lttng/"
#define DEFAULT_SESSION_CONFIG_XSD_PATH_ENV   "LTTNG_SESSION_CONFIG_XSD_PATH"

#define DEFAULT_APPS_UNIX_SOCK		  DEFAULT_LTTNG_EXPLICIT_RUNDIR "/" LTTNG_UST_SOCK_FILENAME
#define DEFAULT_GLOBAL_APPS_WAIT_SHM_PATH "/" LTTNG_UST_WAIT_FILENAME
#define DEFAULT_HOME_APPS_WAIT_SHM_PATH	  DEFAULT_GLOBAL_APPS_WAIT_SHM_PATH "-%d"

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
#define DEFAULT_STREAM_NAME_LEN (LTTNG_SYMBOL_NAME_LEN + 8)

/* Default channel attributes */
#define DEFAULT_CHANNEL_NAME "channel0"
/* Default JUL domain channel name. */
#define DEFAULT_JUL_CHANNEL_NAME "lttng_jul_channel"
/* Default JUL tracepoint name. This is a wildcard for the JUL domain. */
#define DEFAULT_JUL_EVENT_COMPONENT "lttng_jul"
#define DEFAULT_JUL_EVENT_NAME	    DEFAULT_JUL_EVENT_COMPONENT ":*"

/* Default log4j domain channel name. */
#define DEFAULT_LOG4J_CHANNEL_NAME "lttng_log4j_channel"
/* Default log4j tracepoint name. This is a wildcard for the log4j domain. */
#define DEFAULT_LOG4J_EVENT_COMPONENT "lttng_log4j"
#define DEFAULT_LOG4J_EVENT_NAME      DEFAULT_LOG4J_EVENT_COMPONENT ":*"

/* Default log4j2 domain channel name. */
#define DEFAULT_LOG4J2_CHANNEL_NAME "lttng_log4j2_channel"
/* Default log4j tracepoint name. This is a wildcard for the log4j2 domain. */
#define DEFAULT_LOG4J2_EVENT_COMPONENT "lttng_log4j2"
#define DEFAULT_LOG4J2_EVENT_NAME      DEFAULT_LOG4J2_EVENT_COMPONENT ":*"

/* Default Python domain channel name. */
#define DEFAULT_PYTHON_CHANNEL_NAME "lttng_python_channel"
/* Default Python tracepoint name. This is a wildcard for the python domain. */
#define DEFAULT_PYTHON_EVENT_COMPONENT "lttng_python"
#define DEFAULT_PYTHON_EVENT_NAME      DEFAULT_PYTHON_EVENT_COMPONENT ":*"

#define DEFAULT_CHANNEL_ALLOCATION_POLICY LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU

#define DEFAULT_CHANNEL_OVERWRITE	(-1)
#define DEFAULT_CHANNEL_TRACEFILE_SIZE	CONFIG_DEFAULT_CHANNEL_TRACEFILE_SIZE
#define DEFAULT_CHANNEL_TRACEFILE_COUNT CONFIG_DEFAULT_CHANNEL_TRACEFILE_COUNT

#define _DEFAULT_CHANNEL_SUBBUF_SIZE CONFIG_DEFAULT_CHANNEL_SUBBUF_SIZE
#define _DEFAULT_CHANNEL_OUTPUT	     LTTNG_EVENT_MMAP

/* Metadata channel defaults. */
#define DEFAULT_METADATA_SUBBUF_SIZE  CONFIG_DEFAULT_METADATA_SUBBUF_SIZE
#define DEFAULT_METADATA_SUBBUF_NUM   CONFIG_DEFAULT_METADATA_SUBBUF_NUM
#define DEFAULT_METADATA_CACHE_SIZE   CONFIG_DEFAULT_METADATA_CACHE_SIZE
#define DEFAULT_METADATA_SWITCH_TIMER 0
#define DEFAULT_METADATA_READ_TIMER   0
#define DEFAULT_METADATA_OVERWRITE    0
#define DEFAULT_METADATA_OUTPUT	      LTTNG_EVENT_MMAP

/* Kernel has different defaults */

/* DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE must always be a power of 2 */
#define DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE CONFIG_DEFAULT_KERNEL_CHANNEL_SUBBUF_SIZE
/*
 * DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM must always be a power of 2.
 * Update help manually if override.
 */
#define DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM CONFIG_DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM
/* See lttng-kernel.h enum lttng_kernel_output for channel output */
#define DEFAULT_KERNEL_CHANNEL_OUTPUT		LTTNG_EVENT_SPLICE
#define DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER	CONFIG_DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER
#define DEFAULT_KERNEL_CHANNEL_MONITOR_TIMER	CONFIG_DEFAULT_KERNEL_CHANNEL_MONITOR_TIMER
#define DEFAULT_KERNEL_CHANNEL_READ_TIMER	CONFIG_DEFAULT_KERNEL_CHANNEL_READ_TIMER
#define DEFAULT_KERNEL_CHANNEL_LIVE_TIMER	CONFIG_DEFAULT_KERNEL_CHANNEL_LIVE_TIMER
#define DEFAULT_KERNEL_CHANNEL_BLOCKING_TIMEOUT CONFIG_DEFAULT_KERNEL_CHANNEL_BLOCKING_TIMEOUT

/* User space defaults */

/* Must be a power of 2 */
#define DEFAULT_UST_PID_CHANNEL_SUBBUF_SIZE CONFIG_DEFAULT_UST_PID_CHANNEL_SUBBUF_SIZE
#define DEFAULT_UST_UID_CHANNEL_SUBBUF_SIZE CONFIG_DEFAULT_UST_UID_CHANNEL_SUBBUF_SIZE
/* Must be a power of 2. Update help manuall if override. */
#define DEFAULT_UST_PID_CHANNEL_SUBBUF_NUM CONFIG_DEFAULT_UST_PID_CHANNEL_SUBBUF_NUM
#define DEFAULT_UST_UID_CHANNEL_SUBBUF_NUM CONFIG_DEFAULT_UST_UID_CHANNEL_SUBBUF_NUM
/* See lttng-ust.h enum lttng_ust_output */
#define DEFAULT_UST_PID_CHANNEL_OUTPUT _DEFAULT_CHANNEL_OUTPUT
#define DEFAULT_UST_UID_CHANNEL_OUTPUT _DEFAULT_CHANNEL_OUTPUT
/* Timers in usec. */
#define DEFAULT_UST_PID_CHANNEL_SWITCH_TIMER  CONFIG_DEFAULT_UST_PID_CHANNEL_SWITCH_TIMER
#define DEFAULT_UST_UID_CHANNEL_SWITCH_TIMER  CONFIG_DEFAULT_UST_UID_CHANNEL_SWITCH_TIMER
#define DEFAULT_UST_PID_CHANNEL_LIVE_TIMER    CONFIG_DEFAULT_UST_PID_CHANNEL_LIVE_TIMER
#define DEFAULT_UST_UID_CHANNEL_LIVE_TIMER    CONFIG_DEFAULT_UST_UID_CHANNEL_LIVE_TIMER
#define DEFAULT_UST_PID_CHANNEL_MONITOR_TIMER CONFIG_DEFAULT_UST_PID_CHANNEL_MONITOR_TIMER
#define DEFAULT_UST_UID_CHANNEL_MONITOR_TIMER CONFIG_DEFAULT_UST_UID_CHANNEL_MONITOR_TIMER

#define DEFAULT_UST_PID_CHANNEL_READ_TIMER CONFIG_DEFAULT_UST_PID_CHANNEL_READ_TIMER
#define DEFAULT_UST_UID_CHANNEL_READ_TIMER CONFIG_DEFAULT_UST_UID_CHANNEL_READ_TIMER

#define DEFAULT_UST_PID_CHANNEL_BLOCKING_TIMEOUT CONFIG_DEFAULT_UST_PID_CHANNEL_BLOCKING_TIMEOUT
#define DEFAULT_UST_UID_CHANNEL_BLOCKING_TIMEOUT CONFIG_DEFAULT_UST_UID_CHANNEL_BLOCKING_TIMEOUT

/*
 * Default timeout value for the sem_timedwait() call. Blocking forever is not
 * wanted so a timeout is used to control the data flow and not freeze the
 * session daemon.
 */
#define DEFAULT_SEM_WAIT_TIMEOUT 30 /* in seconds */

/* Default bind addresses for network services. */
#define DEFAULT_NETWORK_CONTROL_BIND_ADDRESS CONFIG_DEFAULT_NETWORK_CONTROL_BIND_ADDRESS
#define DEFAULT_NETWORK_DATA_BIND_ADDRESS    CONFIG_DEFAULT_NETWORK_DATA_BIND_ADDRESS
#define DEFAULT_NETWORK_VIEWER_BIND_ADDRESS  CONFIG_DEFAULT_NETWORK_VIEWER_BIND_ADDRESS
#define DEFAULT_AGENT_BIND_ADDRESS	     CONFIG_DEFAULT_AGENT_BIND_ADDRESS

/* Default network ports for trace streaming support. */
#define DEFAULT_NETWORK_CONTROL_PORT CONFIG_DEFAULT_NETWORK_CONTROL_PORT
#define DEFAULT_NETWORK_DATA_PORT    CONFIG_DEFAULT_NETWORK_DATA_PORT
#define DEFAULT_NETWORK_VIEWER_PORT  CONFIG_DEFAULT_NETWORK_VIEWER_PORT

/* Agent registration TCP port range. */
#define DEFAULT_AGENT_TCP_PORT_RANGE_BEGIN CONFIG_DEFAULT_AGENT_TCP_PORT_RANGE_BEGIN
#define DEFAULT_AGENT_TCP_PORT_RANGE_END   CONFIG_DEFAULT_AGENT_TCP_PORT_RANGE_END

/* Number of buckets in the event notifier error count map. */
#define DEFAULT_EVENT_NOTIFIER_ERROR_COUNT_MAP_SIZE \
	CONFIG_DEFAULT_EVENT_NOTIFIER_ERROR_COUNT_MAP_SIZE

/*
 * If a thread stalls for this amount of time, it will be considered bogus (bad
 * health).
 */
#define DEFAULT_HEALTH_CHECK_DELTA_S  20
#define DEFAULT_HEALTH_CHECK_DELTA_NS 0

/*
 * Wait period before retrying the lttng_data_pending command in the lttng
 * stop command of liblttng-ctl.
 */
#define DEFAULT_DATA_AVAILABILITY_WAIT_TIME_US 200000 /* usec */

/*
 * Wait period before retrying the lttng_consumer_flushed_cache when
 * the consumer receives metadata.
 */
#define DEFAULT_METADATA_AVAILABILITY_WAIT_TIME 200000 /* usec */

/*
 * The usual value for the maximum TCP SYN retries time and TCP FIN timeout is
 * 180 and 60 seconds on most Linux system and the default value since kernel
 * 2.2 thus using the highest value. See tcp(7) for more details.
 */
#define DEFAULT_INET_TCP_TIMEOUT 180 /* sec */

/* Maximum payload size for a control connection */

#define DEFAULT_NETWORK_RELAYD_CTRL_MAX_PAYLOAD_SIZE \
	CONFIG_DEFAULT_NETWORK_RELAYD_CTRL_MAX_PAYLOAD_SIZE

/*
 * Default receiving and sending timeout for an application socket.
 */
#define DEFAULT_APP_SOCKET_RW_TIMEOUT  CONFIG_DEFAULT_APP_SOCKET_RW_TIMEOUT
#define DEFAULT_APP_SOCKET_TIMEOUT_ENV "LTTNG_APP_SOCKET_TIMEOUT"

#define DEFAULT_UST_STREAM_FD_NUM 2 /* Number of fd per UST stream. */

#define DEFAULT_SNAPSHOT_NAME	  "snapshot"
#define DEFAULT_SNAPSHOT_MAX_SIZE 0 /* Unlimited. */

/* Suffix of an index file. */
#define DEFAULT_INDEX_FILE_SUFFIX ".idx"
#define DEFAULT_INDEX_DIR	  "index"

/* Default lttng command live timer value in usec. */
#define DEFAULT_LTTNG_LIVE_TIMER CONFIG_DEFAULT_LTTNG_LIVE_TIMER

/* Default runas worker name */
#define DEFAULT_RUN_AS_WORKER_NAME "lttng-runas"

/* Default LTTng MI XML namespace. */
#define DEFAULT_LTTNG_MI_NAMESPACE "https://lttng.org/xml/ns/lttng-mi"

/* Default thread stack size; the default mandated by pthread_create(3) */
#define DEFAULT_LTTNG_THREAD_STACK_SIZE 2097152

/* Default maximal size of message notification channel message payloads. */
#define DEFAULT_MAX_NOTIFICATION_CLIENT_MESSAGE_PAYLOAD_SIZE 65536

/* Default maximal size of trace archive location. */
#define DEFAULT_MAX_TRACE_ARCHIVE_LOCATION_PAYLOAD_SIZE 65536

/* Default maximal size of message notification channel message payloads. */
#define DEFAULT_CLIENT_MAX_QUEUED_NOTIFICATIONS_COUNT 100

#define DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ENV		  "LTTNG_RELAYD_TCP_KEEP_ALIVE"
#define DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME_ENV "LTTNG_RELAYD_TCP_KEEP_ALIVE_IDLE_TIME"
#define DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT_ENV \
	"LTTNG_RELAYD_TCP_KEEP_ALIVE_MAX_PROBE_COUNT"
#define DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL_ENV \
	"LTTNG_RELAYD_TCP_KEEP_ALIVE_PROBE_INTERVAL"
#define DEFAULT_LTTNG_RELAYD_TCP_KEEP_ALIVE_ABORT_THRESHOLD_ENV \
	"LTTNG_RELAYD_TCP_KEEP_ALIVE_ABORT_THRESHOLD"
#define DEFAULT_LTTNG_RELAYD_DISALLOW_CLEAR_ENV "LTTNG_RELAYD_DISALLOW_CLEAR"

#define DEFAULT_LTTNG_RELAYD_WORKING_DIRECTORY_ENV "LTTNG_RELAYD_WORKING_DIRECTORY"

/*
 * Name of the intermediate directory used to rename the trace chunk of a
 * session's first rotation.
 */
#define DEFAULT_CHUNK_TMP_OLD_DIRECTORY		".tmp_old_chunk"
#define DEFAULT_CHUNK_TMP_NEW_DIRECTORY		".tmp_new_chunk"
#define DEFAULT_ARCHIVED_TRACE_CHUNKS_DIRECTORY "archives"
#define DEFAULT_UNLINKED_FILES_DIRECTORY	".unlinked"

/*
 * Default timer value in usec for the rotate pending polling check on the
 * relay when a rotation has completed on the consumer.
 */
#define DEFAULT_ROTATE_PENDING_TIMER CONFIG_DEFAULT_ROTATE_PENDING_TIMER

#define DEFAULT_LINUX_POSSIBLE_CPU_PATH	       "/sys/devices/system/cpu/possible"
#define DEFAULT_LINUX_POSSIBLE_CPU_MASK_LENGTH 4096

/*
 * Returns the default subbuf size.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
size_t default_get_channel_subbuf_size();

/*
 * Returns the default metadata subbuf size.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
size_t default_get_metadata_subbuf_size();

/*
 * Returns the default subbuf size for the kernel domain.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
size_t default_get_kernel_channel_subbuf_size();

/*
 * Returns the default subbuf size for the UST domain per PID.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
size_t default_get_ust_pid_channel_subbuf_size();

/*
 * Returns the default subbuf size for the UST domain per UID.
 *
 * This function depends on a value that is set at constructor time, so it is
 * unsafe to call it from another constructor.
 */
size_t default_get_ust_uid_channel_subbuf_size();

/*
 * Get the default pthread_attr to use on thread creation.
 *
 * Some libc, such as musl, don't honor the limit set for the stack size and use
 * their own empirically chosen static value. This function checks if the
 * current stack size is smaller than the stack size limit and if so returns a
 * pthread_attr_t pointer where the thread stack size is set to the soft stack
 * size limit.
 */
pthread_attr_t *default_pthread_attr();

#endif /* _DEFAULTS_H */
