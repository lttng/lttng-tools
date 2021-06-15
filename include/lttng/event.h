/*
 * Copyright (C) 2014 David Goulet <dgoulet@efficios.com>
 * Copyright (C) 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_EVENT_H
#define LTTNG_EVENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <lttng/handle.h>
#include <lttng/lttng-export.h>
#include <lttng/userspace-probe.h>

/*!
@brief
    \ref api-rer-conds-inst-pt-type "Instrumentation type condition"
    of a recording event

@ingroup api_rer
*/
enum lttng_event_type {
	/// Match LTTng kernel tracepoint and Linux system call events.
	LTTNG_EVENT_ALL = -1,

	/// Match LTTng tracepoint or Java/Python logging events.
	LTTNG_EVENT_TRACEPOINT = 0,

	/*!
	Match Linux
	<a href="https://www.kernel.org/doc/html/latest/trace/kprobes.html">kprobe</a>
	events.
	*/
	LTTNG_EVENT_PROBE = 1,

	/*!
	Match Linux
	<a href="https://www.kernel.org/doc/html/latest/trace/kprobes.html">kretprobe</a>
	events.
	*/
	LTTNG_EVENT_FUNCTION = 2,

	/// @cond UNUSED
	LTTNG_EVENT_FUNCTION_ENTRY = 3,
	LTTNG_EVENT_NOOP = 4,
	/// @endcond

	/// Match Linux system call events.
	LTTNG_EVENT_SYSCALL = 5,

	/*!
	Match Linux
	<a href="https://lwn.net/Articles/499190/">uprobe</a>
	events.
	*/
	LTTNG_EVENT_USERSPACE_PROBE = 6,
};

/*!
@brief
    Operand of the
    \ref api-rer-conds-ll "instrumentation point log level condition"
    of a recording event rule.

@ingroup api_rer

In the enumerator descriptions below, consider that \lt_var{LL} is the
log level value of the condition, that is, the value of the
lttng_event::loglevel member when the lttng_event::loglevel_type member
is the described enumerator.

Depending on the \lt_obj_domain of the recording event rule, \lt_var{LL}
is one of the enumerators of #lttng_loglevel, #lttng_loglevel_jul,
#lttng_loglevel_log4j, or #lttng_loglevel_python.
*/
enum lttng_loglevel_type {
	/// Match events regardless of their log level.
	LTTNG_EVENT_LOGLEVEL_ALL = 0,

	/*!
	Match events with a log level that's at least as severe as
	\lt_var{LL}.
	*/
	LTTNG_EVENT_LOGLEVEL_RANGE = 1,

	/// Match events with a log level that's exacty \lt_var{LL}.
	LTTNG_EVENT_LOGLEVEL_SINGLE = 2,
};

/*!
@brief
    Value of the
    \ref api-rer-conds-ll "instrumentation point log level condition"=
    of an LTTng
    \link #LTTNG_DOMAIN_UST user space\endlink tracepoint
    recording event rule.

@ingroup api_rer

@sa #lttng_loglevel_type --
    Operand of the log level condition of a recording event rule.
*/
enum lttng_loglevel {
	/// System is unusable.
	LTTNG_LOGLEVEL_EMERG = 0,

	/// Action must be taken immediately.
	LTTNG_LOGLEVEL_ALERT = 1,

	/// Critical conditions.
	LTTNG_LOGLEVEL_CRIT = 2,

	/// Error conditions.
	LTTNG_LOGLEVEL_ERR = 3,

	/// Warning conditions.
	LTTNG_LOGLEVEL_WARNING = 4,

	/// Normal, but significant, condition.
	LTTNG_LOGLEVEL_NOTICE = 5,

	/// Informational message.
	LTTNG_LOGLEVEL_INFO = 6,

	/// Debug information with system-level scope (set of programs).
	LTTNG_LOGLEVEL_DEBUG_SYSTEM = 7,

	/// Debug information with program-level scope (set of processes).
	LTTNG_LOGLEVEL_DEBUG_PROGRAM = 8,

	/// Debug information with process-level scope (set of modules).
	LTTNG_LOGLEVEL_DEBUG_PROCESS = 9,

	/*!
	Debug information with module (executable/library) scope
	(set of units).
	*/
	LTTNG_LOGLEVEL_DEBUG_MODULE = 10,

	/// Debug information with compilation unit scope (set of functions).
	LTTNG_LOGLEVEL_DEBUG_UNIT = 11,

	/// Debug information with function-level scope.
	LTTNG_LOGLEVEL_DEBUG_FUNCTION = 12,

	/// Debug information with line-level scope.
	LTTNG_LOGLEVEL_DEBUG_LINE = 13,

	/// Debug-level message.
	LTTNG_LOGLEVEL_DEBUG = 14,
};

/*!
@brief
    Value of the
    \ref api-rer-conds-ll "instrumentation point log level condition"
    of a
    \link #LTTNG_DOMAIN_JUL <code>java.util.logging</code>\endlink
    recording event rule.

@ingroup api_rer

@sa #lttng_loglevel_type --
    Operand of the log level condition of a recording event rule.
*/
enum lttng_loglevel_jul {
	/// Logging turned off.
	LTTNG_LOGLEVEL_JUL_OFF = INT32_MAX,

	/// Serious failure.
	LTTNG_LOGLEVEL_JUL_SEVERE = 1000,

	/// Potential problem.
	LTTNG_LOGLEVEL_JUL_WARNING = 900,

	/// Informational messages.
	LTTNG_LOGLEVEL_JUL_INFO = 800,

	/// Static configuration messages.
	LTTNG_LOGLEVEL_JUL_CONFIG = 700,

	/// Tracing information.
	LTTNG_LOGLEVEL_JUL_FINE = 500,

	/// Fairly detailed tracing message.
	LTTNG_LOGLEVEL_JUL_FINER = 400,

	/// Highly detailed tracing message.
	LTTNG_LOGLEVEL_JUL_FINEST = 300,

	/// All messages.
	LTTNG_LOGLEVEL_JUL_ALL = INT32_MIN,
};

/*!
@brief
    Value of the
    \ref api-rer-conds-ll "instrumentation point log level condition"
    of an
    \link #LTTNG_DOMAIN_LOG4J Apache log4j\endlink
    recording event rule.

@ingroup api_rer

@sa #lttng_loglevel_type --
    Operand of the log level condition of a recording event rule.
*/
enum lttng_loglevel_log4j {
	/// Logging turned off.
	LTTNG_LOGLEVEL_LOG4J_OFF = INT32_MAX,

	/*!
	Very severe error events that will presumably lead the
	application to abort.
	*/
	LTTNG_LOGLEVEL_LOG4J_FATAL = 50000,

	/*!
	Error events that might still allow the application to continue
	running.
	*/
	LTTNG_LOGLEVEL_LOG4J_ERROR = 40000,

	/// Potentially harmful situations.
	LTTNG_LOGLEVEL_LOG4J_WARN = 30000,

	/*!
	Informational messages that highlight the progress of the
	application at coarse-grained level.
	*/
	LTTNG_LOGLEVEL_LOG4J_INFO = 20000,

	/*!
	Fine-grained informational events that are most useful to debug
	an application.
	*/
	LTTNG_LOGLEVEL_LOG4J_DEBUG = 10000,

	/*!
	Finer-grained informational events than the
	#LTTNG_LOGLEVEL_LOG4J_DEBUG level.
	*/
	LTTNG_LOGLEVEL_LOG4J_TRACE = 5000,

	/// All levels, including custom levels.
	LTTNG_LOGLEVEL_LOG4J_ALL = INT32_MIN,
};

/*!
@brief
    Value of the
    \ref api-rer-conds-ll "instrumentation point log level condition"
    of a
    \link #LTTNG_DOMAIN_PYTHON Python\endlink
    recording event rule.

@ingroup api_rer

@sa #lttng_loglevel_type --
    Operand of the log level condition of a recording event rule.
*/
enum lttng_loglevel_python {
	/// Critical.
	LTTNG_LOGLEVEL_PYTHON_CRITICAL = 50,

	/// Error.
	LTTNG_LOGLEVEL_PYTHON_ERROR = 40,

	/// Warning.
	LTTNG_LOGLEVEL_PYTHON_WARNING = 30,

	/// Information.
	LTTNG_LOGLEVEL_PYTHON_INFO = 20,

	/// Debugging.
	LTTNG_LOGLEVEL_PYTHON_DEBUG = 10,

	/// Logging turned off.
	LTTNG_LOGLEVEL_PYTHON_NOTSET = 0,
};

/*!
@brief
    Channel output type.

@ingroup api_channel
*/
enum lttng_event_output {
	/// Use the \lt_man_gen{splice,2} system call.
	LTTNG_EVENT_SPLICE = 0,

	/// Use the \lt_man_gen{mmap,2} system call.
	LTTNG_EVENT_MMAP = 1,
};

/*!
@brief
    Context field type.

@ingroup api_channel

The following table indicates, for each enumerator, its description, for
which \lt_obj_domain it's available, and the
data type and the name of the resulting context field in traces.

<table>
  <tr>
    <th>Enumerator
    <th>Description
    <th>Tracing domain
    <th>Field type
    <th>Field name
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_PID
    <td>Process ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>pid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_PROCNAME
    <td>Process name
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>String
    <td><code>procname</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_PRIO
    <td>Process priority
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>prio</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_NICE
    <td>Nice value of the process
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>nice</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_VPID
    <td>Virtual process ID
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>vpid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_TID
    <td>Thread ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>tid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_VTID
    <td>Virtual thread ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>vtid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_PPID
    <td>ID of the parent process
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>ppid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_VPPID
    <td>Virtual ID of the parent process
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>vppid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_PTHREAD_ID
    <td>POSIX thread ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>pthread_id</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_HOSTNAME
    <td>Hostname
    <td>#LTTNG_DOMAIN_KERNEL
    <td>String
    <td><code>hostname</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_IP
    <td>Instruction pointer
    <td>#LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>ip</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER
    <td>
      Per-CPU perf counter.

      If the lttng_event_context::ctx member of an #lttng_event_context
      structure is #LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER, then the
      lttng_event_context::lttng_event_context_u::perf_counter member
      of lttng_event_context::u selects a specific per-CPU perf counter.
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td>Depends on the selected perf counter
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER
    <td>
      Per-thread perf counter.

      If the lttng_event_context::ctx member of an #lttng_event_context
      structure is #LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER, then the
      lttng_event_context::lttng_event_context_u::perf_counter member
      of lttng_event_context::u selects a specific per-thread
      perf counter.
    <td>#LTTNG_DOMAIN_UST
    <td>Integer
    <td>Depends on the selected perf counter
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_APP_CONTEXT
    <td>
      Application-specific context.

      If the lttng_event_context::ctx member of an #lttng_event_context
      structure is #LTTNG_EVENT_CONTEXT_APP_CONTEXT, then the
      lttng_event_context::lttng_event_context_u::app_ctx member of
      of lttng_event_context::u selects
      a specific application-specific context.
    <td>#LTTNG_DOMAIN_JUL or #LTTNG_DOMAIN_LOG4J
    <td>Integer or string
    <td>Depends on the selected application-specific context
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_INTERRUPTIBLE
    <td>Whether or not the process is interruptible
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer (0 or 1)
    <td><code>interruptible</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_PREEMPTIBLE
    <td>Whether or not the process is preemptible
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer (0 or 1)
    <td><code>preemptible</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_NEED_RESCHEDULE
    <td>Whether or not the process needs a reschedule
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer (0 or 1)
    <td><code>need_reschedule</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_MIGRATABLE
    <td>Whether or not the process is migratable
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer (0 or 1)
    <td><code>migratable</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_CALLSTACK_KERNEL
    <td>Linux kernel call stack
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Dynamic-length array of integers (instruction pointers)
    <td><code>callstack_kernel</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_CALLSTACK_USER
    <td>
      User space call stack.

      Only supported on IA-32 and x86-64 architectures.
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Dynamic-length array of integers (instruction pointers)
    <td><code>callstack_user</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_CGROUP_NS
    <td>
      Control group root directory namespace ID.

      @sa \lt_man_gen{cgroup_namespaces,7}
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>cgroup_ns</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_IPC_NS
    <td>
      System&nbsp;V IPC and POSIX message queue namespace ID.

      @sa \lt_man_gen{ipc_namespaces,7}
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>ipc_ns</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_MNT_NS
    <td>
      Mount point namespace ID.

      @sa \lt_man_gen{mount_namespaces,7}
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>mnt_ns</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_NET_NS
    <td>
      Networking namespace ID.

      @sa \lt_man_gen{network_namespaces,7}
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>net_ns</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_PID_NS
    <td>
      Process ID namespace ID.

      @sa \lt_man_gen{pid_namespaces,7}
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>pid_ns</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_USER_NS
    <td>
      User and group ID namespace ID.

      @sa \lt_man_gen{user_namespaces,7}
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>user_ns</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_UTS_NS
    <td>
      Hostname and NIS domain name namespace ID.

      @sa \lt_man_gen{uts_namespaces,7}
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>uts_ns</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_TIME_NS
    <td>
      Boot and monotonic clock namespace ID.

      @sa \lt_man_gen{time_namespaces,7}
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>time_ns</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_UID
    <td>User ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>uid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_EUID
    <td>Effective user ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>euid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_SUID
    <td>Set owner user ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>suid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_GID
    <td>Group ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>gid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_EGID
    <td>Effective group ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>egid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_SGID
    <td>Set owner group ID
    <td>#LTTNG_DOMAIN_KERNEL
    <td>Integer
    <td><code>sgid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_VUID
    <td>Virtual user ID
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>vuid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_VEUID
    <td>Virtual effective user ID
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>veuid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_VSUID
    <td>Virtual set owner user ID
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>vsuid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_VGID
    <td>Virtual group ID
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>vgid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_VEGID
    <td>Virtual effective group ID
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>vegid</code>
  <tr>
    <td>#LTTNG_EVENT_CONTEXT_VSGID
    <td>Virtual set owner group ID
    <td>#LTTNG_DOMAIN_KERNEL and #LTTNG_DOMAIN_UST
    <td>Integer
    <td><code>vsgid</code>
</table>

@ingroup api_channel
*/
enum lttng_event_context_type {
	/// Process ID.
	LTTNG_EVENT_CONTEXT_PID = 0,

	/// @cond BACKWARD_COMPAT_EVENT_CTX_TYPES
	LTTNG_EVENT_CONTEXT_PERF_COUNTER = 1, /* Backward compat. */
	/// @endcond

	/// Process name.
	LTTNG_EVENT_CONTEXT_PROCNAME = 2,

	/// Process priority.
	LTTNG_EVENT_CONTEXT_PRIO = 3,

	/// Nice value of the process.
	LTTNG_EVENT_CONTEXT_NICE = 4,

	/// Virtual process ID.
	LTTNG_EVENT_CONTEXT_VPID = 5,

	/// Thread ID.
	LTTNG_EVENT_CONTEXT_TID = 6,

	/// Virtual thread ID.
	LTTNG_EVENT_CONTEXT_VTID = 7,

	/// ID of the parent process.
	LTTNG_EVENT_CONTEXT_PPID = 8,

	/// Virtual ID of the parent process.
	LTTNG_EVENT_CONTEXT_VPPID = 9,

	/// POSIX thread ID.
	LTTNG_EVENT_CONTEXT_PTHREAD_ID = 10,

	/// Hostname.
	LTTNG_EVENT_CONTEXT_HOSTNAME = 11,

	/// Instruction pointer.
	LTTNG_EVENT_CONTEXT_IP = 12,

	/// Per-CPU perf counter.
	LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER = 13,

	/// Per-thread perf counter.
	LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER = 14,

	/// Application-specific context.
	LTTNG_EVENT_CONTEXT_APP_CONTEXT = 15,

	/// Whether or not the process is interruptible.
	LTTNG_EVENT_CONTEXT_INTERRUPTIBLE = 16,

	/// Whether or not the process is preemptible.
	LTTNG_EVENT_CONTEXT_PREEMPTIBLE = 17,

	/// Whether or not the process needs a reschedule.
	LTTNG_EVENT_CONTEXT_NEED_RESCHEDULE = 18,

	/// Whether or not the process is migratable.
	LTTNG_EVENT_CONTEXT_MIGRATABLE = 19,

	/// Linux kernel call stack.
	LTTNG_EVENT_CONTEXT_CALLSTACK_KERNEL = 20,

	/// User space call stack.
	LTTNG_EVENT_CONTEXT_CALLSTACK_USER = 21,

	/// Control group root directory namespace ID.
	LTTNG_EVENT_CONTEXT_CGROUP_NS = 22,

	/// System&nbsp;V IPC and POSIX message queue namespace ID.
	LTTNG_EVENT_CONTEXT_IPC_NS = 23,

	/// Mount point namespace ID.
	LTTNG_EVENT_CONTEXT_MNT_NS = 24,

	/// Networking namespace ID.
	LTTNG_EVENT_CONTEXT_NET_NS = 25,

	/// Process ID namespace ID.
	LTTNG_EVENT_CONTEXT_PID_NS = 26,

	/// User and group ID namespace ID.
	LTTNG_EVENT_CONTEXT_USER_NS = 27,

	/// Hostname and NIS domain name namespace ID.
	LTTNG_EVENT_CONTEXT_UTS_NS = 28,

	/// User ID namespace ID.
	LTTNG_EVENT_CONTEXT_UID = 29,

	/// Effective user ID namespace ID.
	LTTNG_EVENT_CONTEXT_EUID = 30,

	/// Set owner user ID namespace ID.
	LTTNG_EVENT_CONTEXT_SUID = 31,

	/// Group ID namespace ID.
	LTTNG_EVENT_CONTEXT_GID = 32,

	/// Effective group ID namespace ID.
	LTTNG_EVENT_CONTEXT_EGID = 33,

	/// Set owner group ID namespace ID.
	LTTNG_EVENT_CONTEXT_SGID = 34,

	/// Virtual user ID namespace ID.
	LTTNG_EVENT_CONTEXT_VUID = 35,

	/// Virtual effective user ID namespace ID.
	LTTNG_EVENT_CONTEXT_VEUID = 36,

	/// Virtual set owner user ID namespace ID.
	LTTNG_EVENT_CONTEXT_VSUID = 37,

	/// Virtual group ID namespace ID.
	LTTNG_EVENT_CONTEXT_VGID = 38,

	/// Virtual effective group ID namespace ID.
	LTTNG_EVENT_CONTEXT_VEGID = 39,

	/// Virtual set owner group ID namespace ID.
	LTTNG_EVENT_CONTEXT_VSGID = 40,

	/// Boot and monotonic clock namespace ID.
	LTTNG_EVENT_CONTEXT_TIME_NS = 41,
};

/*!
@brief
    LTTng tracepoint field data type
    (type of the lttng_event_field::type member).

@ingroup api_inst_pt
*/
enum lttng_event_field_type {
	/// Other/unknown.
	LTTNG_EVENT_FIELD_OTHER = 0,

	/// Integer.
	LTTNG_EVENT_FIELD_INTEGER = 1,

	/// Enumeration.
	LTTNG_EVENT_FIELD_ENUM = 2,

	/// Floating point number.
	LTTNG_EVENT_FIELD_FLOAT = 3,

	/// String.
	LTTNG_EVENT_FIELD_STRING = 4,
};

/*!
@brief
    \ref api-rer-inst-pt-descr "Instrumentation point descriptor"
    flag (type of the lttng_event::flags member).

@ingroup api_inst_pt
*/
enum lttng_event_flag {
	/*!
	@brief
	    32-bit Linux system call.

	Only valid when the lttng_event::type member is
	#LTTNG_EVENT_SYSCALL.
	*/
	LTTNG_EVENT_FLAG_SYSCALL_32 = (1U << 0),

	/*!
	@brief
	    64-bit Linux system call.

	Only valid when the lttng_event::type member is
	#LTTNG_EVENT_SYSCALL.
	*/
	LTTNG_EVENT_FLAG_SYSCALL_64 = (1U << 1),
};

#define LTTNG_PERF_EVENT_PADDING1 16

/*!
@brief
    perf counter context field descriptor.

@ingroup api_channel

If the lttng_event_context::ctx member of an #lttng_event_context
structure is #LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER or
#LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER, then the
lttng_event_context::lttng_event_context_u::perf_counter member
of lttng_event_context::u selects a specific perf counter.

You must initialize such a structure to zeros before setting its members
and using it, for example:

@code
struct lttng_event_perf_counter_ctx perf_counter_ctx;

memset(&perf_counter_ctx, 0, sizeof(perf_counter_ctx));
@endcode
*/
struct lttng_event_perf_counter_ctx {
	/*!
	@brief
	    perf counter type ID.

	One of:

	<table>
	  <tr>
	    <th>Type
	    <th>ID
	  <tr>
	    <td>Hardware counter
	    <td>0
	  <tr>
	    <td>Software counter
	    <td>1
	  <tr>
	    <td>Hardware cache counter
	    <td>3
	  <tr>
	    <td>Performance Monitoring Unit (PMU) counter
	    <td>4
	</table>
	*/
	uint32_t type;

	/*!
	@brief
	    perf counter configuration.

	Depending on the lttng_event_perf_counter_ctx::type member:

	<dl>
	  <dt>0 (hardware counter)
	  <dd>
	    One of:

	    <table>
	      <tr>
		<th>Counter
		<th>ID
	      <tr>
		<td>CPU cycles
		<td>0
	      <tr>
		<td>Instructions
		<td>1
	      <tr>
		<td>Cache references
		<td>2
	      <tr>
		<td>Cache misses
		<td>3
	      <tr>
		<td>Branch instructions
		<td>4
	      <tr>
		<td>Branch misses
		<td>5
	      <tr>
		<td>Bus cycles
		<td>6
	      <tr>
		<td>Stalled cycles (front end)
		<td>7
	      <tr>
		<td>Stalled cycles (back end)
		<td>8
	    </table>

	  <dt>1 (software counter)
	  <dd>
	    One of:

	    <table>
	      <tr>
		<th>Counter
		<th>ID
	      <tr>
		<td>CPU clock
		<td>0
	      <tr>
		<td>Task clock
		<td>1
	      <tr>
		<td>Page faults
		<td>2
	      <tr>
		<td>Context switches
		<td>3
	      <tr>
		<td>CPU migrations
		<td>4
	      <tr>
		<td>Minor page faults
		<td>5
	      <tr>
		<td>Major page faults
		<td>6
	      <tr>
		<td>Alignment faults
		<td>7
	      <tr>
		<td>Emulation faults
		<td>8
	    </table>

	  <dt>3 (hardware cache counter)
	  <dd>
	    The result of a bitwise OR operation between a cache ID,
	    an operation ID, and a result ID, as follows:

	    <table>
	      <tr>
		<th>Cache ID
		<th>Description
	      <tr>
		<td>0
		<td>Data L1
	      <tr>
		<td>1
		<td>Instructions L1
	      <tr>
		<td>2
		<td>LL
	      <tr>
		<td>3
		<td>Data <a
	href="https://en.wikipedia.org/wiki/Translation_lookaside_buffer">TLB</a> <tr> <td>4
		<td>Instruction TLB
	      <tr>
		<td>5
		<td>Branch prediction unit (BPU)
	    </table>

	    <table>
	      <tr>
		<th>Operator ID
		<th>Description
	      <tr>
		<td>0
		<td>Read
	      <tr>
		<td>0x100
		<td>Write
	      <tr>
		<td>0x200
		<td>Prefetch
	    </table>

	    <table>
	      <tr>
		<th>Result ID
		<th>Description
	      <tr>
		<td>0
		<td>Access
	      <tr>
		<td>0x10000
		<td>Miss
	    </table>

	  <dt>4 (PMU counter)
	  <dd>
	    PMU counter raw ID.

	    @sa \lt_man_gen{perf-record,1}
	</dl>
	*/
	uint64_t config;

	/// Context field name.
	char name[LTTNG_SYMBOL_NAME_LEN];

	char padding[LTTNG_PERF_EVENT_PADDING1];
};

#define LTTNG_EVENT_CONTEXT_PADDING1 16
#define LTTNG_EVENT_CONTEXT_PADDING2 LTTNG_SYMBOL_NAME_LEN + 32

/*!
@brief
    Context field descriptor.

@ingroup api_channel

Such a structure describes a context field to be recorded within all the
\ref api_rer "event records" of a given \lt_obj_channel (see
lttng_add_context()).

You must initialize such a structure to zeros before setting its members
and using it, for example:

@code
struct lttng_event_context ctx;

memset(&ctx, 0, sizeof(ctx));
@endcode
*/
struct lttng_event_context {
	/*!
	@brief
	    Context field type.

	Some types have a \lt_obj_domain
	constraint.

	If this member has the value
	#LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER or
	#LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER, then you must also set
	the lttng_event_context::lttng_event_context_u::perf_counter
	member of lttng_event_context::u.

	If this member has the value #LTTNG_EVENT_CONTEXT_APP_CONTEXT,
	then you must also set the
	lttng_event_context::lttng_event_context_u::app_ctx member
	of lttng_event_context::u.
	*/
	enum lttng_event_context_type ctx;

	char padding[LTTNG_EVENT_CONTEXT_PADDING1];

	/*!
	@brief
	    perf counter or application-specific context field
	    descriptor.

	@ingroup api_channel
	*/
	union lttng_event_context_u {
		/*!
		@brief
		    perf counter context field descriptor.

		Only used when the lttng_event_context::ctx member
		is #LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER or
		#LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER.
		*/
		struct lttng_event_perf_counter_ctx perf_counter;

		struct {
			/// Provider name.
			char *provider_name;

			/// Field type.
			char *ctx_name;
		}

		/*!
		@brief
		    Application-specific context field descriptor.

		Only used when the lttng_event_context::ctx member
		is #LTTNG_EVENT_CONTEXT_APP_CONTEXT.
		*/
		app_ctx;

		char padding[LTTNG_EVENT_CONTEXT_PADDING2];
	}

	/// perf counter or application-specific context field descriptor.
	u;
};

#define LTTNG_EVENT_PROBE_PADDING1 16

/*!
@brief
    Legacy Linux kprobe/kretprobe location.

@ingroup api_rer

Such a structure indicates the location of a Linux kprobe/kretprobe for
a \lt_obj_rer having such an instrumentation point type.

You must initialize such a structure to zeros before setting its members
and using it, for example:

@code
struct lttng_event_probe_attr loc;

memset(&loc, 0, sizeof(loc));
@endcode

Set either lttng_event_probe_attr::addr or
lttng_event_probe_attr::symbol_name and lttng_event_probe_attr::offset.

@sa \ref api-rer-conds-inst-pt-type "Instrumentation point type condition".
*/
struct lttng_event_probe_attr {
	/*!
	@brief
	    kprobe/kretprobe address.

	If this member is not 0, then
	lttng_event_probe_attr::symbol_name must be an empty string.
	*/
	uint64_t addr;

	/*!
	@brief
	    kprobe/kretprobe address offset from the symbol named
	    lttng_event_probe_attr::symbol_name.
	*/
	uint64_t offset;

	/*!
	@brief
	    kprobe/kretprobe symbol name.

	The actual kprobe/kretprobe address is the address of the named
	symbol plus the value of lttng_event_probe_attr::offset.

	If this member is not an empty string, then
	lttng_event_probe_attr::addr must be 0.
	*/
	char symbol_name[LTTNG_SYMBOL_NAME_LEN];

	char padding[LTTNG_EVENT_PROBE_PADDING1];
};

/*
 * Function tracer
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_EVENT_FUNCTION_PADDING1 16
struct lttng_event_function_attr {
	char symbol_name[LTTNG_SYMBOL_NAME_LEN];

	char padding[LTTNG_EVENT_FUNCTION_PADDING1];
};

/*
 * Generic lttng event
 *
 * The structures should be initialized to zero before use.
 */
#define LTTNG_EVENT_PADDING1 12
#define LTTNG_EVENT_PADDING2 LTTNG_SYMBOL_NAME_LEN + 32

/*!
@brief
    \lt_obj_c_rer descriptor.

@ingroup api_rer

Such a structure describes a recording event rule. More specifically,
it describes the \ref api-rer-conds "conditions" of a recording
event rule.

lttng_list_events() sets a pointer to an array of all the recording
event rule descriptors of a given \lt_obj_channel.

@note
    \anchor api-rer-inst-pt-descr lttng_list_tracepoints()
    and lttng_list_syscalls() also set
    a pointer to an array of instances of this structure. In this
    context, the #lttng_event structure is named
    \"<em>instrumentation point descriptor</em>\".

lttng_enable_event(), lttng_enable_event_with_filter(), and
lttng_enable_event_with_exclusions() expect such a structure to create
or enable a recording event rule.

Most properties are members of the structure itself, but the
following ones have their own dedicated accessors:

<dl>
  <dt>
    Linux uprobe location (when the lttng_event::type member is
    #LTTNG_EVENT_USERSPACE_PROBE)
  <dd>
    - lttng_event_get_userspace_probe_location()
    - lttng_event_set_userspace_probe_location()

  <dt>\ref api-rer-conds-event-name "Event name" exclusion patterns
  <dd>
    lttng_event_get_exclusion_name()

  <dt>\ref api-rer-conds-filter "Event payload and context filter" expression
  <dd>
    lttng_event_get_filter_expression()
</dl>

Create an empty recording event rule descriptor with
lttng_event_create().

\anchor api-rer-valid-event-struct A \em valid #lttng_event structure
satisfies the following constraints:

- If the lttng_event::type member is #LTTNG_EVENT_PROBE or
  #LTTNG_EVENT_FUNCTION, then the lttng_event::lttng_event_attr_u::probe
  member of lttng_event::attr is valid according to the
  documentation of #lttng_event_probe_attr.

- If the lttng_event::type member is #LTTNG_EVENT_USERSPACE_PROBE, then
  the recording event rule descriptor has a Linux uprobe location
  (you called lttng_event_set_userspace_probe_location() on it to
  set it).

Destroy a recording event rule descriptor with lttng_event_destroy().
*/
struct lttng_event {
	/* Offset 0 */
	/// \ref api-rer-conds-inst-pt-type "Instrumentation point type condition".
	enum lttng_event_type type;

	/* Offset 4 */
	/*!
	    @brief \ref api-rer-conds-event-name "Event name" pattern
	    condition.

	If empty, lttng_enable_event(),
	lttng_enable_event_with_filter(), and
	lttng_enable_event_with_exclusions() use <code>*</code> (match
	events with any name).

	If the lttng_event::type member is #LTTNG_EVENT_PROBE,
	#LTTNG_EVENT_FUNCTION, or #LTTNG_EVENT_USERSPACE_PROBE, then
	this member is actually the name of the created Linux
	kprobe/kretprobe/uprobe instrumentation point (future event
	name).

	If this structure is an
	\ref api-rer-inst-pt-descr "instrumentation point descriptor",
	then this member is the name of the LTTng tracepoint, Linux
	system call, or Java/Python logger.
	*/
	char name[LTTNG_SYMBOL_NAME_LEN];

	/* Offset 260 */
	/*!
	@brief
	    Operand of the
	    \ref api-rer-conds-ll "instrumentation point log level condition".
	*/
	enum lttng_loglevel_type loglevel_type;

	/* Offset 264 */
	/*!
	    @brief Value of the
	    \ref api-rer-conds-ll "instrumentation point log level condition".

	This member must be one of the enumerators of
	#lttng_loglevel, #lttng_loglevel_jul, #lttng_loglevel_log4j, or
	#lttng_loglevel_python, depending on the
	\lt_obj_domain when you call lttng_enable_event(),
	lttng_enable_event_with_filter(), or
	lttng_enable_event_with_exclusions().

	If this structure is an
	\ref api-rer-inst-pt-descr "instrumentation point descriptor",
	then this member is the log level of the LTTng tracepoint or
	Java/Python logger.
	*/
	int loglevel;

	/* Offset 268 */
	/*!
	@brief
	    1 if this recording event rule is enabled, or 0 otherwise.

	This is a read-only member.

	@sa lttng_enable_event() --
	    Creates or enables a recording event rule.
	@sa lttng_disable_event_ext() --
	    Disables a recording event rule.
	*/
	int32_t enabled; /* Does not apply: -1 */

	/* Offset 272 */
	/*!
	@brief
	    ID of the process which offers the instrumentation point
	    described by this structure.

	This is a read-only member.

	This member is \em not part of a recording event rule.
	*/
	pid_t pid;

	/* Offset 276 */
	/*!
	@brief
	    1 if the recording event rule described by this has an
	    \ref api-rer-conds-filter "event payload and context filter"
	    expression, or 0 otherwise.

	This is a read-only member: use the \lt_p{filter_expr} parameter
	of lttng_enable_event_with_filter() or
	lttng_enable_event_with_exclusions() when you create a
	recording event rule to set an event payload and context
	filter expression.

	If this member is 1, then get the actual filter expression
	string with lttng_event_get_filter_expression().
	*/
	unsigned char filter;

	/* Offset 277 */
	/*!
	@brief
	    1 if the recording event rule described by this has
	    \ref api-rer-conds-event-name "event name" exclusion
	    patterns (part of the event name condition), or 0 otherwise.

	This is a read-only member: use the
	\lt_p{event_name_exclusion_count} and
	\lt_p{event_name_exclusions} parameters of
	lttng_enable_event_with_exclusions() when you create a recording
	event rule to set event name exclusion patterns.

	If this member is 1, then get the actual event name exclusion
	patterns with lttng_event_get_exclusion_name_count() and
	lttng_event_get_exclusion_name().
	*/
	unsigned char exclusion;

	/* Offset 278 */
	char padding2[2];

	/* Offset 280 */
	/*!
	@brief
	    \ref api-rer-inst-pt-descr "Instrumentation point descriptor"
	    flags (bitwise OR).

	This is a read-only member.

	This member is \em not part of a recording event rule.
	*/
	enum lttng_event_flag flags;

	/* Offset 284 */
	char padding[4];

	/* Offset 288 */
	union {
		uint64_t padding;
		void *ptr;
	} extended;

	/* Offset 296 */
	/*!
	@brief
	    Linux kprobe/kretprobe recording event rule configuration.

	@ingroup api_rer
	*/
	union lttng_event_attr_u {
		/*!
		@brief
		    Linux kprobe/kretprobe location.

		Only valid when the lttng_event::type member is
		#LTTNG_EVENT_PROBE or #LTTNG_EVENT_FUNCTION.
		*/
		struct lttng_event_probe_attr probe;

		struct lttng_event_function_attr ftrace;

		char padding[LTTNG_EVENT_PADDING2];
	}

	/*!
	@brief
	    Linux kprobe/kretprobe recording event rule configuration.

	Only valid when the lttng_event::type member is
	#LTTNG_EVENT_PROBE or #LTTNG_EVENT_FUNCTION.
	*/
	attr;
};

#define LTTNG_EVENT_FIELD_PADDING LTTNG_SYMBOL_NAME_LEN + 32

/*!
@brief
    LTTng tracepoint field description.

@ingroup api_inst_pt

lttng_list_tracepoint_fields() sets a pointer to an array of all the
tracepoint field descriptions of a given \lt_obj_domain.
*/
struct lttng_event_field {
	/// Field name.
	char field_name[LTTNG_SYMBOL_NAME_LEN];

	/// Field data type.
	enum lttng_event_field_type type;

	char padding[LTTNG_EVENT_FIELD_PADDING];

	/*!
	@brief
	    \ref api-rer-inst-pt-descr "Descriptor" of the tracepoint
	    which contains this field.
	*/
	struct lttng_event event;

	/*!
	@brief
	    0 if LTTng writes this field to an event record, or 1
	    otherwise.
	*/
	int nowrite;
};

/*!
@brief
    Sets \lt_p{*event_rules} to the descriptors of the
    \lt_obj_rers of the \lt_obj_channel named \lt_p{channel_name}
    within the recording session handle \lt_p{handle}.

@ingroup api_channel

@param[in] handle
    Recording session handle which contains the name of the
    recording session and the summary
    of the \lt_obj_domain which own the channel (named
    \lt_p{channel_name}) of which to get the recording event rule
    descriptors.
@param[in] channel_name
    Name of the channel, within \lt_p{handle}, of which to get all the
    recording event rule descriptors.
@param[out] event_rules
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*event_rules}
    to the recording event rule descriptors.

    Free \lt_p{*event_rules} with <code>free()</code>.
    @endparblock

@returns
    The number of items in \lt_p{*event_rules} on success, or a
    \em negative #lttng_error_code enumerator otherwise.

@lt_pre_conn
@lt_pre_not_null{handle}
@lt_pre_valid_c_str{handle->session_name}
@lt_pre_sess_exists{handle->session_name}
@pre
    \lt_p{handle->domain} is valid as per the documentation of
    #lttng_domain.
@lt_pre_not_null{channel_name}
@pre
    \lt_p{channel_name} names an existing channel within the recording
    session and tracing domain of \lt_p{handle}.
@lt_pre_not_null{event_rules}
*/
LTTNG_EXPORT extern int lttng_list_events(struct lttng_handle *handle,
					  const char *channel_name,
					  struct lttng_event **event_rules);

/*!
@brief
    Creates and returns an empty recording event rule descriptor.

@ingroup api_rer

After you create a recording event rule descriptor with this function,
you can modify its properties and call
lttng_enable_event_with_exclusions() to create and enable a recording
event rule.

@returns
    @parblock
    New recording event rule descriptor.

    Destroy the returned recording event rule descriptor with
    lttng_event_destroy().
    @endparblock

@sa lttng_event_destroy() --
    Destroys a recording event rule descriptor.
*/
LTTNG_EXPORT extern struct lttng_event *lttng_event_create(void);

/*!
@brief
    Destroys the recording event rule descriptor \lt_p{event_rule}.

@ingroup api_rer

@note
    This function doesn't destroy the recording event rule
    which \lt_p{event_rule} describes: you can't destroy a
    recording event rule.

@param[in] event_rule
    @parblock
    Recording event rule descriptor to destroy.

    May be \c NULL.
    @endparblock

@pre
    <strong>If not \c NULL</strong>, \lt_p{event_rule} was created with
    lttng_event_create().

@sa lttng_event_create() --
    Creates an empty recording event rule descriptor.
*/
LTTNG_EXPORT extern void lttng_event_destroy(struct lttng_event *event_rule);

/*!
@brief
    Sets \lt_p{*filter_expr} to the
    \ref api-rer-conds-filter "event payload and context filter"
    expression of the recording event rule described by
    \lt_p{event_rule}.

@ingroup api_rer

@param[in] event_rule
    Descriptor of the recording event rule of which to get the event
    payload and context filter expression.
@param[out] filter_expr
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*filter_expr}
    to:

    <dl>
      <dt>
	If \lt_p{event_rule} has an event payload and context filter
	expression
      <dd>
	The event payload and context filter
	expression of \lt_p{event_rule}.

	\lt_p{*filter_expr} remains valid as long as \lt_p{event_rule}
	exists and you don't modify it.

      <dt>Otherwise
      <dd>\c NULL
    </dl>
    @endparblock

@returns
    0 on success, or a \em negative #lttng_error_code enumerator
    otherwise.

@lt_pre_not_null{event_rule}
@lt_pre_not_null{filter_expr}

@sa lttng_event::filter --
    Indicates whether or not a recording event rule has an event payload
    and context filter.
*/
LTTNG_EXPORT extern int lttng_event_get_filter_expression(struct lttng_event *event_rule,
							  const char **filter_expr);

/*!
@brief
    Returns the number of \ref api-rer-conds-event-name "event name"
    exclusion patterns of the recording
    event rule described by \lt_p{event_rule}.

@ingroup api_rer

@param[in] event_rule
    Descriptor of the recording event rule of which to get the number
    of event name exclusion patterns.

@returns
    Number of event name exclusion patterns of \lt_p{event_rule}, or a
    \em negative #lttng_error_code enumerator otherwise.

@lt_pre_not_null{event_rule}

@sa lttng_event_get_exclusion_name() --
    Returns an event name exclusion pattern by index of a recording
    event rule.
@sa lttng_event::exclusion --
    Indicates whether or not a recording event rule has event name
    exclusion patterns.
*/
LTTNG_EXPORT extern int lttng_event_get_exclusion_name_count(struct lttng_event *event_rule);

/*!
@brief
    Sets \lt_p{*event_name_exclusion} to the
    \ref api-rer-conds-event-name "event name" exclusion
    pattern at index \lt_p{index} of the recording event rule described
    by \lt_p{event_rule}.

@ingroup api_rer

@param[in] event_rule
    Descriptor of the recording event rule of which to get the event
    name exclusion pattern at index \lt_p{index}.
@param[in] index
    Index of the event name exclusion pattern to get from
    \lt_p{event_rule}.
@param[out] event_name_exclusion
    @parblock
    <strong>On success</strong>, this function sets
    \lt_p{*event_name_exclusion} to the event name exclusion pattern at
    index \lt_p{index} of
    \lt_p{event_rule}.

    \lt_p{*event_name_exclusion} remains valis as long as
    \lt_p{event_rule} exists and you don't modify it.
    @endparblock

@returns
    0 on success, or a \em negative #lttng_error_code enumerator
    otherwise.

@lt_pre_not_null{event_rule}
@pre
    \lt_p{index} is less than the number of event name exclusion
    patterns (as returned by lttng_event_get_exclusion_name_count())
    of \lt_p{event_rule}.
@lt_pre_not_null{event_name_exclusion}

@sa lttng_event_get_exclusion_name_count() --
    Returns the number of event name exclusion patterns of a recording
    event rule.
*/
LTTNG_EXPORT extern int lttng_event_get_exclusion_name(struct lttng_event *event_rule,
						       size_t index,
						       const char **event_name_exclusion);

/*!
@brief
    Returns the Linux uprobe location of the recording event rule
    described by \lt_p{event_rule}.

@ingroup api_rer

@param[in] event_rule
    Descriptor of the recording event rule of which to get the
    Linux uprobe location.

@returns
    @parblock
    Linux uprobe location of the recording event rule described by
    \lt_p{event_rule}, or \c NULL if none.

    The returned location remains valid as long as \lt_p{event_rule}
    exists and you don't modify it.
    @endparblock

@lt_pre_not_null{event_rule}
@pre
    \lt_p{event_rule->type} (see lttng_event::type) is
    #LTTNG_EVENT_USERSPACE_PROBE.

@sa lttng_event_set_userspace_probe_location() --
    Sets the Linux uprobe location of a recording event rule.
@sa \ref api-rer-conds-inst-pt-type "Instrumentation point type condition".
*/
LTTNG_EXPORT extern const struct lttng_userspace_probe_location *
lttng_event_get_userspace_probe_location(const struct lttng_event *event_rule);

/*!
@brief
    Sets the Linux uprobe location of the recording event rule described
    by \lt_p{event_rule} to \lt_p{location}.

@ingroup api_rer

@param[in] event_rule
    Descriptor of the recording event rule of which to set the
    Linux uprobe location to \lt_p{location}.
@param[in] location
    New Linux uprobe location of \lt_p{event_rule}.

@returns
    0 on success, or a \em negative #lttng_error_code enumerator
    otherwise.

@lt_pre_not_null{event_rule}
@pre
    \lt_p{event_rule} was created with lttng_event_create().
@pre
    \lt_p{event_rule->type} (see lttng_event::type) is
    #LTTNG_EVENT_USERSPACE_PROBE.
@lt_pre_not_null{location}

@post
    <strong>On success</strong>, \lt_p{*location} is invalid
    (its ownership is transfered to \lt_p{event_rule}).

@sa lttng_event_get_userspace_probe_location() --
    Returns the Linux uprobe location of a recording event rule.
@sa \ref api-rer-conds-inst-pt-type "Instrumentation point type condition".
*/
LTTNG_EXPORT extern int
lttng_event_set_userspace_probe_location(struct lttng_event *event_rule,
					 struct lttng_userspace_probe_location *location);

/*!
@brief
    Sets \lt_p{*descrs} to the
    \ref api-rer-inst-pt-descr "descriptors" of the
    available LTTng tracepoints or Java/Python loggers for the
    \lt_obj_domain of \lt_p{handle}.

@ingroup api_inst_pt

@param[in] handle
    @parblock
    Recording session handle which contains the summary of the
    \lt_obj_domain which offers the LTTng tracepoints or Java/Python
    loggers of which to get the descriptors.

    This function ignores \lt_p{handle->session_name}.
    @endparblock
@param[out] descrs
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*descrs}
    to the descriptors of the available tracepoints or Java/Python
    loggers of \lt_p{handle}.

    Free \lt_p{*descrs} with <code>free()</code>.
    @endparblock

@returns
    The number of items in \lt_p{*descrs} on success, or a \em
    negative #lttng_error_code enumerator otherwise.

@lt_pre_conn
@lt_pre_not_null{handle}
@pre
    \lt_p{handle->domain} is valid as per the documentation of
    #lttng_domain.
@lt_pre_not_null{descrs}

@sa lttng_list_tracepoint_fields() --
    Returns all the field descriptions of all the available LTTng
    tracepoints.
@sa lttng_list_syscalls() --
    Returns the descriptors of all the available Linux system calls.
*/
LTTNG_EXPORT extern int lttng_list_tracepoints(struct lttng_handle *handle,
					       struct lttng_event **descrs);

/*!
@brief
    Sets \lt_p{*fields} to the field descriptions of all the available
    LTTng tracepoints for the \lt_obj_domain of \lt_p{handle}.

@ingroup api_inst_pt

@param[in] handle
    @parblock
    Recording session handle which contains the summary of the
    \lt_obj_domain which offers the LTTng tracepoints of which to get
    the field descriptions.

    This function ignores \lt_p{handle->session_name}.
    @endparblock
@param[out] fields
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*fields}
    to the descriptions of the available LTTng tracepoint fields of
    \lt_p{handle}.

    Each #lttng_event_field instance in \lt_p{*fields} contains a
    pointer to the \ref api-rer-inst-pt-descr "descriptor" of
    a tracepoint which contains the described field
    (lttng_event_field::event member).

    Free \lt_p{*fields} with <code>free()</code>.
    @endparblock

@returns
    The number of items in \lt_p{*fields} on success, or a \em
    negative #lttng_error_code enumerator otherwise.

@lt_pre_conn
@lt_pre_not_null{handle}
@pre
    \lt_p{handle->domain} is valid as per the documentation of
    #lttng_domain.
@lt_pre_not_null{fields}

@sa lttng_list_tracepoints() --
    Returns the descriptors of all the available LTTng tracepoints
    or Java/Python loggers.
@sa lttng_list_syscalls() --
    Returns the descriptors of all the available Linux system calls.
*/
LTTNG_EXPORT extern int lttng_list_tracepoint_fields(struct lttng_handle *handle,
						     struct lttng_event_field **fields);

/*!
@brief
    Sets \lt_p{*descrs} to the
    \ref api-rer-inst-pt-descr "descriptors" of the
    available Linux system calls for the
    #LTTNG_DOMAIN_KERNEL tracing domain.

@ingroup api_inst_pt

@param[out] descrs
    @parblock
    <strong>On success</strong>, this function sets \lt_p{*descrs}
    to the available system calls.

    The #lttng_event instances of \lt_p{*descrs} have an
    lttng_event::flags member which indicates whether the described
    system call is 32-bit, 64-bit, or both.

    Free \lt_p{*descrs} with <code>free()</code>.
    @endparblock

@returns
    The number of items in \lt_p{*descrs} on success, or a \em
    negative #lttng_error_code enumerator otherwise.

@lt_pre_conn
@lt_pre_not_null{descrs}

@sa lttng_list_tracepoint_fields() --
    Returns all the field descriptions of all the available LTTng
    tracepoints.
@sa lttng_list_syscalls() --
    Returns the descriptors of all the available Linux system calls.
*/
LTTNG_EXPORT extern int lttng_list_syscalls(struct lttng_event **descrs);

/*!
@brief
    Makes the future \ref api_rer "event records" of the
    \lt_obj_channel named \lt_p{channel_name} (or of a default channel
    or all the channels if \c NULL) within the
    \lt_obj_session and \lt_obj_domain of \lt_p{handle}
    have a context field described by \lt_p{context_field_descriptor}.

@ingroup api_channel

Context values (for example, the ID of the current process, the
instruction pointer, or the hostname) are always available during
tracing. This function makes LTTng record a specific context value as a
field for each future event record of the selected channel(s).

@param[in] handle
    Recording session handle which contains the name of the recording
    session and the summary of the \lt_obj_domain which own the
    channel(s) to select.
@param[in] context_field_descriptor
    Descriptor of the context field to add to each event record of
    the selected channel(s).
@param[in] event_name
    Unused: must be \c NULL.
@param[in] channel_name
    @parblock
    Name of the channel to select.

    If \c NULL, then:

    <dl>
      <dt>
	If the recording session and tracing domain of
	\lt_p{handle} have no channels
      <dd>
	LTTng creates a new, default channel named \c channel0 within
	\lt_p{handle} which becomes the selected channel.

      <dt>Otherwise
      <dd>
	LTTng selects all the channels of \lt_p{handle}.
    </dl>
    @endparblock

@returns
    0 on success, or a \em negative #lttng_error_code enumerator
    otherwise.

@lt_pre_conn
@lt_pre_not_null{handle}
@lt_pre_valid_c_str{handle->session_name}
@lt_pre_sess_exists{handle->session_name}
@lt_pre_sess_never_active{handle->session_name}
@pre
    \lt_p{handle->domain} is valid (you passed a
    \lt_obj_domain summary to
    lttng_create_handle() when you created \lt_p{handle}).
@pre
    \lt_p{context_field_descriptor} is valid according to the
    documentation of #lttng_event_context.
@pre
    \lt_p{event_name} is \c NULL.
@pre
    <strong>If not \c NULL</strong>, \lt_p{channel_name} names an
    existing channel within the recording session and tracing domain of
    \lt_p{handle}.
*/
LTTNG_EXPORT extern int lttng_add_context(struct lttng_handle *handle,
					  struct lttng_event_context *context_field_descriptor,
					  const char *event_name,
					  const char *channel_name);

/*!
@brief
    Alias of lttng_enable_event_with_exclusions() which passes the
    \ref api-rer-conds-filter "event payload and context filter"
    expression of \lt_p{event_rule}
    as the \lt_p{filter_expr} parameter and the
    \ref api-rer-conds-event-name "event name" exclusion patterns
    of \lt_p{event_rule} as the
    \lt_p{event_name_exclusion_count} and
    \lt_p{event_name_exclusions} parameters.

@ingroup api_rer

This function is equivalent to:

@code
int ret;
int i;
char **event_name_exclusions = NULL;
const char *filter_expr = NULL;
const int event_name_exclusion_count = lttng_event_get_exclusion_name_count(event_rule);

assert(event_name_exclusion_count >= 0);

if (event_name_exclusion_count > 0) {
    event_name_exclusions = calloc(event_name_exclusion_count,
				   sizeof(*event_name_exclusions));
    assert(event_name_exclusions);

    for (i = 0; i < event_name_exclusion_count; i++) {
	const char *event_name_exclusion;

	ret = lttng_event_get_exclusion_name(event_rule, (size_t) i,
					     &event_name_exclusion);
	assert(ret == 0);
	event_name_exclusions[i] = (char *) event_name_exclusion;
    }
}

ret = lttng_event_get_filter_expression(event_rule, &filter_expr);
assert(ret == 0);
ret = lttng_enable_event_with_exclusions(handle, event_rule, channel_name,
					 filter_expr,
					 event_name_exclusion_count,
					 event_name_exclusions);
free(event_name_exclusions);
return ret;
@endcode
*/
LTTNG_EXPORT extern int lttng_enable_event(struct lttng_handle *handle,
					   struct lttng_event *event_rule,
					   const char *channel_name);

/*!
@brief
    Alias of lttng_enable_event_with_exclusions() which passes the
    the \ref api-rer-conds-event-name "event name" exclusion patterns
    of \lt_p{event_rule} as the
    \lt_p{event_name_exclusion_count} and
    \lt_p{event_name_exclusions} parameters.

@ingroup api_rer

This function is equivalent to:

@code
int ret;
int i;
char **event_name_exclusions = NULL;
const char *filter_expr = NULL;
const int event_name_exclusion_count = lttng_event_get_exclusion_name_count(event_rule);

assert(event_name_exclusion_count >= 0);

if (event_name_exclusion_count > 0) {
    event_name_exclusions = calloc(event_name_exclusion_count,
				   sizeof(*event_name_exclusions));
    assert(event_name_exclusions);

    for (i = 0; i < event_name_exclusion_count; i++) {
	const char *event_name_exclusion;

	ret = lttng_event_get_exclusion_name(event_rule, (size_t) i,
					     &event_name_exclusion);
	assert(ret == 0);
	event_name_exclusions[i] = (char *) event_name_exclusion;
    }
}

ret = lttng_enable_event_with_exclusions(handle, event_rule, channel_name,
					 filter_expr,
					 event_name_exclusion_count,
					 event_name_exclusions);
free(event_name_exclusions);
return ret;
@endcode
*/
LTTNG_EXPORT extern int lttng_enable_event_with_filter(struct lttng_handle *handle,
						       struct lttng_event *event_rule,
						       const char *channel_name,
						       const char *filter_expr);

/*!
@brief
    Creates or enables a recording event rule
    described by \lt_p{event_rule}, having the
    \ref api-rer-conds-filter "event payload and context filter"
    expression \lt_p{filter_expr} and the
    \ref api-rer-conds-event-name "event name" exclusion patterns
    \lt_p{event_name_exclusions}, within
    the \lt_obj_channel named \lt_p{channel_name}
    (or within a default channel if \c NULL) within the recording
    session handle \lt_p{handle}.

@ingroup api_rer

This function, depending on the
\ref api-rer-conds-inst-pt-type "instrumentation point type",
\ref api-rer-conds-event-name "event name",
and \ref api-rer-conds-ll "log level" conditions of \lt_p{event_rule},
as well as on \lt_p{filter_expr} and \lt_p{event_name_exclusions}:

<dl>
  <dt>
    The conditions and parameters describe an existing recording event
    rule within the selected channel
  <dd>
    Enables the existing recording event rule.

  <dt>Otherwise
  <dd>
    Creates and enables a new recording event rule within the
    selected channel.
</dl>

If \lt_p{event_rule->type} is #LTTNG_EVENT_ALL and
\lt_p{handle->domain.type} is #LTTNG_DOMAIN_KERNEL, then this
function actually creates or enables two recording event rules: one with
the #LTTNG_EVENT_TRACEPOINT type, and one with the #LTTNG_EVENT_SYSCALL
type.

@param[in] handle
    Recording session handle which contains the name of the recording
    session and the summary of the \lt_obj_domain which own the selected
    channel.
@param[in] event_rule
    @parblock
    Descriptor of the recording event rule to create or enable.

    This function:

    - Ignores any event payload and context filter
      expression within \lt_p{event_rule}: it always uses
      \lt_p{filter_expr}.

    - Ignores any event name exclusion patterns within
      \lt_p{event_rule}: it always uses \lt_p{event_name_exclusions}.
    @endparblock
@param[in] channel_name
    @parblock
    Name of the channel, within \lt_p{handle}, to select (that is,
    containing the recording event rule to create or enable).

    If \c NULL, then this function uses \c channel0. If no channel named
    \c channel0 within \lt_p{handle} exists, then LTTng creates a new,
    default channel named as such and selects it before it creates the
    recording event rule described by \lt_p{event_rule}.
    @endparblock
@param[in] filter_expr
    @parblock
    Event payload and context filter expression of the recording
    event rule to create or enable.

    <strong>If \c NULL</strong>, the created or enabled recording event
    rule has no event payload and context filter expression.

    This parameter, even when \c NULL, overrides any existing
    event payload and context filter expression within
    \lt_p{event_rule}.
    @endparblock
@param[in] event_name_exclusion_count
    Number of items in \lt_p{event_name_exclusions}.
@param[in] event_name_exclusions
    @parblock
    Event name exclusion patterns of the recording event rule to create
    or enable.

    This function copies the strings of this array.

    \lt_p{event_name_exclusion_count} indicates the size of this
    array, which may be \c NULL if \lt_p{event_name_exclusion_count}
    is&nbsp;0.

    This parameter, even when \c NULL or empty, overrides any existing
    event name exclusion patterns within \lt_p{event_rule}.
    @endparblock

@returns
    0 on success, or a \em negative #lttng_error_code enumerator
    otherwise.

@lt_pre_conn
@lt_pre_not_null{handle}
@lt_pre_valid_c_str{handle->session_name}
@lt_pre_sess_exists{handle->session_name}
@pre
    \lt_p{handle->domain} is valid as per the documentation of
    #lttng_domain.
@lt_pre_not_null{event_rule}
@pre
    \lt_p{event_rule} is \ref api-rer-valid-event-struct "valid".
@pre
    <strong>If \lt_p{handle->domain.type} is \em not
    #LTTNG_DOMAIN_KERNEL</strong>, then \lt_p{event_rule->type} is
    #LTTNG_EVENT_TRACEPOINT.
@pre
    <strong>If \lt_p{handle->domain.type} is \em not
    #LTTNG_DOMAIN_UST</strong>, then \lt_p{event_name_exclusion_count}
    is&nbsp;0.
@pre
    <strong>If this function must enable an existing recording event
    rule</strong>, then the recording event rule to enable is disabled.
@pre
    <strong>If not \c NULL</strong>, \lt_p{channel_name} names an
    existing channel within the recording session and tracing domain of
    \lt_p{handle}.
@pre
    <strong>If \lt_p{channel_name} is \c NULL</strong>, then
    \lt_p{handle} contains either no channels or a default channel named
    \c channel0.
@pre
    <strong>If not \c NULL</strong>, \lt_p{filter_expr} is a valid
    event payload and context filter expression.
@pre
    \lt_p{event_name_exclusion_count}&nbsp;≥&nbsp;0.

@sa lttng_enable_event() --
    Alias which calls this function with the event payload and context
    filter expression and event name exclusion patterns of the
    recording event rule descriptor.
@sa lttng_enable_event_with_filter() --
    Alias which calls this function with the event name exclusion
    patterns of the recording event rule descriptor.
@sa lttng_disable_event_ext() --
    Disables a recording event rule.
*/
LTTNG_EXPORT extern int lttng_enable_event_with_exclusions(struct lttng_handle *handle,
							   struct lttng_event *event_rule,
							   const char *channel_name,
							   const char *filter_expr,
							   int event_name_exclusion_count,
							   char **event_name_exclusions);

/*!
@brief
    Alias of lttng_disable_event_ext() which creates a temporary
    recording event rule descriptor, settings its
    lttng_event::name member to \lt_p{event_name} if not \c NULL and
    its lttng_event::type member to #LTTNG_EVENT_ALL.

@ingroup api_rer

This function is equivalent to:

@code
struct lttng_event event_rule = { 0 };

event_rule.type = LTTNG_EVENT_ALL;

if (event_name) {
    strcpy(event_rule.name, event_name);
}

event_rule.loglevel = -1;
return lttng_disable_event_ext(handle, &event_rule, channel_name, NULL);
@endcode
*/
LTTNG_EXPORT extern int
lttng_disable_event(struct lttng_handle *handle, const char *event_name, const char *channel_name);

/*!
@brief
    Disables recording event rules by
    \ref api-rer-conds-inst-pt-type "instrumentation point type" and
    \ref api-rer-conds-event-name "event name" condition within the
    \lt_obj_channel named \lt_p{channel_name}
    (or within a default channel if \c NULL) within the recording
    session handle \lt_p{handle}.

@ingroup api_rer

Depending on \lt_p{event_rule->name}, this function:

<dl>
  <dt>Not empty
  <dd>
    Depending on \lt_p{event_rule->type}:

    <dl>
      <dt>#LTTNG_EVENT_ALL
      <dd>
	Disables \em all the recording event rules of which the event
	name pattern is exactly \lt_p{event_rule->name} within the
	selected channel.

      <dt>Otherwise
      <dd>
	Disables all the recording event rules of which the
	instrumentation point type is
	\lt_p{event_rule->type} and the event
	name pattern is exactly \lt_p{event_rule->name} within the
	selected channel.

	Only supported when \lt_p{handle->domain.type} is
	#LTTNG_DOMAIN_KERNEL.
    </dl>

  <dt>Empty
  <dd>
    Depending on \lt_p{event_rule->type}:

    <dl>
      <dt>#LTTNG_EVENT_ALL
      <dd>
	Disables \em all the recording event rules within the selected
	channel.

      <dt>Otherwise
      <dd>
	Disables all the recording event rules of which the
	instrumentation point type is
	\lt_p{event_rule->type} within the
	selected channel.

	Only supported when \lt_p{handle->domain.type} is
	#LTTNG_DOMAIN_KERNEL.
    </dl>
</dl>

This function ignores all the other \ref api-rer-conds "condition"
properties of \lt_p{event_rule}.

To use this function, create a temporary, zeroed
\link #lttng_event recording event rule descriptor\endlink,
setting only:

- <strong>Optional, and only if \lt_p{handle->domain.type}
  is #LTTNG_DOMAIN_KERNEL</strong>: its lttng_event::type member.

- <strong>Optional</strong>: its lttng_event::name member

- Its lttng_event::loglevel member to&nbsp;-1.

For example:

@code
struct lttng_event event_rule = { 0 };

event_rule.type = LTTNG_EVENT_SYSCALL;
strcpy(event_rule.name, "open*");
event_rule.loglevel = -1;
@endcode

@param[in] handle
    Recording session handle which contains the name of the recording
    session and the summary of the \lt_obj_domain which own the selected
    channel.
@param[in] event_rule
    @parblock
    Recording event rule descriptor which contains the
    instrumentation point type and event name conditions to consider
    to disable recording event rules within the selected channel.
    @endparblock
@param[in] channel_name
    @parblock
    Name of the channel, within \lt_p{handle}, to select (that is,
    containing the recording event rules to disable).

    If \c NULL, then this function uses \c channel0.
    @endparblock
@param[in] filter_expr
    Unused: must be \c NULL.

@returns
    0 on success, or a \em negative #lttng_error_code enumerator
    otherwise.

@lt_pre_conn
@lt_pre_not_null{handle}
@lt_pre_valid_c_str{handle->session_name}
@lt_pre_sess_exists{handle->session_name}
@pre
    \lt_p{handle->domain} is valid as per the documentation of
    #lttng_domain.
@lt_pre_not_null{event_rule}
@pre
    <strong>If \lt_p{handle->domain.type} is \em not
    #LTTNG_DOMAIN_KERNEL</strong>, then \lt_p{event_rule->type}
    is #LTTNG_EVENT_ALL.
@pre
    <strong>If not #LTTNG_EVENT_ALL</strong>, then
    \lt_p{event_rule->type} is the instrumentation point type of at
    least one Linux kernel recording event rule within the selected
    channel.
@pre
    <strong>If not empty</strong>, then \lt_p{event_rule->name} is the
    exact event name pattern of at least one recording event rule within
    the selected channel.
@pre
    The recording event rules to disable are enabled.
@pre
    <strong>If not \c NULL</strong>, then \lt_p{channel_name} names an
    existing channel within the recording session and tracing domain of
    \lt_p{handle}.
@pre
    <strong>If \lt_p{channel_name} is \c NULL</strong>, then the
    channel named \c channel0 exists within the recording session and
    tracing domain of \lt_p{handle}.

@sa lttng_disable_event() --
    Alias which calls this function with \lt_p{event_rule->type}
    set to #LTTNG_EVENT_ALL.
@sa lttng_enable_event_with_exclusions() --
    Creates or enables a recording event rule.
*/
LTTNG_EXPORT extern int lttng_disable_event_ext(struct lttng_handle *handle,
						struct lttng_event *event_rule,
						const char *channel_name,
						const char *filter_expr);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_EVENT_H */
