/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 * SPDX-FileCopyrightText: 2016 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"

#include <common/mi-lttng.hpp>

#include <lttng/domain-internal.hpp>

#include <ctype.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <urcu/list.h>

static char *opt_channel_name;
static char *opt_session_name;
static int opt_kernel;
static int opt_userspace;
static int opt_jul;
static int opt_log4j;
static int opt_log4j2;
static char *opt_type;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-add-context.1.h>
	;
#endif

enum {
	OPT_HELP = 1,
	OPT_TYPE,
	OPT_USERSPACE,
	OPT_JUL,
	OPT_LOG4J,
	OPT_LOG4J2,
	OPT_LIST_OPTIONS,
	OPT_LIST,
};

static struct lttng_handle *handle;
static struct mi_writer *writer;

/*
 * Taken from the LTTng ABI except for "UNKNOWN".
 */
enum context_type {
	CONTEXT_UNKNOWN = -1,
	CONTEXT_PID = 0,
	CONTEXT_PERF_COUNTER = 1, /* Backward compat. */
	CONTEXT_PROCNAME = 2,
	CONTEXT_PRIO = 3,
	CONTEXT_NICE = 4,
	CONTEXT_VPID = 5,
	CONTEXT_TID = 6,
	CONTEXT_VTID = 7,
	CONTEXT_PPID = 8,
	CONTEXT_VPPID = 9,
	CONTEXT_PTHREAD_ID = 10,
	CONTEXT_HOSTNAME = 11,
	CONTEXT_IP = 12,
	CONTEXT_PERF_CPU_COUNTER = 13,
	CONTEXT_PERF_THREAD_COUNTER = 14,
	CONTEXT_APP_CONTEXT = 15,
	CONTEXT_INTERRUPTIBLE = 16,
	CONTEXT_PREEMPTIBLE = 17,
	CONTEXT_NEED_RESCHEDULE = 18,
	CONTEXT_MIGRATABLE = 19,
	CONTEXT_CALLSTACK_KERNEL = 20,
	CONTEXT_CALLSTACK_USER = 21,
	CONTEXT_CGROUP_NS = 22,
	CONTEXT_IPC_NS = 23,
	CONTEXT_MNT_NS = 24,
	CONTEXT_NET_NS = 25,
	CONTEXT_PID_NS = 26,
	CONTEXT_USER_NS = 27,
	CONTEXT_UTS_NS = 28,
	CONTEXT_UID = 29,
	CONTEXT_EUID = 30,
	CONTEXT_SUID = 31,
	CONTEXT_GID = 32,
	CONTEXT_EGID = 33,
	CONTEXT_SGID = 34,
	CONTEXT_VUID = 35,
	CONTEXT_VEUID = 36,
	CONTEXT_VSUID = 37,
	CONTEXT_VGID = 38,
	CONTEXT_VEGID = 39,
	CONTEXT_VSGID = 40,
	CONTEXT_TIME_NS = 41,
	CONTEXT_CPU_ID = 42,
};

/*
 * Taken from the Perf ABI (all enum perf_*)
 */
enum perf_type {
	PERF_TYPE_HARDWARE = 0,
	PERF_TYPE_SOFTWARE = 1,
	PERF_TYPE_HW_CACHE = 3,
	PERF_TYPE_RAW = 4,
};

enum perf_count_hard {
	PERF_COUNT_HW_CPU_CYCLES = 0,
	PERF_COUNT_HW_INSTRUCTIONS = 1,
	PERF_COUNT_HW_CACHE_REFERENCES = 2,
	PERF_COUNT_HW_CACHE_MISSES = 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4,
	PERF_COUNT_HW_BRANCH_MISSES = 5,
	PERF_COUNT_HW_BUS_CYCLES = 6,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 7,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 8,
};

enum perf_count_soft {
	PERF_COUNT_SW_CPU_CLOCK = 0,
	PERF_COUNT_SW_TASK_CLOCK = 1,
	PERF_COUNT_SW_PAGE_FAULTS = 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
	PERF_COUNT_SW_CPU_MIGRATIONS = 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
	PERF_COUNT_SW_EMULATION_FAULTS = 8,
};

/*
 * Generalized hardware cache events:
 *
 *       { L1-D, L1-I, LLC, ITLB, DTLB, BPU } x
 *       { read, write, prefetch } x
 *       { accesses, misses }
 */
enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D = 0,
	PERF_COUNT_HW_CACHE_L1I = 1,
	PERF_COUNT_HW_CACHE_LL = 2,
	PERF_COUNT_HW_CACHE_DTLB = 3,
	PERF_COUNT_HW_CACHE_ITLB = 4,
	PERF_COUNT_HW_CACHE_BPU = 5,

	PERF_COUNT_HW_CACHE_MAX, /* non-ABI */
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ = 0,
	PERF_COUNT_HW_CACHE_OP_WRITE = 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH = 2,

	PERF_COUNT_HW_CACHE_OP_MAX, /* non-ABI */
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS = 1,

	PERF_COUNT_HW_CACHE_RESULT_MAX, /* non-ABI */
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "session", 's', POPT_ARG_STRING, &opt_session_name, 0, nullptr, nullptr },
	{ "channel", 'c', POPT_ARG_STRING, &opt_channel_name, 0, nullptr, nullptr },
	{ "kernel", 'k', POPT_ARG_VAL, &opt_kernel, 1, nullptr, nullptr },
	{ "userspace", 'u', POPT_ARG_NONE, nullptr, OPT_USERSPACE, nullptr, nullptr },
	{ "jul", 'j', POPT_ARG_NONE, nullptr, OPT_JUL, nullptr, nullptr },
	{ "log4j", 'l', POPT_ARG_NONE, nullptr, OPT_LOG4J, nullptr, nullptr },
	{ "log4j2", 0, POPT_ARG_NONE, nullptr, OPT_LOG4J2, nullptr, nullptr },
	{ "type", 't', POPT_ARG_STRING, &opt_type, OPT_TYPE, nullptr, nullptr },
	{ "list", 0, POPT_ARG_NONE, nullptr, OPT_LIST, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};

/*
 * Context options
 */
#define PERF_HW(optstr, name, type, hide)                \
	{                                                \
		optstr, type, PERF_COUNT_HW_##name, hide \
	}

#define PERF_SW(optstr, name, type, hide)                \
	{                                                \
		optstr, type, PERF_COUNT_SW_##name, hide \
	}

#define _PERF_HW_CACHE(optstr, name, type, op, result, hide)                           \
	{                                                                              \
		optstr, type, PERF_COUNT_HW_CACHE_##name, PERF_COUNT_HW_CACHE_OP_##op, \
			PERF_COUNT_HW_CACHE_RESULT_##result, hide,                     \
	}

#define PERF_HW_CACHE(optstr, name, type, hide)                                           \
	_PERF_HW_CACHE(optstr "-loads", name, type, READ, ACCESS, hide),                  \
		_PERF_HW_CACHE(optstr "-load-misses", name, type, READ, MISS, hide),      \
		_PERF_HW_CACHE(optstr "-stores", name, type, WRITE, ACCESS, hide),        \
		_PERF_HW_CACHE(optstr "-store-misses", name, type, WRITE, MISS, hide),    \
		_PERF_HW_CACHE(optstr "-prefetches", name, type, PREFETCH, ACCESS, hide), \
		_PERF_HW_CACHE(optstr "-prefetch-misses", name, type, PREFETCH, MISS, hide)

namespace {
const struct ctx_opts {
	/* Needed for end-of-list item. */
	ctx_opts() : ctx_opts(nullptr, CONTEXT_UNKNOWN)
	{
	}

	ctx_opts(const char *symbol_, context_type ctx_type_, bool hide_help_ = false) :
		symbol((char *) symbol_), ctx_type(ctx_type_), hide_help(hide_help_)
	{
	}

	ctx_opts(const char *symbol_,
		 context_type ctx_type_,
		 perf_count_hard perf_count_hard,
		 bool hide_help_) :
		ctx_opts(symbol_, ctx_type_, hide_help_)
	{
		u.perf.type = PERF_TYPE_HARDWARE;
		u.perf.config = perf_count_hard;
	}

	ctx_opts(const char *symbol_,
		 context_type ctx_type_,
		 perf_count_soft perf_count_soft,
		 bool hide_help_) :
		ctx_opts(symbol_, ctx_type_, hide_help_)
	{
		u.perf.type = PERF_TYPE_SOFTWARE;
		u.perf.config = perf_count_soft;
	}

	ctx_opts(const char *symbol_,
		 context_type ctx_type_,
		 perf_hw_cache_id perf_hw_cache_id,
		 perf_hw_cache_op_id perf_hw_cache_op_id,
		 perf_hw_cache_op_result_id perf_hw_cache_op_result_id,
		 bool hide_help_) :
		ctx_opts(symbol_, ctx_type_, hide_help_)
	{
		u.perf.type = PERF_TYPE_HW_CACHE;
		u.perf.config = perf_hw_cache_id | perf_hw_cache_op_id << 8 |
			perf_hw_cache_op_result_id << 16;
	}

	char *symbol;
	enum context_type ctx_type;
	bool hide_help; /* Hide from --help */
	union {
		struct {
			uint32_t type;
			uint64_t config;
		} perf;
		struct {
			char *provider_name;
			char *ctx_name;
		} app_ctx;
	} u;
} ctx_opts[] = {
	/*
	 * These (char *) casts (as well as those in the PERF_* macros) are
	 * safe because we never free these instances of `struct ctx_opts`.
	 */
	{ (char *) "pid", CONTEXT_PID },
	{ (char *) "procname", CONTEXT_PROCNAME },
	{ (char *) "prio", CONTEXT_PRIO },
	{ (char *) "nice", CONTEXT_NICE },
	{ (char *) "vpid", CONTEXT_VPID },
	{ (char *) "tid", CONTEXT_TID },
	{ (char *) "pthread_id", CONTEXT_PTHREAD_ID },
	{ (char *) "vtid", CONTEXT_VTID },
	{ (char *) "ppid", CONTEXT_PPID },
	{ (char *) "vppid", CONTEXT_VPPID },
	{ (char *) "hostname", CONTEXT_HOSTNAME },
	{ (char *) "ip", CONTEXT_IP },
	{ (char *) "interruptible", CONTEXT_INTERRUPTIBLE },
	{ (char *) "preemptible", CONTEXT_PREEMPTIBLE },
	{ (char *) "need_reschedule", CONTEXT_NEED_RESCHEDULE },
	{ (char *) "migratable", CONTEXT_MIGRATABLE },
	{ (char *) "callstack-kernel", CONTEXT_CALLSTACK_KERNEL },
#ifdef HAVE_MODULES_USERSPACE_CALLSTACK_CONTEXT
	{ (char *) "callstack-user", CONTEXT_CALLSTACK_USER },
#endif
	{ (char *) "cgroup_ns", CONTEXT_CGROUP_NS },
	{ (char *) "ipc_ns", CONTEXT_IPC_NS },
	{ (char *) "mnt_ns", CONTEXT_MNT_NS },
	{ (char *) "net_ns", CONTEXT_NET_NS },
	{ (char *) "pid_ns", CONTEXT_PID_NS },
	{ (char *) "time_ns", CONTEXT_TIME_NS },
	{ (char *) "user_ns", CONTEXT_USER_NS },
	{ (char *) "uts_ns", CONTEXT_UTS_NS },
	{ (char *) "uid", CONTEXT_UID },
	{ (char *) "euid", CONTEXT_EUID },
	{ (char *) "suid", CONTEXT_SUID },
	{ (char *) "gid", CONTEXT_GID },
	{ (char *) "egid", CONTEXT_EGID },
	{ (char *) "sgid", CONTEXT_SGID },
	{ (char *) "vuid", CONTEXT_VUID },
	{ (char *) "veuid", CONTEXT_VEUID },
	{ (char *) "vsuid", CONTEXT_VSUID },
	{ (char *) "vgid", CONTEXT_VGID },
	{ (char *) "vegid", CONTEXT_VEGID },
	{ (char *) "vsgid", CONTEXT_VSGID },
	{ (char *) "cpu_id", CONTEXT_CPU_ID },

	/* Perf options */

	/* Perf per-CPU counters */
	PERF_HW("perf:cpu:cpu-cycles", CPU_CYCLES, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:cycles", CPU_CYCLES, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:stalled-cycles-frontend",
		STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_CPU_COUNTER,
		0),
	PERF_HW("perf:cpu:idle-cycles-frontend",
		STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_CPU_COUNTER,
		0),
	PERF_HW("perf:cpu:stalled-cycles-backend",
		STALLED_CYCLES_BACKEND,
		CONTEXT_PERF_CPU_COUNTER,
		0),
	PERF_HW("perf:cpu:idle-cycles-backend", STALLED_CYCLES_BACKEND, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:instructions", INSTRUCTIONS, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:cache-references", CACHE_REFERENCES, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:cache-misses", CACHE_MISSES, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:branch-instructions", BRANCH_INSTRUCTIONS, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:branches", BRANCH_INSTRUCTIONS, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:branch-misses", BRANCH_MISSES, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:bus-cycles", BUS_CYCLES, CONTEXT_PERF_CPU_COUNTER, 0),

	PERF_HW_CACHE("perf:cpu:L1-dcache", L1D, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW_CACHE("perf:cpu:L1-icache", L1I, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW_CACHE("perf:cpu:LLC", LL, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW_CACHE("perf:cpu:dTLB", DTLB, CONTEXT_PERF_CPU_COUNTER, 0),
	_PERF_HW_CACHE("perf:cpu:iTLB-loads", ITLB, CONTEXT_PERF_CPU_COUNTER, READ, ACCESS, 0),
	_PERF_HW_CACHE("perf:cpu:iTLB-load-misses", ITLB, CONTEXT_PERF_CPU_COUNTER, READ, MISS, 0),
	_PERF_HW_CACHE("perf:cpu:branch-loads", BPU, CONTEXT_PERF_CPU_COUNTER, READ, ACCESS, 0),
	_PERF_HW_CACHE("perf:cpu:branch-load-misses", BPU, CONTEXT_PERF_CPU_COUNTER, READ, MISS, 0),

	PERF_SW("perf:cpu:cpu-clock", CPU_CLOCK, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:task-clock", TASK_CLOCK, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:page-fault", PAGE_FAULTS, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:faults", PAGE_FAULTS, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:major-faults", PAGE_FAULTS_MAJ, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:minor-faults", PAGE_FAULTS_MIN, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:context-switches", CONTEXT_SWITCHES, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:cs", CONTEXT_SWITCHES, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:cpu-migrations", CPU_MIGRATIONS, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:migrations", CPU_MIGRATIONS, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:alignment-faults", ALIGNMENT_FAULTS, CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:emulation-faults", EMULATION_FAULTS, CONTEXT_PERF_CPU_COUNTER, 0),

	/* Perf per-thread counters */
	PERF_HW("perf:thread:cpu-cycles", CPU_CYCLES, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:cycles", CPU_CYCLES, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:stalled-cycles-frontend",
		STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_THREAD_COUNTER,
		0),
	PERF_HW("perf:thread:idle-cycles-frontend",
		STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_THREAD_COUNTER,
		0),
	PERF_HW("perf:thread:stalled-cycles-backend",
		STALLED_CYCLES_BACKEND,
		CONTEXT_PERF_THREAD_COUNTER,
		0),
	PERF_HW("perf:thread:idle-cycles-backend",
		STALLED_CYCLES_BACKEND,
		CONTEXT_PERF_THREAD_COUNTER,
		0),
	PERF_HW("perf:thread:instructions", INSTRUCTIONS, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:cache-references", CACHE_REFERENCES, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:cache-misses", CACHE_MISSES, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:branch-instructions",
		BRANCH_INSTRUCTIONS,
		CONTEXT_PERF_THREAD_COUNTER,
		0),
	PERF_HW("perf:thread:branches", BRANCH_INSTRUCTIONS, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:branch-misses", BRANCH_MISSES, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:bus-cycles", BUS_CYCLES, CONTEXT_PERF_THREAD_COUNTER, 0),

	PERF_HW_CACHE("perf:thread:L1-dcache", L1D, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW_CACHE("perf:thread:L1-icache", L1I, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW_CACHE("perf:thread:LLC", LL, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW_CACHE("perf:thread:dTLB", DTLB, CONTEXT_PERF_THREAD_COUNTER, 0),
	_PERF_HW_CACHE("perf:thread:iTLB-loads", ITLB, CONTEXT_PERF_THREAD_COUNTER, READ, ACCESS, 0),
	_PERF_HW_CACHE(
		"perf:thread:iTLB-load-misses", ITLB, CONTEXT_PERF_THREAD_COUNTER, READ, MISS, 0),
	_PERF_HW_CACHE(
		"perf:thread:branch-loads", BPU, CONTEXT_PERF_THREAD_COUNTER, READ, ACCESS, 0),
	_PERF_HW_CACHE(
		"perf:thread:branch-load-misses", BPU, CONTEXT_PERF_THREAD_COUNTER, READ, MISS, 0),

	PERF_SW("perf:thread:cpu-clock", CPU_CLOCK, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:task-clock", TASK_CLOCK, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:page-fault", PAGE_FAULTS, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:faults", PAGE_FAULTS, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:major-faults", PAGE_FAULTS_MAJ, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:minor-faults", PAGE_FAULTS_MIN, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:context-switches", CONTEXT_SWITCHES, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:cs", CONTEXT_SWITCHES, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:cpu-migrations", CPU_MIGRATIONS, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:migrations", CPU_MIGRATIONS, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:alignment-faults", ALIGNMENT_FAULTS, CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:emulation-faults", EMULATION_FAULTS, CONTEXT_PERF_THREAD_COUNTER, 0),

	/*
	 * Perf per-CPU counters, backward compatibilty for names.
	 * Hidden from help listing.
	 */
	PERF_HW("perf:cpu-cycles", CPU_CYCLES, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:cycles", CPU_CYCLES, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:stalled-cycles-frontend", STALLED_CYCLES_FRONTEND, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:idle-cycles-frontend", STALLED_CYCLES_FRONTEND, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:stalled-cycles-backend", STALLED_CYCLES_BACKEND, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:idle-cycles-backend", STALLED_CYCLES_BACKEND, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:instructions", INSTRUCTIONS, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:cache-references", CACHE_REFERENCES, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:cache-misses", CACHE_MISSES, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:branch-instructions", BRANCH_INSTRUCTIONS, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:branches", BRANCH_INSTRUCTIONS, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:branch-misses", BRANCH_MISSES, CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:bus-cycles", BUS_CYCLES, CONTEXT_PERF_COUNTER, 1),

	PERF_HW_CACHE("perf:L1-dcache", L1D, CONTEXT_PERF_COUNTER, 1),
	PERF_HW_CACHE("perf:L1-icache", L1I, CONTEXT_PERF_COUNTER, 1),
	PERF_HW_CACHE("perf:LLC", LL, CONTEXT_PERF_COUNTER, 1),
	PERF_HW_CACHE("perf:dTLB", DTLB, CONTEXT_PERF_COUNTER, 1),
	_PERF_HW_CACHE("perf:iTLB-loads", ITLB, CONTEXT_PERF_COUNTER, READ, ACCESS, 1),
	_PERF_HW_CACHE("perf:iTLB-load-misses", ITLB, CONTEXT_PERF_COUNTER, READ, MISS, 1),
	_PERF_HW_CACHE("perf:branch-loads", BPU, CONTEXT_PERF_COUNTER, READ, ACCESS, 1),
	_PERF_HW_CACHE("perf:branch-load-misses", BPU, CONTEXT_PERF_COUNTER, READ, MISS, 1),

	PERF_SW("perf:cpu-clock", CPU_CLOCK, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:task-clock", TASK_CLOCK, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:page-fault", PAGE_FAULTS, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:faults", PAGE_FAULTS, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:major-faults", PAGE_FAULTS_MAJ, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:minor-faults", PAGE_FAULTS_MIN, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:context-switches", CONTEXT_SWITCHES, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:cs", CONTEXT_SWITCHES, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:cpu-migrations", CPU_MIGRATIONS, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:migrations", CPU_MIGRATIONS, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:alignment-faults", ALIGNMENT_FAULTS, CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:emulation-faults", EMULATION_FAULTS, CONTEXT_PERF_COUNTER, 1),

	{}, /* Closure */
};

#undef PERF_HW_CACHE
#undef _PERF_HW_CACHE
#undef PERF_SW
#undef PERF_HW

/*
 * Context type for command line option parsing.
 */
struct ctx_type {
	struct ctx_opts *opt;
	struct cds_list_head list;
};

/*
 * List of context type. Use to enable multiple context on a single command
 * line entry.
 */
struct ctx_type_list {
	struct cds_list_head head;
} ctx_type_list = {
	.head = CDS_LIST_HEAD_INIT(ctx_type_list.head),
};
} /* namespace */

/*
 * Find context numerical value from string.
 *
 * Return -1 if not found.
 */
static int find_ctx_type_idx(const char *opt)
{
	int ret, i = 0;

	while (ctx_opts[i].symbol != nullptr) {
		if (strcmp(opt, ctx_opts[i].symbol) == 0) {
			ret = i;
			goto end;
		}
		i++;
	}

	ret = -1;
end:
	return ret;
}

static enum lttng_domain_type get_domain()
{
	if (opt_kernel) {
		return LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		return LTTNG_DOMAIN_UST;
	} else if (opt_jul) {
		return LTTNG_DOMAIN_JUL;
	} else if (opt_log4j) {
		return LTTNG_DOMAIN_LOG4J;
	} else if (opt_log4j2) {
		return LTTNG_DOMAIN_LOG4J2;
	} else {
		abort();
	}
}

static int mi_open()
{
	int ret;

	/* MI check */
	if (!lttng_opt_mi) {
		ret = 0;
		goto end;
	}

	ret = fileno(stdout);
	if (ret < 0) {
		PERROR("Unable to retrieve fileno of stdout");
		ret = CMD_ERROR;
		goto end;
	}

	writer = mi_lttng_writer_create(ret, lttng_opt_mi);
	if (!writer) {
		ret = CMD_ERROR;
		goto end;
	}

	/* Open command element */
	ret = mi_lttng_writer_command_open(writer, mi_lttng_element_command_add_context);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	/* Open output element */
	ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_output);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}
end:
	return ret;
}

static int mi_close(enum cmd_error_code success)
{
	int ret;

	/* MI closing */
	if (!lttng_opt_mi) {
		ret = 0;
		goto end;
	}
	/* Close  output element */
	ret = mi_lttng_writer_close_element(writer);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	/* Success ? */
	ret = mi_lttng_writer_write_element_bool(
		writer, mi_lttng_element_command_success, !success);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	/* Command element close */
	ret = mi_lttng_writer_command_close(writer);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}
end:
	return ret;
}

static void populate_context(struct lttng_event_context *context, const struct ctx_opts *opt)
{
	char *ptr;

	context->ctx = (enum lttng_event_context_type) opt->ctx_type;
	switch (context->ctx) {
	case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
	case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
		context->u.perf_counter.type = opt->u.perf.type;
		context->u.perf_counter.config = opt->u.perf.config;
		strncpy(context->u.perf_counter.name, opt->symbol, LTTNG_SYMBOL_NAME_LEN);
		context->u.perf_counter.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
		/* Replace : and - by _ */
		while ((ptr = strchr(context->u.perf_counter.name, '-')) != nullptr) {
			*ptr = '_';
		}
		while ((ptr = strchr(context->u.perf_counter.name, ':')) != nullptr) {
			*ptr = '_';
		}
		break;
	case LTTNG_EVENT_CONTEXT_APP_CONTEXT:
		context->u.app_ctx.provider_name = opt->u.app_ctx.provider_name;
		context->u.app_ctx.ctx_name = opt->u.app_ctx.ctx_name;
		break;
	default:
		break;
	}
}

/*
 * Pretty print context type.
 */
static int print_ctx_type()
{
	FILE *ofp = stdout;
	int i = 0;
	int ret;
	struct lttng_event_context context;

	memset(&context, 0, sizeof(context));

	ret = mi_open();
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	if (lttng_opt_mi) {
		/* Open a contexts element */
		ret = mi_lttng_writer_open_element(writer, config_element_contexts);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	while (ctx_opts[i].symbol != nullptr) {
		if (!ctx_opts[i].hide_help) {
			if (lttng_opt_mi) {
				populate_context(&context, &ctx_opts[i]);
				ret = mi_lttng_context(writer, &context, 1);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}

				ret = mi_lttng_writer_write_element_string(
					writer,
					mi_lttng_element_context_symbol,
					ctx_opts[i].symbol);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}

				ret = mi_lttng_writer_close_element(writer);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}
			} else {
				fprintf(ofp, "%s\n", ctx_opts[i].symbol);
			}
		}
		i++;
	}

	if (lttng_opt_mi) {
		/* Close contexts element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}
	}

end:
	ret = mi_close((cmd_error_code) ret);
	if (ret) {
		ret = CMD_ERROR;
	}
	return ret;
}

/*
 * Add context to channel or event.
 */
static int add_context(char *session_name)
{
	int ret = CMD_SUCCESS, warn = 0, success = 0;
	struct lttng_event_context context;
	struct lttng_domain dom;
	struct ctx_type *type;

	memset(&context, 0, sizeof(context));
	memset(&dom, 0, sizeof(dom));

	dom.type = get_domain();
	handle = lttng_create_handle(session_name, &dom);
	if (handle == nullptr) {
		ret = CMD_ERROR;
		goto error;
	}

	if (lttng_opt_mi) {
		/* Open a contexts element */
		ret = mi_lttng_writer_open_element(writer, config_element_contexts);
		if (ret) {
			goto error;
		}
	}

	/* Iterate over all the context types given */
	cds_list_for_each_entry (type, &ctx_type_list.head, list) {
		DBG("Adding context...");

		populate_context(&context, type->opt);

		if (lttng_opt_mi) {
			/* We leave context open the update the success of the command */
			ret = mi_lttng_context(writer, &context, 1);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			ret = mi_lttng_writer_write_element_string(
				writer, mi_lttng_element_context_symbol, type->opt->symbol);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}
		}

		ret = lttng_add_context(handle, &context, nullptr, opt_channel_name);
		if (ret < 0) {
			ERR("%s: %s", type->opt->symbol, lttng_strerror(ret));
			warn = 1;
			success = 0;
		} else {
			if (opt_channel_name) {
				MSG("%s context %s added to channel %s",
				    lttng_domain_type_str(dom.type),
				    type->opt->symbol,
				    opt_channel_name);
			} else {
				MSG("%s context %s added to all channels",
				    lttng_domain_type_str(dom.type),
				    type->opt->symbol);
			}
			success = 1;
		}

		if (lttng_opt_mi) {
			/* Is the single operation a success ? */
			ret = mi_lttng_writer_write_element_bool(
				writer, mi_lttng_element_success, success);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* Close the context element */
			ret = mi_lttng_writer_close_element(writer);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}
		}
	}

	if (lttng_opt_mi) {
		/* Close contexts element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto error;
		}
	}

	ret = CMD_SUCCESS;

error:
	lttng_destroy_handle(handle);

	/*
	 * This means that at least one add_context failed and tells the user to
	 * look on stderr for error(s).
	 */
	if (!ret && warn) {
		ret = CMD_WARNING;
	}
	return ret;
}

static void destroy_ctx_type(struct ctx_type *type)
{
	if (!type) {
		return;
	}

	if (type->opt) {
		free(type->opt->symbol);

		if (type->opt->ctx_type == CONTEXT_APP_CONTEXT) {
			free(type->opt->u.app_ctx.ctx_name);
			free(type->opt->u.app_ctx.provider_name);
		}
	}

	delete type->opt;
	free(type);
}

static struct ctx_type *create_ctx_type()
{
	struct ctx_type *type = zmalloc<ctx_type>();

	if (!type) {
		PERROR("malloc ctx_type");
		goto end;
	}

	type->opt = new struct ctx_opts;
	if (!type->opt) {
		PERROR("malloc ctx_type options");
		destroy_ctx_type(type);
		type = nullptr;
		goto end;
	}
end:
	return type;
}

static int find_ctx_type_perf_raw(const char *ctx, struct ctx_type *type)
{
	int ret;
	int field_pos = 0;
	char *tmp_list, *cur_list;

	cur_list = tmp_list = strdup(ctx);
	if (!tmp_list) {
		PERROR("strdup temp list");
		ret = -ENOMEM;
		goto end;
	}

	/* Looking for "perf:[cpu|thread]:raw:<mask>:<name>". */
	for (;;) {
		char *next;

		next = strtok(cur_list, ":");
		if (!next) {
			break;
		}
		cur_list = nullptr;
		switch (field_pos) {
		case 0:
			if (strncmp(next, "perf", 4) != 0) {
				ret = -1;
				goto end;
			}
			break;
		case 1:
			if (strncmp(next, "cpu", 3) == 0) {
				type->opt->ctx_type = CONTEXT_PERF_CPU_COUNTER;
			} else if (strncmp(next, "thread", 4) == 0) {
				type->opt->ctx_type = CONTEXT_PERF_THREAD_COUNTER;
			} else {
				ret = -1;
				goto end;
			}
			break;
		case 2:
			if (strncmp(next, "raw", 3) != 0) {
				ret = -1;
				goto end;
			}
			break;
		case 3:
		{
			char *endptr;

			if (strlen(next) < 2 || next[0] != 'r') {
				ERR("Wrong perf raw mask format: expected rNNN");
				ret = -1;
				goto end;
			}
			errno = 0;
			type->opt->u.perf.config = strtoll(next + 1, &endptr, 16);
			if (errno != 0 || !endptr || *endptr) {
				ERR("Wrong perf raw mask format: expected rNNN");
				ret = -1;
				goto end;
			}
			break;
		}
		case 4:
			/* name */
			break;
		case 5:
			ERR("Too many ':' in perf raw format");
			ret = -1;
			goto end;
		};
		field_pos++;
	}

	if (field_pos < 5) {
		ERR("Invalid perf counter specifier, expected a specifier of "
		    "the form perf:cpu:raw:rNNN:<name> or "
		    "perf:thread:raw:rNNN:<name>");
		ret = -1;
		goto end;
	}

	ret = 0;
	goto end;

end:
	free(tmp_list);
	return ret;
}

static struct ctx_type *get_context_type(const char *ctx)
{
	int opt_index, ret;
	struct ctx_type *type = nullptr;
	const char app_ctx_prefix[] = "$app.";
	char *provider_name = nullptr, *ctx_name = nullptr;
	size_t i, len, colon_pos = 0, provider_name_len, ctx_name_len;

	if (!ctx) {
		goto not_found;
	}

	type = create_ctx_type();
	if (!type) {
		goto not_found;
	}

	/* Check if ctx matches a known static context. */
	opt_index = find_ctx_type_idx(ctx);
	if (opt_index >= 0) {
		*type->opt = ctx_opts[opt_index];
		type->opt->symbol = strdup(ctx_opts[opt_index].symbol);
		goto found;
	}

	/* Check if ctx is a raw perf context. */
	ret = find_ctx_type_perf_raw(ctx, type);
	if (ret == 0) {
		type->opt->u.perf.type = PERF_TYPE_RAW;
		type->opt->symbol = strdup(ctx);
		if (!type->opt->symbol) {
			PERROR("Copy perf field name");
			goto not_found;
		}
		goto found;
	}

	/*
	 * No match found against static contexts; check if it is an app
	 * context.
	 */
	len = strlen(ctx);
	if (len <= sizeof(app_ctx_prefix) - 1) {
		goto not_found;
	}

	/* String starts with $app. */
	if (strncmp(ctx, app_ctx_prefix, sizeof(app_ctx_prefix) - 1) != 0) {
		goto not_found;
	}

	/* Validate that the ':' separator is present. */
	for (i = sizeof(app_ctx_prefix); i < len; i++) {
		const char c = ctx[i];

		if (c == ':') {
			colon_pos = i;
			break;
		}
	}

	/*
	 * No colon found or no ctx name ("$app.provider:") or no provider name
	 * given ("$app.:..."), which is invalid.
	 */
	if (!colon_pos || colon_pos == len || colon_pos == sizeof(app_ctx_prefix)) {
		ERR("Invalid application context provided: no provider or context name provided.");
		goto not_found;
	}

	provider_name_len = colon_pos - sizeof(app_ctx_prefix) + 2;
	provider_name = calloc<char>(provider_name_len);
	if (!provider_name) {
		PERROR("malloc provider_name");
		goto not_found;
	}
	strncpy(provider_name, ctx + sizeof(app_ctx_prefix) - 1, provider_name_len - 1);
	type->opt->u.app_ctx.provider_name = provider_name;

	ctx_name_len = len - colon_pos;
	ctx_name = calloc<char>(ctx_name_len);
	if (!ctx_name) {
		PERROR("malloc ctx_name");
		goto not_found;
	}
	strncpy(ctx_name, ctx + colon_pos + 1, ctx_name_len - 1);
	type->opt->u.app_ctx.ctx_name = ctx_name;
	type->opt->ctx_type = CONTEXT_APP_CONTEXT;
	type->opt->symbol = strdup(ctx);
found:
	return type;
not_found:
	free(provider_name);
	free(ctx_name);
	destroy_ctx_type(type);
	return nullptr;
}

/*
 * Add context to channel or event.
 */
int cmd_add_context(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS;
	static poptContext pc;
	struct ctx_type *type, *tmptype;
	char *session_name = nullptr;
	const char *leftover = nullptr;

	if (argc < 2) {
		ret = CMD_ERROR;
		goto end;
	}

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST:
			ret = print_ctx_type();
			goto end;
		case OPT_TYPE:
		{
			type = get_context_type(opt_type);
			if (!type) {
				ERR("Unknown context type %s", opt_type);
				ret = CMD_FATAL;
				goto end;
			}
			cds_list_add_tail(&type->list, &ctx_type_list.head);
			break;
		}
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_JUL:
			opt_jul = 1;
			break;
		case OPT_LOG4J:
			opt_log4j = 1;
			break;
		case OPT_LOG4J2:
			opt_log4j2 = 1;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		goto end;
	}

	ret = print_missing_or_multiple_domains(
		opt_kernel + opt_userspace + opt_jul + opt_log4j + opt_log4j2, true);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	if (!opt_type) {
		ERR("Missing mandatory -t TYPE");
		ret = CMD_ERROR;
		goto end;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == nullptr) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	ret = mi_open();
	if (ret) {
		goto end;
	}

	command_ret = add_context(session_name);
	ret = mi_close((cmd_error_code) command_ret);
	if (ret) {
		goto end;
	}

end:
	if (!opt_session_name) {
		free(session_name);
	}

	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : LTTNG_ERR_MI_IO_FAIL;
	}

	/* Cleanup allocated memory */
	cds_list_for_each_entry_safe (type, tmptype, &ctx_type_list.head, list) {
		destroy_ctx_type(type);
	}

	/* Overwrite ret if an error occurred during add_context() */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
