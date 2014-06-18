/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <urcu/list.h>

#include <common/mi-lttng.h>

#include "../command.h"

#define PRINT_LINE_LEN	80

static char *opt_channel_name;
static char *opt_session_name;
static int opt_kernel;
static int opt_userspace;
static char *opt_type;

#if 0
/* Not implemented yet */
static char *opt_cmd_name;
static pid_t opt_pid;
#endif

enum {
	OPT_HELP = 1,
	OPT_TYPE,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
};

static struct lttng_handle *handle;
static struct mi_writer *writer;

/*
 * Taken from the LTTng ABI
 */
enum context_type {
	CONTEXT_PID          = 0,
	CONTEXT_PERF_COUNTER = 1,	/* Backward compat. */
	CONTEXT_PROCNAME     = 2,
	CONTEXT_PRIO         = 3,
	CONTEXT_NICE         = 4,
	CONTEXT_VPID         = 5,
	CONTEXT_TID          = 6,
	CONTEXT_VTID         = 7,
	CONTEXT_PPID         = 8,
	CONTEXT_VPPID        = 9,
	CONTEXT_PTHREAD_ID   = 10,
	CONTEXT_HOSTNAME     = 11,
	CONTEXT_IP           = 12,
	CONTEXT_PERF_CPU_COUNTER = 13,
	CONTEXT_PERF_THREAD_COUNTER = 14,
};

/*
 * Taken from the Perf ABI (all enum perf_*)
 */
enum perf_type {
	PERF_TYPE_HARDWARE = 0,
	PERF_TYPE_SOFTWARE = 1,
	PERF_TYPE_HW_CACHE = 3,
};

enum perf_count_hard {
	PERF_COUNT_HW_CPU_CYCLES		= 0,
	PERF_COUNT_HW_INSTRUCTIONS		= 1,
	PERF_COUNT_HW_CACHE_REFERENCES		= 2,
	PERF_COUNT_HW_CACHE_MISSES		= 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS	= 4,
	PERF_COUNT_HW_BRANCH_MISSES		= 5,
	PERF_COUNT_HW_BUS_CYCLES		= 6,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND	= 7,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND	= 8,
};

enum perf_count_soft {
	PERF_COUNT_SW_CPU_CLOCK        = 0,
	PERF_COUNT_SW_TASK_CLOCK       = 1,
	PERF_COUNT_SW_PAGE_FAULTS      = 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
	PERF_COUNT_SW_CPU_MIGRATIONS   = 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN  = 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ  = 6,
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
	PERF_COUNT_HW_CACHE_L1D			= 0,
	PERF_COUNT_HW_CACHE_L1I			= 1,
	PERF_COUNT_HW_CACHE_LL			= 2,
	PERF_COUNT_HW_CACHE_DTLB		= 3,
	PERF_COUNT_HW_CACHE_ITLB		= 4,
	PERF_COUNT_HW_CACHE_BPU			= 5,

	PERF_COUNT_HW_CACHE_MAX,		/* non-ABI */
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ		= 0,
	PERF_COUNT_HW_CACHE_OP_WRITE		= 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH		= 2,

	PERF_COUNT_HW_CACHE_OP_MAX,		/* non-ABI */
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS	= 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS		= 1,

	PERF_COUNT_HW_CACHE_RESULT_MAX,		/* non-ABI */
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"channel",        'c', POPT_ARG_STRING, &opt_channel_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
	{"type",           't', POPT_ARG_STRING, &opt_type, OPT_TYPE, 0, 0},
	{"list-options",   0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * Context options
 */
#define PERF_HW(optstr, name, type, hide)				\
	{								\
		optstr, type, hide,					\
		.u.perf = { PERF_TYPE_HARDWARE, PERF_COUNT_HW_##name, },\
	}

#define PERF_SW(optstr, name, type, hide)				\
	{								\
		optstr, type, hide,					\
		.u.perf = { PERF_TYPE_SOFTWARE, PERF_COUNT_SW_##name, },\
	}

#define _PERF_HW_CACHE(optstr, name, type, op, result, hide)		\
	{								\
		optstr, type, hide,					\
		.u.perf = {						\
			PERF_TYPE_HW_CACHE,				\
			(uint64_t) PERF_COUNT_HW_CACHE_##name		\
			| ((uint64_t) PERF_COUNT_HW_CACHE_OP_##op << 8)	\
			| ((uint64_t) PERF_COUNT_HW_CACHE_RESULT_##result << 16), \
		},							\
	}

#define PERF_HW_CACHE(optstr, name, type, hide)				\
	_PERF_HW_CACHE(optstr "-loads", name, type,			\
		READ, ACCESS, hide),					\
	_PERF_HW_CACHE(optstr "-load-misses", name, type,		\
		READ, MISS, hide),					\
	_PERF_HW_CACHE(optstr "-stores", name, type,			\
		WRITE, ACCESS, hide),					\
	_PERF_HW_CACHE(optstr "-store-misses", name, type,		\
		WRITE, MISS, hide), 					\
	_PERF_HW_CACHE(optstr "-prefetches", name, type,		\
		PREFETCH, ACCESS, hide), 				\
	_PERF_HW_CACHE(optstr "-prefetch-misses", name, type,		\
		PREFETCH, MISS, hide)

static
const struct ctx_opts {
	char *symbol;
	enum context_type ctx_type;
	int hide_help;	/* Hide from --help */
	union {
		struct {
			uint32_t type;
			uint64_t config;
		} perf;
	} u;
} ctx_opts[] = {
	{ "pid", CONTEXT_PID },
	{ "procname", CONTEXT_PROCNAME },
	{ "prio", CONTEXT_PRIO },
	{ "nice", CONTEXT_NICE },
	{ "vpid", CONTEXT_VPID },
	{ "tid", CONTEXT_TID },
	{ "pthread_id", CONTEXT_PTHREAD_ID },
	{ "vtid", CONTEXT_VTID },
	{ "ppid", CONTEXT_PPID },
	{ "vppid", CONTEXT_VPPID },
	{ "hostname", CONTEXT_HOSTNAME },
	{ "ip", CONTEXT_IP },

	/* Perf options */

	/* Perf per-CPU counters */
	PERF_HW("perf:cpu:cpu-cycles", CPU_CYCLES,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:cycles", CPU_CYCLES,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:stalled-cycles-frontend", STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:idle-cycles-frontend", STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:stalled-cycles-backend", STALLED_CYCLES_BACKEND,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:idle-cycles-backend", STALLED_CYCLES_BACKEND,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:instructions", INSTRUCTIONS,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:cache-references", CACHE_REFERENCES,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:cache-misses", CACHE_MISSES,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:branch-instructions", BRANCH_INSTRUCTIONS,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:branches", BRANCH_INSTRUCTIONS,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:branch-misses", BRANCH_MISSES,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW("perf:cpu:bus-cycles", BUS_CYCLES,
		CONTEXT_PERF_CPU_COUNTER, 0),

	PERF_HW_CACHE("perf:cpu:L1-dcache", L1D,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW_CACHE("perf:cpu:L1-icache", L1I,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW_CACHE("perf:cpu:LLC", LL,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_HW_CACHE("perf:cpu:dTLB", DTLB,
		CONTEXT_PERF_CPU_COUNTER, 0),
	_PERF_HW_CACHE("perf:cpu:iTLB-loads", ITLB,
		CONTEXT_PERF_CPU_COUNTER, READ, ACCESS, 0),
	_PERF_HW_CACHE("perf:cpu:iTLB-load-misses", ITLB,
		CONTEXT_PERF_CPU_COUNTER, READ, MISS, 0),
	_PERF_HW_CACHE("perf:cpu:branch-loads", BPU,
		CONTEXT_PERF_CPU_COUNTER, READ, ACCESS, 0),
	_PERF_HW_CACHE("perf:cpu:branch-load-misses", BPU,
		CONTEXT_PERF_CPU_COUNTER, READ, MISS, 0),

	PERF_SW("perf:cpu:cpu-clock", CPU_CLOCK,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:task-clock", TASK_CLOCK,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:page-fault", PAGE_FAULTS,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:faults", PAGE_FAULTS,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:major-faults", PAGE_FAULTS_MAJ,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:minor-faults", PAGE_FAULTS_MIN,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:context-switches", CONTEXT_SWITCHES,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:cs", CONTEXT_SWITCHES,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:cpu-migrations", CPU_MIGRATIONS,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:migrations", CPU_MIGRATIONS,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:alignment-faults", ALIGNMENT_FAULTS,
		CONTEXT_PERF_CPU_COUNTER, 0),
	PERF_SW("perf:cpu:emulation-faults", EMULATION_FAULTS,
		CONTEXT_PERF_CPU_COUNTER, 0),

	/* Perf per-thread counters */
	PERF_HW("perf:thread:cpu-cycles", CPU_CYCLES,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:cycles", CPU_CYCLES,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:stalled-cycles-frontend", STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:idle-cycles-frontend", STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:stalled-cycles-backend", STALLED_CYCLES_BACKEND,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:idle-cycles-backend", STALLED_CYCLES_BACKEND,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:instructions", INSTRUCTIONS,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:cache-references", CACHE_REFERENCES,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:cache-misses", CACHE_MISSES,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:branch-instructions", BRANCH_INSTRUCTIONS,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:branches", BRANCH_INSTRUCTIONS,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:branch-misses", BRANCH_MISSES,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW("perf:thread:bus-cycles", BUS_CYCLES,
		CONTEXT_PERF_THREAD_COUNTER, 0),

	PERF_HW_CACHE("perf:thread:L1-dcache", L1D,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW_CACHE("perf:thread:L1-icache", L1I,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW_CACHE("perf:thread:LLC", LL,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_HW_CACHE("perf:thread:dTLB", DTLB,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	_PERF_HW_CACHE("perf:thread:iTLB-loads", ITLB,
		CONTEXT_PERF_THREAD_COUNTER, READ, ACCESS, 0),
	_PERF_HW_CACHE("perf:thread:iTLB-load-misses", ITLB,
		CONTEXT_PERF_THREAD_COUNTER, READ, MISS, 0),
	_PERF_HW_CACHE("perf:thread:branch-loads", BPU,
		CONTEXT_PERF_THREAD_COUNTER, READ, ACCESS, 0),
	_PERF_HW_CACHE("perf:thread:branch-load-misses", BPU,
		CONTEXT_PERF_THREAD_COUNTER, READ, MISS, 0),

	PERF_SW("perf:thread:cpu-clock", CPU_CLOCK,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:task-clock", TASK_CLOCK,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:page-fault", PAGE_FAULTS,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:faults", PAGE_FAULTS,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:major-faults", PAGE_FAULTS_MAJ,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:minor-faults", PAGE_FAULTS_MIN,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:context-switches", CONTEXT_SWITCHES,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:cs", CONTEXT_SWITCHES,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:cpu-migrations", CPU_MIGRATIONS,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:migrations", CPU_MIGRATIONS,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:alignment-faults", ALIGNMENT_FAULTS,
		CONTEXT_PERF_THREAD_COUNTER, 0),
	PERF_SW("perf:thread:emulation-faults", EMULATION_FAULTS,
		CONTEXT_PERF_THREAD_COUNTER, 0),

	/*
	 * Perf per-CPU counters, backward compatibilty for names.
	 * Hidden from help listing.
	 */
	PERF_HW("perf:cpu-cycles", CPU_CYCLES,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:cycles", CPU_CYCLES,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:stalled-cycles-frontend", STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:idle-cycles-frontend", STALLED_CYCLES_FRONTEND,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:stalled-cycles-backend", STALLED_CYCLES_BACKEND,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:idle-cycles-backend", STALLED_CYCLES_BACKEND,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:instructions", INSTRUCTIONS,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:cache-references", CACHE_REFERENCES,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:cache-misses", CACHE_MISSES,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:branch-instructions", BRANCH_INSTRUCTIONS,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:branches", BRANCH_INSTRUCTIONS,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:branch-misses", BRANCH_MISSES,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW("perf:bus-cycles", BUS_CYCLES,
		CONTEXT_PERF_COUNTER, 1),

	PERF_HW_CACHE("perf:L1-dcache", L1D,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW_CACHE("perf:L1-icache", L1I,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW_CACHE("perf:LLC", LL,
		CONTEXT_PERF_COUNTER, 1),
	PERF_HW_CACHE("perf:dTLB", DTLB,
		CONTEXT_PERF_COUNTER, 1),
	_PERF_HW_CACHE("perf:iTLB-loads", ITLB,
		CONTEXT_PERF_COUNTER, READ, ACCESS, 1),
	_PERF_HW_CACHE("perf:iTLB-load-misses", ITLB,
		CONTEXT_PERF_COUNTER, READ, MISS, 1),
	_PERF_HW_CACHE("perf:branch-loads", BPU,
		CONTEXT_PERF_COUNTER, READ, ACCESS, 1),
	_PERF_HW_CACHE("perf:branch-load-misses", BPU,
		CONTEXT_PERF_COUNTER, READ, MISS, 1),

	PERF_SW("perf:cpu-clock", CPU_CLOCK,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:task-clock", TASK_CLOCK,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:page-fault", PAGE_FAULTS,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:faults", PAGE_FAULTS,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:major-faults", PAGE_FAULTS_MAJ,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:minor-faults", PAGE_FAULTS_MIN,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:context-switches", CONTEXT_SWITCHES,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:cs", CONTEXT_SWITCHES,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:cpu-migrations", CPU_MIGRATIONS,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:migrations", CPU_MIGRATIONS,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:alignment-faults", ALIGNMENT_FAULTS,
		CONTEXT_PERF_COUNTER, 1),
	PERF_SW("perf:emulation-faults", EMULATION_FAULTS,
		CONTEXT_PERF_COUNTER, 1),

	{ NULL, -1 },		/* Closure */
};

#undef PERF_HW_CACHE
#undef _PERF_HW_CACHE
#undef PERF_SW
#undef PERF_HW

/*
 * Context type for command line option parsing.
 */
struct ctx_type {
	const struct ctx_opts *opt;
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

/*
 * Pretty print context type.
 */
static void print_ctx_type(FILE *ofp)
{
	const char *indent = "                               ";
	int indent_len = strlen(indent);
	int len, i = 0;

	fprintf(ofp, "%s", indent);
	len = indent_len;
	while (ctx_opts[i].symbol != NULL) {
		if (!ctx_opts[i].hide_help) {
			if (len > indent_len) {
				if (len + strlen(ctx_opts[i].symbol) + 2
						>= PRINT_LINE_LEN) {
					fprintf(ofp, ",\n");
					fprintf(ofp, "%s", indent);
					len = indent_len;
				} else {
					len += fprintf(ofp, ", ");
				}
			}
			len += fprintf(ofp, "%s", ctx_opts[i].symbol);
		}
		i++;
	}
}

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng add-context -t TYPE [-k|-u] [OPTIONS]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "If no channel is given (-c), the context is added to\n");
	fprintf(ofp, "all channels.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Otherwise the context is added only to the channel (-c).\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Exactly one domain (-k or -u) must be specified.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "      --list-options       Simple listing of options\n");
	fprintf(ofp, "  -s, --session NAME       Apply to session name\n");
	fprintf(ofp, "  -c, --channel NAME       Apply to channel\n");
	fprintf(ofp, "  -k, --kernel             Apply to the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace          Apply to the user-space tracer\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Context:\n");
	fprintf(ofp, "  -t, --type TYPE          Context type. You can repeat that option on\n");
	fprintf(ofp, "                           the command line to specify multiple contexts at once.\n");
	fprintf(ofp, "                           (--kernel preempts --userspace)\n");
	fprintf(ofp, "                           TYPE can be one of the strings below:\n");
	print_ctx_type(ofp);
	fprintf(ofp, "\n");
	fprintf(ofp, "Note that the vpid, vppid and vtid context types represent the virtual process id,\n"
			"virtual parent process id and virtual thread id as seen from the current execution context\n"
			"as opposed to the pid, ppid and tid which are kernel internal data structures.\n\n");
	fprintf(ofp, "Example:\n");
	fprintf(ofp, "This command will add the context information 'prio' and two per-cpu\n"
			"perf counters (hardware branch misses and cache misses), to all channels\n"
			"in the trace data output:\n");
	fprintf(ofp, "# lttng add-context -k -t prio -t perf:cpu:branch-misses -t perf:cpu:cache-misses\n");
	fprintf(ofp, "\n");
}

/*
 * Find context numerical value from string.
 */
static int find_ctx_type_idx(const char *opt)
{
	int ret = -1, i = 0;

	while (ctx_opts[i].symbol != NULL) {
		if (strcmp(opt, ctx_opts[i].symbol) == 0) {
			ret = i;
			goto end;
		}
		i++;
	}

end:
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
	char *ptr;

	memset(&context, 0, sizeof(context));
	memset(&dom, 0, sizeof(dom));

	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else {
		print_missing_domain();
		ret = CMD_ERROR;
		goto error;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
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
	cds_list_for_each_entry(type, &ctx_type_list.head, list) {
		context.ctx = (enum lttng_event_context_type) type->opt->ctx_type;
		switch (context.ctx) {
		case LTTNG_EVENT_CONTEXT_PERF_COUNTER:
		case LTTNG_EVENT_CONTEXT_PERF_CPU_COUNTER:
		case LTTNG_EVENT_CONTEXT_PERF_THREAD_COUNTER:
			context.u.perf_counter.type = type->opt->u.perf.type;
			context.u.perf_counter.config = type->opt->u.perf.config;
			strncpy(context.u.perf_counter.name, type->opt->symbol,
				LTTNG_SYMBOL_NAME_LEN);
			context.u.perf_counter.name[LTTNG_SYMBOL_NAME_LEN - 1] = '\0';
			/* Replace : and - by _ */
			while ((ptr = strchr(context.u.perf_counter.name, '-')) != NULL) {
				*ptr = '_';
			}
			while ((ptr = strchr(context.u.perf_counter.name, ':')) != NULL) {
				*ptr = '_';
			}
			break;
		default:
			break;
		}
		DBG("Adding context...");

		if (lttng_opt_mi) {
			/* We leave context open the update the success of the command */
			ret = mi_lttng_context(writer, &context, 1);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}
		}

		ret = lttng_add_context(handle, &context, NULL, opt_channel_name);
		if (ret < 0) {
			ERR("%s: %s", type->opt->symbol, lttng_strerror(ret));
			warn = 1;
			success = 0;
		} else {
			if (opt_channel_name) {
				MSG("%s context %s added to channel %s",
						opt_kernel ? "kernel" : "UST", type->opt->symbol,
						opt_channel_name);
			} else {
				MSG("%s context %s added to all channels",
						opt_kernel ? "kernel" : "UST", type->opt->symbol)
			}
			success = 1;
		}

		if (lttng_opt_mi) {
			/* Is the single operation a success ? */
			ret = mi_lttng_writer_write_element_bool(writer,
					mi_lttng_element_success, success);
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

/*
 * Add context to channel or event.
 */
int cmd_add_context(int argc, const char **argv)
{
	int index, opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS;
	int success = 1;
	static poptContext pc;
	struct ctx_type *type, *tmptype;
	char *session_name = NULL;

	if (argc < 2) {
		usage(stderr);
		ret = CMD_ERROR;
		goto end;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
			goto end;
		case OPT_TYPE:
			/*
			 * Look up the index of opt_type in ctx_opts[] first, so we don't
			 * have to free(type) on failure.
			 */
			index = find_ctx_type_idx(opt_type);
			if (index < 0) {
				ERR("Unknown context type %s", opt_type);
				ret = CMD_ERROR;
				goto end;
			}

			type = malloc(sizeof(struct ctx_type));
			if (type == NULL) {
				perror("malloc ctx_type");
				ret = CMD_FATAL;
				goto end;
			}

			type->opt = &ctx_opts[index];
			if (type->opt->symbol == NULL) {
				ERR("Unknown context type %s", opt_type);
				free(type);
				ret = CMD_ERROR;
				goto end;
			} else {
				cds_list_add_tail(&type->list, &ctx_type_list.head);
			}
			break;
		case OPT_USERSPACE:
			opt_userspace = 1;
#if 0
			opt_cmd_name = poptGetOptArg(pc);
#endif
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (!opt_type) {
		ERR("Missing mandatory -t TYPE");
		usage(stderr);
		ret = CMD_ERROR;
		goto end;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = CMD_ERROR;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_add_context);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	command_ret = add_context(session_name);
	if (command_ret) {
		success = 0;
	}

	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close  output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_command_success, success);
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
	cds_list_for_each_entry_safe(type, tmptype, &ctx_type_list.head, list) {
		free(type);
	}

	/* Overwrite ret if an error occurred during add_context() */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
