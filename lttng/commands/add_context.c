/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

#include "../cmd.h"
#include "../conf.h"
#include "../utils.h"

#define PRINT_LINE_LEN	80

static char *opt_event_name;
static char *opt_channel_name;
static char *opt_session_name;
static int *opt_kernel;
static int opt_pid_all;
static int opt_userspace;
static char *opt_cmd_name;
static pid_t opt_pid;

enum {
	OPT_HELP = 1,
	OPT_TYPE,
	OPT_USERSPACE,
};

static struct lttng_handle *handle;

/*
 * Taken from the LTTng ABI
 */
enum context_type {
	CONTEXT_PID          = 0,
	CONTEXT_PERF_COUNTER = 1,
	CONTEXT_COMM         = 2,
	CONTEXT_PRIO         = 3,
	CONTEXT_NICE         = 4,
	CONTEXT_VPID         = 5,
	CONTEXT_TID          = 6,
	CONTEXT_VTID         = 7,
	CONTEXT_PPID         = 8,
	CONTEXT_VPPID        = 9,
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
	{"event",          'e', POPT_ARG_STRING, &opt_event_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, 0, OPT_USERSPACE, 0, 0},
	{"all",            0,   POPT_ARG_VAL, &opt_pid_all, 1, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
	{"type",           't', POPT_ARG_STRING, 0, OPT_TYPE, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * Context options
 */
#define PERF_HW(opt, name)						\
	{								\
		"perf:" #opt, CONTEXT_PERF_COUNTER,			\
		.u.perf = { PERF_TYPE_HARDWARE, PERF_COUNT_HW_##name, },\
	}

#define PERF_SW(opt, name)						\
	{								\
		"perf:" #opt, CONTEXT_PERF_COUNTER,			\
		.u.perf = { PERF_TYPE_SOFTWARE, PERF_COUNT_SW_##name, },\
	}

#define _PERF_HW_CACHE(optstr, name, op, result)			\
	{								\
		"perf:" optstr, CONTEXT_PERF_COUNTER,			\
		.u.perf = {						\
			PERF_TYPE_HW_CACHE,				\
			(uint64_t) PERF_COUNT_HW_CACHE_##name		\
			| ((uint64_t) PERF_COUNT_HW_CACHE_OP_##op << 8)	\
			| ((uint64_t) PERF_COUNT_HW_CACHE_RESULT_##result << 16), \
		},							\
	}

#define PERF_HW_CACHE(opt, name)					\
	_PERF_HW_CACHE(#opt "-loads", name, READ, ACCESS),		\
	_PERF_HW_CACHE(#opt "-load-misses", name, READ, MISS),		\
	_PERF_HW_CACHE(#opt "-stores", name, WRITE, ACCESS),		\
	_PERF_HW_CACHE(#opt "-store-misses", name, WRITE, MISS),	\
	_PERF_HW_CACHE(#opt "-prefetches", name, PREFETCH, ACCESS),	\
	_PERF_HW_CACHE(#opt "-prefetch-misses", name, PREFETCH, MISS)	\

static
const struct ctx_opts {
	char *symbol;
	enum context_type ctx_type;
	union {
		struct {
			uint32_t type;
			uint64_t config;
		} perf;
	} u;
} ctx_opts[] = {
	{ "pid", CONTEXT_PID },
	{ "comm", CONTEXT_COMM },
	{ "prio", CONTEXT_PRIO },
	{ "nice", CONTEXT_NICE },
	{ "vpid", CONTEXT_VPID },
	{ "tid", CONTEXT_TID },
	{ "vtid", CONTEXT_VTID },
	{ "ppid", CONTEXT_PPID },
	{ "vppid", CONTEXT_VPPID },
	/* Perf options */
	PERF_HW(cpu-cycles, CPU_CYCLES),
	PERF_HW(cycles, CPU_CYCLES),
	PERF_HW(stalled-cycles-frontend, STALLED_CYCLES_FRONTEND),
	PERF_HW(idle-cycles-frontend, STALLED_CYCLES_FRONTEND),
	PERF_HW(stalled-cycles-backend, STALLED_CYCLES_BACKEND),
	PERF_HW(idle-cycles-backend, STALLED_CYCLES_BACKEND),
	PERF_HW(instructions, INSTRUCTIONS),
	PERF_HW(cache-references, CACHE_REFERENCES),
	PERF_HW(cache-misses, CACHE_MISSES),
	PERF_HW(branch-instructions, BRANCH_INSTRUCTIONS),
	PERF_HW(branches, BRANCH_INSTRUCTIONS),
	PERF_HW(branch-misses, BRANCH_MISSES),
	PERF_HW(bus-cycles, BUS_CYCLES),

	PERF_HW_CACHE(L1-dcache, L1D),
	PERF_HW_CACHE(L1-icache, L1I),
	PERF_HW_CACHE(LLC, LL),
	PERF_HW_CACHE(dTLB, DTLB),
	_PERF_HW_CACHE("iTLB-loads", ITLB, READ, ACCESS),
	_PERF_HW_CACHE("iTLB-load-misses", ITLB, READ, MISS),
	_PERF_HW_CACHE("branch-loads", BPU, READ, ACCESS),
	_PERF_HW_CACHE("branch-load-misses", BPU, READ, MISS),


	PERF_SW(cpu-clock, CPU_CLOCK),
	PERF_SW(task-clock, TASK_CLOCK),
	PERF_SW(page-fault, PAGE_FAULTS),
	PERF_SW(faults, PAGE_FAULTS),
	PERF_SW(major-faults, PAGE_FAULTS_MAJ),
	PERF_SW(minor-faults, PAGE_FAULTS_MIN),
	PERF_SW(context-switches, CONTEXT_SWITCHES),
	PERF_SW(cs, CONTEXT_SWITCHES),
	PERF_SW(cpu-migrations, CPU_MIGRATIONS),
	PERF_SW(migrations, CPU_MIGRATIONS),
	PERF_SW(alignment-faults, ALIGNMENT_FAULTS),
	PERF_SW(emulation-faults, EMULATION_FAULTS),
	{ NULL, -1 },		/* Closure */
};

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
		i++;
	}
}

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng add-context -t TYPE\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "If no event name is given (-e), the context will be added to\n");
	fprintf(ofp, "all events in the channel.\n");
	fprintf(ofp, "If no channel and no event is given (-c/-e), the context\n");
	fprintf(ofp, "will be added to all events in all channels.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "  -s, --session            Apply on session name\n");
	fprintf(ofp, "  -c, --channel NAME       Apply on channel\n");
	fprintf(ofp, "  -e, --event NAME         Apply on event\n");
	fprintf(ofp, "  -k, --kernel             Apply for the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace          Apply for the user-space tracer\n");
	fprintf(ofp, "      --all                If -u, apply on all traceable apps\n");
	fprintf(ofp, "  -p, --pid PID            If -u, apply on a specific PID\n");
	fprintf(ofp, "  -t, --type TYPE          Context type. You can repeat that option on\n");
	fprintf(ofp, "                           the command line.\n");
	fprintf(ofp, "                           TYPE can be one of the strings below:\n");
	print_ctx_type(ofp);
	fprintf(ofp, "\n");
	fprintf(ofp, "Example:\n");
	fprintf(ofp, "This command will add the context information 'prio' and two perf\n"
			"counters: hardware branch misses and cache misses, to all events\n"
			"in the trace data output:\n");
	fprintf(ofp, "# lttng add-context -k -t prio -t perf:branch-misses -t perf:cache-misses\n");
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
	int ret = CMD_SUCCESS;
	struct lttng_event_context context;
	struct lttng_domain dom;
	struct ctx_type *type;
	char *ptr;

	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	/* Iterate over all context type given */
	cds_list_for_each_entry(type, &ctx_type_list.head, list) {

		context.ctx = type->opt->ctx_type;
		if (context.ctx == LTTNG_EVENT_CONTEXT_PERF_COUNTER) {
			context.u.perf_counter.type = type->opt->u.perf.type;
			context.u.perf_counter.config = type->opt->u.perf.config;
			strcpy(context.u.perf_counter.name, type->opt->symbol);
			/* Replace : and - by _ */
			while ((ptr = strchr(context.u.perf_counter.name, '-')) != NULL) {
				*ptr = '_';
			}
			while ((ptr = strchr(context.u.perf_counter.name, ':')) != NULL) {
				*ptr = '_';
			}
		}
		if (opt_kernel) {
			DBG("Adding kernel context");
			ret = lttng_add_context(handle, &context, opt_event_name,
					opt_channel_name);
			if (ret < 0) {
				fprintf(stderr, "%s: ", type->opt->symbol);
				continue;
			} else {
				MSG("Kernel context %s added", type->opt->symbol);
			}
		} else if (opt_userspace) {		/* User-space tracer action */
			/*
			 * TODO: Waiting on lttng UST 2.0
			 */
			if (opt_pid_all) {
			} else if (opt_pid != 0) {
			}
			ret = CMD_NOT_IMPLEMENTED;
			goto error;
		} else {
			ERR("Please specify a tracer (--kernel or --userspace)");
			goto error;
		}
	}

error:
	lttng_destroy_handle(handle);

	return ret;
}

/*
 * Add context on channel or event.
 */
int cmd_add_context(int argc, const char **argv)
{
	int index, opt, ret = CMD_SUCCESS;
	char *tmp;
	static poptContext pc;
	struct ctx_type *type, *tmptype;
	char *session_name = NULL;

	if (argc < 2) {
		usage(stderr);
		goto end;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stderr);
			ret = CMD_SUCCESS;
			goto end;
		case OPT_TYPE:
			/* Mandatory field */
			tmp = poptGetOptArg(pc);
			if (tmp == NULL) {
				usage(stderr);
				ret = CMD_ERROR;
				free(tmp);
				goto end;
			}
			type = malloc(sizeof(struct ctx_type));
			if (type == NULL) {
				perror("malloc ctx_type");
				ret = -1;
				goto end;
			}
			index = find_ctx_type_idx(tmp);
			if (index < 0) {
				ERR("Unknown context type %s", tmp);
				goto end;
			}
			type->opt = &ctx_opts[index];
			if (type->opt->ctx_type == -1) {
				ERR("Unknown context type %s", tmp);
			} else {
				cds_list_add(&type->list, &ctx_type_list.head);
			}
			free(tmp);
			break;
		case OPT_USERSPACE:
			opt_userspace = 1;
			opt_cmd_name = poptGetOptArg(pc);
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = -1;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	ret = add_context(session_name);

	/* Cleanup allocated memory */
	cds_list_for_each_entry_safe(type, tmptype, &ctx_type_list.head, list) {
		free(type);
	}

end:
	return ret;
}
