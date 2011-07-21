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

static char *opt_event_name;
static char *opt_channel_name;
static char *opt_session_name;
static int *opt_kernel;
static int opt_pid_all;
static int opt_userspace;
static char *opt_perf_type;
static char *opt_perf_id;
static pid_t opt_pid;

enum {
	OPT_HELP = 1,
	OPT_TYPE,
};

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
};

enum perf_count_hard {
	PERF_COUNT_HW_CPU_CYCLES          = 0,
	PERF_COUNT_HW_INSTRUCTIONS        = 1,
	PERF_COUNT_HW_CACHE_REFERENCES    = 2,
	PERF_COUNT_HW_CACHE_MISSES        = 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4,
	PERF_COUNT_HW_BRANCH_MISSES       = 5,
	PERF_COUNT_HW_BUS_CYCLES          = 6,
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

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"channel",        'c', POPT_ARG_STRING, &opt_channel_name, 0, 0, 0},
	{"event",          'e', POPT_ARG_STRING, &opt_event_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_VAL, &opt_userspace, 1, 0, 0},
	{"all",            0,   POPT_ARG_VAL, &opt_pid_all, 1, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
	{"type",           't', POPT_ARG_STRING, 0, OPT_TYPE, 0, 0},
	{"perf-type",      0,   POPT_ARG_STRING, &opt_perf_type, 0, 0, 0},
	{"perf-id",        0,   POPT_ARG_STRING, &opt_perf_id, 0, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * Context type for command line option parsing.
 */
struct ctx_type {
	int type;
	struct cds_list_head list;
};

/*
 * Perf counter type
 */
static struct ctx_perf_type {
	enum perf_type value;
	char *symbol;
} ctx_perf_type[] = {
	{ PERF_TYPE_HARDWARE, "hw" },
	{ PERF_TYPE_SOFTWARE, "sw" },
};

/*
 * Perf counter IDs
 */
static struct ctx_perf {
	enum perf_type type;
	union {
		enum perf_count_hard hard;
		enum perf_count_soft soft;
	} id;
	char *symbol;
} ctx_perf[] = {
	/* Hardware counter */
	{ PERF_TYPE_HARDWARE, .id.hard = PERF_COUNT_HW_CPU_CYCLES, "cpu_cycles" },
	{ PERF_TYPE_HARDWARE, .id.hard = PERF_COUNT_HW_INSTRUCTIONS, "instr" },
	{ PERF_TYPE_HARDWARE, .id.hard = PERF_COUNT_HW_CACHE_REFERENCES, "cache_refs" },
	{ PERF_TYPE_HARDWARE, .id.hard = PERF_COUNT_HW_CACHE_MISSES, "cache_miss" },
	{ PERF_TYPE_HARDWARE, .id.hard = PERF_COUNT_HW_BRANCH_INSTRUCTIONS, "branch_instr" },
	{ PERF_TYPE_HARDWARE, .id.hard = PERF_COUNT_HW_BRANCH_MISSES, "branch_miss" },
	{ PERF_TYPE_HARDWARE, .id.hard = PERF_COUNT_HW_BUS_CYCLES, "bus_cycles" },
	/* Sofware counter */
	{ PERF_TYPE_SOFTWARE, .id.soft = PERF_COUNT_SW_CPU_CLOCK, "cpu_clock" },
	{ PERF_TYPE_SOFTWARE, .id.soft = PERF_COUNT_SW_TASK_CLOCK, "task_clock" },
	{ PERF_TYPE_SOFTWARE, .id.soft = PERF_COUNT_SW_PAGE_FAULTS, "page_faults" },
	{ PERF_TYPE_SOFTWARE, .id.soft = PERF_COUNT_SW_CONTEXT_SWITCHES, "ctx_switches" },
	{ PERF_TYPE_SOFTWARE, .id.soft = PERF_COUNT_SW_CPU_MIGRATIONS, "cpu_migration" },
	{ PERF_TYPE_SOFTWARE, .id.soft = PERF_COUNT_SW_PAGE_FAULTS_MIN, "page_faults_minor" },
	{ PERF_TYPE_SOFTWARE, .id.soft = PERF_COUNT_SW_PAGE_FAULTS_MAJ, "page_faults_major" },
	{ PERF_TYPE_SOFTWARE, .id.soft = PERF_COUNT_SW_ALIGNMENT_FAULTS, "align_faults" },
	{ PERF_TYPE_SOFTWARE, .id.soft = PERF_COUNT_SW_EMULATION_FAULTS, "emu_faults" },
	/* Closure */
	{ -1, .id.hard = -1 , NULL },
};

/*
 * Context options
 */
static struct ctx_opts {
	enum context_type value;
	char *symbol;
} ctx_opts[] = {
	{ CONTEXT_PID, "pid" },
	{ CONTEXT_PERF_COUNTER, "perf" },
	{ CONTEXT_COMM, "comm" },
	{ CONTEXT_PRIO, "prio" },
	{ CONTEXT_NICE, "nice" },
	{ CONTEXT_VPID, "vpid" },
	{ CONTEXT_TID, "tid" },
	{ CONTEXT_VTID, "vtid" },
	{ CONTEXT_PPID, "ppid" },
	{ CONTEXT_VPPID, "vppid" },
	{ -1, NULL },		/* Closure */
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
 * Pretty print perf type.
 */
static void print_perf_type(FILE *ofp)
{
	fprintf(ofp, "                               ");
	fprintf(ofp, "%s = %d, ", ctx_perf_type[0].symbol, ctx_perf_type[0].value);
	fprintf(ofp, "%s = %d\n", ctx_perf_type[1].symbol, ctx_perf_type[1].value);
}

/*
 * Pretty print context type.
 */
static void print_ctx_type(FILE *ofp)
{
	int i = 0;

	fprintf(ofp, "                               ");
	while (ctx_opts[i].symbol != NULL) {
		fprintf(ofp, "%s = %d, ", ctx_opts[i].symbol, ctx_opts[i].value);
		i++;
		if (!(i%3)) {
			fprintf(ofp, "\n                               ");
		}
	}
}

/*
 * Pretty print perf hardware counter.
 */
static void print_perf_hw(FILE *ofp)
{
	int i = 0, count = 0;

	fprintf(ofp, "                               ");
	while (ctx_perf[i].symbol != NULL) {
		if (ctx_perf[i].type == PERF_TYPE_HARDWARE) {
			fprintf(ofp, "%s = %d, ", ctx_perf[i].symbol, ctx_perf[i].id.hard);
			count++;
			if (!(count % 3)) {
				fprintf(ofp, "\n                               ");
			}
		}
		i++;
	}
	fprintf(ofp, "\n");
}

/*
 * Pretty print perf software counter.
 */
static void print_perf_sw(FILE *ofp)
{
	int i = 0, count = 0;

	fprintf(ofp, "                               ");
	while (ctx_perf[i].symbol != NULL) {
		if (ctx_perf[i].type == PERF_TYPE_SOFTWARE) {
			fprintf(ofp, "%s = %d, ", ctx_perf[i].symbol, ctx_perf[i].id.soft);
			count++;
			if (!(count % 3)) {
				fprintf(ofp, "\n                               ");
			}
		}
		i++;
	}
	fprintf(ofp, "\n");
}

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng add-context -t TYPE [options] [context_options]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "If no event name is given (-e), the context will be added to "
			"all events in the channel.\n");
	fprintf(ofp, "If no channel and no event is given (-c/-e), the context "
			"will be added to all events in all channels\n");
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
	fprintf(ofp, "  -t, --type TYPE          Context type. You can repeat that option on the command line.\n");
	fprintf(ofp, "                           TYPE can be a digit or a string below:\n");
	print_ctx_type(ofp);
	fprintf(ofp, "\n");
	fprintf(ofp, "Context options:\n");
	fprintf(ofp, "      --perf-type TYPE     Perf event type. TYPE can be a digit or a string below:\n");
	print_perf_type(ofp);
	fprintf(ofp, "      --perf-id ID         Perf event id. ID can be a digit or a string below:\n");
	fprintf(ofp, "                           Hardware IDs (%s: %d):\n", ctx_perf_type[0].symbol, ctx_perf_type[0].value);
	print_perf_hw(ofp);
	fprintf(ofp, "                           Software IDs (%s: %d):\n", ctx_perf_type[1].symbol, ctx_perf_type[1].value);
	print_perf_sw(ofp);
	fprintf(ofp, "Example:\n");
	fprintf(ofp, "This command will add the context information 'prio' and a perf counter hardware branch miss to\n"
			"the 'sys_enter' event in the trace data output.\n");
	fprintf(ofp, "# lttng add-context -k -e sys_enter -t prio -t perf --perf-type hw --perf-id branch_miss\n");
	fprintf(ofp, "\n");
}

/*
 * Return perf hardware counter index.
 */
static int find_perf_idx(const char *opt)
{
	int ret = -1, i = 0;

	while (ctx_perf[i].symbol != NULL) {
		if (strcmp(opt, ctx_perf[i].symbol) == 0) {
			ret = i;
			goto end;
		}
		i++;
	}

end:
	return ret;
}

/*
 * Return perf type index in global array.
 */
static int find_perf_type_idx(const char *opt)
{
	int ret = -1, i = 0;

	while (ctx_perf_type[i].symbol != NULL) {
		if (strcmp(opt, ctx_perf_type[i].symbol) == 0) {
			ret = i;
			goto end;
		}
		i++;
	}

end:
	return ret;
}

/*
 * Return perf counter index
 */
static int find_perf_symbol_idx(int type, int id)
{
	int ret = -1, i = 0;

	while (ctx_perf[i].symbol != NULL) {
		if (ctx_perf[i].type == type) {
			switch (type) {
			case PERF_TYPE_HARDWARE:
				if (ctx_perf[i].id.hard == id) {
					ret = i;
					goto end;
				}
				break;
			case PERF_TYPE_SOFTWARE:
				if (ctx_perf[i].id.soft == id) {
					ret = i;
					goto end;
				}
				break;
			}
		}
		i++;
	}

end:
	return ret;
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
 * Return context symbol index
 */
static int find_ctx_symbol_idx(int type)
{
	int ret = -1, i = 0;

	while (ctx_opts[i].symbol != NULL) {
		if (type == ctx_opts[i].value) {
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
static int add_context(void)
{
	int ret = CMD_SUCCESS, index;
	struct lttng_event_context context;
	struct lttng_domain dom;
	struct ctx_type *type;

	if (set_session_name(opt_session_name) < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	/* Iterate over all context type given */
	cds_list_for_each_entry(type, &ctx_type_list.head, list) {
		context.ctx = type->type;
		if (type->type == LTTNG_KERNEL_CONTEXT_PERF_COUNTER) {
			/* Check perf type */
			if (isdigit(*opt_perf_type)) {
				context.u.perf_counter.type = atoi(opt_perf_type);
			} else {
				index = find_perf_type_idx(opt_perf_type);
				if (index == -1) {
					ERR("Bad event type given. Please use --perf-type TYPE.");
					goto error;
				}
				context.u.perf_counter.type = ctx_perf_type[index].value;
			}

			/* Check perf counter ID */
			if (isdigit(*opt_perf_id)) {
				context.u.perf_counter.config = atoi(opt_perf_id);
				index = find_perf_symbol_idx(context.u.perf_counter.type,
						context.u.perf_counter.config);
			} else {
				index = find_perf_idx(opt_perf_id);
				switch (context.u.perf_counter.type) {
				case PERF_TYPE_HARDWARE:
					context.u.perf_counter.config = ctx_perf[index].id.hard;
					break;
				case PERF_TYPE_SOFTWARE:
					context.u.perf_counter.config = ctx_perf[index].id.soft;
					break;
				}
			}

			if (index == -1) {
				ERR("Bad perf event id given. Please use --perf-id ID.");
				goto error;
			}

			strncpy(context.u.perf_counter.name, ctx_perf[index].symbol,
					LTTNG_SYMBOL_NAME_LEN);
		}

		if (opt_kernel) {
			/* Create kernel domain */
			dom.type = LTTNG_DOMAIN_KERNEL;

			DBG("Adding kernel context");
			ret = lttng_add_context(&dom, &context, opt_event_name,
					opt_channel_name);
			if (ret < 0) {
				goto error;
			} else {
				if (type->type == LTTNG_KERNEL_CONTEXT_PERF_COUNTER) {
					MSG("Perf counter %s added", context.u.perf_counter.name);
				} else {
					index = find_ctx_symbol_idx(type->type);
					MSG("Kernel context %s added", ctx_opts[index].symbol);
				}
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
			ERR("Please specify a tracer (kernel or user-space)");
			goto error;
		}
	}

error:
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
	struct ctx_type *type;

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
			/* Numerical value are allowed also */
			if (isdigit(*tmp)) {
				type->type = atoi(tmp);
			} else {
				index = find_ctx_type_idx(tmp);
				if (index < 0) {
					ERR("Unknown context type %s", tmp);
					goto end;
				}
				type->type = ctx_opts[index].value;
			}
			if (type->type == -1) {
				ERR("Unknown context type %s", tmp);
			} else {
				cds_list_add(&type->list, &ctx_type_list.head);
			}
			free(tmp);
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = add_context();

	/* Cleanup allocated memory */
	cds_list_for_each_entry(type, &ctx_type_list.head, list) {
		free(type);
	}

end:
	return ret;
}
