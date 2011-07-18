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
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "cmd.h"
#include "conf.h"
#include "utils.h"

static char *opt_event_name;
static char *opt_channel_name;
static char *opt_perf_name;
static char *opt_session_name;
static int *opt_kernel;
static int opt_pid_all;
static int opt_userspace;
static int opt_perf_type;
static int opt_perf_id;
static pid_t opt_pid;

enum {
	OPT_HELP = 1,
	OPT_TYPE,
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
	{"type",           't', POPT_ARG_INT, 0, OPT_TYPE, 0, 0},
	{"perf-name",      0,   POPT_ARG_STRING, &opt_perf_name, 0, 0, 0},
	{"perf-type",      0,   POPT_ARG_INT, &opt_perf_type, 0, 0, 0},
	{"perf-id",        0,   POPT_ARG_INT, &opt_perf_id, 0, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng add-context [options] [context_options]\n");
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
	fprintf(ofp, "  -t, --type TYPE          Context type. TYPE must be a numerical value:\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_PID = 0\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_PERF_COUNTER = 1\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_COMM = 2\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_PRIO = 3\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_NICE = 4\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_VPID = 5\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_TID = 6\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_VTID = 7\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_PPID = 8\n");
	fprintf(ofp, "                             KERNEL_CONTEXT_VPPID = 9\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Context options:\n");
	fprintf(ofp, "      --perf-name NAME     Perf event name\n");
	fprintf(ofp, "      --perf-type TYPE     Perf event type. TYPE must be a numeric value:\n");
	fprintf(ofp, "                             PERF_TYPE_HARDWARE = 0\n");
	fprintf(ofp, "                             PERF_TYPE_SOFTWARE = 1\n");
	fprintf(ofp, "      --perf-id ID         Perf event id. ID must be a numeric value:\n");
	fprintf(ofp, "                           Hardware IDs (0):\n");
	fprintf(ofp, "                             PERF_COUNT_HW_CPU_CYCLES = 0\n");
	fprintf(ofp, "                             PERF_COUNT_HW_INSTRUCTIONS = 1\n");
	fprintf(ofp, "                             PERF_COUNT_HW_CACHE_REFERENCES = 2\n");
	fprintf(ofp, "                             PERF_COUNT_HW_CACHE_MISSES = 3\n");
	fprintf(ofp, "                             PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4\n");
	fprintf(ofp, "                             PERF_COUNT_HW_BRANCH_MISSES = 5\n");
	fprintf(ofp, "                             PERF_COUNT_HW_BUS_CYCLES = 6\n");
	fprintf(ofp, "                           Software IDs (1):\n");
	fprintf(ofp, "                             PERF_COUNT_SW_CPU_CLOCK = 0\n");
	fprintf(ofp, "                             PERF_COUNT_SW_TASK_CLOCK = 1\n");
	fprintf(ofp, "                             PERF_COUNT_SW_PAGE_FAULTS = 2\n");
	fprintf(ofp, "                             PERF_COUNT_SW_CONTEXT_SWITCHES = 3\n");
	fprintf(ofp, "                             PERF_COUNT_SW_CPU_MIGRATIONS = 4\n");
	fprintf(ofp, "                             PERF_COUNT_SW_PAGE_FAULTS_MIN = 5\n");
	fprintf(ofp, "                             PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6\n");
	fprintf(ofp, "\n");
}

/*
 *  add_context
 *
 *  Add context to channel or event.
 */
static int add_context(int type)
{
	int ret = CMD_SUCCESS;
	struct lttng_event_context context;
	struct lttng_domain dom;

	if (set_session_name(opt_session_name) < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	context.ctx = type;
	if (type == LTTNG_KERNEL_CONTEXT_PERF_COUNTER) {
		context.u.perf_counter.type = opt_perf_type;
		context.u.perf_counter.config = opt_perf_id;
		strncpy(context.u.perf_counter.name, opt_perf_name,
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
			MSG("Kernel context added");
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

error:
	return ret;
}

/*
 *  cmd_add_context
 *
 *  Add context on channel or event.
 */
int cmd_add_context(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	char *tmp;
	static poptContext pc;

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
			ret = add_context(atoi(tmp));
			if (ret < 0) {
				free(tmp);
				goto end;
			}
			free(tmp);
			break;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

end:
	return ret;
}
