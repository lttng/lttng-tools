/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <inttypes.h>
#include <ctype.h>

#include "../command.h"

static int opt_event_type;
static char *opt_kernel;
static int opt_userspace;
#if 0
/* Not implemented yet */
static char *opt_cmd_name;
static pid_t opt_pid;
#endif

enum {
	OPT_HELP = 1,
	OPT_TRACEPOINT,
	OPT_MARKER,
	OPT_PROBE,
	OPT_FUNCTION,
	OPT_FUNCTION_ENTRY,
	OPT_SYSCALL,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
};

static struct lttng_handle *handle;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
#if 0
	/* Not implemented yet */
	{"userspace",      'u', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_cmd_name, OPT_USERSPACE, 0, 0},
	{"pid",            'p', POPT_ARG_INT, &opt_pid, 0, 0, 0},
	{"tracepoint",     0,   POPT_ARG_NONE, 0, OPT_TRACEPOINT, 0, 0},
	{"marker",         0,   POPT_ARG_NONE, 0, OPT_MARKER, 0, 0},
	{"probe",          0,   POPT_ARG_NONE, 0, OPT_PROBE, 0, 0},
#else
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
	{"function",       0,   POPT_ARG_NONE, 0, OPT_FUNCTION, 0, 0},
#endif
#if 0
	/*
	 * Removed from options to discourage its use. Not in kernel
	 * tracer anymore.
	 */
	{"function:entry", 0,   POPT_ARG_NONE, 0, OPT_FUNCTION_ENTRY, 0, 0},
#endif
	{"syscall",        0,   POPT_ARG_NONE, 0, OPT_SYSCALL, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng calibrate [options] [calibrate_options]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "      --list-options       Simple listing of options\n");
	fprintf(ofp, "  -k, --kernel             Apply for the kernel tracer\n");
#if 0
	fprintf(ofp, "  -u, --userspace [CMD]    Apply for the user-space tracer\n");
	fprintf(ofp, "                           If no CMD, the domain used is UST global\n");
	fprintf(ofp, "                           or else the domain is UST EXEC_NAME\n");
	fprintf(ofp, "  -p, --pid PID            If -u, apply to specific PID (domain: UST PID)\n");
#else
	fprintf(ofp, "  -u, --userspace          Apply for the user-space tracer\n");
#endif
	fprintf(ofp, "\n");
	fprintf(ofp, "Calibrate options:\n");
#if 0
	fprintf(ofp, "    --tracepoint           Tracepoint event (default)\n");
	fprintf(ofp, "    --probe\n");
	fprintf(ofp, "                           Dynamic probe.\n");
#if 0
	fprintf(ofp, "    --function:entry symbol\n");
	fprintf(ofp, "                           Function tracer event\n");
#endif
	fprintf(ofp, "    --syscall              System call eventl\n");
	fprintf(ofp, "    --marker               User-space marker (deprecated)\n");
#else
	fprintf(ofp, "    --function             Dynamic function entry/return probe (default)\n");
#endif
	fprintf(ofp, "\n");
}

/*
 *  calibrate_lttng
 *
 *  Calibrate LTTng.
 */
static int calibrate_lttng(void)
{
	int ret = CMD_SUCCESS;
	struct lttng_domain dom;
	struct lttng_calibrate calibrate;

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else {
		ERR("Please specify a tracer (-k/--kernel or -u/--userspace)");
		ret = CMD_UNDEFINED;
		goto error;
	}

	handle = lttng_create_handle(NULL, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	switch (opt_event_type) {
	case LTTNG_EVENT_TRACEPOINT:
		DBG("Calibrating kernel tracepoints");
		break;
	case LTTNG_EVENT_PROBE:
		DBG("Calibrating kernel probes");
		break;
	case LTTNG_EVENT_FUNCTION:
		DBG("Calibrating kernel functions");
		calibrate.type = LTTNG_CALIBRATE_FUNCTION;
		ret = lttng_calibrate(handle, &calibrate);
		if (ret < 0) {
			goto error;
		}
		MSG("%s calibration done", opt_kernel ? "Kernel" : "UST");
		break;
	case LTTNG_EVENT_FUNCTION_ENTRY:
		DBG("Calibrating kernel function entry");
		break;
	case LTTNG_EVENT_SYSCALL:
		DBG("Calibrating kernel syscall");
		break;
	default:
		ret = CMD_UNDEFINED;
		goto error;
	}

error:
	lttng_destroy_handle(handle);

	return ret;
}

/*
 *  cmd_calibrate
 *
 *  Calibrate LTTng tracer.
 */
int cmd_calibrate(int argc, const char **argv)
{
	int opt, ret;
	static poptContext pc;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	/* Default event type */
	opt_event_type = LTTNG_EVENT_FUNCTION;

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stderr);
			ret = CMD_SUCCESS;
			goto end;
		case OPT_TRACEPOINT:
			ret = CMD_UNDEFINED;
			goto end;
		case OPT_MARKER:
			ret = CMD_UNDEFINED;
			goto end;
		case OPT_PROBE:
			ret = CMD_UNDEFINED;
			break;
		case OPT_FUNCTION:
			opt_event_type = LTTNG_EVENT_FUNCTION;
			break;
		case OPT_FUNCTION_ENTRY:
			ret = CMD_UNDEFINED;
			goto end;
		case OPT_SYSCALL:
			ret = CMD_UNDEFINED;
			goto end;
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			ret = CMD_SUCCESS;
			goto end;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = calibrate_lttng();

end:
	return ret;
}
