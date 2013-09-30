/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
	{"syscall",        0,   POPT_ARG_NONE, 0, OPT_SYSCALL, 0, 0},
#endif
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng calibrate [-k|-u] [OPTIONS]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "      --list-options       Simple listing of options\n");
	fprintf(ofp, "  -k, --kernel             Apply to the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace          Apply to the user-space tracer\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Calibrate options:\n");
	fprintf(ofp, "    --function             Dynamic function entry/return probe (default)\n");
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
#endif
	fprintf(ofp, "\n");
}

/*
 * Calibrate LTTng.
 *
 * Returns a CMD_* error.
 */
static int calibrate_lttng(void)
{
	int ret = CMD_SUCCESS;
	struct lttng_domain dom;
	struct lttng_calibrate calibrate;

	memset(&dom, 0, sizeof(dom));
	memset(&calibrate, 0, sizeof(calibrate));

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else {
		print_missing_domain();
		ret = CMD_ERROR;
		goto error;
	}

	handle = lttng_create_handle(NULL, &dom);
	if (handle == NULL) {
		ret = CMD_ERROR;
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
			ERR("%s", lttng_strerror(ret));
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

	ret = CMD_SUCCESS;

error:
	lttng_destroy_handle(handle);

	return ret;
}

/*
 * Calibrate LTTng tracer.
 *
 * Returns a CMD_* error.
 */
int cmd_calibrate(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	/* Default event type */
	opt_event_type = LTTNG_EVENT_FUNCTION;

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
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
			goto end;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = calibrate_lttng();

end:
	poptFreeContext(pc);
	return ret;
}
