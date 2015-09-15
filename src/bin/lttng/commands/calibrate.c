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
#define _LGPL_SOURCE
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>
#include <assert.h>

#include <common/mi-lttng.h>

#include "../command.h"

static int opt_event_type;
static int opt_kernel;
static int opt_userspace;

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
static struct mi_writer *writer;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
	{"function",       0,   POPT_ARG_NONE, 0, OPT_FUNCTION, 0, 0},
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
		assert(0);
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

	if (lttng_opt_mi) {
		assert(writer);
		ret = mi_lttng_calibrate(writer, &calibrate);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

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
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
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

	ret = print_missing_or_multiple_domains(opt_kernel + opt_userspace);

	if (ret) {
		ret = CMD_ERROR;
		goto end;
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
				mi_lttng_element_command_calibrate);
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

	command_ret = calibrate_lttng();
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
	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : -LTTNG_ERR_MI_IO_FAIL;
	}

	/* Overwrite ret if an error occurred during calibrate_lttng() */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
