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
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>

#include "../command.h"

#include <src/common/sessiond-comm/sessiond-comm.h>
#include <src/common/utils.h>

static char *opt_channels;
static int opt_kernel;
static char *opt_session_name;
static int opt_userspace;
static struct lttng_channel chan;
static char *opt_output;
static int opt_buffer_uid;
static int opt_buffer_pid;
static int opt_buffer_global;

enum {
	OPT_HELP = 1,
	OPT_DISCARD,
	OPT_OVERWRITE,
	OPT_SUBBUF_SIZE,
	OPT_NUM_SUBBUF,
	OPT_SWITCH_TIMER,
	OPT_READ_TIMER,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
	OPT_TRACEFILE_SIZE,
	OPT_TRACEFILE_COUNT,
};

static struct lttng_handle *handle;

const char *output_mmap = "mmap";
const char *output_splice = "splice";

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",           'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",        's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"kernel",         'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0},
	{"userspace",      'u', POPT_ARG_NONE, 0, OPT_USERSPACE, 0, 0},
	{"discard",        0,   POPT_ARG_NONE, 0, OPT_DISCARD, 0, 0},
	{"overwrite",      0,   POPT_ARG_NONE, 0, OPT_OVERWRITE, 0, 0},
	{"subbuf-size",    0,   POPT_ARG_STRING, 0, OPT_SUBBUF_SIZE, 0, 0},
	{"num-subbuf",     0,   POPT_ARG_INT, 0, OPT_NUM_SUBBUF, 0, 0},
	{"switch-timer",   0,   POPT_ARG_INT, 0, OPT_SWITCH_TIMER, 0, 0},
	{"read-timer",     0,   POPT_ARG_INT, 0, OPT_READ_TIMER, 0, 0},
	{"list-options",   0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"output",         0,   POPT_ARG_STRING, &opt_output, 0, 0, 0},
	{"buffers-uid",    0,	POPT_ARG_VAL, &opt_buffer_uid, 1, 0, 0},
	{"buffers-pid",    0,	POPT_ARG_VAL, &opt_buffer_pid, 1, 0, 0},
	{"buffers-global", 0,	POPT_ARG_VAL, &opt_buffer_global, 1, 0, 0},
	{"tracefile-size", 'C',   POPT_ARG_INT, 0, OPT_TRACEFILE_SIZE, 0, 0},
	{"tracefile-count", 'W',   POPT_ARG_INT, 0, OPT_TRACEFILE_COUNT, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng enable-channel NAME[,NAME2,...] [-u|-k] [OPTIONS]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help               Show this help\n");
	fprintf(ofp, "      --list-options       Simple listing of options\n");
	fprintf(ofp, "  -s, --session NAME       Apply to session name\n");
	fprintf(ofp, "  -k, --kernel             Apply to the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace          Apply to the user-space tracer\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Channel options:\n");
	fprintf(ofp, "      --discard            Discard event when buffers are full%s\n",
		DEFAULT_CHANNEL_OVERWRITE ? "" : " (default)");
	fprintf(ofp, "      --overwrite          Flight recorder mode%s\n",
		DEFAULT_CHANNEL_OVERWRITE ? " (default)" : "");
	fprintf(ofp, "      --subbuf-size SIZE   Subbuffer size in bytes {+k,+M,+G}\n");
	fprintf(ofp, "                               (default: %zu, kernel default: %zu)\n",
		default_get_channel_subbuf_size(),
		default_get_kernel_channel_subbuf_size());
	fprintf(ofp, "                               Needs to be a power of 2 for\n");
        fprintf(ofp, "                               kernel and ust tracers\n");
	fprintf(ofp, "      --num-subbuf NUM     Number of subbufers\n");
	fprintf(ofp, "                               (default: %u)\n",
		DEFAULT_CHANNEL_SUBBUF_NUM);
	fprintf(ofp, "                               Needs to be a power of 2 for\n");
        fprintf(ofp, "                               kernel and ust tracers\n");
	fprintf(ofp, "      --switch-timer USEC  Switch timer interval in usec (default: %u)\n",
		DEFAULT_CHANNEL_SWITCH_TIMER);
	fprintf(ofp, "      --read-timer USEC    Read timer interval in usec (UST default: %u, kernel default: %u)\n",
		DEFAULT_UST_CHANNEL_READ_TIMER, DEFAULT_KERNEL_CHANNEL_READ_TIMER);
	fprintf(ofp, "      --output TYPE        Channel output type (Values: %s, %s)\n",
			output_mmap, output_splice);
	fprintf(ofp, "      --buffers-uid        Use per UID buffer (-u only)\n");
	fprintf(ofp, "      --buffers-pid        Use per PID buffer (-u only)\n");
	fprintf(ofp, "      --buffers-global     Use shared buffer for the whole system (-k only)\n");
	fprintf(ofp, "  -C, --tracefile-size SIZE\n");
	fprintf(ofp, "                           Maximum size of each tracefile within a stream (in bytes).\n");
	fprintf(ofp, "  -W, --tracefile-count COUNT\n");
	fprintf(ofp, "                           Used in conjunction with -C option, this will limit the number\n");
	fprintf(ofp, "                           of files created to the specified count.\n");
	fprintf(ofp, "\n");
}

/*
 * Set default attributes depending on those already defined from the command
 * line.
 */
static void set_default_attr(struct lttng_domain *dom)
{
	struct lttng_channel_attr default_attr;

	/* Set attributes */
	lttng_channel_set_default_attr(dom, &default_attr);

	if (chan.attr.overwrite == -1) {
		chan.attr.overwrite = default_attr.overwrite;
	}
	if (chan.attr.subbuf_size == -1) {
		chan.attr.subbuf_size = default_attr.subbuf_size;
	}
	if (chan.attr.num_subbuf == -1) {
		chan.attr.num_subbuf = default_attr.num_subbuf;
	}
	if (chan.attr.switch_timer_interval == -1) {
		chan.attr.switch_timer_interval = default_attr.switch_timer_interval;
	}
	if (chan.attr.read_timer_interval == -1) {
		chan.attr.read_timer_interval = default_attr.read_timer_interval;
	}
	if (chan.attr.output == -1) {
		chan.attr.output = default_attr.output;
	}
	if (chan.attr.tracefile_count == -1) {
		chan.attr.tracefile_count = default_attr.tracefile_count;
	}
	if (chan.attr.tracefile_size == -1) {
		chan.attr.tracefile_size = default_attr.tracefile_size;
	}
}

/*
 * Adding channel using the lttng API.
 */
static int enable_channel(char *session_name)
{
	int ret = CMD_SUCCESS, warn = 0;
	char *channel_name;
	struct lttng_domain dom;

	memset(&dom, 0, sizeof(dom));

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
		dom.buf_type = LTTNG_BUFFER_GLOBAL;
		if (opt_buffer_uid || opt_buffer_pid) {
			ERR("Buffer type not supported for domain -k");
			ret = CMD_ERROR;
			goto error;
		}
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
		if (opt_buffer_uid) {
			dom.buf_type = LTTNG_BUFFER_PER_UID;
		} else {
			if (opt_buffer_global) {
				ERR("Buffer type not supported for domain -u");
				ret = CMD_ERROR;
				goto error;
			}
			dom.buf_type = LTTNG_BUFFER_PER_PID;
		}
	} else {
		ERR("Please specify a tracer (-k/--kernel or -u/--userspace)");
		ret = CMD_ERROR;
		goto error;
	}

	set_default_attr(&dom);

	if ((chan.attr.tracefile_size > 0) &&
			(chan.attr.tracefile_size < chan.attr.subbuf_size)) {
		ERR("Tracefile_size must be greater than or equal to subbuf_size "
				"(%" PRIu64 " < %" PRIu64 ")",
				chan.attr.tracefile_size, chan.attr.subbuf_size);
		ret = CMD_ERROR;
		goto error;
	}

	/* Setting channel output */
	if (opt_output) {
		if (!strncmp(output_mmap, opt_output, strlen(output_mmap))) {
			chan.attr.output = LTTNG_EVENT_MMAP;
		} else if (!strncmp(output_splice, opt_output, strlen(output_splice))) {
			chan.attr.output = LTTNG_EVENT_SPLICE;
		} else {
			ERR("Unknown output type %s. Possible values are: %s, %s\n",
					opt_output, output_mmap, output_splice);
			usage(stderr);
			ret = CMD_ERROR;
			goto error;
		}
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	/* Strip channel list (format: chan1,chan2,...) */
	channel_name = strtok(opt_channels, ",");
	while (channel_name != NULL) {
		/* Copy channel name and normalize it */
		strncpy(chan.name, channel_name, NAME_MAX);
		chan.name[NAME_MAX - 1] = '\0';

		DBG("Enabling channel %s", channel_name);

		ret = lttng_enable_channel(handle, &chan);
		if (ret < 0) {
			switch (-ret) {
			case LTTNG_ERR_KERN_CHAN_EXIST:
			case LTTNG_ERR_UST_CHAN_EXIST:
				WARN("Channel %s: %s (session %s)", channel_name,
						lttng_strerror(ret), session_name);
				goto error;
			default:
				ERR("Channel %s: %s (session %s)", channel_name,
						lttng_strerror(ret), session_name);
				break;
			}
			warn = 1;
		} else {
			MSG("%s channel %s enabled for session %s",
					opt_kernel ? "Kernel" : "UST", channel_name,
					session_name);
		}

		/* Next event */
		channel_name = strtok(NULL, ",");
	}

	ret = CMD_SUCCESS;

error:
	if (warn) {
		ret = CMD_WARNING;
	}

	lttng_destroy_handle(handle);

	return ret;
}

/*
 * Default value for channel configuration.
 */
static void init_channel_config(void)
{
	/*
	 * Put -1 everywhere so we can identify those set by the command line and
	 * those needed to be set by the default values.
	 */
	memset(&chan.attr, -1, sizeof(chan.attr));
}

/*
 * Add channel to trace session
 */
int cmd_enable_channels(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;
	char *session_name = NULL;
	char *opt_arg = NULL;

	init_channel_config();

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
			goto end;
		case OPT_DISCARD:
			chan.attr.overwrite = 0;
			DBG("Channel set to discard");
			break;
		case OPT_OVERWRITE:
			chan.attr.overwrite = 1;
			DBG("Channel set to overwrite");
			break;
		case OPT_SUBBUF_SIZE:
			/* Parse the size */
			opt_arg = poptGetOptArg(pc);
			if (utils_parse_size_suffix(opt_arg, &chan.attr.subbuf_size) < 0) {
				ERR("Wrong value the --subbuf-size parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			/* Check if power of 2 */
			if ((chan.attr.subbuf_size - 1) & chan.attr.subbuf_size) {
				ERR("The subbuf size is not a power of 2: %" PRIu64 " (%s)",
						chan.attr.subbuf_size, opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			DBG("Channel subbuf size set to %" PRIu64, chan.attr.subbuf_size);
			break;
		case OPT_NUM_SUBBUF:
			/* TODO Replace atoi with strtol and check for errors */
			chan.attr.num_subbuf = atoi(poptGetOptArg(pc));
			DBG("Channel subbuf num set to %" PRIu64, chan.attr.num_subbuf);
			break;
		case OPT_SWITCH_TIMER:
			/* TODO Replace atoi with strtol and check for errors */
			chan.attr.switch_timer_interval = atoi(poptGetOptArg(pc));
			DBG("Channel switch timer interval set to %d", chan.attr.switch_timer_interval);
			break;
		case OPT_READ_TIMER:
			/* TODO Replace atoi with strtol and check for errors */
			chan.attr.read_timer_interval = atoi(poptGetOptArg(pc));
			DBG("Channel read timer interval set to %d", chan.attr.read_timer_interval);
			break;
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_TRACEFILE_SIZE:
			chan.attr.tracefile_size = atoll(poptGetOptArg(pc));
			DBG("Maximum tracefile size set to %" PRIu64,
					chan.attr.tracefile_size);
			break;
		case OPT_TRACEFILE_COUNT:
			chan.attr.tracefile_count = atoll(poptGetOptArg(pc));
			DBG("Maximum tracefile count set to %" PRIu64,
					chan.attr.tracefile_count);
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

	opt_channels = (char*) poptGetArg(pc);
	if (opt_channels == NULL) {
		ERR("Missing channel name.\n");
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

	ret = enable_channel(session_name);

end:
	if (!opt_session_name && session_name) {
		free(session_name);
	}
	poptFreeContext(pc);
	return ret;
}
