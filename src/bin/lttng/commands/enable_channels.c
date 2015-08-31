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
#define _LGPL_SOURCE
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>
#include <ctype.h>

#include <common/sessiond-comm/sessiond-comm.h>
#include <common/utils.h>
#include <common/mi-lttng.h>

#include "../command.h"
#include "../utils.h"


static char *opt_channels;
static int opt_kernel;
static char *opt_session_name;
static int opt_userspace;
static struct lttng_channel chan;
static char *opt_output;
static int opt_buffer_uid;
static int opt_buffer_pid;
static int opt_buffer_global;

static struct mi_writer *writer;

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
	fprintf(ofp, "Usage: lttng enable-channel <name>[,<name2>,...] (-k | -u) [options]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Domain options:\n");
	fprintf(ofp, "  -k, --kernel               Apply to the kernel tracer\n");
	fprintf(ofp, "  -u, --userspace            Apply to the user space tracer\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Target options:\n");
	fprintf(ofp, "  -s, --session SESSION      Apply to session SESSION\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Mode options:\n");
	fprintf(ofp, "      --discard              Discard event when buffers are full%s\n",
		DEFAULT_CHANNEL_OVERWRITE ? "" : " (default)");
	fprintf(ofp, "      --overwrite            Flight recorder mode (always keep a fixed amount\n");
	fprintf(ofp, "                             of the latest data%s)\n",
		DEFAULT_CHANNEL_OVERWRITE ? "; default" : "");
	fprintf(ofp, "\n");
	fprintf(ofp, "Sub-buffer options:\n");
	fprintf(ofp, "      --subbuf-size SIZE     Set sub-buffer size to SIZE bytes ('k', 'M',\n");
	fprintf(ofp, "                             and 'G' suffixes can be used). Rounded up to the\n");
	fprintf(ofp, "                             next power of 2. Default values:\n");
	fprintf(ofp, "                               UST per-user:    %zu\n",
		default_get_ust_uid_channel_subbuf_size());
	fprintf(ofp, "                               UST per-process: %zu\n",
		default_get_ust_pid_channel_subbuf_size());
	fprintf(ofp, "                               Kernel:          %zu\n",
		default_get_kernel_channel_subbuf_size());
	fprintf(ofp, "                               Metadata:        %zu\n",
		default_get_metadata_subbuf_size());
	fprintf(ofp, "      --num-subbuf NUM       Use NUM sub-buffers. Rounded up to the next power\n");
	fprintf(ofp, "                             of 2. Default values:\n");
	fprintf(ofp, "                               UST per-user:    %u\n",
		DEFAULT_UST_UID_CHANNEL_SUBBUF_NUM);
	fprintf(ofp, "                               UST per-process: %u\n",
		DEFAULT_UST_PID_CHANNEL_SUBBUF_NUM);
	fprintf(ofp, "                               Kernel:          %u\n",
		DEFAULT_KERNEL_CHANNEL_SUBBUF_NUM);
	fprintf(ofp, "                               Metadata:        %u\n",
		DEFAULT_METADATA_SUBBUF_NUM);
	fprintf(ofp, "      --output TYPE          Set channel output type to TYPE\n");
	fprintf(ofp, "                               Available types: %s, %s\n",
		output_mmap, output_splice);
	fprintf(ofp, "                             Default values:\n");
	fprintf(ofp, "                               UST per-user:    %s\n",
		DEFAULT_UST_UID_CHANNEL_OUTPUT == LTTNG_EVENT_MMAP ? output_mmap : output_splice);
	fprintf(ofp, "                               UST per-process: %s\n",
		DEFAULT_UST_PID_CHANNEL_OUTPUT == LTTNG_EVENT_MMAP ? output_mmap : output_splice);
	fprintf(ofp, "                               Kernel:          %s\n",
		DEFAULT_KERNEL_CHANNEL_OUTPUT == LTTNG_EVENT_MMAP ? output_mmap : output_splice);
	fprintf(ofp, "                               Metadata:        %s\n",
		DEFAULT_METADATA_OUTPUT == LTTNG_EVENT_MMAP ? output_mmap : output_splice);
	fprintf(ofp, "\n");
	fprintf(ofp, "Buffering scheme options:\n");
	fprintf(ofp, "      --buffers-global       Use shared buffer for the whole system\n");
	fprintf(ofp, "                             (with -k, --kernel option only)\n");
	fprintf(ofp, "      --buffers-pid          Use per-process buffer\n");
	fprintf(ofp, "                             (with -u, --userspace option only)\n");
	fprintf(ofp, "      --buffers-uid          Use per-user buffer\n");
	fprintf(ofp, "                             (-u, --userspace option only)\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Timer options:\n");
	fprintf(ofp, "      --read-timer USEC      Set read timer period to USEC microseconds. Use 0\n");
	fprintf(ofp, "                             to disable the read timer. Default values:\n");
	fprintf(ofp, "                               UST per-user:    %u\n",
		DEFAULT_UST_UID_CHANNEL_READ_TIMER);
	fprintf(ofp, "                               UST per-process: %u\n",
		DEFAULT_UST_PID_CHANNEL_READ_TIMER);
	fprintf(ofp, "                               Kernel:          %u\n",
		DEFAULT_KERNEL_CHANNEL_READ_TIMER);
	fprintf(ofp, "                               Metadata:        %u\n",
		DEFAULT_METADATA_READ_TIMER);
	fprintf(ofp, "      --switch-timer USEC    Set switch timer period to USEC microseconds.\n");
	fprintf(ofp, "                             Use 0 to disable the switch timer. Default values:\n");
	fprintf(ofp, "                               UST per-user:    %u\n",
		DEFAULT_UST_UID_CHANNEL_SWITCH_TIMER);
	fprintf(ofp, "                               UST per-process: %u\n",
		DEFAULT_UST_PID_CHANNEL_SWITCH_TIMER);
	fprintf(ofp, "                               Kernel:          %u\n",
		DEFAULT_KERNEL_CHANNEL_SWITCH_TIMER);
	fprintf(ofp, "                               Metadata:        %u\n",
		DEFAULT_METADATA_SWITCH_TIMER);
	fprintf(ofp, "\n");
	fprintf(ofp, "Trace file options:\n");
	fprintf(ofp, "  -W, --tracefile-count CNT  Used in conjunction with -C, --tracefile-size\n");
	fprintf(ofp, "                             option, set the trace files limit to CNT (0 means\n");
	fprintf(ofp, "                             unlimited; default: %u)\n",
		DEFAULT_CHANNEL_TRACEFILE_COUNT);
	fprintf(ofp, "  -C, --tracefile-size SIZE  Set maximum size of each trace file within a stream\n");
	fprintf(ofp, "                             to SIZE bytes (0 means unlimited; default: %u).\n",
		DEFAULT_CHANNEL_TRACEFILE_SIZE);
	fprintf(ofp, "                             Note: traces generated with this option may\n");
	fprintf(ofp, "                             inaccurately report discarded events as per\n");
	fprintf(ofp, "                             CTF 1.8.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Help options:\n");
	fprintf(ofp, "  -h, --help                 Show this help\n");
	fprintf(ofp, "      --list-options         List options\n");
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
	if ((int) chan.attr.output == -1) {
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
	int ret = CMD_SUCCESS, warn = 0, error = 0, success = 0;
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
		if (opt_buffer_pid) {
			dom.buf_type = LTTNG_BUFFER_PER_PID;
		} else {
			if (opt_buffer_global) {
				ERR("Buffer type not supported for domain -u");
				ret = CMD_ERROR;
				goto error;
			}
			dom.buf_type = LTTNG_BUFFER_PER_UID;
		}
	} else {
		print_missing_domain_no_agents();
		ret = CMD_ERROR;
		goto error;
	}

	set_default_attr(&dom);

	if (chan.attr.tracefile_size == 0 && chan.attr.tracefile_count) {
		ERR("Missing option --tracefile-size. "
				"A file count without a size won't do anything.");
		ret = CMD_ERROR;
		goto error;
	}

	if ((chan.attr.tracefile_size > 0) &&
			(chan.attr.tracefile_size < chan.attr.subbuf_size)) {
		WARN("Tracefile size rounded up from (%" PRIu64 ") to subbuffer size (%" PRIu64 ")",
				chan.attr.tracefile_size, chan.attr.subbuf_size);
		chan.attr.tracefile_size = chan.attr.subbuf_size;
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

	/* Mi open channels element */
	if (lttng_opt_mi) {
		assert(writer);
		ret = mi_lttng_channels_open(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	/* Strip channel list (format: chan1,chan2,...) */
	channel_name = strtok(opt_channels, ",");
	while (channel_name != NULL) {
		/* Validate channel name's length */
		if (strlen(channel_name) >= NAME_MAX) {
			ERR("Channel name is too long (max. %zu characters)",
					sizeof(chan.name) - 1);
			error = 1;
			goto skip_enable;
		}

		/* Copy channel name */
		strcpy(chan.name, channel_name);

		DBG("Enabling channel %s", channel_name);

		ret = lttng_enable_channel(handle, &chan);
		if (ret < 0) {
			success = 0;
			switch (-ret) {
			case LTTNG_ERR_KERN_CHAN_EXIST:
			case LTTNG_ERR_UST_CHAN_EXIST:
			case LTTNG_ERR_CHAN_EXIST:
				WARN("Channel %s: %s (session %s)", channel_name,
						lttng_strerror(ret), session_name);
				warn = 1;
				break;
			case LTTNG_ERR_INVALID_CHANNEL_NAME:
				ERR("Invalid channel name: \"%s\". "
				    "Channel names may not start with '.', and "
				    "may not contain '/'.", channel_name);
				error = 1;
				break;
			default:
				ERR("Channel %s: %s (session %s)", channel_name,
						lttng_strerror(ret), session_name);
				error = 1;
				break;
			}
		} else {
			MSG("%s channel %s enabled for session %s",
					get_domain_str(dom.type), channel_name, session_name);
			success = 1;
		}

skip_enable:
		if (lttng_opt_mi) {
			/* Mi print the channel element and leave it open */
			ret = mi_lttng_channel(writer, &chan, 1);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* Individual Success ? */
			ret = mi_lttng_writer_write_element_bool(writer,
					mi_lttng_element_command_success, success);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}

			/* Close channel element */
			ret = mi_lttng_writer_close_element(writer);
			if (ret) {
				ret = CMD_ERROR;
				goto error;
			}
		}

		/* Next channel */
		channel_name = strtok(NULL, ",");
	}

	if (lttng_opt_mi) {
		/* Close channels element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	ret = CMD_SUCCESS;

error:
	/* If more important error happen bypass the warning */
	if (!ret && warn) {
		ret = CMD_WARNING;
	}
	/* If more important error happen bypass the warning */
	if (!ret && error) {
		ret = CMD_ERROR;
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
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
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
		{
			uint64_t rounded_size;
			int order;

			/* Parse the size */
			opt_arg = poptGetOptArg(pc);
			if (utils_parse_size_suffix(opt_arg, &chan.attr.subbuf_size) < 0 || !chan.attr.subbuf_size) {
				ERR("Wrong value in --subbuf-size parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			order = get_count_order_u64(chan.attr.subbuf_size);
			assert(order >= 0);
			rounded_size = 1ULL << order;
			if (rounded_size < chan.attr.subbuf_size) {
				ERR("The subbuf size (%" PRIu64 ") is rounded and overflows!",
						chan.attr.subbuf_size);
				ret = CMD_ERROR;
				goto end;
			}

			if (rounded_size != chan.attr.subbuf_size) {
				WARN("The subbuf size (%" PRIu64 ") is rounded to the next power of 2 (%" PRIu64 ")",
						chan.attr.subbuf_size, rounded_size);
				chan.attr.subbuf_size = rounded_size;
			}

			/* Should now be power of 2 */
			assert(!((chan.attr.subbuf_size - 1) & chan.attr.subbuf_size));

			DBG("Channel subbuf size set to %" PRIu64, chan.attr.subbuf_size);
			break;
		}
		case OPT_NUM_SUBBUF:
		{
			uint64_t rounded_size;
			int order;

			errno = 0;
			opt_arg = poptGetOptArg(pc);
			chan.attr.num_subbuf = strtoull(opt_arg, NULL, 0);
			if (errno != 0 || !chan.attr.num_subbuf || !isdigit(opt_arg[0])) {
				ERR("Wrong value in --num-subbuf parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			order = get_count_order_u64(chan.attr.num_subbuf);
			assert(order >= 0);
			rounded_size = 1ULL << order;
			if (rounded_size < chan.attr.num_subbuf) {
				ERR("The number of subbuffers (%" PRIu64 ") is rounded and overflows!",
						chan.attr.num_subbuf);
				ret = CMD_ERROR;
				goto end;
			}

			if (rounded_size != chan.attr.num_subbuf) {
				WARN("The number of subbuffers (%" PRIu64 ") is rounded to the next power of 2 (%" PRIu64 ")",
						chan.attr.num_subbuf, rounded_size);
				chan.attr.num_subbuf = rounded_size;
			}

			/* Should now be power of 2 */
			assert(!((chan.attr.num_subbuf - 1) & chan.attr.num_subbuf));

			DBG("Channel subbuf num set to %" PRIu64, chan.attr.num_subbuf);
			break;
		}
		case OPT_SWITCH_TIMER:
		{
			unsigned long v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);
			v = strtoul(opt_arg, NULL, 0);
			if (errno != 0 || !isdigit(opt_arg[0])) {
				ERR("Wrong value in --switch-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			if (v != (uint32_t) v) {
				ERR("32-bit overflow in --switch-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			chan.attr.switch_timer_interval = (uint32_t) v;
			DBG("Channel switch timer interval set to %d", chan.attr.switch_timer_interval);
			break;
		}
		case OPT_READ_TIMER:
		{
			unsigned long v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);
			v = strtoul(opt_arg, NULL, 0);
			if (errno != 0 || !isdigit(opt_arg[0])) {
				ERR("Wrong value in --read-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			if (v != (uint32_t) v) {
				ERR("32-bit overflow in --read-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			chan.attr.read_timer_interval = (uint32_t) v;
			DBG("Channel read timer interval set to %d", chan.attr.read_timer_interval);
			break;
		}
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_TRACEFILE_SIZE:
			opt_arg = poptGetOptArg(pc);
			if (utils_parse_size_suffix(opt_arg, &chan.attr.tracefile_size) < 0) {
				ERR("Wrong value in --tracefile-size parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			DBG("Maximum tracefile size set to %" PRIu64,
					chan.attr.tracefile_size);
			break;
		case OPT_TRACEFILE_COUNT:
		{
			unsigned long v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);
			v = strtoul(opt_arg, NULL, 0);
			if (errno != 0 || !isdigit(opt_arg[0])) {
				ERR("Wrong value in --tracefile-count parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			if (v != (uint32_t) v) {
				ERR("32-bit overflow in --tracefile-count parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			chan.attr.tracefile_count = (uint32_t) v;
			DBG("Maximum tracefile count set to %" PRIu64,
					chan.attr.tracefile_count);
			break;
		}
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			usage(stderr);
			ret = CMD_UNDEFINED;
			goto end;
		}
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
				mi_lttng_element_command_enable_channels);
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

	opt_channels = (char*) poptGetArg(pc);
	if (opt_channels == NULL) {
		ERR("Missing channel name.\n");
		usage(stderr);
		ret = CMD_ERROR;
		success = 0;
		goto mi_closing;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			command_ret = CMD_ERROR;
			success = 0;
			goto mi_closing;
		}
	} else {
		session_name = opt_session_name;
	}

	command_ret = enable_channel(session_name);
	if (command_ret) {
		success = 0;
	}

mi_closing:
	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close  output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_command_success, success);
		if (ret) {
			goto end;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			goto end;
		}
	}

end:
	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		ret = ret ? ret : LTTNG_ERR_MI_IO_FAIL;
	}

	if (!opt_session_name && session_name) {
		free(session_name);
	}

	/* Overwrite ret if an error occurred when enable_channel */
	ret = command_ret ? command_ret : ret;
	poptFreeContext(pc);
	return ret;
}
