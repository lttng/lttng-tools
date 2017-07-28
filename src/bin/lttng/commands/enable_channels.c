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


static struct lttng_channel chan_opts;
static char *opt_channels;
static int opt_kernel;
static char *opt_session_name;
static int opt_userspace;
static char *opt_output;
static int opt_buffer_uid;
static int opt_buffer_pid;
static int opt_buffer_global;
static struct {
	bool set;
	uint64_t interval;
} opt_monitor_timer;
static struct {
	bool set;
	int64_t value;
} opt_blocking_timeout;

static struct mi_writer *writer;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-enable-channel.1.h>
;
#endif

enum {
	OPT_HELP = 1,
	OPT_DISCARD,
	OPT_OVERWRITE,
	OPT_SUBBUF_SIZE,
	OPT_NUM_SUBBUF,
	OPT_SWITCH_TIMER,
	OPT_MONITOR_TIMER,
	OPT_READ_TIMER,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
	OPT_TRACEFILE_SIZE,
	OPT_TRACEFILE_COUNT,
	OPT_BLOCKING_TIMEOUT,
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
	{"monitor-timer",  0,   POPT_ARG_INT, 0, OPT_MONITOR_TIMER, 0, 0},
	{"read-timer",     0,   POPT_ARG_INT, 0, OPT_READ_TIMER, 0, 0},
	{"list-options",   0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"output",         0,   POPT_ARG_STRING, &opt_output, 0, 0, 0},
	{"buffers-uid",    0,	POPT_ARG_VAL, &opt_buffer_uid, 1, 0, 0},
	{"buffers-pid",    0,	POPT_ARG_VAL, &opt_buffer_pid, 1, 0, 0},
	{"buffers-global", 0,	POPT_ARG_VAL, &opt_buffer_global, 1, 0, 0},
	{"tracefile-size", 'C',   POPT_ARG_INT, 0, OPT_TRACEFILE_SIZE, 0, 0},
	{"tracefile-count", 'W',   POPT_ARG_INT, 0, OPT_TRACEFILE_COUNT, 0, 0},
	{"blocking-timeout",     0,   POPT_ARG_INT, 0, OPT_BLOCKING_TIMEOUT, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * Set default attributes depending on those already defined from the command
 * line.
 */
static void set_default_attr(struct lttng_domain *dom)
{
	struct lttng_channel_attr default_attr;

	memset(&default_attr, 0, sizeof(default_attr));

	/* Set attributes */
	lttng_channel_set_default_attr(dom, &default_attr);

	if (chan_opts.attr.overwrite == -1) {
		chan_opts.attr.overwrite = default_attr.overwrite;
	}
	if (chan_opts.attr.subbuf_size == -1) {
		chan_opts.attr.subbuf_size = default_attr.subbuf_size;
	}
	if (chan_opts.attr.num_subbuf == -1) {
		chan_opts.attr.num_subbuf = default_attr.num_subbuf;
	}
	if (chan_opts.attr.switch_timer_interval == -1) {
		chan_opts.attr.switch_timer_interval = default_attr.switch_timer_interval;
	}
	if (chan_opts.attr.read_timer_interval == -1) {
		chan_opts.attr.read_timer_interval = default_attr.read_timer_interval;
	}
	if ((int) chan_opts.attr.output == -1) {
		chan_opts.attr.output = default_attr.output;
	}
	if (chan_opts.attr.tracefile_count == -1) {
		chan_opts.attr.tracefile_count = default_attr.tracefile_count;
	}
	if (chan_opts.attr.tracefile_size == -1) {
		chan_opts.attr.tracefile_size = default_attr.tracefile_size;
	}
}

/*
 * Adding channel using the lttng API.
 */
static int enable_channel(char *session_name)
{
	struct lttng_channel *channel = NULL;
	int ret = CMD_SUCCESS, warn = 0, error = 0, success = 0;
	char *channel_name;
	struct lttng_domain dom;

	memset(&dom, 0, sizeof(dom));

	/* Validate options. */
	if (opt_kernel) {
		if (opt_blocking_timeout.set) {
			ERR("Retry timeout option not supported for kernel domain (-k)");
			ret = CMD_ERROR;
			goto error;
		}
	}

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
		/* Checked by the caller. */
		assert(0);
	}

	set_default_attr(&dom);

	if (chan_opts.attr.tracefile_size == 0 && chan_opts.attr.tracefile_count) {
		ERR("Missing option --tracefile-size. "
				"A file count without a size won't do anything.");
		ret = CMD_ERROR;
		goto error;
	}

	if ((chan_opts.attr.tracefile_size > 0) &&
			(chan_opts.attr.tracefile_size < chan_opts.attr.subbuf_size)) {
		WARN("Tracefile size rounded up from (%" PRIu64 ") to subbuffer size (%" PRIu64 ")",
				chan_opts.attr.tracefile_size, chan_opts.attr.subbuf_size);
		chan_opts.attr.tracefile_size = chan_opts.attr.subbuf_size;
	}

	/* Setting channel output */
	if (opt_output) {
		if (!strncmp(output_mmap, opt_output, strlen(output_mmap))) {
			chan_opts.attr.output = LTTNG_EVENT_MMAP;
		} else if (!strncmp(output_splice, opt_output, strlen(output_splice))) {
			chan_opts.attr.output = LTTNG_EVENT_SPLICE;
		} else {
			ERR("Unknown output type %s. Possible values are: %s, %s\n",
					opt_output, output_mmap, output_splice);
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
		void *extended_ptr;

		/* Validate channel name's length */
		if (strlen(channel_name) >= NAME_MAX) {
			ERR("Channel name is too long (max. %zu characters)",
					sizeof(chan_opts.name) - 1);
			error = 1;
			goto skip_enable;
		}

		/*
		 * A dynamically-allocated channel is used in order to allow
		 * the configuration of extended attributes (post-2.9).
		 */
		channel = lttng_channel_create(&dom);
		if (!channel) {
			ERR("Unable to create channel object");
			error = 1;
			goto error;
		}

		/* Copy channel name */
		strcpy(channel->name, channel_name);
		channel->enabled = 1;
		extended_ptr = channel->attr.extended.ptr;
		memcpy(&channel->attr, &chan_opts.attr, sizeof(chan_opts.attr));
		channel->attr.extended.ptr = extended_ptr;
		if (opt_monitor_timer.set) {
			ret = lttng_channel_set_monitor_timer_interval(channel,
					opt_monitor_timer.interval);
			if (ret) {
				ERR("Failed to set the channel's monitor timer interval");
				error = 1;
				goto error;
			}
		}
		if (opt_blocking_timeout.set) {
			ret = lttng_channel_set_blocking_timeout(channel,
					opt_blocking_timeout.value);
			if (ret) {
				ERR("Failed to set the channel's blocking timeout");
				error = 1;
				goto error;
			}
		}

		DBG("Enabling channel %s", channel_name);

		ret = lttng_enable_channel(handle, channel);
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
			ret = mi_lttng_channel(writer, channel, 1);
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
		lttng_channel_destroy(channel);
		channel = NULL;
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
	if (channel) {
		lttng_channel_destroy(channel);
	}
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
	memset(&chan_opts.attr, -1, sizeof(chan_opts.attr));
	chan_opts.attr.extended.ptr = NULL;
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
			SHOW_HELP();
			goto end;
		case OPT_DISCARD:
			chan_opts.attr.overwrite = 0;
			DBG("Channel set to discard");
			break;
		case OPT_OVERWRITE:
			chan_opts.attr.overwrite = 1;
			DBG("Channel set to overwrite");
			break;
		case OPT_SUBBUF_SIZE:
		{
			uint64_t rounded_size;
			int order;

			/* Parse the size */
			opt_arg = poptGetOptArg(pc);
			if (utils_parse_size_suffix(opt_arg, &chan_opts.attr.subbuf_size) < 0 || !chan_opts.attr.subbuf_size) {
				ERR("Wrong value in --subbuf-size parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			order = get_count_order_u64(chan_opts.attr.subbuf_size);
			assert(order >= 0);
			rounded_size = 1ULL << order;
			if (rounded_size < chan_opts.attr.subbuf_size) {
				ERR("The subbuf size (%" PRIu64 ") is rounded and overflows!",
						chan_opts.attr.subbuf_size);
				ret = CMD_ERROR;
				goto end;
			}

			if (rounded_size != chan_opts.attr.subbuf_size) {
				WARN("The subbuf size (%" PRIu64 ") is rounded to the next power of 2 (%" PRIu64 ")",
						chan_opts.attr.subbuf_size, rounded_size);
				chan_opts.attr.subbuf_size = rounded_size;
			}

			/* Should now be power of 2 */
			assert(!((chan_opts.attr.subbuf_size - 1) & chan_opts.attr.subbuf_size));

			DBG("Channel subbuf size set to %" PRIu64, chan_opts.attr.subbuf_size);
			break;
		}
		case OPT_NUM_SUBBUF:
		{
			uint64_t rounded_size;
			int order;

			errno = 0;
			opt_arg = poptGetOptArg(pc);
			chan_opts.attr.num_subbuf = strtoull(opt_arg, NULL, 0);
			if (errno != 0 || !chan_opts.attr.num_subbuf || !isdigit(opt_arg[0])) {
				ERR("Wrong value in --num-subbuf parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			order = get_count_order_u64(chan_opts.attr.num_subbuf);
			assert(order >= 0);
			rounded_size = 1ULL << order;
			if (rounded_size < chan_opts.attr.num_subbuf) {
				ERR("The number of subbuffers (%" PRIu64 ") is rounded and overflows!",
						chan_opts.attr.num_subbuf);
				ret = CMD_ERROR;
				goto end;
			}

			if (rounded_size != chan_opts.attr.num_subbuf) {
				WARN("The number of subbuffers (%" PRIu64 ") is rounded to the next power of 2 (%" PRIu64 ")",
						chan_opts.attr.num_subbuf, rounded_size);
				chan_opts.attr.num_subbuf = rounded_size;
			}

			/* Should now be power of 2 */
			assert(!((chan_opts.attr.num_subbuf - 1) & chan_opts.attr.num_subbuf));

			DBG("Channel subbuf num set to %" PRIu64, chan_opts.attr.num_subbuf);
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
			chan_opts.attr.switch_timer_interval = (uint32_t) v;
			DBG("Channel switch timer interval set to %d", chan_opts.attr.switch_timer_interval);
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
			chan_opts.attr.read_timer_interval = (uint32_t) v;
			DBG("Channel read timer interval set to %d", chan_opts.attr.read_timer_interval);
			break;
		}
		case OPT_MONITOR_TIMER:
		{
			unsigned long long v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);
			v = strtoull(opt_arg, NULL, 0);
			if (errno != 0 || !isdigit(opt_arg[0])) {
				ERR("Wrong value in --monitor-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			opt_monitor_timer.interval = (uint64_t) v;
			opt_monitor_timer.set = true;
			DBG("Channel monitor timer interval set to %" PRIu64" (µs)", opt_monitor_timer.interval);
			break;
		}
		case OPT_BLOCKING_TIMEOUT:
		{
			long long v;	/* in usec */
			long long v_msec;

			errno = 0;
			opt_arg = poptGetOptArg(pc);

			if (strcmp(opt_arg, "inf") == 0) {
				opt_blocking_timeout.value = (int64_t) -1;
				opt_blocking_timeout.set = true;
				DBG("Channel blocking timeout set to infinity");
				break;
			}

			v = strtoll(opt_arg, NULL, 0);
			if (errno != 0 || (!isdigit(opt_arg[0]) && opt_arg[0] != '-')
					|| v < 0) {
				ERR("Wrong value in --blocking-timeout parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			/*
			 * While LTTng-UST and LTTng-tools will accept a
			 * blocking timeout expressed in µs, the current
			 * tracer implementation relies on poll() which
			 * takes an "int timeout" parameter expressed in
			 * msec.
			 *
			 * Since the error reporting from the tracer is
			 * not precise, we perform this check here to
			 * provide a helpful error message in case of
			 * overflow.
			 *
			 * The setter (liblttng-ctl) also performs an
			 * equivalent check.
			 */
			v_msec = v / 1000;
			if (v_msec != (int32_t) v_msec) {
				ERR("32-bit milliseconds overflow in --blocking-timeout parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			opt_blocking_timeout.value = (int64_t) v;
			opt_blocking_timeout.set = true;
			DBG("Channel blocking timeout set to %" PRId64 " µs%s",
					opt_blocking_timeout.value,
					opt_blocking_timeout.value == 0 ?
						" (non-blocking)" : "");
			break;
		}
		case OPT_USERSPACE:
			opt_userspace = 1;
			break;
		case OPT_TRACEFILE_SIZE:
			opt_arg = poptGetOptArg(pc);
			if (utils_parse_size_suffix(opt_arg, &chan_opts.attr.tracefile_size) < 0) {
				ERR("Wrong value in --tracefile-size parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			DBG("Maximum tracefile size set to %" PRIu64,
					chan_opts.attr.tracefile_size);
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
			chan_opts.attr.tracefile_count = (uint32_t) v;
			DBG("Maximum tracefile count set to %" PRIu64,
					chan_opts.attr.tracefile_count);
			break;
		}
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = print_missing_or_multiple_domains(opt_kernel + opt_userspace);
	if (ret) {
		ret = CMD_ERROR;
		goto end;
	}

	if (chan_opts.attr.overwrite == 1 && opt_blocking_timeout.set &&
			opt_blocking_timeout.value != 0) {
		ERR("You cannot specify --overwrite and --blocking-timeout=N, "
			"where N is different than 0");
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
