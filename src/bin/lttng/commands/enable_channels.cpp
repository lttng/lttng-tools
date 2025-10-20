/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include "../command.hpp"
#include "../utils.hpp"

#include <common/defaults.hpp>
#include <common/lttng-kernel.hpp>
#include <common/make-unique-wrapper.hpp>
#include <common/mi-lttng.hpp>
#include <common/sessiond-comm/sessiond-comm.hpp>
#include <common/utils.hpp>

#include <lttng/domain-internal.hpp>

#include <ctype.h>
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static struct lttng_channel chan_opts;
static int opt_kernel;
static char *opt_session_name;
static int opt_userspace;
static char *opt_output;
static int opt_buffer_type = -1;
static enum lttng_channel_allocation_policy opt_allocation_policy =
	DEFAULT_CHANNEL_ALLOCATION_POLICY;

static enum lttng_channel_preallocation_policy opt_preallocation_policy =
	DEFAULT_CHANNEL_PREALLOCATION_POLICY;

static struct {
	bool set;
	uint64_t interval;
} opt_monitor_timer;
static struct {
	bool set;
	uint64_t interval;
} opt_watchdog_timer;
static struct {
	bool set;
	uint64_t interval;
} opt_auto_reclaim_older_than_duration;
static bool opt_auto_reclaim_consumed = false;
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
	OPT_AUTO_RECLAIM_OLDER_THAN,
	OPT_AUTO_RECLAIM_CONSUMED,
	OPT_READ_TIMER,
	OPT_USERSPACE,
	OPT_LIST_OPTIONS,
	OPT_TRACEFILE_SIZE,
	OPT_TRACEFILE_COUNT,
	OPT_BLOCKING_TIMEOUT,
	OPT_BUFFER_OWNERSHIP,
	OPT_BUFFER_ALLOCATION,
	OPT_WATCHDOG_TIMER,
	OPT_BUFFER_PREALLOCATION,
};

static struct lttng_handle *handle;

const char *output_mmap = "mmap";
const char *output_splice = "splice";

/* clang-format off */
static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, nullptr, OPT_HELP, nullptr, nullptr },
	{ "session", 's', POPT_ARG_STRING, &opt_session_name, 0, nullptr, nullptr },
	{ "kernel", 'k', POPT_ARG_VAL, &opt_kernel, 1, nullptr, nullptr },
	{ "userspace", 'u', POPT_ARG_NONE, nullptr, OPT_USERSPACE, nullptr, nullptr },
	{ "discard", 0, POPT_ARG_NONE, nullptr, OPT_DISCARD, nullptr, nullptr },
	{ "overwrite", 0, POPT_ARG_NONE, nullptr, OPT_OVERWRITE, nullptr, nullptr },
	{ "subbuf-size", 0, POPT_ARG_STRING, nullptr, OPT_SUBBUF_SIZE, nullptr, nullptr },
	{ "num-subbuf", 0, POPT_ARG_INT, nullptr, OPT_NUM_SUBBUF, nullptr, nullptr },
	{ "switch-timer", 0, POPT_ARG_INT, nullptr, OPT_SWITCH_TIMER, nullptr, nullptr },
	{ "monitor-timer", 0, POPT_ARG_INT, nullptr, OPT_MONITOR_TIMER, nullptr, nullptr },
	{ "watchdog-timer", 0, POPT_ARG_INT, nullptr, OPT_WATCHDOG_TIMER, nullptr, nullptr },
	{ "auto-reclaim-memory-older-than", 0, POPT_ARG_STRING, nullptr, OPT_AUTO_RECLAIM_OLDER_THAN, nullptr, nullptr },
	{ "auto-reclaim-memory-consumed", 0, POPT_ARG_NONE, nullptr, OPT_AUTO_RECLAIM_CONSUMED, nullptr, nullptr },
	{ "read-timer", 0, POPT_ARG_INT, nullptr, OPT_READ_TIMER, nullptr, nullptr },
	{ "list-options", 0, POPT_ARG_NONE, nullptr, OPT_LIST_OPTIONS, nullptr, nullptr },
	{ "output", 0, POPT_ARG_STRING, &opt_output, 0, nullptr, nullptr },
	{ "buffers-uid", 0, POPT_ARG_VAL, &opt_buffer_type, LTTNG_BUFFER_PER_UID, nullptr, nullptr },
	{ "buffers-pid", 0, POPT_ARG_VAL, &opt_buffer_type, LTTNG_BUFFER_PER_PID, nullptr, nullptr },
	{ "buffers-global", 0, POPT_ARG_VAL, &opt_buffer_type, LTTNG_BUFFER_GLOBAL, nullptr, nullptr },
	{ "buffer-ownership", 0, POPT_ARG_STRING, nullptr, OPT_BUFFER_OWNERSHIP, nullptr, nullptr },
	{ "buffer-allocation", 0, POPT_ARG_STRING, nullptr, OPT_BUFFER_ALLOCATION, nullptr, nullptr },
	{ "buffer-preallocation", 0, POPT_ARG_STRING, nullptr, OPT_BUFFER_PREALLOCATION, nullptr, nullptr },
	{ "tracefile-size", 'C', POPT_ARG_INT, nullptr, OPT_TRACEFILE_SIZE, nullptr, nullptr },
	{ "tracefile-count", 'W', POPT_ARG_INT, nullptr, OPT_TRACEFILE_COUNT, nullptr, nullptr },
	{ "blocking-timeout", 0, POPT_ARG_INT, nullptr, OPT_BLOCKING_TIMEOUT, nullptr, nullptr },
	{ nullptr, 0, 0, nullptr, 0, nullptr, nullptr }
};
/* clang-format on */

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

static bool system_has_memory_for_channel_buffers(char *session_name,
						  struct lttng_channel *channel,
						  uint64_t *bytes_required,
						  uint64_t *bytes_available)
{
	/*
	 * Verify that the amount of memory required to create the requested
	 * buffer is available on the system at the moment.
	 */
	unsigned long total_buffer_size_needed_per_cpu{ 0 };
	const auto spec =
		lttng::cli::session_spec(lttng::cli::session_spec::type::NAME, session_name);
	const auto sessions = list_sessions(spec);
	int ncpus{ 0 };

	if (sessions.size() <= 0) {
		/* Session not found */
		ERR_FMT("Session not found, name='{}'", session_name);
		return false;
	}

	if (channel->attr.num_subbuf > UINT64_MAX / channel->attr.subbuf_size) {
		/* Overflow */
		ERR_FMT("Integer overflow calculating total buffer size per CPU on channel '{}': num_subbuf={}, subbuf_size={}",
			channel->name,
			channel->attr.num_subbuf,
			channel->attr.subbuf_size)
		return false;
	}

	total_buffer_size_needed_per_cpu = channel->attr.num_subbuf * channel->attr.subbuf_size;
	try {
		switch (opt_allocation_policy) {
		case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU:
			ncpus = utils_get_cpu_count();
			break;
		case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CHANNEL:
			ncpus = 1;
			break;
		}
	} catch (const std::exception& ex) {
		ERR_FMT("Exception when getting CPU count: {}", ex.what());
		return false;
	}

	/* In snapshot mode, an extra set of buffers is required. */
	const auto _bytes_required = static_cast<uint64_t>(
		total_buffer_size_needed_per_cpu * ncpus + sessions[0].snapshot_mode);
	if (bytes_required != nullptr) {
		*bytes_required = _bytes_required;
	}

	return utils_check_enough_available_memory(_bytes_required, bytes_available) == LTTNG_OK;
}

/*
 * Adding channel using the lttng API.
 */
static int enable_channel(char *session_name, char *channel_list)
{
	struct lttng_channel *channel = nullptr;
	int ret = CMD_SUCCESS, warn = 0, error = 0, success = 0;
	auto bytes_required = static_cast<uint64_t>(0);
	auto bytes_available = static_cast<uint64_t>(0);
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
		if (opt_watchdog_timer.set) {
			ERR("Watchdog timer option not supported for kernel domain (-k)");
			ret = CMD_ERROR;
			goto error;
		}
	}

	/* Create lttng domain */
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
		switch (opt_buffer_type) {
		case -1:
			/* fall-through */
		case LTTNG_BUFFER_GLOBAL:
			dom.buf_type = LTTNG_BUFFER_GLOBAL;
			break;
		default:
			ERR("Buffer ownership not supported for the kernel domain");
			ret = CMD_ERROR;
			goto error;
		}
		switch (opt_allocation_policy) {
		case LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU:
			break;
		default:
			ERR_FMT("Buffer allocation not supported for the kernel domain");
			ret = CMD_ERROR;
			goto error;
		}
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
		switch (opt_buffer_type) {
		case -1:
			dom.buf_type = LTTNG_BUFFER_PER_UID;
			break;
		case LTTNG_BUFFER_PER_PID:
			/* fall-through */
		case LTTNG_BUFFER_PER_UID:
			dom.buf_type = static_cast<enum lttng_buffer_type>(opt_buffer_type);
			break;
		default:
			ERR("Buffer ownership not supported for the user space domain");
			ret = CMD_ERROR;
			goto error;
		}

		if (opt_watchdog_timer.set && (dom.buf_type != LTTNG_BUFFER_PER_UID)) {
			ERR("Watchdog timer is only valid for channels with the `user` ownership model");
			ret = CMD_ERROR;
			goto error;
		}
	} else {
		/* Checked by the caller. */
		abort();
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
		     chan_opts.attr.tracefile_size,
		     chan_opts.attr.subbuf_size);
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
			    opt_output,
			    output_mmap,
			    output_splice);
			ret = CMD_ERROR;
			goto error;
		}
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == nullptr) {
		ret = -1;
		goto error;
	}

	/* Mi open channels element */
	if (lttng_opt_mi) {
		LTTNG_ASSERT(writer);
		ret = mi_lttng_channels_open(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	/* Strip channel list (format: chan1,chan2,...) */
	channel_name = strtok(channel_list, ",");
	while (channel_name != nullptr) {
		void *extended_ptr;

		/* Validate channel name's length */
		if (strlen(channel_name) >= sizeof(chan_opts.name)) {
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
		if (opt_watchdog_timer.set) {
			ret = lttng_channel_set_watchdog_timer_interval(
				channel, opt_watchdog_timer.interval);
			if (ret) {
				ERR("Failed to set the channel's watchdog timer interval");
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

		ret = lttng_channel_set_allocation_policy(channel, opt_allocation_policy);
		if (ret != LTTNG_OK) {
			ERR("Failed to set the channel's buffer allocation");
			error = 1;
			goto error;
		}

		ret = lttng_channel_set_preallocation_policy(channel, opt_preallocation_policy);
		if (ret != LTTNG_OK) {
			ERR("Failed to set the channel's buffer preallocation policy");
			error = 1;
			goto error;
		}

		if (opt_auto_reclaim_older_than_duration.set) {
			ret = lttng_channel_set_automatic_memory_reclamation_policy(
				channel, opt_auto_reclaim_older_than_duration.interval);
			if (ret != LTTNG_CHANNEL_STATUS_OK) {
				ERR("Failed to set the channel's automatic memory reclamation policy");
				error = 1;
				goto error;
			}
		} else if (opt_auto_reclaim_consumed) {
			ret = lttng_channel_set_automatic_memory_reclamation_policy(channel, 0);
			if (ret != LTTNG_CHANNEL_STATUS_OK) {
				ERR("Failed to set the channel's automatic memory reclamation policy to 'consumed'");
				error = 1;
				goto error;
			}
		}

		if (!system_has_memory_for_channel_buffers(
			    session_name, channel, &bytes_required, &bytes_available)) {
			ERR_FMT("Not enough system memory available for channel '{}'. At least {}MiB required, {}MiB available",
				channel->name,
				bytes_required / 1024 / 1024,
				bytes_available / 1024 / 1024);
			error = 1;
			goto error;
		}

		DBG("Enabling channel %s", channel_name);
		ret = lttng_enable_channel(handle, channel);
		if (ret < 0) {
			bool msg_already_printed = false;

			success = 0;
			switch (-ret) {
			case LTTNG_ERR_KERN_CHAN_EXIST:
			case LTTNG_ERR_UST_CHAN_EXIST:
			case LTTNG_ERR_CHAN_EXIST:
				warn = 1;
				break;
			case LTTNG_ERR_INVALID_CHANNEL_NAME:
				ERR("Invalid channel name: \"%s\". "
				    "Channel names may not start with '.', and "
				    "may not contain '/'.",
				    channel_name);
				msg_already_printed = true;
				error = 1;
				break;
			default:
				error = 1;
				break;
			}

			if (!msg_already_printed) {
				LOG(error ? PRINT_ERR : PRINT_WARN,
				    "Failed to enable channel `%s` under session `%s`: %s",
				    channel_name,
				    session_name,
				    lttng_strerror(ret));
			}

			if (opt_kernel) {
				print_kernel_tracer_status_error();
			}
		} else {
			MSG("%s channel `%s` enabled for session `%s`",
			    lttng_domain_type_str(dom.type),
			    channel_name,
			    session_name);
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
			ret = mi_lttng_writer_write_element_bool(
				writer, mi_lttng_element_command_success, success);
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
		channel_name = strtok(nullptr, ",");
		lttng_channel_destroy(channel);
		channel = nullptr;
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
static void init_channel_config()
{
	/*
	 * Put -1 everywhere so we can identify those set by the command line and
	 * those needed to be set by the default values.
	 */
	memset(&chan_opts.attr, -1, sizeof(chan_opts.attr));
	chan_opts.attr.extended.ptr = nullptr;
}

/*
 * Add channel to trace session
 */
int cmd_enable_channels(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	static poptContext pc;
	char *session_name = nullptr;
	char *channel_list = nullptr;
	char *opt_arg = nullptr;
	const char *arg_channel_list = nullptr;
	const char *leftover = nullptr;

	init_channel_config();

	pc = poptGetContext(nullptr, argc, argv, long_options, 0);
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
			if (utils_parse_size_suffix(opt_arg, &chan_opts.attr.subbuf_size) < 0 ||
			    !chan_opts.attr.subbuf_size) {
				ERR("Wrong value in --subbuf-size parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			order = get_count_order_u64(chan_opts.attr.subbuf_size);
			LTTNG_ASSERT(order >= 0);
			rounded_size = 1ULL << order;
			if (rounded_size < chan_opts.attr.subbuf_size) {
				ERR("The subbuf size (%" PRIu64 ") is rounded and overflows!",
				    chan_opts.attr.subbuf_size);
				ret = CMD_ERROR;
				goto end;
			}

			if (rounded_size != chan_opts.attr.subbuf_size) {
				WARN("The subbuf size (%" PRIu64
				     ") is rounded to the next power of 2 (%" PRIu64 ")",
				     chan_opts.attr.subbuf_size,
				     rounded_size);
				chan_opts.attr.subbuf_size = rounded_size;
			}

			/* Should now be power of 2 */
			LTTNG_ASSERT(
				!((chan_opts.attr.subbuf_size - 1) & chan_opts.attr.subbuf_size));

			DBG("Channel subbuf size set to %" PRIu64, chan_opts.attr.subbuf_size);
			break;
		}
		case OPT_NUM_SUBBUF:
		{
			uint64_t rounded_size;
			int order;

			errno = 0;
			opt_arg = poptGetOptArg(pc);
			chan_opts.attr.num_subbuf = strtoull(opt_arg, nullptr, 0);
			if (errno != 0 || !chan_opts.attr.num_subbuf || !isdigit(opt_arg[0])) {
				ERR("Wrong value in --num-subbuf parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			order = get_count_order_u64(chan_opts.attr.num_subbuf);
			LTTNG_ASSERT(order >= 0);
			rounded_size = 1ULL << order;
			if (rounded_size < chan_opts.attr.num_subbuf) {
				ERR("The number of subbuffers (%" PRIu64
				    ") is rounded and overflows!",
				    chan_opts.attr.num_subbuf);
				ret = CMD_ERROR;
				goto end;
			}

			if (rounded_size != chan_opts.attr.num_subbuf) {
				WARN("The number of subbuffers (%" PRIu64
				     ") is rounded to the next power of 2 (%" PRIu64 ")",
				     chan_opts.attr.num_subbuf,
				     rounded_size);
				chan_opts.attr.num_subbuf = rounded_size;
			}

			/* Should now be power of 2 */
			LTTNG_ASSERT(
				!((chan_opts.attr.num_subbuf - 1) & chan_opts.attr.num_subbuf));

			DBG("Channel subbuf num set to %" PRIu64, chan_opts.attr.num_subbuf);
			break;
		}
		case OPT_SWITCH_TIMER:
		{
			uint64_t v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);

			if (utils_parse_time_suffix(opt_arg, &v) < 0) {
				ERR("Wrong value for --switch-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			if (v != (uint32_t) v) {
				ERR("32-bit overflow in --switch-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			chan_opts.attr.switch_timer_interval = (uint32_t) v;
			DBG("Channel switch timer interval set to %d %s",
			    chan_opts.attr.switch_timer_interval,
			    USEC_UNIT);
			break;
		}
		case OPT_READ_TIMER:
		{
			uint64_t v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);

			if (utils_parse_time_suffix(opt_arg, &v) < 0) {
				ERR("Wrong value for --read-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			if (v != (uint32_t) v) {
				ERR("32-bit overflow in --read-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			chan_opts.attr.read_timer_interval = (uint32_t) v;
			DBG("Channel read timer interval set to %d %s",
			    chan_opts.attr.read_timer_interval,
			    USEC_UNIT);
			break;
		}
		case OPT_MONITOR_TIMER:
		{
			uint64_t v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);

			if (utils_parse_time_suffix(opt_arg, &v) < 0) {
				ERR("Wrong value for --monitor-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			opt_monitor_timer.interval = (uint64_t) v;
			opt_monitor_timer.set = true;
			DBG("Channel monitor timer interval set to %" PRIu64 " %s",
			    opt_monitor_timer.interval,
			    USEC_UNIT);
			break;
		}
		case OPT_WATCHDOG_TIMER:
		{
			uint64_t v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);

			if (utils_parse_time_suffix(opt_arg, &v) < 0) {
				ERR("Wrong value for --watchdog-timer parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			opt_watchdog_timer.interval = (uint64_t) v;
			opt_watchdog_timer.set = true;
			DBG("Channel watchdog timer interval set to %" PRIu64 " %s",
			    opt_watchdog_timer.interval,
			    USEC_UNIT);
			break;
		}
		case OPT_AUTO_RECLAIM_OLDER_THAN:
		{
			uint64_t v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);

			if (utils_parse_time_suffix(opt_arg, &v) < 0) {
				ERR("Wrong value for --auto-reclaim-memory-older-than parameter: %s",
				    opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			opt_auto_reclaim_older_than_duration.set = true;
			opt_auto_reclaim_older_than_duration.interval = v;
			DBG("Channel automatic memory reclamation set to older than %" PRIu64 " %s",
			    opt_monitor_timer.interval,
			    USEC_UNIT);
			break;
		}
		case OPT_AUTO_RECLAIM_CONSUMED:
			opt_auto_reclaim_consumed = true;
			DBG("Channel automatic memory reclamation set to when consumed");
			break;
		case OPT_BLOCKING_TIMEOUT:
		{
			uint64_t v;
			long long v_msec;

			errno = 0;
			opt_arg = poptGetOptArg(pc);

			if (strcmp(opt_arg, "inf") == 0) {
				opt_blocking_timeout.value = (int64_t) -1;
				opt_blocking_timeout.set = true;
				DBG("Channel blocking timeout set to infinity");
				break;
			}

			if (utils_parse_time_suffix(opt_arg, &v) < 0) {
				ERR("Wrong value for --blocking-timeout parameter: %s", opt_arg);
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
				ERR("32-bit milliseconds overflow in --blocking-timeout parameter: %s",
				    opt_arg);
				ret = CMD_ERROR;
				goto end;
			}

			opt_blocking_timeout.value = (int64_t) v;
			opt_blocking_timeout.set = true;
			DBG("Channel blocking timeout set to %" PRId64 " %s%s",
			    opt_blocking_timeout.value,
			    USEC_UNIT,
			    opt_blocking_timeout.value == 0 ? " (non-blocking)" : "");
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
			v = strtoul(opt_arg, nullptr, 0);
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
		case OPT_BUFFER_OWNERSHIP:
		{
			const auto ownership_ptr =
				lttng::make_unique_wrapper<char, lttng::memory::free>(
					poptGetOptArg(pc));
			const lttng::c_string_view ownership(ownership_ptr.get());

			if (ownership == "user") {
				opt_buffer_type = LTTNG_BUFFER_PER_UID;
			} else if (ownership == "process") {
				opt_buffer_type = LTTNG_BUFFER_PER_PID;
			} else if (ownership == "system") {
				opt_buffer_type = LTTNG_BUFFER_GLOBAL;
			} else {
				ERR_FMT("Wrong value for --buffer-ownership: `{}`: "
					"expecting `user`, `process` or `system",
					ownership.data());
				ret = CMD_ERROR;
				goto end;
			}
			break;
		}
		case OPT_BUFFER_ALLOCATION:
		{
			const auto policy_ptr =
				lttng::make_unique_wrapper<char, lttng::memory::free>(
					poptGetOptArg(pc));
			const lttng::c_string_view policy(policy_ptr.get());

			if (policy == "per-cpu") {
				opt_allocation_policy = LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CPU;
			} else if (policy == "per-channel") {
				opt_allocation_policy = LTTNG_CHANNEL_ALLOCATION_POLICY_PER_CHANNEL;
			} else {
				ERR_FMT("Wrong value for --buffer-allocation: `{}`: "
					"expecting `per-cpu` or `per-channel`",
					policy.data());
				ret = CMD_ERROR;
				goto end;
			}
			break;
		}
		case OPT_BUFFER_PREALLOCATION:
		{
			const auto mode_ptr = lttng::make_unique_wrapper<char, lttng::memory::free>(
				poptGetOptArg(pc));
			const lttng::c_string_view mode(mode_ptr.get());

			if (mode == "preallocate") {
				opt_preallocation_policy =
					LTTNG_CHANNEL_PREALLOCATION_POLICY_PREALLOCATE;
			} else if (mode == "on-demand") {
				opt_preallocation_policy =
					LTTNG_CHANNEL_PREALLOCATION_POLICY_ON_DEMAND;
			} else {
				ERR_FMT("Wrong value for --buffer-preallocation: `{}`: "
					"expecting `preallocate` or `on-demand`",
					mode.data());
				ret = CMD_ERROR;
				goto end;
			}
			break;
		}
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}

		if (opt_arg) {
			free(opt_arg);
			opt_arg = nullptr;
		}
	}

	ret = print_missing_or_multiple_domains(opt_kernel + opt_userspace, false);
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

	if (opt_auto_reclaim_older_than_duration.set && opt_auto_reclaim_consumed) {
		ERR("You cannot specify --auto-reclaim-memory-older-than and --auto-reclaim-memory-consumed.");
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
		ret = mi_lttng_writer_open_element(writer, mi_lttng_element_command_output);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	arg_channel_list = poptGetArg(pc);
	if (arg_channel_list == nullptr) {
		ERR("Missing channel name.");
		ret = CMD_ERROR;
		success = 0;
		goto mi_closing;
	}

	channel_list = strdup(arg_channel_list);
	if (channel_list == nullptr) {
		PERROR("Failed to copy channel name");
		ret = CMD_ERROR;
		success = 0;
		goto mi_closing;
	}

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		success = 0;
		goto mi_closing;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == nullptr) {
			command_ret = CMD_ERROR;
			success = 0;
			goto mi_closing;
		}
	} else {
		session_name = opt_session_name;
	}

	command_ret = enable_channel(session_name, channel_list);
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
		ret = mi_lttng_writer_write_element_bool(
			writer, mi_lttng_element_command_success, success);
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

	free(channel_list);

	/* Overwrite ret if an error occurred when enable_channel */
	ret = command_ret ? command_ret : ret;
	poptFreeContext(pc);
	free(opt_arg);
	return ret;
}
