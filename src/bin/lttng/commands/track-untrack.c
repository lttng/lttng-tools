/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2015 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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
#include <ctype.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <urcu/list.h>

#include <common/mi-lttng.h>

#include "../command.h"

enum cmd_type {
	CMD_TRACK,
	CMD_UNTRACK,
};

static char *opt_session_name;
static int opt_kernel;
static int opt_userspace;
static int opt_all;
static char *opt_pid_string;
static int opt_pid;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_SESSION,
	OPT_PID,
};

static struct poptOption long_options[] = {
	/* { longName, shortName, argInfo, argPtr, value, descrip, argDesc, } */
	{ "help",		'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0, },
	{ "session",		's', POPT_ARG_STRING, &opt_session_name, OPT_SESSION, 0, 0, },
	{ "kernel",		'k', POPT_ARG_VAL, &opt_kernel, 1, 0, 0, },
	{ "userspace",		'u', POPT_ARG_VAL, &opt_userspace, 1, 0, 0, },
	{ "pid",		'p', POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_pid_string, OPT_PID, 0, 0, },
	{ "all",		'a', POPT_ARG_VAL, &opt_all, 1, 0, 0, },
	{ "list-options",	0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, 0, 0, },
	{ 0, 0, 0, 0, 0, 0, 0, },
};

static
int parse_pid_string(const char *_pid_string,
		int all, int **_pid_list, int *nr_pids)
{
	const char *one_pid_str;
	char *iter;
	int retval = CMD_SUCCESS;
	int count = 0;
	int *pid_list = NULL;
	char *pid_string = NULL;
	char *endptr;

	if (all && _pid_string) {
		ERR("An empty PID string is expected with --all");
		retval = CMD_ERROR;
		goto error;
	}
	if (!all && !_pid_string) {
		ERR("Please specify --all with an empty PID string");
		retval = CMD_ERROR;
		goto error;
	}
	if (all) {
		pid_list = zmalloc(sizeof(*pid_list));
		if (!pid_list) {
			ERR("Out of memory");
			retval = CMD_ERROR;
			goto error;
		}
		/* Empty PID string means all PIDs */
		count = 1;
		pid_list[0] = -1;
		goto assign;
	}

	pid_string = strdup(_pid_string);
	if (!pid_string) {
		ERR("Out of memory");
		retval = CMD_ERROR;
		goto error;
	}

	/* Count */
	one_pid_str = strtok_r(pid_string, ",", &iter);
	while (one_pid_str != NULL) {
		unsigned long v;

		errno = 0;
		v = strtoul(one_pid_str, &endptr, 10);
		if ((v == 0 && errno == EINVAL)
				|| (v == ULONG_MAX && errno == ERANGE)
				|| (*one_pid_str != '\0' && *endptr != '\0')){
			ERR("Error parsing PID %s", one_pid_str);
			retval = CMD_ERROR;
			goto error;
		}

		if ((long) v > INT_MAX || (int) v < 0) {
			ERR("Invalid PID value %ld", (long) v);
			retval = CMD_ERROR;
			goto error;
		}
		count++;

		/* For next loop */
		one_pid_str = strtok_r(NULL, ",", &iter);
	}

	free(pid_string);
	/* Identity of delimiter has been lost in first pass. */
	pid_string = strdup(_pid_string);
	if (!pid_string) {
		ERR("Out of memory");
		retval = CMD_ERROR;
		goto error;
	}

	/* Allocate */
	pid_list = zmalloc(count * sizeof(*pid_list));
	if (!pid_list) {
		ERR("Out of memory");
		retval = CMD_ERROR;
		goto error;
	}

	/* Reparse string and populate the pid list. */
	count = 0;
	one_pid_str = strtok_r(pid_string, ",", &iter);
	while (one_pid_str != NULL) {
		unsigned long v;

		v = strtoul(one_pid_str, NULL, 10);
		pid_list[count++] = (int) v;

		/* For next loop */
		one_pid_str = strtok_r(NULL, ",", &iter);
	}

assign:
	*nr_pids = count;
	*_pid_list = pid_list;
	goto end;	/* SUCCESS */

	/* ERROR */
error:
	free(pid_list);
end:
	free(pid_string);
	return retval;
}

static
enum cmd_error_code track_untrack_pid(enum cmd_type cmd_type, const char *cmd_str,
		const char *session_name, const char *pid_string,
		int all, struct mi_writer *writer)
{
	int ret, success = 1 , i;
	enum cmd_error_code retval = CMD_SUCCESS;
	int *pid_list = NULL;
	int nr_pids;
	struct lttng_domain dom;
	struct lttng_handle *handle = NULL;
	int (*cmd_func)(struct lttng_handle *handle, int pid);

	switch (cmd_type) {
	case CMD_TRACK:
		cmd_func = lttng_track_pid;
		break;
	case CMD_UNTRACK:
		cmd_func = lttng_untrack_pid;
		break;
	default:
		ERR("Unknown command");
		retval = CMD_ERROR;
		goto end;
	}

	memset(&dom, 0, sizeof(dom));
	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
	} else if (opt_userspace) {
		dom.type = LTTNG_DOMAIN_UST;
	} else {
		/* Checked by the caller. */
		assert(0);
	}

	ret = parse_pid_string(pid_string, all, &pid_list, &nr_pids);
	if (ret != CMD_SUCCESS) {
		ERR("Error parsing PID string");
		retval = CMD_ERROR;
		goto end;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		retval = CMD_ERROR;
		goto end;
	}

	if (writer) {
		/* Open process element */
		ret = mi_lttng_targets_open(writer);
		if (ret) {
			retval = CMD_ERROR;
			goto end;
		}
	}

	for (i = 0; i < nr_pids; i++) {
		DBG("%s PID %d", cmd_str, pid_list[i]);
		ret = cmd_func(handle, pid_list[i]);
		if (ret) {
			switch (-ret) {
			case LTTNG_ERR_PID_TRACKED:
				WARN("PID %i already tracked in session %s",
						pid_list[i], session_name);
				success = 1;
				retval = CMD_SUCCESS;
				break;
			case LTTNG_ERR_PID_NOT_TRACKED:
				WARN("PID %i not tracked in session %s",
						pid_list[i], session_name);
				success = 1;
				retval = CMD_SUCCESS;
				break;
			default:
				ERR("%s", lttng_strerror(ret));
				success = 0;
				retval = CMD_ERROR;
				break;
			}
		} else {
			if (pid_list[i] != -1) {
				MSG("PID %i %sed in session %s",
						pid_list[i], cmd_str,
						session_name);
			} else {
				MSG("All PIDs %sed in session %s",
						cmd_str, session_name);
			}
			success = 1;
		}

		/* Mi */
		if (writer) {
			ret = mi_lttng_pid_target(writer, pid_list[i], 1);
			if (ret) {
				retval = CMD_ERROR;
				goto end;
			}

			ret = mi_lttng_writer_write_element_bool(writer,
					mi_lttng_element_success, success);
			if (ret) {
				retval = CMD_ERROR;
				goto end;
			}

			ret = mi_lttng_writer_close_element(writer);
			if (ret) {
				retval = CMD_ERROR;
				goto end;
			}
		}
	}

	if (writer) {
		/* Close targets element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			retval = CMD_ERROR;
			goto end;
		}
	}

end:
	if (handle) {
		lttng_destroy_handle(handle);
	}
	free(pid_list);
	return retval;
}

static
const char *get_mi_element_command(enum cmd_type cmd_type)
{
	switch (cmd_type) {
	case CMD_TRACK:
		return mi_lttng_element_command_track;
	case CMD_UNTRACK:
		return mi_lttng_element_command_untrack;
	default:
		return NULL;
	}
}

/*
 * Add/remove tracker to/from session.
 */
static
int cmd_track_untrack(enum cmd_type cmd_type, const char *cmd_str,
		int argc, const char **argv, const char *help_msg)
{
	int opt, ret = 0;
	enum cmd_error_code command_ret = CMD_SUCCESS;
	int success = 1;
	static poptContext pc;
	char *session_name = NULL;
	struct mi_writer *writer = NULL;

	if (argc < 1) {
		command_ret = CMD_ERROR;
		goto end;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		case OPT_SESSION:
		case OPT_PID:
			opt_pid = 1;
			break;
		default:
			command_ret = CMD_UNDEFINED;
			goto end;
		}
	}

	ret = print_missing_or_multiple_domains(opt_kernel + opt_userspace);
	if (ret) {
		command_ret = CMD_ERROR;
		goto end;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			command_ret = CMD_ERROR;
			goto end;
		}
	} else {
		session_name = opt_session_name;
	}

	/* Currently only PID tracker is supported */
	if (!opt_pid) {
		ERR("Please specify at least one tracker with its expected arguments");
		command_ret = CMD_ERROR;
		goto end;
	}

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			command_ret = CMD_ERROR;
			goto end;
		}
	}

	if (writer) {
		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				get_mi_element_command(cmd_type));
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Open output element */
		ret = mi_lttng_writer_open_element(writer,
				mi_lttng_element_command_output);
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}
	}

	command_ret = track_untrack_pid(cmd_type,
			cmd_str, session_name, opt_pid_string,
			opt_all, writer);
	if (command_ret != CMD_SUCCESS) {
		success = 0;
	}

	/* Mi closing */
	if (writer) {
		/* Close  output element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Success ? */
		ret = mi_lttng_writer_write_element_bool(writer,
				mi_lttng_element_command_success, success);
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}

		/* Command element close */
		ret = mi_lttng_writer_command_close(writer);
		if (ret) {
			command_ret = CMD_ERROR;
			goto end;
		}
	}

end:
	if (!opt_session_name) {
		free(session_name);
	}

	/* Mi clean-up */
	if (writer && mi_lttng_writer_destroy(writer)) {
		/* Preserve original error code */
		command_ret = CMD_ERROR;
	}

	poptFreeContext(pc);
	return (int) command_ret;
}

int cmd_track(int argc, const char **argv)
{
	static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-track.1.h>
#else
	NULL
#endif
	;

	return cmd_track_untrack(CMD_TRACK, "track", argc, argv, help_msg);
}

int cmd_untrack(int argc, const char **argv)
{
	static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng-untrack.1.h>
#else
	NULL
#endif
	;

	return cmd_track_untrack(CMD_UNTRACK, "untrack", argc, argv, help_msg);
}
