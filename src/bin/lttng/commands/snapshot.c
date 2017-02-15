/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include <common/utils.h>
#include <common/mi-lttng.h>
#include <lttng/snapshot.h>

#include "../command.h"

static const char *opt_session_name;
static const char *opt_output_name;
static const char *opt_data_url;
static const char *opt_ctrl_url;
static const char *current_session_name;
static uint64_t opt_max_size;

/* Stub for the cmd struct actions. */
static int cmd_add_output(int argc, const char **argv);
static int cmd_del_output(int argc, const char **argv);
static int cmd_list_output(int argc, const char **argv);
static int cmd_record(int argc, const char **argv);

static const char *indent4 = "    ";

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-snapshot.1.h>
;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_MAX_SIZE,
	OPT_LIST_COMMANDS,
};

static struct mi_writer *writer;

static struct poptOption snapshot_opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",      's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"ctrl-url",     'C', POPT_ARG_STRING, &opt_ctrl_url, 0, 0, 0},
	{"data-url",     'D', POPT_ARG_STRING, &opt_data_url, 0, 0, 0},
	{"name",         'n', POPT_ARG_STRING, &opt_output_name, 0, 0, 0},
	{"max-size",     'm', POPT_ARG_STRING, 0, OPT_MAX_SIZE, 0, 0},
	{"list-options",   0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"list-commands",  0, POPT_ARG_NONE, NULL, OPT_LIST_COMMANDS},
	{0, 0, 0, 0, 0, 0, 0}
};

static struct cmd_struct actions[] = {
	{ "add-output", cmd_add_output },
	{ "del-output", cmd_del_output },
	{ "list-output", cmd_list_output },
	{ "record", cmd_record },
	{ NULL, NULL }	/* Array closure */
};

/*
 * Count and return the number of arguments in argv.
 */
static int count_arguments(const char **argv)
{
	int i = 0;

	assert(argv);

	while (argv[i] != NULL) {
		i++;
	}

	return i;
}

/*
 * Create a snapshot output object from arguments using the given URL.
 *
 * Return a newly allocated object or NULL on error.
 */
static struct lttng_snapshot_output *create_output_from_args(const char *url)
{
	int ret = 0;
	struct lttng_snapshot_output *output = NULL;

	output = lttng_snapshot_output_create();
	if (!output) {
		goto error_create;
	}

	if (url) {
		ret = lttng_snapshot_output_set_ctrl_url(url, output);
		if (ret < 0) {
			goto error;
		}
	} else if (opt_ctrl_url) {
		ret = lttng_snapshot_output_set_ctrl_url(opt_ctrl_url, output);
		if (ret < 0) {
			goto error;
		}
	}

	if (opt_data_url) {
		ret = lttng_snapshot_output_set_data_url(opt_data_url, output);
		if (ret < 0) {
			goto error;
		}
	}

	if (opt_max_size) {
		ret = lttng_snapshot_output_set_size(opt_max_size, output);
		if (ret < 0) {
			goto error;
		}
	}

	if (opt_output_name) {
		ret = lttng_snapshot_output_set_name(opt_output_name, output);
		if (ret < 0) {
			goto error;
		}
	}

	return output;

error:
	lttng_snapshot_output_destroy(output);
error_create:
	return NULL;
}

static int list_output(void)
{
	int ret, output_seen = 0;
	struct lttng_snapshot_output *s_iter;
	struct lttng_snapshot_output_list *list;

	ret = lttng_snapshot_list_output(current_session_name, &list);
	if (ret < 0) {
		goto error;
	}

	MSG("Snapshot output list for session %s", current_session_name);

	if (lttng_opt_mi) {
		ret = mi_lttng_snapshot_output_session_name(writer,
				current_session_name);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	while ((s_iter = lttng_snapshot_output_list_get_next(list)) != NULL) {
		MSG("%s[%" PRIu32 "] %s: %s (max-size: %" PRId64 ")", indent4,
				lttng_snapshot_output_get_id(s_iter),
				lttng_snapshot_output_get_name(s_iter),
				lttng_snapshot_output_get_ctrl_url(s_iter),
				lttng_snapshot_output_get_maxsize(s_iter));
		output_seen = 1;
		if (lttng_opt_mi) {
			ret = mi_lttng_snapshot_list_output(writer, s_iter);
			if (ret) {
				ret = CMD_ERROR;
				goto end;
			}
		}
	}

	if (lttng_opt_mi) {
		/* Close snapshot snapshots element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}

		/* Close snapshot session element */
		ret = mi_lttng_writer_close_element(writer);
		if (ret) {
			ret = CMD_ERROR;
		}
	}
end:
	lttng_snapshot_output_list_destroy(list);

	if (!output_seen) {
		MSG("%sNone", indent4);
	}

error:
	return ret;
}

/*
 * Delete output by ID.
 */
static int del_output(uint32_t id, const char *name)
{
	int ret;
	struct lttng_snapshot_output *output = NULL;

	output = lttng_snapshot_output_create();
	if (!output) {
		ret = CMD_FATAL;
		goto error;
	}

	if (name) {
		ret = lttng_snapshot_output_set_name(name, output);
	} else if (id != UINT32_MAX) {
		ret = lttng_snapshot_output_set_id(id, output);
	} else {
		ret = CMD_ERROR;
		goto error;
	}
	if (ret < 0) {
		ret = CMD_FATAL;
		goto error;
	}

	ret = lttng_snapshot_del_output(current_session_name, output);
	if (ret < 0) {
		goto error;
	}

	if (id != UINT32_MAX) {
		MSG("Snapshot output id %" PRIu32 " successfully deleted for session %s",
				id, current_session_name);
	} else {
		MSG("Snapshot output %s successfully deleted for session %s",
				name, current_session_name);
	}

	if (lttng_opt_mi) {
		ret = mi_lttng_snapshot_del_output(writer, id, name,
				current_session_name);
		if (ret) {
			ret = CMD_ERROR;
		}
	}

error:
	lttng_snapshot_output_destroy(output);
	return ret;
}

/*
 * Add output from the user URL.
 */
static int add_output(const char *url)
{
	int ret;
	struct lttng_snapshot_output *output = NULL;
	char name[NAME_MAX];
	const char *n_ptr;

	if (!url && (!opt_data_url || !opt_ctrl_url)) {
		ret = CMD_ERROR;
		goto error;
	}

	output = create_output_from_args(url);
	if (!output) {
		ret = CMD_FATAL;
		goto error;
	}

	/* This call, if successful, populates the id of the output object. */
	ret = lttng_snapshot_add_output(current_session_name, output);
	if (ret < 0) {
		goto error;
	}

	n_ptr = lttng_snapshot_output_get_name(output);
	if (*n_ptr == '\0') {
		int pret;
		pret = snprintf(name, sizeof(name), DEFAULT_SNAPSHOT_NAME "-%" PRIu32,
				lttng_snapshot_output_get_id(output));
		if (pret < 0) {
			PERROR("snprintf add output name");
		}
		n_ptr = name;
	}

	MSG("Snapshot output successfully added for session %s",
			current_session_name);
	MSG("  [%" PRIu32 "] %s: %s (max-size: %" PRId64 ")",
			lttng_snapshot_output_get_id(output), n_ptr,
			lttng_snapshot_output_get_ctrl_url(output),
			lttng_snapshot_output_get_maxsize(output));
	if (lttng_opt_mi) {
		ret = mi_lttng_snapshot_add_output(writer, current_session_name,
				n_ptr, output);
		if (ret) {
			ret = CMD_ERROR;
		}
	}
error:
	lttng_snapshot_output_destroy(output);
	return ret;
}

static int cmd_add_output(int argc, const char **argv)
{
	int ret;

	if (argc < 2 && (!opt_data_url || !opt_ctrl_url)) {
		ret = CMD_ERROR;
		goto end;
	}

	ret = add_output(argv[1]);

end:
	return ret;
}

static int cmd_del_output(int argc, const char **argv)
{
	int ret;
	char *name;
	long id;

	if (argc < 2) {
		ret = CMD_ERROR;
		goto end;
	}

	errno = 0;
	id = strtol(argv[1], &name, 10);
	if (id == 0 && (errno == 0 || errno == EINVAL)) {
		ret = del_output(UINT32_MAX, name);
	} else if (errno == 0 && *name == '\0') {
		ret = del_output(id, NULL);
	} else {
		ERR("Argument %s not recognized", argv[1]);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static int cmd_list_output(int argc, const char **argv)
{
	int ret;

	ret = list_output();

	return ret;
}

/*
 * Do a snapshot record with the URL if one is given.
 */
static int record(const char *url)
{
	int ret;
	struct lttng_snapshot_output *output = NULL;

	output = create_output_from_args(url);
	if (!output) {
		ret = CMD_FATAL;
		goto error;
	}

	ret = lttng_snapshot_record(current_session_name, output, 0);
	if (ret < 0) {
		if (ret == -LTTNG_ERR_MAX_SIZE_INVALID) {
			ERR("Invalid snapshot size. Cannot fit at least one packet per stream.");
		}
		goto error;
	}

	MSG("Snapshot recorded successfully for session %s", current_session_name);

	if (url) {
		MSG("Snapshot written at: %s", url);
	} else if (opt_ctrl_url) {
		MSG("Snapshot written to ctrl: %s, data: %s", opt_ctrl_url,
				opt_data_url);
	}

	if (lttng_opt_mi) {
		ret = mi_lttng_snapshot_record(writer, current_session_name, url,
				opt_ctrl_url, opt_data_url);
		if (ret) {
			ret = CMD_ERROR;
		}
	}

error:
	lttng_snapshot_output_destroy(output);
	return ret;
}

static int cmd_record(int argc, const char **argv)
{
	int ret;

	if (argc == 2) {
		ret = record(argv[1]);
	} else {
		ret = record(NULL);
	}

	return ret;
}

static int handle_command(const char **argv)
{
	int ret = CMD_SUCCESS, i = 0, argc, command_ret =  CMD_SUCCESS;
	struct cmd_struct *cmd;

	if (argv == NULL || (!opt_ctrl_url && opt_data_url) ||
			(opt_ctrl_url && !opt_data_url)) {
		command_ret = CMD_ERROR;
		goto end;
	}

	argc = count_arguments(argv);

	cmd = &actions[i];
	while (cmd->func != NULL) {
		/* Find command */
		if (strcmp(argv[0], cmd->name) == 0) {
			if (lttng_opt_mi) {
				/* Action element */
				ret = mi_lttng_writer_open_element(writer,
						mi_lttng_element_command_action);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}

				/* Name of the action */
				ret = mi_lttng_writer_write_element_string(writer,
						config_element_name, argv[0]);
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

			command_ret = cmd->func(argc, argv);

			if (lttng_opt_mi) {
				/* Close output and action element */
				ret = mi_lttng_close_multi_element(writer, 2);
				if (ret) {
					ret = CMD_ERROR;
					goto end;
				}
			}
			goto end;
		}
		i++;
		cmd = &actions[i];
	}

	ret = CMD_UNDEFINED;

end:
	/* Overwrite ret if an error occurred in cmd->func() */
	ret = command_ret ? command_ret : ret;
	return ret;
}
/*
 * The 'snapshot <cmd> <options>' first level command
 */
int cmd_snapshot(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	char *session_name = NULL;
	static poptContext pc;

	pc = poptGetContext(NULL, argc, argv, snapshot_opts, 0);
	poptReadDefaultConfig(pc, 0);

	/* Mi check */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_snapshot);
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

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, snapshot_opts);
			goto end;
		case OPT_LIST_COMMANDS:
			list_commands(actions, stdout);
			goto end;
		case OPT_MAX_SIZE:
		{
			uint64_t val;
			const char *opt = poptGetOptArg(pc);

			if (utils_parse_size_suffix((char *) opt, &val) < 0) {
				ERR("Unable to handle max-size value %s", opt);
				ret = CMD_ERROR;
				goto end;
			}

			opt_max_size = val;

			break;
		}
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = CMD_ERROR;
			goto end;
		}
		current_session_name = session_name;
	} else {
		current_session_name = opt_session_name;
	}

	command_ret = handle_command(poptGetArgs(pc));
	if (command_ret) {
		switch (-command_ret) {
		case LTTNG_ERR_SNAPSHOT_NODATA:
			WARN("%s", lttng_strerror(command_ret));

			/*  A warning is fine since the user has no control on
			 *  whether or not applications (or the kernel) have
			 *  produced any event between the start of the tracing
			 *  session and the recording of the snapshot. MI wise
			 *  the command is not a success since nothing was
			 *  recorded.
			 */
			command_ret = 0;
			break;
		default:
			ERR("%s", lttng_strerror(command_ret));
			break;
		}
		success = 0;
	}

	if (lttng_opt_mi) {
		/* Close output element */
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

	if (!opt_session_name) {
		free(session_name);
	}

	/* Overwrite ret if an error occurred during handle_command */
	ret = command_ret ? command_ret : ret;
	poptFreeContext(pc);
	return ret;
}
