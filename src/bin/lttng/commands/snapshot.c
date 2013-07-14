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

#define _GNU_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_MAX_SIZE,
};

static struct poptOption snapshot_opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"session",      's', POPT_ARG_STRING, &opt_session_name, 0, 0, 0},
	{"ctrl-url",     'C', POPT_ARG_STRING, &opt_ctrl_url, 0, 0, 0},
	{"data-url",     'D', POPT_ARG_STRING, &opt_data_url, 0, 0, 0},
	{"name",         'n', POPT_ARG_STRING, &opt_output_name, 0, 0, 0},
	{"max-size",     'm', POPT_ARG_DOUBLE, 0, OPT_MAX_SIZE, 0, 0},
	{"list-options",   0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
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
 * usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "usage: lttng snapshot ACTION\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Actions:\n");
	fprintf(ofp, "   add-output [-m <SIZE>] [-s <NAME>] [-n <NAME>] <URL> | -C <URL> -D <URL>\n");
	fprintf(ofp, "      Setup and add an snapshot output for a session.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "   del-output ID | NAME [-s <NAME>]\n");
	fprintf(ofp, "      Delete an output for a session using the ID.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "   list-output [-s <NAME>]\n");
	fprintf(ofp, "      List the output of a session.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "   record [-m <SIZE>] [-s <NAME>] [-n <NAME>] [<URL> | -C <URL> -D <URL>]\n");
	fprintf(ofp, "      Snapshot a session's buffer(s) for all domains. If an URL is\n");
	fprintf(ofp, "      specified, it is used instead of a previously added output.\n");
	fprintf(ofp, "      Specifying only a name or/a size will override the current output value.\n");
	fprintf(ofp, "      For instance, you can record a snapshot with a custom maximum size\n");
	fprintf(ofp, "      or with a different name.\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help           Show this help\n");
	fprintf(ofp, "      --list-options   Simple listing of options\n");
	fprintf(ofp, "  -s, --session NAME   Apply to session name\n");
	fprintf(ofp, "  -n, --name NAME      Name of the output or snapshot\n");
	fprintf(ofp, "  -m, --max-size SIZE  Maximum bytes size of the snapshot\n");
	fprintf(ofp, "  -C, --ctrl-url URL   Set control path URL. (Must use -D also)\n");
	fprintf(ofp, "  -D, --data-url URL   Set data path URL. (Must use -C also)\n");
	fprintf(ofp, "\n");
}

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

	while ((s_iter = lttng_snapshot_output_list_get_next(list)) != NULL) {
		MSG("%s[%" PRIu32 "] %s: %s", indent4,
				lttng_snapshot_output_get_id(s_iter),
				lttng_snapshot_output_get_name(s_iter),
				lttng_snapshot_output_get_ctrl_url(s_iter));
		output_seen = 1;
	}

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

	MSG("Snapshot output successfully added for session %s",
			current_session_name);
	MSG("  [%" PRIu32 "] %s: %s (max-size: %" PRId64 ")",
			lttng_snapshot_output_get_id(output),
			lttng_snapshot_output_get_name(output),
			lttng_snapshot_output_get_ctrl_url(output),
			lttng_snapshot_output_get_maxsize(output));
error:
	lttng_snapshot_output_destroy(output);
	return ret;
}

static int cmd_add_output(int argc, const char **argv)
{
	int ret = CMD_SUCCESS;

	if (argc < 2 && (!opt_data_url || !opt_ctrl_url)) {
		usage(stderr);
		ret = CMD_ERROR;
		goto end;
	}

	ret = add_output(argv[1]);

end:
	return ret;
}

static int cmd_del_output(int argc, const char **argv)
{
	int ret = CMD_SUCCESS;
	char *name;
	long id;

	if (argc < 2) {
		usage(stderr);
		ret = CMD_ERROR;
		goto end;
	}

	errno = 0;
	id = strtol(argv[1], &name, 10);
	if (id == 0 && errno == 0) {
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
	return list_output();
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
		goto error;
	}

	MSG("Snapshot recorded successfully for session %s", current_session_name);

	if (url) {
		MSG("Snapshot written at: %s", url);
	} else if (opt_ctrl_url) {
		MSG("Snapshot written to ctrl: %s, data: %s", opt_ctrl_url,
				opt_data_url);
	}

error:
	lttng_snapshot_output_destroy(output);
	return ret;
}

static int cmd_record(int argc, const char **argv)
{
	int ret;

	if (argc == 2) {
		/* With a given URL */
		ret = record(argv[1]);
	} else {
		ret = record(NULL);
	}

	return ret;
}

static int handle_command(const char **argv)
{
	int ret, i = 0, argc;
	struct cmd_struct *cmd;

	if (argv == NULL || (!opt_ctrl_url && opt_data_url) ||
			(opt_ctrl_url && !opt_data_url)) {
		usage(stderr);
		ret = CMD_ERROR;
		goto end;
	}

	argc = count_arguments(argv);

	cmd = &actions[i];
	while (cmd->func != NULL) {
		/* Find command */
		if (strcmp(argv[0], cmd->name) == 0) {
			ret = cmd->func(argc, argv);
			goto end;
		}
		i++;
		cmd = &actions[i];
	}

	/* Command not found */
	ret = CMD_UNDEFINED;

end:
	return ret;
}

/*
 * The 'snapshot <cmd> <options>' first level command
 */
int cmd_snapshot(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	char *session_name = NULL;
	static poptContext pc;

	pc = poptGetContext(NULL, argc, argv, snapshot_opts, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stdout);
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, snapshot_opts);
			goto end;
		case OPT_MAX_SIZE:
		{
			long long int val;
			char *endptr;
			const char *opt = poptGetOptArg(pc);

			/* Documented by the man page of strtoll(3). */
			errno = 0;
			val = strtoll(opt, &endptr, 10);
			if ((errno == ERANGE && (val == LLONG_MAX || val == LONG_MIN))
					|| (errno != 0 && val == 0)) {
				ERR("Unable to handle max-size value %s", opt);
				ret = CMD_ERROR;
				goto end;
			}

			if (endptr == opt) {
				ERR("No digits were found in %s", opt);
				ret = CMD_ERROR;
				goto end;
			}
			opt_max_size = val;

			break;
		}
		default:
			usage(stderr);
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

	ret = handle_command(poptGetArgs(pc));
	if (ret < 0) {
		if (ret == -LTTNG_ERR_EPERM) {
			ERR("The session needs to be set in no output mode (--no-output)");
		}
		ERR("%s", lttng_strerror(ret));
		goto end;
	}

end:
	if (!opt_session_name) {
		free(session_name);
	}
	poptFreeContext(pc);
	return ret;
}
