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
#include <stdbool.h>

#include "../command.h"

#include <common/mi-lttng.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/utils.h>

static char *opt_session_name;
static int opt_destroy_all;
static int opt_no_wait;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-destroy.1.h>
;
#endif

/* Mi writer */
static struct mi_writer *writer;

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",      'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"all",       'a', POPT_ARG_VAL, &opt_destroy_all, 1, 0, 0},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"no-wait",   'n', POPT_ARG_VAL, &opt_no_wait, 1, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * destroy_session
 *
 * Unregister the provided session to the session daemon. On success, removes
 * the default configuration.
 */
static int destroy_session(struct lttng_session *session)
{
	int ret;
	char *session_name = NULL;
	bool session_was_stopped;

	ret = lttng_stop_tracing_no_wait(session->name);
	if (ret < 0 && ret != -LTTNG_ERR_TRACE_ALREADY_STOPPED) {
		ERR("%s", lttng_strerror(ret));
	}
	session_was_stopped = ret == -LTTNG_ERR_TRACE_ALREADY_STOPPED;
	if (!opt_no_wait) {
		bool printed_wait_msg = false;

		do {
			ret = lttng_data_pending(session->name);
			if (ret < 0) {
				/* Return the data available call error. */
				goto error;
			}

			/*
			 * Data sleep time before retrying (in usec). Don't sleep if the call
			 * returned value indicates availability.
			 */
			if (ret) {
				if (!printed_wait_msg) {
					_MSG("Waiting for data availability");
					fflush(stdout);
				}

				printed_wait_msg = true;
				usleep(DEFAULT_DATA_AVAILABILITY_WAIT_TIME);
				_MSG(".");
				fflush(stdout);
			}
		} while (ret != 0);
		if (printed_wait_msg) {
			MSG("");
		}
	}
	if (!session_was_stopped) {
		/*
		 * Don't print the event and packet loss warnings since the user
		 * already saw them when stopping the trace.
		 */
		print_session_stats(session->name);
	}

	ret = lttng_destroy_session_no_wait(session->name);
	if (ret < 0) {
		goto error;
	}

	MSG("Session %s destroyed", session->name);

	session_name = get_session_name_quiet();
	if (session_name && !strncmp(session->name, session_name, NAME_MAX)) {
		config_destroy_default();
	}

	if (lttng_opt_mi) {
		ret = mi_lttng_session(writer, session, 0);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	ret = CMD_SUCCESS;
error:
	free(session_name);
	return ret;
}

/*
 * destroy_all_sessions
 *
 * Call destroy_sessions for each registered sessions
 */
static int destroy_all_sessions(struct lttng_session *sessions, int count)
{
	int i, ret = CMD_SUCCESS;

	if (count == 0) {
		MSG("No session found, nothing to do.");
	} else if (count < 0) {
		ERR("%s", lttng_strerror(ret));
		goto error;
	}

	for (i = 0; i < count; i++) {
		ret = destroy_session(&sessions[i]);
		if (ret < 0) {
			goto error;
		}
	}
error:
	return ret;
}

/*
 * The 'destroy <options>' first level command
 */
int cmd_destroy(int argc, const char **argv)
{
	int opt;
	int ret = CMD_SUCCESS , i, command_ret = CMD_SUCCESS, success = 1;
	static poptContext pc;
	char *session_name = NULL;

	struct lttng_session *sessions;
	int count;
	int found;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			break;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			break;
		default:
			ret = CMD_UNDEFINED;
			break;
		}
		goto end;
	}

	/* Mi preparation */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_destroy);
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

		/* For validation and semantic purpose we open a sessions element */
		ret = mi_lttng_sessions_open(writer);
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	/* Recuperate all sessions for further operation */
	count = lttng_list_sessions(&sessions);
	if (count < 0) {
		ERR("%s", lttng_strerror(count));
		command_ret = CMD_ERROR;
		success = 0;
		goto mi_closing;
	}

	/* Ignore session name in case all sessions are to be destroyed */
	if (opt_destroy_all) {
		command_ret = destroy_all_sessions(sessions, count);
		if (command_ret) {
			success = 0;
		}
	} else {
		opt_session_name = (char *) poptGetArg(pc);

		if (!opt_session_name) {
			/* No session name specified, lookup default */
			session_name = get_session_name();
			if (session_name == NULL) {
				command_ret = CMD_ERROR;
				success = 0;
				goto mi_closing;
			}
		} else {
			session_name = opt_session_name;
		}

		/* Find the corresponding lttng_session struct */
		found = 0;
		for (i = 0; i < count; i++) {
			if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
				found = 1;
				command_ret = destroy_session(&sessions[i]);
				if (command_ret) {
					success = 0;
				}

			}
		}

		if (!found) {
			ERR("Session name %s not found", session_name);
			command_ret = LTTNG_ERR_SESS_NOT_FOUND;
			success = 0;
			goto mi_closing;
		}
	}

mi_closing:
	/* Mi closing */
	if (lttng_opt_mi) {
		/* Close sessions and output element element */
		ret = mi_lttng_close_multi_element(writer, 2);
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

	if (opt_session_name == NULL) {
		free(session_name);
	}

	/* Overwrite ret if an error occurred during destroy_session/all */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
