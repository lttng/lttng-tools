/*
 * Copyright (C) 2011 David Goulet <dgoulet@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/spawn-viewer.h>
#include "../command.h"

static char *opt_viewer;
static char *opt_trace_path;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-view.1.h>
;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help",        'h', POPT_ARG_NONE, 0, OPT_HELP, 0, 0},
	{"list-options", 0,  POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"viewer",      'e', POPT_ARG_STRING, &opt_viewer, 0, 0, 0},
	{"trace-path",  't', POPT_ARG_STRING, &opt_trace_path, 0, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/* Is the session we are trying to view is in live mode. */
static int session_live_mode;

/*
 * Build the live path we need for the lttng live view.
 */
static char *build_live_path(char *session_name)
{
	int ret;
	char *path = NULL;
	char hostname[HOST_NAME_MAX];

	ret = gethostname(hostname, sizeof(hostname));
	if (ret < 0) {
		PERROR("gethostname");
		goto error;
	}

	ret = asprintf(&path, "net://localhost/host/%s/%s", hostname,
			session_name);
	if (ret < 0) {
		PERROR("asprintf live path");
		goto error;
	}

error:
	return path;
}

/*
 * Exec viewer if found and use session name path.
 */
static int view_trace(const char *arg_session_name)
{
	int ret;
	char *session_name, *trace_path = NULL;
	struct lttng_session *sessions = NULL;
	bool free_trace_path = false;

	/*
	 * Safety net. If lttng is suid at some point for *any* useless reasons,
	 * this prevent any bad execution of binaries.
	 */
	if (getuid() != 0) {
		if (getuid() != geteuid()) {
			ERR("UID does not match effective UID.");
			ret = CMD_ERROR;
			goto error;
		} else if (getgid() != getegid()) {
			ERR("GID does not match effective GID.");
			ret = CMD_ERROR;
			goto error;
		}
	}

	/* User define trace path override the session name */
	if (opt_trace_path) {
		session_name = NULL;
	} else {
		if (arg_session_name == NULL) {
			session_name = get_session_name();
		} else {
			session_name = strdup(arg_session_name);
			if (session_name == NULL) {
				PERROR("Failed to copy session name");
			}
		}

		if (session_name == NULL) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	DBG("Viewing trace for session %s", session_name);

	if (session_name) {
		int i, count, found = 0;

		/* Getting all sessions */
		count = lttng_list_sessions(&sessions);
		if (count < 0) {
			ERR("Unable to list sessions. Session name %s not found.",
					session_name);
			MSG("Is there a session daemon running?");
			ret = CMD_ERROR;
			goto free_error;
		}

		/* Find our session listed by the session daemon */
		for (i = 0; i < count; i++) {
			if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
				found = 1;
				break;
			}
		}

		if (!found) {
			MSG("Session name %s not found", session_name);
			ret = CMD_ERROR;
			goto free_sessions;
		}

		session_live_mode = sessions[i].live_timer_interval;

		DBG("Session live mode set to %d", session_live_mode);

		if (sessions[i].enabled && !session_live_mode) {
			WARN("Session %s is running. Please stop it before reading it.",
					session_name);
			ret = CMD_ERROR;
			goto free_sessions;
		}

		/* If the timer interval is set we are in live mode. */
		if (session_live_mode) {
			trace_path = build_live_path(session_name);
			if (!trace_path) {
				ret = CMD_ERROR;
				goto free_sessions;
			}
			free_trace_path = true;
		} else {
			/* Get file system session path. */
			trace_path = sessions[i].path;
		}
	} else {
		trace_path = opt_trace_path;
	}

	MSG("Trace directory: %s\n", trace_path);

	ret = spawn_viewer(trace_path, opt_viewer, session_live_mode);
	if (ret < 0) {
		/* Don't set ret so lttng can interpret the sessiond error. */
		goto free_sessions;
	}

free_sessions:
	if (session_live_mode && free_trace_path) {
		free(trace_path);
	}
	free(sessions);
free_error:
	free(session_name);
error:
	return ret;
}

/*
 * The 'view <options>' first level command
 */
int cmd_view(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS;
	static poptContext pc;
	const char *arg_session_name = NULL;
	const char *leftover = NULL;

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	if (lttng_opt_mi) {
		WARN("mi does not apply to view command");
	}

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			SHOW_HELP();
			goto end;
		case OPT_LIST_OPTIONS:
			list_cmd_options(stdout, long_options);
			goto end;
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	arg_session_name = poptGetArg(pc);

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		goto end;
	}

	ret = view_trace(arg_session_name);

end:
	poptFreeContext(pc);
	return ret;
}
