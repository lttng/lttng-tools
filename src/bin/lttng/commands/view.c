/*
 * Copyright (C) 2011 - David Goulet <dgoulet@efficios.com>
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

#include "../command.h"

static char *opt_session_name;
static char *opt_viewer;
static char *opt_trace_path;
static const char *babeltrace_bin = CONFIG_BABELTRACE_BIN;
//static const char *lttv_gui_bin = CONFIG_LTTV_GUI_BIN;

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

/*
 * This is needed for each viewer since we are using execvp().
 */
static const char *babeltrace_opts[] = { "babeltrace" };
//static const char *lttv_gui_opts[] = { "lttv-gui", "-t", };

/*
 * Type is also use as the index in the viewers array. So please, make sure
 * your enum value is in the right order in the array below.
 */
enum viewer_type {
	VIEWER_BABELTRACE    = 0,
	VIEWER_LTTV_GUI      = 1,
	VIEWER_USER_DEFINED  = 2,
};

/*
 * NOTE: "lttv" is a shell command and it's not working for exec() family
 * functions so we might think of removing this wrapper or using bash.
 */
static struct viewers {
	const char *exec_name;
	enum viewer_type type;
} viewers[] = {
	{ "babeltrace", VIEWER_BABELTRACE },
	{ "lttv-gui", VIEWER_LTTV_GUI },
	{ NULL, VIEWER_USER_DEFINED },
};

/* Is the session we are trying to view is in live mode. */
static int session_live_mode;

static struct viewers *parse_options(void)
{
	if (opt_viewer == NULL) {
		/* Default is babeltrace */
		return &(viewers[VIEWER_BABELTRACE]);
	}

	/*
	 * This means that if -e, --viewers is used, we just override everything
	 * with it. For supported viewers like lttv, we could simply detect if "-t"
	 * is passed and if not, add the trace directory to it.
	 */
	return &(viewers[VIEWER_USER_DEFINED]);
}

/*
 * Alloc an array of string pointer from a simple string having all options
 * seperated by spaces. Also adds the trace path to the arguments.
 *
 * The returning pointer is ready to be passed to execvp().
 */
static char **alloc_argv_from_user_opts(char *opts, const char *trace_path)
{
	int i = 0, ignore_space = 0;
	unsigned int num_opts = 1;
	char **argv, *token = opts;

	/* Count number of arguments. */
	do {
		if (*token == ' ') {
			/* Use to ignore consecutive spaces */
			if (!ignore_space) {
				num_opts++;
			}
			ignore_space = 1;
		} else {
			ignore_space = 0;
		}
		token++;
	} while (*token != '\0');

	/* Add two here for the NULL terminating element and trace path */
	argv = zmalloc(sizeof(char *) * (num_opts + 2));
	if (argv == NULL) {
		goto error;
	}

	token = strtok(opts, " ");
	while (token != NULL) {
		argv[i] = strdup(token);
		if (argv[i] == NULL) {
			goto error;
		}
		token = strtok(NULL, " ");
		i++;
	}

	argv[num_opts] = (char *) trace_path;
	argv[num_opts + 1] = NULL;

	return argv;

error:
	if (argv) {
		for (i = 0; i < num_opts + 2; i++) {
			free(argv[i]);
		}
		free(argv);
	}

	return NULL;
}

/*
 * Alloc an array of string pointer from an array of strings. It also adds
 * the trace path to the argv.
 *
 * The returning pointer is ready to be passed to execvp().
 */
static char **alloc_argv_from_local_opts(const char **opts, size_t opts_len,
		const char *trace_path)
{
	char **argv;
	size_t size, mem_len;


	/* Add one for the NULL terminating element. */
	mem_len = opts_len + 1;
	if (session_live_mode) {
		/* Add 3 option for the live mode being "-i lttng-live URL". */
		mem_len += 3;
	} else {
		/* Add option for the trace path. */
		mem_len += 1;
	}

	size = sizeof(char *) * mem_len;

	/* Add two here for the trace_path and the NULL terminating element. */
	argv = zmalloc(size);
	if (argv == NULL) {
		goto error;
	}

	memcpy(argv, opts, size);

	if (session_live_mode) {
		argv[opts_len] = "-i";
		argv[opts_len + 1] = "lttng-live";
		argv[opts_len + 2] = (char *) trace_path;
		argv[opts_len + 3] = NULL;
	} else {
		argv[opts_len] = (char *) trace_path;
		argv[opts_len + 1] = NULL;
	}

error:
	return argv;
}

/*
 * Spawn viewer with the trace directory path.
 */
static int spawn_viewer(const char *trace_path)
{
	int ret = 0;
	struct stat status;
	const char *viewer_bin = NULL;
	struct viewers *viewer;
	char **argv = NULL;

	/* Check for --viewer options */
	viewer = parse_options();
	if (viewer == NULL) {
		ret = CMD_ERROR;
		goto error;
	}

	switch (viewer->type) {
	case VIEWER_BABELTRACE:
		if (stat(babeltrace_bin, &status) == 0) {
			viewer_bin = babeltrace_bin;
		} else {
			viewer_bin = viewer->exec_name;
		}
		argv = alloc_argv_from_local_opts(babeltrace_opts,
				ARRAY_SIZE(babeltrace_opts), trace_path);
		break;
	case VIEWER_USER_DEFINED:
		argv = alloc_argv_from_user_opts(opt_viewer, trace_path);
		if (argv) {
			viewer_bin = argv[0];
		}
		break;
	default:
		viewer_bin = viewers[VIEWER_BABELTRACE].exec_name;
		argv = alloc_argv_from_local_opts(babeltrace_opts,
				ARRAY_SIZE(babeltrace_opts), trace_path);
		break;
	}

	if (argv == NULL || !viewer_bin) {
		ret = CMD_FATAL;
		goto error;
	}

	DBG("Using %s viewer", viewer_bin);

	ret = execvp(viewer_bin, argv);
	if (ret) {
		if (errno == ENOENT) {
			ERR("%s not found on the system", viewer_bin);
		} else {
			PERROR("exec: %s", viewer_bin);
		}
		ret = CMD_FATAL;
		goto error;
	}

error:
	free(argv);
	return ret;
}

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
static int view_trace(void)
{
	int ret;
	char *session_name, *trace_path = NULL;
	struct lttng_session *sessions = NULL;

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
	} else if(opt_session_name == NULL) {
		session_name = get_session_name();
		if (session_name == NULL) {
			ret = CMD_ERROR;
			goto error;
		}
	} else {
		session_name = opt_session_name;
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
		} else {
			/* Get file system session path. */
			trace_path = sessions[i].path;
		}
	} else {
		trace_path = opt_trace_path;
	}

	MSG("Trace directory: %s\n", trace_path);

	ret = spawn_viewer(trace_path);
	if (ret < 0) {
		/* Don't set ret so lttng can interpret the sessiond error. */
		goto free_sessions;
	}

free_sessions:
	if (session_live_mode) {
		free(trace_path);
	}
	free(sessions);
free_error:
	if (opt_session_name == NULL) {
		free(session_name);
	}
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

	opt_session_name = (char*) poptGetArg(pc);

	ret = view_trace();

end:
	poptFreeContext(pc);
	return ret;
}
