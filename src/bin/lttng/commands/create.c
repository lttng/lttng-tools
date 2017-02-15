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
#include <assert.h>
#include <ctype.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <common/compat/time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include <common/mi-lttng.h>

#include "../command.h"
#include "../utils.h"

#include <common/defaults.h>
#include <common/sessiond-comm/sessiond-comm.h>
#include <common/uri.h>
#include <common/utils.h>
#include <lttng/snapshot.h>

static char *opt_output_path;
static char *opt_session_name;
static char *opt_url;
static char *opt_ctrl_url;
static char *opt_data_url;
static char *opt_shm_path;
static int opt_no_consumer;
static int opt_no_output;
static int opt_snapshot;
static unsigned int opt_live_timer;

#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-create.1.h>
;
#endif

enum {
	OPT_HELP = 1,
	OPT_LIST_OPTIONS,
	OPT_LIVE_TIMER,
};

static struct mi_writer *writer;

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"help", 'h', POPT_ARG_NONE, NULL, OPT_HELP, NULL, NULL},
	{"output", 'o', POPT_ARG_STRING, &opt_output_path, 0, NULL, NULL},
	{"list-options", 0, POPT_ARG_NONE, NULL, OPT_LIST_OPTIONS, NULL, NULL},
	{"set-url",        'U', POPT_ARG_STRING, &opt_url, 0, 0, 0},
	{"ctrl-url",       'C', POPT_ARG_STRING, &opt_ctrl_url, 0, 0, 0},
	{"data-url",       'D', POPT_ARG_STRING, &opt_data_url, 0, 0, 0},
	{"no-output",       0, POPT_ARG_VAL, &opt_no_output, 1, 0, 0},
	{"no-consumer",     0, POPT_ARG_VAL, &opt_no_consumer, 1, 0, 0},
	{"snapshot",        0, POPT_ARG_VAL, &opt_snapshot, 1, 0, 0},
	{"live",            0, POPT_ARG_INT | POPT_ARGFLAG_OPTIONAL, 0, OPT_LIVE_TIMER, 0, 0},
	{"shm-path",        0, POPT_ARG_STRING, &opt_shm_path, 0, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

/*
 * Please have a look at src/lib/lttng-ctl/lttng-ctl.c for more information on
 * why this declaration exists and used ONLY in for this command.
 */
extern int _lttng_create_session_ext(const char *name, const char *url,
		const char *datetime);

/*
 * Retrieve the created session and mi output it based on provided argument
 * This is currently a summary of what was pretty printed and is subject to
 * enhancements.
 */
static int mi_created_session(const char *session_name)
{
	int ret, i, count, found;
	struct lttng_session *sessions;

	/* session_name should not be null */
	assert(session_name);
	assert(writer);

	count = lttng_list_sessions(&sessions);
	if (count < 0) {
		ret = count;
		ERR("%s", lttng_strerror(ret));
		goto error;
	}

	if (count == 0) {
		ERR("Error session creation failed: session %s not found", session_name);
		ret = -LTTNG_ERR_SESS_NOT_FOUND;
		goto end;
	}

	found = 0;
	for (i = 0; i < count; i++) {
		if (strncmp(sessions[i].name, session_name, NAME_MAX) == 0) {
			found = 1;
			ret = mi_lttng_session(writer, &sessions[i], 0);
			if (ret) {
				goto error;
			}
			break;
		}
	}

	if (!found) {
		ret = -LTTNG_ERR_SESS_NOT_FOUND;
	} else {
		ret = CMD_SUCCESS;
	}

error:
	free(sessions);
end:
	return ret;
}

/*
 * For a session name, set the consumer URLs.
 */
static int set_consumer_url(const char *session_name, const char *ctrl_url,
		const char *data_url)
{
	int ret;
	struct lttng_handle *handle;

	assert(session_name);

	/*
	 * Set handle with the session_name, but no domain. This implies that
	 * the actions taken with this handle apply on the tracing session
	 * rather then the domain-specific session.
	 */
	handle = lttng_create_handle(session_name, NULL);
	if (handle == NULL) {
		ret = CMD_FATAL;
		goto error;
	}

	ret = lttng_set_consumer_url(handle, ctrl_url, data_url);
	if (ret < 0) {
		goto error;
	}

	if (ctrl_url) {
		MSG("Control URL %s set for session %s", ctrl_url, session_name);
	}

	if (data_url) {
		MSG("Data URL %s set for session %s", data_url, session_name);
	}

error:
	lttng_destroy_handle(handle);
	return ret;
}

static int add_snapshot_output(const char *session_name, const char *ctrl_url,
		const char *data_url)
{
	int ret;
	struct lttng_snapshot_output *output = NULL;

	assert(session_name);

	output = lttng_snapshot_output_create();
	if (!output) {
		ret = CMD_FATAL;
		goto error_create;
	}

	if (ctrl_url) {
		ret = lttng_snapshot_output_set_ctrl_url(ctrl_url, output);
		if (ret < 0) {
			goto error;
		}
	}

	if (data_url) {
		ret = lttng_snapshot_output_set_data_url(data_url, output);
		if (ret < 0) {
			goto error;
		}
	}

	/* This call, if successful, populates the id of the output object. */
	ret = lttng_snapshot_add_output(session_name, output);
	if (ret < 0) {
		goto error;
	}

error:
	lttng_snapshot_output_destroy(output);
error_create:
	return ret;
}

/*
 *  Create a tracing session.
 *  If no name is specified, a default name is generated.
 *
 *  Returns one of the CMD_* result constants.
 */
static int create_session(void)
{
	int ret;
	char *session_name = NULL, *traces_path = NULL, *alloc_path = NULL;
	char *alloc_url = NULL, *url = NULL, datetime[16];
	char session_name_date[NAME_MAX + 17], *print_str_url = NULL;
	time_t rawtime;
	struct tm *timeinfo;
	char shm_path[PATH_MAX] = "";

	/* Get date and time for automatic session name/path */
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(datetime, sizeof(datetime), "%Y%m%d-%H%M%S", timeinfo);

	/* Auto session name creation */
	if (opt_session_name == NULL) {
		ret = snprintf(session_name_date, sizeof(session_name_date),
				DEFAULT_SESSION_NAME "-%s", datetime);
		if (ret < 0) {
			PERROR("snprintf session name");
			goto error;
		}
		session_name = session_name_date;
		DBG("Auto session name set to %s", session_name_date);
	} else {
		if (strlen(opt_session_name) > NAME_MAX) {
			ERR("Session name too long. Length must be lower or equal to %d",
					NAME_MAX);
			ret = LTTNG_ERR_SESSION_FAIL;
			goto error;
		}
		/*
		 * Check if the session name begins with "auto-" or is exactly "auto".
		 * Both are reserved for the default session name. See bug #449 to
		 * understand why we need to check both here.
		 */
		if ((strncmp(opt_session_name, DEFAULT_SESSION_NAME "-",
					strlen(DEFAULT_SESSION_NAME) + 1) == 0) ||
				(strncmp(opt_session_name, DEFAULT_SESSION_NAME,
					strlen(DEFAULT_SESSION_NAME)) == 0 &&
				strlen(opt_session_name) == strlen(DEFAULT_SESSION_NAME))) {
			ERR("%s is a reserved keyword for default session(s)",
					DEFAULT_SESSION_NAME);
			ret = CMD_ERROR;
			goto error;
		}
		session_name = opt_session_name;
		ret = snprintf(session_name_date, sizeof(session_name_date),
				"%s-%s", session_name, datetime);
		if (ret < 0) {
			PERROR("snprintf session name");
			goto error;
		}
	}

	if ((!opt_ctrl_url && opt_data_url) || (opt_ctrl_url && !opt_data_url)) {
		ERR("You need both control and data URL.");
		ret = CMD_ERROR;
		goto error;
	}

	if (opt_output_path != NULL) {
		traces_path = utils_expand_path(opt_output_path);
		if (traces_path == NULL) {
			ret = CMD_ERROR;
			goto error;
		}

		/* Create URL string from the local file system path */
		ret = asprintf(&alloc_url, "file://%s", traces_path);
		if (ret < 0) {
			PERROR("asprintf url path");
			ret = CMD_FATAL;
			goto error;
		}
		/* URL to use in the lttng_create_session() call */
		url = alloc_url;
		print_str_url = traces_path;
	} else if (opt_url) { /* Handling URL (-U opt) */
		url = opt_url;
		print_str_url = url;
	} else if (opt_data_url && opt_ctrl_url) {
		/*
		 * With both control and data, we'll be setting the consumer URL after
		 * session creation thus use no URL.
		 */
		url = NULL;
	} else if (!opt_no_output) {
		char *tmp_path;

		/* Auto output path */
		tmp_path = utils_get_home_dir();
		if (tmp_path == NULL) {
			ERR("HOME path not found.\n \
					Please specify an output path using -o, --output PATH");
			ret = CMD_FATAL;
			goto error;
		}
		alloc_path = strdup(tmp_path);
		if (!alloc_path) {
			PERROR("allocating alloc_path");
			ret = CMD_FATAL;
			goto error;
		}
		ret = asprintf(&alloc_url,
				"file://%s/" DEFAULT_TRACE_DIR_NAME "/%s",
				alloc_path, session_name_date);
		if (ret < 0) {
			PERROR("asprintf trace dir name");
			ret = CMD_FATAL;
			goto error;
		}

		url = alloc_url;
		print_str_url = alloc_url + strlen("file://");
	} else {
		/* No output means --no-output or --snapshot mode. */
		url = NULL;
	}

	/* Use default live URL if NO url is/are found. */
	if ((opt_live_timer && !opt_url) && (opt_live_timer && !opt_data_url)) {
		/* Override the url */
		free(url);
		url = NULL;

		ret = asprintf(&alloc_url, "net://127.0.0.1");
		if (ret < 0) {
			PERROR("asprintf default live URL");
			ret = CMD_FATAL;
			goto error;
		}
		url = alloc_url;
		print_str_url = url;
	}

	if (opt_snapshot && opt_live_timer) {
		ERR("Snapshot and live modes are mutually exclusive.");
		ret = CMD_ERROR;
		goto error;
	}

	if (opt_snapshot) {
		/* No output by default. */
		const char *snapshot_url = NULL;

		if (opt_url) {
			snapshot_url = url;
		} else if (!opt_data_url && !opt_ctrl_url) {
			/* This is the session path that we need to use as output. */
			snapshot_url = url;
		}
		ret = lttng_create_session_snapshot(session_name, snapshot_url);
	} else if (opt_live_timer) {
		const char *pathname;

		if (opt_relayd_path) {
			pathname = opt_relayd_path;
		} else {
			pathname = INSTALL_BIN_PATH "/lttng-relayd";
		}
		if (!opt_url && !opt_data_url && !check_relayd() &&
				spawn_relayd(pathname, 0) < 0) {
			goto error;
		}
		ret = lttng_create_session_live(session_name, url, opt_live_timer);
	} else {
		ret = _lttng_create_session_ext(session_name, url, datetime);
	}
	if (ret < 0) {
		/* Don't set ret so lttng can interpret the sessiond error. */
		switch (-ret) {
		case LTTNG_ERR_EXIST_SESS:
			WARN("Session %s already exists", session_name);
			break;
		default:
			break;
		}
		goto error;
	}

	if (opt_ctrl_url && opt_data_url) {
		if (opt_snapshot) {
			ret = add_snapshot_output(session_name, opt_ctrl_url,
					opt_data_url);
		} else {
			/* Setting up control URI (-C or/and -D opt) */
			ret = set_consumer_url(session_name, opt_ctrl_url, opt_data_url);
		}
		if (ret < 0) {
			/* Destroy created session because the URL are not valid. */
			lttng_destroy_session(session_name);
			goto error;
		}
	}

	if (opt_shm_path) {
		ret = snprintf(shm_path, sizeof(shm_path),
				"%s/%s", opt_shm_path, session_name_date);
		if (ret < 0) {
			PERROR("snprintf shm_path");
			goto error;
		}

		ret = lttng_set_session_shm_path(session_name, shm_path);
		if (ret < 0) {
			lttng_destroy_session(session_name);
			goto error;
		}
	}

	MSG("Session %s created.", session_name);
	if (print_str_url && !opt_snapshot) {
		MSG("Traces will be written in %s", print_str_url);

		if (opt_live_timer) {
			MSG("Live timer set to %u usec", opt_live_timer);
		}
	} else if (opt_snapshot) {
		if (print_str_url) {
			MSG("Default snapshot output set to: %s", print_str_url);
		}
		MSG("Snapshot mode set. Every channel enabled for that session will "
				"be set to mmap output, and default to overwrite mode.");
	}
	if (opt_shm_path) {
		MSG("Session %s set to shm_path: %s.", session_name,
			shm_path);
	}

	/* Mi output */
	if (lttng_opt_mi) {
		ret = mi_created_session(session_name);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	/* Init lttng session config */
	ret = config_init(session_name);
	if (ret < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	ret = CMD_SUCCESS;

error:
	free(alloc_url);
	free(traces_path);
	free(alloc_path);

	if (ret < 0) {
		ERR("%s", lttng_strerror(ret));
	}
	return ret;
}

/*
 *  spawn_sessiond
 *
 *  Spawn a session daemon by forking and execv.
 */
static int spawn_sessiond(char *pathname)
{
	int ret = 0;
	pid_t pid;

	MSG("Spawning a session daemon");
	pid = fork();
	if (pid == 0) {
		/*
		 * Spawn session daemon in daemon mode.
		 */
		execlp(pathname, "lttng-sessiond",
				"--daemonize", NULL);
		/* execlp only returns if error happened */
		if (errno == ENOENT) {
			ERR("No session daemon found. Use --sessiond-path.");
		} else {
			PERROR("execlp");
		}
		kill(getppid(), SIGTERM);	/* wake parent */
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		/*
		 * In daemon mode (--daemonize), sessiond only exits when
		 * it's ready to accept commands.
		 */
		for (;;) {
			int status;
			pid_t wait_pid_ret = waitpid(pid, &status, 0);

			if (wait_pid_ret < 0) {
				if (errno == EINTR) {
					continue;
				}
				PERROR("waitpid");
				ret = -errno;
				goto end;
			}

			if (WIFSIGNALED(status)) {
				ERR("Session daemon was killed by signal %d",
						WTERMSIG(status));
				ret = -1;
			        goto end;
			} else if (WIFEXITED(status)) {
				DBG("Session daemon terminated normally (exit status: %d)",
						WEXITSTATUS(status));

				if (WEXITSTATUS(status) != 0) {
					ERR("Session daemon terminated with an error (exit status: %d)",
							WEXITSTATUS(status));
					ret = -1;
				        goto end;
				}
				break;
			}
		}

		goto end;
	} else {
		PERROR("fork");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 *  launch_sessiond
 *
 *  Check if the session daemon is available using
 *  the liblttngctl API for the check. If not, try to
 *  spawn a daemon.
 */
static int launch_sessiond(void)
{
	int ret;
	char *pathname = NULL;

	ret = lttng_session_daemon_alive();
	if (ret) {
		/* Sessiond is alive, not an error */
		ret = 0;
		goto end;
	}

	/* Try command line option path */
	pathname = opt_sessiond_path;

	/* Try LTTNG_SESSIOND_PATH env variable */
	if (pathname == NULL) {
		pathname = getenv(DEFAULT_SESSIOND_PATH_ENV);
	}

	/* Try with configured path */
	if (pathname == NULL) {
		if (CONFIG_SESSIOND_BIN[0] != '\0') {
			pathname = CONFIG_SESSIOND_BIN;
		}
	}

	/* Try the default path */
	if (pathname == NULL) {
		pathname = INSTALL_BIN_PATH "/lttng-sessiond";
	}

	DBG("Session daemon binary path: %s", pathname);

	/* Check existence and permissions */
	ret = access(pathname, F_OK | X_OK);
	if (ret < 0) {
		ERR("No such file or access denied: %s", pathname);
		goto end;
	}

	ret = spawn_sessiond(pathname);
end:
	if (ret) {
		ERR("Problem occurred while launching session daemon (%s)",
				pathname);
	}
	return ret;
}

/*
 *  The 'create <options>' first level command
 *
 *  Returns one of the CMD_* result constants.
 */
int cmd_create(int argc, const char **argv)
{
	int opt, ret = CMD_SUCCESS, command_ret = CMD_SUCCESS, success = 1;
	char *opt_arg = NULL;
	static poptContext pc;

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
		case OPT_LIVE_TIMER:
		{
			unsigned long v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);
			if (!opt_arg) {
				/* Set up default values. */
				opt_live_timer = (uint32_t) DEFAULT_LTTNG_LIVE_TIMER;
				DBG("Session live timer interval set to default value %d",
						opt_live_timer);
				break;
			}

			v = strtoul(opt_arg, NULL, 0);
			if (errno != 0 || !isdigit(opt_arg[0])) {
				ERR("Wrong value in --live parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			if (v != (uint32_t) v) {
				ERR("32-bit overflow in --live parameter: %s", opt_arg);
				ret = CMD_ERROR;
				goto end;
			}
			if (v == 0) {
				ERR("Live timer interval must be greater than zero");
				ret = CMD_ERROR;
				goto end;
			}
			opt_live_timer = (uint32_t) v;
			DBG("Session live timer interval set to %d", opt_live_timer);
			break;
		}
		default:
			ret = CMD_UNDEFINED;
			goto end;
		}
	}

	if (opt_no_consumer) {
		MSG("The option --no-consumer is obsolete. Use --no-output now.");
		ret = CMD_WARNING;
		goto end;
	}

	/* Spawn a session daemon if needed */
	if (!opt_no_sessiond) {
		ret = launch_sessiond();
		if (ret) {
			ret = CMD_ERROR;
			goto end;
		}
	}

	/* MI initialization */
	if (lttng_opt_mi) {
		writer = mi_lttng_writer_create(fileno(stdout), lttng_opt_mi);
		if (!writer) {
			ret = -LTTNG_ERR_NOMEM;
			goto end;
		}

		/* Open command element */
		ret = mi_lttng_writer_command_open(writer,
				mi_lttng_element_command_create);
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
	opt_session_name = (char*) poptGetArg(pc);

	command_ret = create_session();
	if (command_ret) {
		success = 0;
	}

	if (lttng_opt_mi) {
		/* Close  output element */
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

	/* Overwrite ret if an error occurred in create_session() */
	ret = command_ret ? command_ret : ret;

	poptFreeContext(pc);
	return ret;
}
