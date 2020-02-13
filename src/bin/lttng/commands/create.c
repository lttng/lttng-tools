/*
 * Copyright (C) 2011 David Goulet <david.goulet@polymtl.ca>
 * Copyright (C) 2019 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
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
#include <lttng/session-descriptor.h>

static char *opt_output_path;
static char *opt_session_name;
static char *opt_url;
static char *opt_ctrl_url;
static char *opt_data_url;
static char *opt_shm_path;
static int opt_no_consumer;
static int opt_no_output;
static int opt_snapshot;
static uint32_t opt_live_timer;

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

enum output_type {
	OUTPUT_NONE,
	OUTPUT_LOCAL,
	OUTPUT_NETWORK,
	OUTPUT_UNSPECIFIED,
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

static
struct lttng_session_descriptor *create_session_descriptor(void)
{
	int ret;
	ssize_t uri_count;
	enum output_type output_type;
	struct lttng_uri *uris = NULL;
	struct lttng_session_descriptor *descriptor = NULL;
	const char *uri_str1 = NULL, *uri_str2 = NULL;
	char local_output_path[LTTNG_PATH_MAX] = {};

	if (opt_no_output) {
		output_type = OUTPUT_NONE;
	} else if (opt_output_path) {
		char *expanded_output_path;

		output_type = OUTPUT_LOCAL;
		expanded_output_path = utils_expand_path(opt_output_path);
		if (!expanded_output_path) {
			ERR("Failed to expand output path.");
			goto end;
		}
		ret = lttng_strncpy(local_output_path, expanded_output_path,
				sizeof(local_output_path));
		free(expanded_output_path);
		if (ret) {
			ERR("Output path exceeds the maximal supported length (%zu bytes)",
					sizeof(local_output_path));
			goto end;
		}
	} else if (opt_url || opt_ctrl_url) {
		uri_str1 = opt_ctrl_url ? opt_ctrl_url : opt_url;
		uri_str2 = opt_data_url;

		uri_count = uri_parse_str_urls(uri_str1, uri_str2, &uris);
		if (uri_count != 1 && uri_count != 2) {
			ERR("Unrecognized URL format.");
			goto end;
		}

		switch (uri_count) {
		case 1:
			output_type = OUTPUT_LOCAL;
			if (uris[0].dtype != LTTNG_DST_PATH) {
				ERR("Unrecognized URL format.");
				goto end;
			}
			ret = lttng_strncpy(local_output_path, uris[0].dst.path,
					sizeof(local_output_path));
			if (ret) {
				ERR("Output path exceeds the maximal supported length (%zu bytes)",
						sizeof(local_output_path));
			}
			break;
		case 2:
			output_type = OUTPUT_NETWORK;
			break;
		default:
			/* Already checked. */
			abort();
		}
	} else {
		output_type = OUTPUT_UNSPECIFIED;
	}

	if (opt_snapshot) {
		/* Snapshot session. */
		switch (output_type) {
		case OUTPUT_UNSPECIFIED:
		case OUTPUT_LOCAL:
			descriptor = lttng_session_descriptor_snapshot_local_create(
					opt_session_name,
					output_type == OUTPUT_LOCAL ?
						local_output_path : NULL);
			break;
		case OUTPUT_NONE:
			descriptor = lttng_session_descriptor_snapshot_create(
					opt_session_name);
			break;
		case OUTPUT_NETWORK:
			descriptor = lttng_session_descriptor_snapshot_network_create(
					opt_session_name, uri_str1, uri_str2);
			break;
		default:
			abort();
		}
	} else if (opt_live_timer) {
		/* Live session. */
		if (output_type != OUTPUT_UNSPECIFIED &&
				output_type != OUTPUT_NETWORK) {
			ERR("Unsupported output type specified for live session.");
			goto end;
		}
		descriptor = lttng_session_descriptor_live_network_create(
				opt_session_name, uri_str1, uri_str2,
				opt_live_timer);
	} else {
		/* Regular session. */
		switch (output_type) {
		case OUTPUT_UNSPECIFIED:
		case OUTPUT_LOCAL:
			descriptor = lttng_session_descriptor_local_create(
					opt_session_name,
					output_type == OUTPUT_LOCAL ?
						local_output_path : NULL);
			break;
		case OUTPUT_NONE:
			descriptor = lttng_session_descriptor_create(
					opt_session_name);
			break;
		case OUTPUT_NETWORK:
			descriptor = lttng_session_descriptor_network_create(
					opt_session_name, uri_str1, uri_str2);
			break;
		default:
			abort();
		}
	}
	if (!descriptor) {
		ERR("Failed to initialize session creation command.");
	} else {
		/*
		 * Auto-launch the relay daemon when a live session
		 * is created using default URLs.
		 */
		if (!opt_url && !opt_ctrl_url && !opt_data_url &&
				opt_live_timer && !check_relayd()) {
			int ret;
			const char *pathname = opt_relayd_path ? :
					INSTALL_BIN_PATH "/lttng-relayd";

			ret = spawn_relayd(pathname, 0);
			if (ret < 0) {
				lttng_session_descriptor_destroy(descriptor);
				descriptor = NULL;
			}
		}
	}
end:
	free(uris);
	return descriptor;
}

/*
 *  Create a tracing session.
 *  If no name is specified, a default name is generated.
 *
 *  Returns one of the CMD_* result constants.
 */
static int create_session(void)
{
	int ret, i;
	char shm_path[LTTNG_PATH_MAX] = {};
	struct lttng_session_descriptor *session_descriptor = NULL;
	enum lttng_session_descriptor_status descriptor_status;
	enum lttng_error_code ret_code;
	struct lttng_session *sessions = NULL;
	const struct lttng_session *created_session = NULL;
	const char *created_session_name;

	/* Validate options. */
	if (opt_session_name) {
		if (strlen(opt_session_name) > NAME_MAX) {
			ERR("Session name too long. Length must be lower or equal to %d",
					NAME_MAX);
			ret = CMD_ERROR;
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
	}

	if (opt_snapshot && opt_live_timer) {
		ERR("Snapshot and live modes are mutually exclusive.");
		ret = CMD_ERROR;
		goto error;
	}

	if ((!opt_ctrl_url && opt_data_url) || (opt_ctrl_url && !opt_data_url)) {
		ERR("Both control and data URLs must be specified.");
		ret = CMD_ERROR;
		goto error;
	}

	session_descriptor = create_session_descriptor();
	if (!session_descriptor) {
		ret = CMD_ERROR;
		goto error;
	}
	ret_code = lttng_create_session_ext(session_descriptor);
	if (ret_code != LTTNG_OK) {
		ERR("%s", lttng_strerror(-ret_code));
		ret = CMD_ERROR;
		goto error;
	}

	descriptor_status = lttng_session_descriptor_get_session_name(
		session_descriptor, &created_session_name);
	if (descriptor_status != LTTNG_SESSION_DESCRIPTOR_STATUS_OK) {
		ERR("Failed to obtain created session name");
		ret = CMD_ERROR;
		goto error;
	}

	ret = lttng_list_sessions(&sessions);
	if (ret < 0) {
		ERR("Failed to fetch properties of created session: %s",
				lttng_strerror(ret));
		ret = CMD_ERROR;
		goto error;
	}
	for (i = 0; i < ret; i++) {
		if (!strcmp(created_session_name, sessions[i].name)) {
			created_session = &sessions[i];
			break;
		}
	}
	if (!created_session) {
		ERR("Failed to fetch properties of created session");
		ret = CMD_ERROR;
		goto error;
	}

	if (opt_shm_path) {
		char datetime_suffix[17] = {};

		/*
		 * An auto-generated session name already includes the creation
		 * timestamp.
		 */
		if (opt_session_name) {
			uint64_t creation_time;
			struct tm *timeinfo;
			time_t creation_time_t;
			size_t strftime_ret;

			ret_code = lttng_session_get_creation_time(
					created_session,
					&creation_time);
			if (ret_code != LTTNG_OK) {
				ERR("%s", lttng_strerror(-ret_code));
				ret = CMD_ERROR;
				goto error;
			}
			creation_time_t = (time_t) creation_time;
			timeinfo = localtime(&creation_time_t);
			if (!timeinfo) {
				PERROR("Failed to interpret session creation time");
				ret = CMD_ERROR;
				goto error;
			}
			strftime_ret = strftime(datetime_suffix,
					sizeof(datetime_suffix),
					"-%Y%m%d-%H%M%S", timeinfo);
			if (strftime_ret == 0) {
				ERR("Failed to format session creation time.");
				ret = CMD_ERROR;
				goto error;
			}
		}

		ret = snprintf(shm_path, sizeof(shm_path),
				"%s/%s%s", opt_shm_path, created_session_name,
				datetime_suffix);
		if (ret < 0 || ret >= sizeof(shm_path)) {
			ERR("Failed to format the shared memory path.");
			ret = CMD_ERROR;
			goto error;
		}
		ret = lttng_set_session_shm_path(created_session_name,
				shm_path);
		if (ret < 0) {
			lttng_destroy_session(created_session_name);
			ret = CMD_ERROR;
			goto error;
		}
	}

	if (opt_snapshot) {
		MSG("Snapshot session %s created.", created_session_name);
	} else if (opt_live_timer) {
		MSG("Live session %s created.", created_session_name);
	} else {
		MSG("Session %s created.", created_session_name);
	}

	if (*created_session->path && !opt_snapshot) {
		MSG("Traces will be output to %s", created_session->path);

		if (opt_live_timer) {
			MSG("Live timer interval set to %u %s", opt_live_timer,
					USEC_UNIT);
		}
	} else if (opt_snapshot) {
		struct lttng_snapshot_output_list *list;
		struct lttng_snapshot_output *iter;
		char snapshot_url[LTTNG_PATH_MAX] = {};

		ret = lttng_snapshot_list_output(created_session_name, &list);
		if (ret < 0) {
			ERR("Failed to list snapshot outputs.");
			ret = CMD_ERROR;
			goto error;
		}

		while ((iter = lttng_snapshot_output_list_get_next(list))) {
			const char *url = NULL;

			url = lttng_snapshot_output_get_ctrl_url(
					iter);
			ret = lttng_strncpy(snapshot_url, url,
					sizeof(snapshot_url));
			if (ret) {
				snapshot_url[0] = '\0';
				ERR("Failed to retrieve snapshot output destination");
			}
			break;
		}
		lttng_snapshot_output_list_destroy(list);

		if (*snapshot_url) {
			MSG("Default snapshot output set to %s",
					snapshot_url);
		}
		MSG("Every channel enabled for this session will be set to mmap output and default to overwrite mode.");
	}
	if (opt_shm_path) {
		MSG("Shared memory path set to %s", shm_path);
	}

	/* Mi output */
	if (lttng_opt_mi) {
		ret = mi_created_session(created_session_name);
		if (ret) {
			ret = CMD_ERROR;
			goto error;
		}
	}

	/* Init lttng session config */
	ret = config_init(created_session_name);
	if (ret < 0) {
		ret = CMD_ERROR;
		goto error;
	}

	ret = CMD_SUCCESS;
error:
	lttng_session_descriptor_destroy(session_descriptor);
	free(sessions);
	return ret;
}

/*
 *  spawn_sessiond
 *
 *  Spawn a session daemon by forking and execv.
 */
static int spawn_sessiond(const char *pathname)
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
	const char *pathname = NULL;

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

static
int validate_url_option_combination(void)
{
	int ret = 0;
	int used_count = 0;

	used_count += !!opt_url;
	used_count += !!opt_output_path;
	used_count += (opt_data_url || opt_ctrl_url);
	if (used_count > 1) {
		ERR("Only one of the --set-url, --ctrl-url/data-url, or --output options may be used at once.");
		ret = -1;
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
	const char *leftover = NULL;
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
			uint64_t v;

			errno = 0;
			opt_arg = poptGetOptArg(pc);
			if (!opt_arg) {
				/* Set up default values. */
				opt_live_timer = (uint32_t) DEFAULT_LTTNG_LIVE_TIMER;
				DBG("Session live timer interval set to default value %d",
						opt_live_timer);
				break;
			}

			if (utils_parse_time_suffix(opt_arg, &v) < 0) {
				ERR("Wrong value for --live parameter: %s", opt_arg);
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

	ret = validate_url_option_combination();
	if (ret) {
		ret = CMD_ERROR;
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

	leftover = poptGetArg(pc);
	if (leftover) {
		ERR("Unknown argument: %s", leftover);
		ret = CMD_ERROR;
		goto end;
	}

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
