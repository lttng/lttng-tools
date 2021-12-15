/*
 * Copyright (C) 2011 EfficiOS Inc.
 * Copyright (C) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <lttng/constant.h>

#include <common/compat/errno.hpp>
#include "error.hpp"
#include "macros.hpp"
#include "spawn-viewer.hpp"


static const char *babeltrace_bin = CONFIG_BABELTRACE_BIN;
static const char *babeltrace2_bin = CONFIG_BABELTRACE2_BIN;

/*
 * This is needed for each viewer since we are using execvp().
 */
static const char *babeltrace_opts[] = { "babeltrace" };
static const char *babeltrace2_opts[] = { "babeltrace2" };

/*
 * Type is also use as the index in the viewers array. So please, make sure
 * your enum value is in the right order in the array below.
 */
enum viewer_type {
	VIEWER_BABELTRACE    = 0,
	VIEWER_BABELTRACE2   = 1,
	VIEWER_USER_DEFINED  = 2,
};

static const struct viewer {
	const char *exec_name;
	enum viewer_type type;
} viewers[] = {
	{ "babeltrace", VIEWER_BABELTRACE },
	{ "babeltrace2", VIEWER_BABELTRACE2 },
	{ NULL, VIEWER_USER_DEFINED },
};

static const struct viewer *parse_viewer_option(const char *opt_viewer)
{
	if (opt_viewer == NULL) {
		/* Default is babeltrace2 */
		return &(viewers[VIEWER_BABELTRACE2]);
	}

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
	char **argv, *token = opts, *saveptr = NULL;

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
	argv = (char **) zmalloc(sizeof(char *) * (num_opts + 2));
	if (argv == NULL) {
		goto error;
	}

	token = strtok_r(opts, " ", &saveptr);
	while (token != NULL) {
		argv[i] = strdup(token);
		if (argv[i] == NULL) {
			goto error;
		}
		token = strtok_r(NULL, " ", &saveptr);
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
		const char *trace_path, bool opt_live_mode)
{
	char **argv;
	size_t size, mem_len;

	/* Add one for the NULL terminating element. */
	mem_len = opts_len + 1;
	if (opt_live_mode) {
		/* Add 3 option for the live mode being "-i lttng-live URL". */
		mem_len += 3;
	} else {
		/* Add option for the trace path. */
		mem_len += 1;
	}

	size = sizeof(char *) * mem_len;

	/* Add two here for the trace_path and the NULL terminating element. */
	argv = (char **) zmalloc(size);
	if (argv == NULL) {
		goto error;
	}

	memcpy(argv, opts, sizeof(char *) * opts_len);

	if (opt_live_mode) {
		argv[opts_len] = (char *) "-i";
		argv[opts_len + 1] = (char *) "lttng-live";
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
int spawn_viewer(const char *trace_path, char *opt_viewer, bool opt_live_mode)
{
	int ret = 0;
	struct stat status;
	const char *viewer_bin = NULL;
	const struct viewer *viewer;
	char **argv = NULL;

	/* Check for --viewer option. */
	viewer = parse_viewer_option(opt_viewer);
	if (viewer == NULL) {
		ret = -1;
		goto error;
	}

retry_viewer:
	switch (viewer->type) {
	case VIEWER_BABELTRACE2:
		if (stat(babeltrace2_bin, &status) == 0) {
			viewer_bin = babeltrace2_bin;
		} else {
			viewer_bin = viewer->exec_name;
		}
		argv = alloc_argv_from_local_opts(babeltrace2_opts,
				ARRAY_SIZE(babeltrace2_opts), trace_path,
				opt_live_mode);
		break;
	case VIEWER_BABELTRACE:
		if (stat(babeltrace_bin, &status) == 0) {
			viewer_bin = babeltrace_bin;
		} else {
			viewer_bin = viewer->exec_name;
		}
		argv = alloc_argv_from_local_opts(babeltrace_opts,
				ARRAY_SIZE(babeltrace_opts), trace_path,
				opt_live_mode);
		break;
	case VIEWER_USER_DEFINED:
		argv = alloc_argv_from_user_opts(opt_viewer, trace_path);
		if (argv) {
			viewer_bin = argv[0];
		}
		break;
	default:
		abort();
	}

	if (argv == NULL || !viewer_bin) {
		ret = -1;
		goto error;
	}

	DBG("Using %s viewer", viewer_bin);

	ret = execvp(viewer_bin, argv);
	if (ret) {
		if (errno == ENOENT && viewer->exec_name) {
			if (viewer->type == VIEWER_BABELTRACE2) {
				/* Fallback to legacy babeltrace. */
				DBG("Default viewer \"%s\" not installed on the system, falling back to \"%s\"",
						viewers[VIEWER_BABELTRACE2].exec_name,
						viewers[VIEWER_BABELTRACE].exec_name);
				viewer = &viewers[VIEWER_BABELTRACE];
				free(argv);
				argv = NULL;
				goto retry_viewer;
			} else {
				ERR("Default viewer \"%s\" (and fallback \"%s\") not found on the system",
						viewers[VIEWER_BABELTRACE2].exec_name,
						viewers[VIEWER_BABELTRACE].exec_name);
			}
		} else {
			PERROR("Failed to launch \"%s\" viewer", viewer_bin);
		}
		ret = -1;
		goto error;
	}

	/*
	 * This function should never return if successfull because `execvp(3)`
	 * onle returns if an error has occurred.
	 */
	LTTNG_ASSERT(ret != 0);
error:
	free(argv);
	return ret;
}
