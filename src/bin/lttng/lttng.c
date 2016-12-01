/*
 * Copyright (c)  2011 David Goulet <david.goulet@polymtl.ca>
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
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <ctype.h>

#include <lttng/lttng.h>
#include <common/error.h>
#include <common/compat/getenv.h>
#include <common/utils.h>

#include "command.h"

static const char *help_msg =
#ifdef LTTNG_EMBED_HELP
#include <lttng.1.h>
#else
NULL
#endif
;

/* Variables */
static char *progname;
int opt_no_sessiond;
char *opt_sessiond_path;

char *opt_relayd_path;

enum {
	OPT_RELAYD_PATH,
	OPT_SESSION_PATH,
	OPT_DUMP_OPTIONS,
	OPT_DUMP_COMMANDS,
};

/* Getopt options. No first level command. */
static struct option long_options[] = {
	{"version",          0, NULL, 'V'},
	{"help",             0, NULL, 'h'},
	{"group",            1, NULL, 'g'},
	{"verbose",          0, NULL, 'v'},
	{"quiet",            0, NULL, 'q'},
	{"mi",               1, NULL, 'm'},
	{"no-sessiond",      0, NULL, 'n'},
	{"sessiond-path",    1, NULL, OPT_SESSION_PATH},
	{"relayd-path",      1, NULL, OPT_RELAYD_PATH},
	{"list-options",     0, NULL, OPT_DUMP_OPTIONS},
	{"list-commands",    0, NULL, OPT_DUMP_COMMANDS},
	{NULL, 0, NULL, 0}
};

/* First level command */
static struct cmd_struct commands[] =  {
	{ "add-context", cmd_add_context},
	{ "create", cmd_create},
	{ "destroy", cmd_destroy},
	{ "disable-channel", cmd_disable_channels},
	{ "disable-event", cmd_disable_events},
	{ "enable-channel", cmd_enable_channels},
	{ "enable-event", cmd_enable_events},
	{ "help", NULL},
	{ "list", cmd_list},
	{ "load", cmd_load},
	{ "metadata", cmd_metadata},
	{ "regenerate", cmd_regenerate},
	{ "save", cmd_save},
	{ "set-session", cmd_set_session},
	{ "snapshot", cmd_snapshot},
	{ "start", cmd_start},
	{ "status", cmd_status},
	{ "stop", cmd_stop},
	{ "track", cmd_track},
	{ "untrack", cmd_untrack},
	{ "version", cmd_version},
	{ "view", cmd_view},
	{ NULL, NULL}	/* Array closure */
};

static void version(FILE *ofp)
{
	fprintf(ofp, "%s (LTTng Trace Control) " VERSION" - " VERSION_NAME "%s\n",
			progname,
			GIT_VERSION[0] == '\0' ? "" : " - " GIT_VERSION);
}

/*
 * Find the MI output type enum from a string. This function is for the support
 * of machine interface output.
 */
static int mi_output_type(const char *output_type)
{
	int ret = 0;

	if (!strncasecmp("xml", output_type, 3)) {
		ret = LTTNG_MI_XML;
	} else {
		/* Invalid output format */
		ERR("MI output format not supported");
		ret = -LTTNG_ERR_MI_OUTPUT_TYPE;
	}

	return ret;
}

/*
 *  list_options
 *
 *  List options line by line. This is mostly for bash auto completion and to
 *  avoid difficult parsing.
 */
static void list_options(FILE *ofp)
{
	int i = 0;
	struct option *option = NULL;

	option = &long_options[i];
	while (option->name != NULL) {
		fprintf(ofp, "--%s\n", option->name);

		if (isprint(option->val)) {
			fprintf(ofp, "-%c\n", option->val);
		}

		i++;
		option = &long_options[i];
	}
}

/*
 * clean_exit
 */
static void clean_exit(int code)
{
	DBG("Clean exit");
	exit(code);
}

/*
 *  sighandler
 *
 *  Signal handler for the daemon
 */
static void sighandler(int sig)
{
	switch (sig) {
		case SIGTERM:
			DBG("SIGTERM caught");
			clean_exit(EXIT_FAILURE);
			break;
		default:
			DBG("Unknown signal %d caught", sig);
			break;
	}

	return;
}

/*
 *  set_signal_handler
 *
 *  Setup signal handler for SIGCHLD and SIGTERM.
 */
static int set_signal_handler(void)
{
	int ret = 0;
	struct sigaction sa;
	sigset_t sigset;

	if ((ret = sigemptyset(&sigset)) < 0) {
		PERROR("sigemptyset");
		goto end;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;

	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		PERROR("sigaction");
		goto end;
	}

end:
	return ret;
}

/*
 *  handle_command
 *
 *  Handle the full argv list of a first level command. Will find the command
 *  in the global commands array and call the function callback associated.
 *
 *  If command not found, return -1
 *  else, return function command error code.
 */
static int handle_command(int argc, char **argv)
{
	int i = 0, ret;
	struct cmd_struct *cmd;

	if (*argv == NULL) {
		ret = CMD_SUCCESS;
		goto end;
	}

	/* Special case for help command which needs the commands array */
	if (strcmp(argv[0], "help") == 0) {
		ret = cmd_help(argc, (const char**) argv, commands);
		goto end;
	}

	cmd = &commands[i];
	while (cmd->name != NULL) {
		/* Find command */
		if (strcmp(argv[0], cmd->name) == 0) {
			ret = cmd->func(argc, (const char**) argv);
			goto end;
		}
		i++;
		cmd = &commands[i];
	}

	/* Command not found */
	ret = CMD_UNDEFINED;

end:
	return ret;
}

static void show_basic_help(void)
{
	puts("Usage: lttng [--group=GROUP] [--mi=TYPE] [--no-sessiond | --sessiond-path=PATH]");
	puts("             [--quiet | -v | -vv | -vvv] COMMAND [COMMAND OPTIONS]");
	puts("");
	puts("Available commands:");
	puts("");
	puts("Tracing sessions:");
	puts("  create            " CONFIG_CMD_DESCR_CREATE);
	puts("  destroy           " CONFIG_CMD_DESCR_DESTROY);
	puts("  load              " CONFIG_CMD_DESCR_LOAD);
	puts("  regenerate        " CONFIG_CMD_DESCR_REGENERATE);
	puts("  save              " CONFIG_CMD_DESCR_SAVE);
	puts("  set-session       " CONFIG_CMD_DESCR_SET_SESSION);
	puts("");
	puts("Channels:");
	puts("  add-context       " CONFIG_CMD_DESCR_ADD_CONTEXT);
	puts("  disable-channel   " CONFIG_CMD_DESCR_DISABLE_CHANNEL);
	puts("  enable-channel    " CONFIG_CMD_DESCR_ENABLE_CHANNEL);
	puts("");
	puts("Event rules:");
	puts("  disable-event     " CONFIG_CMD_DESCR_DISABLE_EVENT);
	puts("  enable-event      " CONFIG_CMD_DESCR_ENABLE_EVENT);
	puts("");
	puts("Status:");
	puts("  list              " CONFIG_CMD_DESCR_LIST);
	puts("  status            " CONFIG_CMD_DESCR_STATUS);
	puts("");
	puts("Control:");
	puts("  snapshot          " CONFIG_CMD_DESCR_SNAPSHOT);
	puts("  start             " CONFIG_CMD_DESCR_START);
	puts("  stop              " CONFIG_CMD_DESCR_STOP);
	puts("");
	puts("Resource tracking:");
	puts("  track             " CONFIG_CMD_DESCR_TRACK);
	puts("  untrack           " CONFIG_CMD_DESCR_UNTRACK);
	puts("");
	puts("Miscellaneous:");
	puts("  help              " CONFIG_CMD_DESCR_HELP);
	puts("  version           " CONFIG_CMD_DESCR_VERSION);
	puts("  view              " CONFIG_CMD_DESCR_VIEW);
	puts("");
	puts("Run `lttng help COMMAND` or `lttng COMMAND --help` to get help with");
	puts("command COMMAND.");
	puts("");
	puts("See `man lttng` for more help with the lttng command.");
}

/*
 * Parse command line arguments.
 *
 * Return 0 if OK, else -1
 */
static int parse_args(int argc, char **argv)
{
	int opt, ret;

	if (lttng_is_setuid_setgid()) {
		ERR("'%s' is not allowed to be executed as a setuid/setgid binary for security reasons. Aborting.", argv[0]);
		clean_exit(EXIT_FAILURE);
	}

	if (argc < 2) {
		show_basic_help();
		clean_exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv, "+Vhnvqg:m:", long_options, NULL)) != -1) {
		switch (opt) {
		case 'V':
			version(stdout);
			ret = 0;
			goto end;
		case 'h':
			ret = utils_show_help(1, "lttng", help_msg);
			if (ret) {
				ERR("Cannot show --help for `lttng`");
				perror("exec");
			}
			goto end;
		case 'v':
			/* There is only 3 possible level of verbosity. (-vvv) */
			if (lttng_opt_verbose < 3) {
				lttng_opt_verbose += 1;
			}
			break;
		case 'q':
			lttng_opt_quiet = 1;
			break;
		case 'm':
			lttng_opt_mi = mi_output_type(optarg);
			if (lttng_opt_mi < 0) {
				ret = lttng_opt_mi;
				goto error;
			}
			break;
		case 'g':
			lttng_set_tracing_group(optarg);
			break;
		case 'n':
			opt_no_sessiond = 1;
			break;
		case OPT_SESSION_PATH:
			free(opt_sessiond_path);
			opt_sessiond_path = strdup(optarg);
			if (!opt_sessiond_path) {
				ret = -1;
				goto error;
			}
			break;
		case OPT_RELAYD_PATH:
			free(opt_relayd_path);
			opt_relayd_path = strdup(optarg);
			if (!opt_relayd_path) {
				ret = -1;
				goto error;
			}
			break;
		case OPT_DUMP_OPTIONS:
			list_options(stdout);
			ret = 0;
			goto end;
		case OPT_DUMP_COMMANDS:
			list_commands(commands, stdout);
			ret = 0;
			goto end;
		default:
			ret = 1;
			goto error;
		}
	}

	/* If both options are specified, quiet wins */
	if (lttng_opt_verbose && lttng_opt_quiet) {
		lttng_opt_verbose = 0;
	}

	/* No leftovers, quit */
	if ((argc - optind) == 0) {
		ret = 1;
		goto error;
	}

	/*
	 * Handle leftovers which is a first level command with the trailing
	 * options.
	 */
	ret = handle_command(argc - optind, argv + optind);
	switch (ret) {
	case CMD_WARNING:
		WARN("Some command(s) went wrong");
		break;
	case CMD_ERROR:
		ERR("Command error");
		break;
	case CMD_UNDEFINED:
		ERR("Undefined command or invalid arguments");
		break;
	case CMD_FATAL:
		ERR("Fatal error");
		break;
	case CMD_UNSUPPORTED:
		ERR("Unsupported command");
		break;
	case -1:
		ret = 1;
		break;
	case 0:
		break;
	default:
		if (ret < 0) {
			ret = -ret;
		}
		break;
	}

end:
error:
	return ret;
}


/*
 *  main
 */
int main(int argc, char *argv[])
{
	int ret;

	progname = argv[0] ? argv[0] : "lttng";

	ret = set_signal_handler();
	if (ret < 0) {
		clean_exit(ret);
	}

	ret = parse_args(argc, argv);
	if (ret != 0) {
		clean_exit(ret);
	}

	return 0;
}
