/*
 * Copyright (c)  2011 David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lttng/lttng.h>

#include "cmd.h"
#include "conf.h"
#include "lttngerr.h"

/* Variables */
static char *progname;

int opt_quiet;
int opt_verbose;
static int opt_no_sessiond;
static char *opt_sessiond_path;

enum {
	OPT_SESSION_PATH,
	OPT_DUMP_OPTIONS,
	OPT_DUMP_COMMANDS,
};

/* Getopt options. No first level command. */
static struct option long_options[] = {
	{"help",             0, NULL, 'h'},
	{"group",            1, NULL, 'g'},
	{"verbose",          0, NULL, 'v'},
	{"quiet",            0, NULL, 'q'},
	{"no-sessiond",      0, NULL, 'n'},
	{"sessiond-path",    1, NULL, OPT_SESSION_PATH},
	{"list-options",     0, NULL, OPT_DUMP_OPTIONS},
	{"list-commands",    0, NULL, OPT_DUMP_COMMANDS},
	{NULL, 0, NULL, 0}
};

/* First level command */
static struct cmd_struct commands[] =  {
	{ "list", cmd_list},
	{ "create", cmd_create},
	{ "destroy", cmd_destroy},
	{ "add-channel", cmd_add_channel},
	{ "start", cmd_start},
	{ "stop", cmd_stop},
	{ "enable-event", cmd_enable_events},
	{ "disable-event", cmd_disable_events},
	{ "enable-channel", cmd_enable_channels},
	{ "disable-channel", cmd_disable_channels},
	{ "add-context", cmd_add_context},
	{ "set-session", cmd_set_session},
	{ "version", cmd_version},
	{ NULL, NULL}	/* Array closure */
};

static void usage(FILE *ofp)
{
	fprintf(ofp, "LTTng Trace Control " VERSION"\n\n");
	fprintf(ofp, "usage: lttng [options] <command>\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -h, --help             Show this help\n");
	fprintf(ofp, "  -g, --group NAME       Unix tracing group name. (default: tracing)\n");
	fprintf(ofp, "  -v, --verbose          Verbose mode\n");
	fprintf(ofp, "  -q, --quiet            Quiet mode\n");
	fprintf(ofp, "  -n, --no-sessiond      Don't spawn a session daemon\n");
	fprintf(ofp, "      --sessiond-path    Session daemon full path\n");
	fprintf(ofp, "      --list-options     Simple listing of lttng options\n");
	fprintf(ofp, "      --list-commands    Simple listing of lttng commands\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Commands:\n");
	fprintf(ofp, "    add-channel     Add channel to tracer\n");
	fprintf(ofp, "    add-context     Add context to event or/and channel\n");
	fprintf(ofp, "    create          Create tracing session\n");
	fprintf(ofp, "    destroy         Teardown tracing session\n");
	fprintf(ofp, "    enable-channel  Enable tracing channel\n");
	fprintf(ofp, "    enable-event    Enable tracing event\n");
	fprintf(ofp, "    disable-channel Disable tracing channel\n");
	fprintf(ofp, "    disable-event   Disable tracing event\n");
	fprintf(ofp, "    list            List possible tracing options\n");
	fprintf(ofp, "    set-session     Set current session name\n");
	fprintf(ofp, "    start           Start tracing\n");
	fprintf(ofp, "    stop            Stop tracing\n");
	fprintf(ofp, "    version         Show version information\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Please see the lttng(1) man page for full documentation.\n");
	fprintf(ofp, "See http://lttng.org for updates, bug reports and news.\n");
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
 *  list_commands
 *
 *  List commands line by line. This is mostly for bash auto completion and to
 *  avoid difficult parsing.
 */
static void list_commands(FILE *ofp)
{
	int i = 0;
	struct cmd_struct *cmd = NULL;

	cmd = &commands[i];
	while (cmd->name != NULL) {
		fprintf(ofp, "%s\n", cmd->name);
		i++;
		cmd = &commands[i];
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
			DBG("SIGTERM catched");
			clean_exit(EXIT_FAILURE);
			break;
		case SIGCHLD:
			/* Notify is done */
			DBG("SIGCHLD catched");
			break;
		default:
			DBG("Unknown signal %d catched", sig);
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
		perror("sigemptyset");
		goto end;
	}

	sa.sa_handler = sighandler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	if ((ret = sigaction(SIGCHLD, &sa, NULL)) < 0) {
		perror("sigaction");
		goto end;
	}

	if ((ret = sigaction(SIGTERM, &sa, NULL)) < 0) {
		perror("sigaction");
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

	cmd = &commands[i];
	while (cmd->func != NULL) {
		/* Find command */
		if (strcmp(argv[0], cmd->name) == 0) {
			ret = cmd->func(argc, (const char**) argv);
			switch (ret) {
			case CMD_ERROR:
				ERR("Command error");
				break;
			case CMD_NOT_IMPLEMENTED:
				ERR("Options not implemented");
				break;
			case CMD_UNDEFINED:
				ERR("Undefined command");
				break;
			case CMD_FATAL:
				ERR("Fatal error");
				break;
			}
			goto end;
		}
		i++;
		cmd = &commands[i];
	}

	/* Command not found */
	ret = -1;

end:
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
		 * Spawn session daemon and tell
		 * it to signal us when ready.
		 */
		execlp(pathname, "ltt-sessiond", "--sig-parent", "--quiet", NULL);
		/* execlp only returns if error happened */
		if (errno == ENOENT) {
			ERR("No session daemon found. Use --sessiond-path.");
		} else {
			perror("execlp");
		}
		kill(getppid(), SIGTERM);	/* unpause parent */
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		/* Wait for ltt-sessiond to start */
		pause();
		goto end;
	} else {
		perror("fork");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 *  check_sessiond
 *
 *  Check if the session daemon is available using
 *  the liblttngctl API for the check. If not, try to
 *  spawn a daemon.
 */
static int check_sessiond(void)
{
	int ret;
	char *pathname = NULL, *alloc_pathname = NULL;

	ret = lttng_session_daemon_alive();
	if (ret == 0) {	/* not alive */
		/* Try command line option path */
		if (opt_sessiond_path != NULL) {
			ret = access(opt_sessiond_path, F_OK | X_OK);
			if (ret < 0) {
				ERR("No such file: %s", opt_sessiond_path);
				goto end;
			}
			pathname = opt_sessiond_path;
		} else {
			/* Try LTTNG_SESSIOND_PATH env variable */
			pathname = getenv(LTTNG_SESSIOND_PATH_ENV);
		}

		/* Let's rock and roll */
		if (pathname == NULL) {
			ret = asprintf(&alloc_pathname, "ltt-sessiond");
			if (ret < 0) {
				goto end;
			}
			pathname = alloc_pathname;
		}

		ret = spawn_sessiond(pathname);
		free(alloc_pathname);
		if (ret < 0) {
			ERR("Problem occurs when starting %s", pathname);
			goto end;
		}
	}

end:
	return ret;
}

/*
 *  parse_args
 *
 *  Parse command line arguments.
 *  Return 0 if OK, else -1
 */
static int parse_args(int argc, char **argv)
{
	int opt, ret;

	if (argc < 2) {
		usage(stderr);
		clean_exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv, "+hnvqg:", long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(stderr);
			goto error;
		case 'v':
			opt_verbose = 1;
			break;
		case 'q':
			opt_quiet = 1;
			break;
		case 'g':
			lttng_set_tracing_group(optarg);
			break;
		case 'n':
			opt_no_sessiond = 1;
			break;
		case OPT_SESSION_PATH:
			opt_sessiond_path = strdup(optarg);
			break;
		case OPT_DUMP_OPTIONS:
			list_options(stdout);
			ret = 0;
			goto error;
		case OPT_DUMP_COMMANDS:
			list_commands(stdout);
			ret = 0;
			goto error;
		default:
			usage(stderr);
			goto error;
		}
	}

	/* If both options are specified, quiet wins */
	if (opt_verbose && opt_quiet) {
		opt_verbose = 0;
	}

	/* Spawn session daemon if needed */
	if (opt_no_sessiond == 0 && (check_sessiond() < 0)) {
		goto error;
	}

	/* No leftovers, print usage and quit */
	if ((argc - optind) == 0) {
		usage(stderr);
		goto error;
	}

	/* 
	 * Handle leftovers which is a first level command with the trailing
	 * options.
	 */
	ret = handle_command(argc - optind, argv + optind);
	if (ret < 0) {
		if (ret == -1) {
			usage(stderr);
		} else {
			ERR("%s", lttng_get_readable_code(ret));
		}
		goto error;
	}

	return 0;

error:
	return -1;
}


/*
 *  main
 */
int main(int argc, char *argv[])
{
	int ret;

	progname = argv[0] ? argv[0] : "lttng";

	/* For Mathieu Desnoyers aka Dr Tracing */
	if (strncmp(progname, "drtrace", 7) == 0) {
		MSG("%c[%d;%dmWelcome back Dr Tracing!%c[%dm\n\n", 27,1,33,27,0);
	}

	ret = set_signal_handler();
	if (ret < 0) {
		clean_exit(ret);
	}

	ret = parse_args(argc, argv);
	if (ret < 0) {
		clean_exit(EXIT_FAILURE);
	}

	return 0;
}
