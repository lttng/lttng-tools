/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <popt.h>
#include <stdlib.h>

#include "lttng.h"

/* Option variables */
char *opt_tracing_group;
char *opt_session_uuid;
char *opt_sessiond_path;
char *opt_session_name;
int opt_create_session;
int opt_destroy_session;
int opt_trace_kernel = 0;
int opt_quiet = 0;
int opt_verbose = 0;
int opt_list_apps = 0;
int opt_no_sessiond = 0;
int opt_list_session = 0;
int opt_list_traces = 0;
int opt_create_trace = 0;
int opt_start_trace = 0;
int opt_stop_trace = 0;
pid_t opt_trace_pid = 0;

enum {
	OPT_HELP = 42,
	OPT_CREATE_SESSION,
	OPT_DESTROY_SESSION,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{"create-session",  'c',	POPT_ARG_STRING,	0, OPT_CREATE_SESSION, 0, 0},
	{"create-trace",	'C',	POPT_ARG_VAL,		&opt_create_trace, 1, 0, 0},
	{"destroy-session", 'd',	POPT_ARG_STRING,	0, OPT_DESTROY_SESSION, 0, 0},
	{"group",			0,		POPT_ARG_STRING,	&opt_tracing_group, 0, 0, 0},
	{"help",			'h',	POPT_ARG_NONE,		0, OPT_HELP, 0, 0},
	{"kernel",			0,		POPT_ARG_VAL,		&opt_trace_kernel, 1, 0, 0},
	{"list-apps",		'L',	POPT_ARG_VAL,		&opt_list_apps, 1, 0, 0},
	{"list-sessions",	'l',	POPT_ARG_VAL,		&opt_list_session, 1, 0, 0},
	{"list-traces",		't',	POPT_ARG_VAL,		&opt_list_traces, 1, 0, 0},
	{"no-kernel",		0,		POPT_ARG_VAL,		&opt_trace_kernel, 0, 0, 0},
	{"no-sessiond",		0,		POPT_ARG_VAL,		&opt_no_sessiond, 1, 0, 0},
	{"pid",				'p',	POPT_ARG_INT,		&opt_trace_pid, 0, 0, 0},
	{"quiet",			'q',	POPT_ARG_VAL,		&opt_quiet, 1, 0, 0},
	{"session",			's',	POPT_ARG_STRING,	&opt_session_uuid, 0, 0, 0},
	{"sessiond-path",	0,		POPT_ARG_STRING,	&opt_sessiond_path, 0, 0, 0},
	{"start",			0,		POPT_ARG_VAL,		&opt_start_trace, 1, 0, 0},
	{"stop",			0,		POPT_ARG_VAL,		&opt_stop_trace, 1, 0, 0},
	{"verbose",			'v',	POPT_ARG_VAL,		&opt_verbose, 1, 0, 0},
	//{"session",			0,		POPT_ARG_STRING | POPT_ARGFLAG_OPTIONAL, &opt_session_name, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};


/*
 * 	usage
 */
static void usage(FILE *ofp)
{
	fprintf(ofp, "LTTng Trace Control " VERSION"\n\n");
	fprintf(ofp, "usage : lttng [OPTION]\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Options:\n");
	fprintf(ofp, "  -v, --verbose                Verbose mode\n");
	fprintf(ofp, "  -q, --quiet                  Quiet mode\n");
	fprintf(ofp, "      --help                   Show help\n");
	fprintf(ofp, "      --group NAME             Unix tracing group name. (default: tracing)\n");
	fprintf(ofp, "      --no-sessiond            Don't spawn a session daemon\n");
	fprintf(ofp, "      --sessiond-path          Session daemon full path\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Session options:\n");
	fprintf(ofp, "  -c, --create-session NAME    Create a new session\n");
	fprintf(ofp, "  -l, --list-sessions          List all available sessions\n");
	fprintf(ofp, "  -s, --session UUID           Specify tracing session using UUID\n");
	fprintf(ofp, "  -d, --destroy-session=NAME   Destroy the session specified by NAME\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Tracing options:\n");
	//fprintf(ofp, "      --kernel               Enable kernel tracing\n");
	//fprintf(ofp, "      --no-kernel            Disable kernel tracing\n");
	fprintf(ofp, "  -p, --pid PID                Set tracing action for PID\n");
	fprintf(ofp, "  -L, --list-apps              List traceable UST applications\n");
	fprintf(ofp, "  -t, --list-traces            List session's traces. Use -s to specify the session\n");
	fprintf(ofp, "  -C, --create-trace           Create a trace\n");
	fprintf(ofp, "      --start                  Start tracing\n");
	fprintf(ofp, "      --stop                   Stop tracing\n");
	fprintf(ofp, "\n");
	fprintf(ofp, "Please see the lttng(1) man page for full documentation.\n");
	fprintf(ofp, "See http://lttng.org/ust for updates, bug reports and news.\n");
}

/*
 *  parse_args
 *
 *  Parse command line arguments.
 *  Return 0 if OK, else -1
 */
int parse_args(int argc, const char **argv)
{
	static poptContext pc;
	int opt;

	/* If no options, fail */
	if (argc < 2) {
		return -1;
	}

	pc = poptGetContext(NULL, argc, argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
		case OPT_HELP:
			usage(stderr);
			clean_exit(EXIT_SUCCESS);
			break;
		case OPT_CREATE_SESSION:
			opt_create_session = 1;
			opt_session_name = poptGetOptArg(pc);
			break;
		case OPT_DESTROY_SESSION:
			opt_destroy_session = 1;
			opt_session_uuid = poptGetOptArg(pc);
			break;
		default:
			usage(stderr);
			clean_exit(EXIT_FAILURE);
			break;
		}
	}

	if (pc) {
		poptFreeContext(pc);
	}

	return 0;
}
