/*
 * Copyright (C) 2019 Michael Jeanson <mjeanson@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <popt.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdarg.h>

#include <common/compat/tid.h>

#include "utils.h"
#include "signal-helper.h"

#define TRACEPOINT_DEFINE
#include "tp.h"

#define LTTNG_PROC_NS_PATH_MAX 40

static int nr_iter = 100;
static int debug = 0;
static char *ns_opt = NULL;
static char *after_unshare_file_path = NULL;
static char *before_second_event_file_path = NULL;

static
struct poptOption opts[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "debug", 'd', POPT_ARG_NONE, &debug, 0, "Enable debug output", NULL },
	{ "ns", 'n', POPT_ARG_STRING, &ns_opt, 0, "Namespace short identifier", NULL },
	{ "iter", 'i', POPT_ARG_INT, &nr_iter, 0, "Number of tracepoint iterations", NULL },
	{ "after", 'a', POPT_ARG_STRING, &after_unshare_file_path, 0, "after_unshare_file_path,", NULL },
	{ "before", 'b', POPT_ARG_STRING, &before_second_event_file_path, 0, "before_second_event_file_path,", NULL },
	POPT_AUTOHELP
	{ NULL, 0, 0, NULL, 0 }
};

static
void debug_printf(const char *format, ...) {
	va_list args;
	va_start(args, format);

	if (debug)
		vfprintf(stderr, format, args);

	va_end(args);
}

static
ino_t get_ns_inum(char ns[]) {
	struct stat sb;
	char proc_ns_path[LTTNG_PROC_NS_PATH_MAX];

	/*
	 * /proc/thread-self was introduced in kernel v3.17
	 */
	if (snprintf(proc_ns_path, LTTNG_PROC_NS_PATH_MAX,
				"/proc/thread-self/ns/%s", ns) >= 0) {
		if (stat(proc_ns_path, &sb) == 0) {
			return sb.st_ino;
		}
	}

	if (snprintf(proc_ns_path, LTTNG_PROC_NS_PATH_MAX,
			"/proc/self/task/%d/%s/net",
			lttng_gettid(), ns) >= 0) {

		if (stat(proc_ns_path, &sb) == 0) {
			return sb.st_ino;
		}
	}

	return 1;
}

static
int do_the_needful(int ns_flag, char ns_str[]) {
	int ret = 0, i;
	ino_t ns1, ns2;

	ns1 = get_ns_inum(ns_str);
	debug_printf("Initial %s ns inode number:      %lu\n", ns_str, ns1);

	for (i = 0; nr_iter < 0 || i < nr_iter; i++) {

		tracepoint(tp, tptest, ns1);

		if (should_quit) {
			break;
		}
	}

	ret = unshare(ns_flag);

	if (ret == -1) {
		perror("unshare");
		ret = 0;
	}

	ns2 = get_ns_inum(ns_str);
	debug_printf("Post unshare %s ns inode number: %lu\n", ns_str, ns2);

	/*
	 * Signal that we emited the first event group and that the
	 * unshare call is completed.
	 */
	if (after_unshare_file_path) {
		ret = create_file(after_unshare_file_path);

		if (ret != 0) {
			goto end;
		}
	}

	/*
	 * Wait on synchronization before writing second event group.
	 */
	if (before_second_event_file_path) {
		ret = wait_on_file(before_second_event_file_path);
		if (ret != 0) {
			goto end;
		}
	}

	for (i = 0; nr_iter < 0 || i < nr_iter; i++) {

		tracepoint(tp, tptest, ns2);

		if (should_quit) {
			break;
		}
	}

end:
	return ret;
}

// Send X events, change NS, wait for file to sync with test script, send X events in new NS


int main(int argc, const char **argv) {
	int opt;
	int ret = EXIT_SUCCESS;
	poptContext pc;

	pc = poptGetContext(NULL, argc, argv, opts, 0);
	poptReadDefaultConfig(pc, 0);

	if (argc < 2) {
		poptPrintHelp(pc, stderr, 0);
		ret = EXIT_FAILURE;
		goto end;
	}

	while ((opt = poptGetNextOpt(pc)) >= 0) {
		switch(opt) {
		default:
			poptPrintUsage(pc, stderr, 0);
			ret = EXIT_FAILURE;
			goto end;
		}
	}

	if (opt < -1) {
		/* an error occurred during option processing */
		poptPrintUsage(pc, stderr, 0);
		fprintf(stderr, "%s: %s\n",
				poptBadOption(pc, POPT_BADOPTION_NOALIAS),
				poptStrerror(opt));
		ret = EXIT_FAILURE;
		goto end;
	}

	if (ns_opt == NULL) {
		poptPrintUsage(pc, stderr, 0);
		ret = EXIT_FAILURE;
		goto end;
	}

	if (set_signal_handler()) {
		ret = EXIT_FAILURE;
		goto end;
	}

	if (strncmp(ns_opt, "cgroup", 3) == 0) {
		do_the_needful(CLONE_NEWCGROUP, "cgroup");
	} else if (strncmp(ns_opt, "ipc", 3) == 0) {
		do_the_needful(CLONE_NEWIPC, "ipc");
	} else if (strncmp(ns_opt, "mnt", 3) == 0) {
		do_the_needful(CLONE_NEWNS, "mnt");
	} else if (strncmp(ns_opt, "net", 3) == 0) {
		do_the_needful(CLONE_NEWNET, "net");
	} else if (strncmp(ns_opt, "pid", 3) == 0) {
		do_the_needful(CLONE_NEWPID, "pid");
	} else if (strncmp(ns_opt, "user", 3) == 0) {
		// Will always fail, requires a single threaded application, which can't happen with UST.
		do_the_needful(CLONE_NEWUSER, "user");
	} else if (strncmp(ns_opt, "uts", 3) == 0) {
		do_the_needful(CLONE_NEWUTS, "uts");
	} else {
		printf("invalid ns id\n");
		ret = EXIT_FAILURE;
	}

end:
	poptFreeContext(pc);
	return ret;
}
