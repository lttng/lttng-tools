/*
 * Copyright (C) 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <dlfcn.h>
#include <popt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if HAS_CALLSITES
#include "callsites.h"
#endif

void exec_callsite(void);
void exec_callsite(void)
{
#if HAS_CALLSITES
	call_tracepoint();
#endif
}

static void print_list(void)
{
	fprintf(stderr, "Test list (-t X):\n");
	fprintf(stderr,
		"\t0: dlopen() all libraries pass in arguments and execute "
		"the callsite.\n");
	fprintf(stderr,
		"\t1: simulate the upgrade of a probe provider using dlopen() and dlclose(). \n");
	fprintf(stderr,
		"\t2: simulate the upgrade of a library containing the callsites using dlopen() and dlclose(). \n");
}

#if HAS_CALLSITES
static int dl_open_all(int nb_libraries, char **libraries)
{
	int i, ret = 0;
	void **handles;

	handles = malloc(nb_libraries * sizeof(void *));
	if (!handles) {
		ret = -1;
		goto error;
	}

	/* Iterate over the libs to dlopen and save the handles. */
	for (i = 0; i < nb_libraries; i++) {
		handles[i] = dlopen(libraries[i], RTLD_NOW);
		if (!handles[i]) {
			ret = -1;
			goto error;
		}
	}

	exec_callsite();
error:
	free(handles);
	return ret;
}

/*
 * Takes 2 paths to libraries, dlopen() the first, trace, dlopen() the second,
 * and dlclose the first to simulate the upgrade of a library.
 */
static int upgrade_lib(int nb_libraries, char **libraries)
{
	int i, ret = 0;
	void *handles[2];

	if (nb_libraries != 2) {
		ret = -1;
		goto error;
	}

	/* Iterate over the libs to dlopen and save the handles. */
	for (i = 0; i < nb_libraries; i++) {
		handles[i] = dlopen(libraries[i], RTLD_NOW);
		if (!handles[i]) {
			ret = -1;
			goto error;
		}

		exec_callsite();
	}

	ret = dlclose(handles[0]);
	if (ret) {
		goto error;
	}

	exec_callsite();

error:
	return ret;
}
#endif /* HAS_CALLSITES */

#if !HAS_CALLSITES
/*
 * Simulate the upgrade of a library containing a callsite.
 * Receives two libraries containing callsites for the same tracepoint.
 */
static int upgrade_callsite(int nb_libraries, char **libraries)
{
	int ret = 0;
	void *handles[2];
	void (*fct_ptr[2])(void);

	if (nb_libraries != 2) {
		ret = -1;
		goto error;
	}

	/* Load the probes in the first library. */
	handles[0] = dlopen(libraries[0], RTLD_NOW);
	if (!handles[0]) {
		ret = -1;
		goto error;
	}

	/*
	 * Get the pointer to the old function containing the callsite and call it.
	 */
	fct_ptr[0] = dlsym(handles[0], "call_tracepoint");
	if (!fct_ptr[0]) {
		ret = -1;
		goto error;
	}
	fct_ptr[0]();

	/* Load the new callsite library. */
	handles[1] = dlopen(libraries[1], RTLD_NOW);
	if (!handles[1]) {
		ret = -1;
		goto error;
	}

	/*
	 * Get the pointer to the new function containing the callsite and call it.
	 */
	fct_ptr[1] = dlsym(handles[1], "call_tracepoint");
	if (!fct_ptr[1]) {
		ret = -1;
		goto error;
	}
	fct_ptr[1]();

	/* Unload the old callsite library. */
	ret = dlclose(handles[0]);
	if (ret) {
		goto error;
	}

	/* Call the function containing the callsite in the new library. */
	fct_ptr[1]();

	ret = dlclose(handles[1]);
	if (ret) {
		goto error;
	}

error:
	return ret;
}
#endif /* !HAS_CALLSITES */

int main(int argc, const char **argv)
{
	int c, ret = 0, test = -1, nb_libraries = 0;
	char **libraries = NULL;
	poptContext optCon;
	struct poptOption optionsTable[] = {
		{ "test", 't', POPT_ARG_INT, &test, 0, "Test to run", NULL },
		{ "list", 'l', 0, 0, 'l', "List of tests (-t X)", NULL },
		POPT_AUTOHELP{ NULL, 0, 0, NULL, 0, NULL, NULL }
	};

	optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
	if (argc < 2) {
		poptPrintUsage(optCon, stderr, 0);
		ret = -1;
		goto error;
	}

	while ((c = poptGetNextOpt(optCon)) >= 0) {
		switch (c) {
		case 'l':
			print_list();
			goto error;
		}
	}

	/*
	 * Populate the libraries array with the arguments passed to the process.
	 */
	while (poptPeekArg(optCon) != NULL) {
		char **realloced_libraries = NULL;

		nb_libraries++;
		realloced_libraries = realloc(libraries, nb_libraries * sizeof(char *));
		if (!realloced_libraries) {
			ret = -1;
			goto error;
		}
		libraries = realloced_libraries;
		libraries[nb_libraries - 1] = (char *) poptGetArg(optCon);
	}

	switch (test) {
	case 0:
#if HAS_CALLSITES
		ret = dl_open_all(nb_libraries, libraries);
#else
		fprintf(stderr,
			"Test not implemented for configuration "
			"(HAS_CALLSITES=%d)\n",
			HAS_CALLSITES == 1);
#endif
		break;
	case 1:
#if HAS_CALLSITES
		ret = upgrade_lib(nb_libraries, libraries);
#else
		fprintf(stderr,
			"Test not implemented for configuration "
			"(HAS_CALLSITES=%d)\n",
			HAS_CALLSITES == 1);
#endif
		break;
	case 2:
#if !HAS_CALLSITES
		ret = upgrade_callsite(nb_libraries, libraries);
#else
		fprintf(stderr,
			"Test not implemented for configuration "
			"(HAS_CALLSITES=%d)\n",
			HAS_CALLSITES == 1);
#endif
		break;
	default:
		fprintf(stderr, "Test %d not implemented\n", test);
		ret = -1;
		break;
	}
error:
	free(libraries);
	poptFreeContext(optCon);
	return ret;
}
