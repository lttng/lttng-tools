/*
 * Copyright (C) - 2018 Francis Deslauriers <francis.deslauriers@efficios.com>
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

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <popt.h>

#if defined(CALLSITES)
	#include "callsites.h"
#endif

void exec_callsite(int arg)
{
#if defined(CALLSITES)
	call_tracepoint(arg);
#endif
}

void print_list(void)
{
	fprintf(stderr, "Test list (-t X):\n");
	fprintf(stderr, "\t0: dlopen all libraries pass in arguments and execute "
			"the callsite. \n");
	fprintf(stderr, "\t1: simulate the upgrade of a probe provider using dlopen and dlclose \n");
	fprintf(stderr, "\t2: simulate the upgrade of a library containing the callsites using dlopen and dlclose \n");
}


int dl_open_all(int nb_libraries, char **libraries)
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

	exec_callsite(11111);
error:
	return ret;
}

/*
 * Takes 2 paths to libraries, dlopen() the first, trace, dlopen() the second,
 * and dlclose the first to simulate the upgrade of a library.
 */
int upgrade_lib(int nb_libraries, char **libraries)
{
	int i, ret = 0;
	void **handles;
	if (nb_libraries != 2) {
		ret = -1;
		goto error;
	}

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

		exec_callsite(i);
	}
	ret = dlclose(handles[0]);
	if (ret) {
		goto error;
	}

	exec_callsite(i+1);

error:
	return ret;
}

/*
 * Simulate the upgrade of a library containing a callsite.
 * Receives two libraries containing callsites for the same tracepoint.
 */
int upgrade_callsite(int nb_libraries, char **libraries)
{
	int ret = 0;
	void *handles[2];
	void (*fct_ptr[2])(int);

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

	fct_ptr[0](11111);

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

	fct_ptr[1](22222);

	/* Unload the old callsite library. */
	ret = dlclose(handles[0]);
	if (ret) {
		goto error;
	}

	/* Call the function containing the callsite in the new library. */
	fct_ptr[1](33333);

	ret = dlclose(handles[1]);
	if (ret) {
		goto error;
	}

error:
	return ret;
}

int main(int argc, const char **argv) {
	int c, ret, test = -1, nb_libraries = 0;
	char **libraries = NULL;
	poptContext optCon;

	struct poptOption optionsTable[] = {
		{ "test", 't', POPT_ARG_INT, &test, 0,
			"Test to run", NULL },
		{ "list", 'l', 0, 0, 'l',
			"List of tests (-t X)", NULL },
		POPT_AUTOHELP
		{ NULL, 0, 0, NULL, 0 }
	};

	optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);

	if (argc < 2) {
		poptPrintUsage(optCon, stderr, 0);
		ret = -1;
		goto error;
	}

	ret = 0;

	while ((c = poptGetNextOpt(optCon)) >= 0) {
		switch(c) {
		case 'l':
			print_list();
			goto error;
		}
	}
	/* Populate the libraries array with the arguments passed to the process. */
	while (poptPeekArg(optCon) != NULL) {
		nb_libraries++;
		libraries = realloc(libraries, nb_libraries * sizeof(char *));
		if (!libraries) {
			ret = -1;
			goto error;
		}
		libraries[nb_libraries-1] = (char*)poptGetArg(optCon);
	}

	switch(test) {
	case 0:
#if defined(CALLSITES)
		ret = dl_open_all(nb_libraries, libraries);
#else
		fprintf(stderr, "Test not implemented for configuration.");
#endif
		break;
	case 1:
#if defined(CALLSITES)
		ret = upgrade_lib(nb_libraries, libraries);
#else
		fprintf(stderr, "Test not implemented for configuration.");
#endif
		break;
	case 2:
#if defined(PROBES)
		ret = upgrade_callsite(nb_libraries, libraries);
#else
		fprintf(stderr, "Test not implemented for configuration.");
#endif
		break;
	case 3:
#if defined(BARE)
		ret = upgrade_callsite(nb_libraries, libraries);
#else
		fprintf(stderr, "Test not implemented for configuration.");
#endif
		break;
	default:
		fprintf(stderr, "Test %d not implemented\n", test);
		ret = -1;
		break;
	}
error:
	poptFreeContext(optCon);
	return ret;
}
