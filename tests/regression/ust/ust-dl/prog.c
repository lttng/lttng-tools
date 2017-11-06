/* _GNU_SOURCE is defined by config.h */
#include <dlfcn.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

/*
 * libfoo has a direct dependency on libbar.
 * libbar has a direct dependency on libzzz.
 * This test is therefore a mix of dlopen/dlclose and dlmopen/dlclose of
 * libfoo, and of its direct dependencies.
 */
int main(int argc, char **argv)
{
	void *h0, *h2, *h3, *h4;

#ifdef HAVE_DLMOPEN
	void *h1;
#endif

	char *error;
	int (*foo)(void);

	h0 = dlopen("libbar.so", RTLD_LAZY);
	if (!h0) {
		goto get_error;
	}

#ifdef HAVE_DLMOPEN
	h1 = dlmopen(LM_ID_BASE, "libfoo.so", RTLD_LAZY);
	if (!h1) {
		goto get_error;
	}
#endif

	h2 = dlopen("libzzz.so", RTLD_LAZY);
	if (!h2) {
		goto get_error;
	}
	h3 = dlopen("libfoo.so", RTLD_LAZY);
	if (!h3) {
		goto get_error;
	}
	h4 = dlopen("libfoo.so", RTLD_LAZY);
	if (!h4) {
		goto get_error;
	}

	foo = dlsym(h3, "foo");
	error = dlerror();
	if (error != NULL) {
		goto error;
	}

	foo();

	if (dlclose(h0)) {
		goto get_error;
	}

#ifdef HAVE_DLMOPEN
	if (dlclose(h1)) {
		goto get_error;
	}
#endif

	if (dlclose(h2)) {
		goto get_error;
	}
	if (dlclose(h3)) {
		goto get_error;
	}
	if (dlclose(h4)) {
		goto get_error;
	}

	exit(EXIT_SUCCESS);

get_error:
	error = dlerror();
error:
	fprintf(stderr, "%s\n", error);
	exit(EXIT_FAILURE);
}
