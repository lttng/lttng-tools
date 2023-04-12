/* Copyright (C) 2009 Pierre-Marc Fournier
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

/* This program is used to test malloc instrumentation with libustinstr-malloc.
 */

#include <stdlib.h>
#include <string.h>

#define N_ITER 1000

int main(void)
{
	int i;
	const char teststr[] = "Hello World! 1234567890abc";
	void *ptrs[N_ITER];

	for (i = 0; i < N_ITER; i++) {
		ptrs[i] = malloc(i + 1000);
		if (!ptrs[i]) {
			exit(EXIT_FAILURE);
		}

		memcpy(ptrs[i], teststr, sizeof(teststr));

		if (i % 2 == 0) {
			free(ptrs[i]);
		}
	}

	for (i = 0; i < N_ITER; i++) {
		if (i % 2 == 1)
			free(ptrs[i]);
	}

	return 0;
}
