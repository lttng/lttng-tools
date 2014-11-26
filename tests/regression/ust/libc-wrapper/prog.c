/* Copyright (C) 2009  Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

/* This program is used to test malloc instrumentation with libustinstr-malloc.
 */

#include <string.h>
#include <stdlib.h>

#define N_ITER 1000

int main(int argc, char **argv)
{
	int i;
	const char teststr[] = "Hello World! 1234567890abc";
	void *ptrs[N_ITER];

	for (i = 0; i < N_ITER; i++) {
		ptrs[i] = malloc(i+1000);
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
