/*
 * lttng-ust-getcpu-override-test.c
 * Based on lttng-getcpu-override-example.c from LTTng-ust exemple
 *
 * Copyright (c) 2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (c) 2015 Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <common/compat/time.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <lttng/ust-getcpu.h>

static long nprocessors;

int plugin_getcpu(void)
{
	/* Generate a sequence based on the number of configurated processor
	 * by using sequence[i] % nb_configured_processors. Where sequence
	 * is a static random sequence.
	 * The expected cpu_id sequence can be regenerated on the test script
	 * side and compared to the extracted cpu sequence for validation.
	 * This does no guarantee in absolute the validity of the getcpu
	 * plugin but provide a strong argument of it's validity.
	 */
	static int i = 0;
	static int seq_seed[256] = { 100, 57, 232, 236, 42, 193, 224, 184, 216,
		150, 92, 91, 108, 118, 55, 243, 65, 101, 209, 0, 147, 36, 29,
		34, 49, 188, 174, 105, 253, 245, 227, 238, 112, 20, 222, 201,
		102, 175, 119, 19, 132, 41, 78, 90, 114, 64, 138, 14, 48, 18,
		162, 85, 204, 124, 133, 73, 172, 106, 241, 126, 28, 104, 111,
		21, 127, 219, 9, 244, 237, 189, 59, 214, 52, 141, 107, 26, 25,
		199, 3, 157, 117, 234, 33, 44, 46, 84, 69, 155, 122, 250, 231,
		86, 239, 76, 190, 120, 1, 94, 206, 8, 148, 159, 167, 215, 164,
		31, 217, 61, 71, 125, 68, 109, 195, 177, 95, 82, 142, 182, 129,
		87, 37, 140, 134, 186, 173, 39, 116, 143, 254, 229, 131, 67,
		121, 192, 240, 15, 221, 30, 242, 185, 80, 170, 135, 51, 187,
		194, 246, 12, 225, 181, 137, 211, 228, 88, 218, 27, 233, 161,
		77, 252, 123, 93, 220, 248, 205, 223, 144, 128, 196, 70, 247,
		210, 178, 203, 154, 24, 169, 149, 163, 35, 7, 151, 103, 197,
		139, 165, 158, 207, 72, 113, 145, 45, 183, 11, 198, 43, 81, 230,
		97, 96, 2, 66, 213, 146, 179, 22, 58, 54, 38, 160, 200, 235,
		226, 156, 56, 208, 249, 32, 176, 168, 110, 191, 79, 152, 115,
		10, 74, 60, 251, 17, 83, 180, 171, 202, 40, 166, 255, 53, 212,
		98, 5, 50, 99, 4, 89, 13, 63, 6, 136, 153, 23, 16, 47, 130, 75,
		62 };
	int ret;

	ret = seq_seed[i] % nprocessors;
	i++;
	i = i % 256;
	return ret;
}

void lttng_ust_getcpu_plugin_init(void)
{
	int ret;

	nprocessors = sysconf(_SC_NPROCESSORS_CONF);
	if (nprocessors < 0) {
		perror("Failed to get _SC_NPROCESSORS_CONF");
		goto error;
	}

	ret = lttng_ust_getcpu_override(plugin_getcpu);
	if (ret) {
		fprintf(stderr, "Error enabling getcpu override: %s\n",
			strerror(-ret));
		goto error;
	}
	return;

error:
	exit(EXIT_FAILURE);
}
