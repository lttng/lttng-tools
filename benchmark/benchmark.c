/*
 * Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; only version 2
 * of the License.
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

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "benchmark.h"

static FILE *fp;

void benchmark_print_boot_results(void)
{
	uint64_t freq = 0;
	double res;
	int i, nb_calib = 10;
	double global_boot_time = 0.0;

	fp = fopen(RESULTS_FILE_NAME, "w");
	if (fp == NULL) {
		perror("fopen benchmark");
		return;
	}

	/* CPU Frequency calibration */
	for (i = 0; i < nb_calib; i++) {
		freq += get_cpu_freq();
	}
	freq = freq / nb_calib;

	fprintf(fp, "CPU frequency %lu Ghz\n\n", freq);

	fprintf(fp, "Results:\n----------\n");

	res = (double) (((double)(time_sessiond_boot_end - time_sessiond_boot_start)
				/ (((double)freq) / 1000)) / 1000000000);

	fprintf(fp, "Boot time inside main() from start to first pthread_join (blocking state)\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	global_boot_time += res;

	res = (double) (((double)(time_sessiond_th_kern_poll - time_sessiond_th_kern_start)
				/ (((double)freq) / 1000)) / 1000000000);

	fprintf(fp, "Boot time of the kernel thread from start to poll() (ready state)\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	global_boot_time += res;

	res = (double) (((double)(time_sessiond_th_apps_poll - time_sessiond_th_apps_start)
				/ (((double)freq) / 1000)) / 1000000000);

	fprintf(fp, "Boot time of the application thread from start to poll() (ready state)\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	global_boot_time += res;

	res = (double) (((double)(time_sessiond_th_cli_poll - time_sessiond_th_cli_start)
				/ (((double)freq) / 1000)) / 1000000000);

	fprintf(fp, "Boot time of the client thread from start to poll() (ready state)\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	global_boot_time += res;

	fprintf(fp, "Global Boot Time of ltt-sessiond: %0.20f sec.\n", global_boot_time);

	fclose(fp);
}
