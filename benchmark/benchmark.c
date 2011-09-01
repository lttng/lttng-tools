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

FILE *fp;
static double g_freq;

static double calibrate_cpu_freq(void)
{
	int i, nb_calib = 10;
	double freq;

	printf("CPU frequency calibration, this should take 10 seconds\n");

	/* CPU Frequency calibration */
	for (i = 0; i < nb_calib; i++) {
		freq += (double) get_cpu_freq();
	}
	return (freq / (double)nb_calib);
}

static void close_logs(void)
{
	fclose(fp);
}

static void open_logs(void)
{
	fp = fopen(RESULTS_FILE_NAME, "a");
	if (fp == NULL) {
		perror("fopen benchmark");
	}
}

static double get_bench_time(cycles_t before, cycles_t after)
{
	double ret;

	ret = (((double)(after - before) / (g_freq / 1000.0)) / 1000000000.0);

	return ret;
}

void bench_init(void)
{
	open_logs();
	if (g_freq == 0) {
		g_freq = calibrate_cpu_freq();
		//fprintf(fp, "CPU frequency %f Ghz\n\n", g_freq);
	}
}

void bench_close(void)
{
	close_logs();
	printf("Benchmark results in %s\n", RESULTS_FILE_NAME);
}

double bench_get_create_session(void)
{
	if ((time_create_session_start == 0) &&
			(time_create_session_end == 0)) {
		fprintf(fp, "NO DATA\n");
		return 0;
	}

	return get_bench_time(time_create_session_start, time_create_session_end);
}

double bench_get_destroy_session(void)
{
	if ((time_destroy_session_start == 0) &&
			(time_destroy_session_end == 0)) {
		fprintf(fp, "NO DATA\n");
		return 0;
	}

	return get_bench_time(time_destroy_session_start, time_destroy_session_end);
}

/*
 * Complete UST notification process time break down in different actions.
 */
void bench_print_ust_notification(void)
{
	double res, total = 0;

	fprintf(fp, "--- UST notification time ---\n");

	if (time_ust_notify_mmap_start == 0 || time_ust_notify_mmap_stop == 0) {
		goto no_data;
	}

	res = get_bench_time(time_ust_notify_mmap_start,
			time_ust_notify_mmap_stop);
	fprintf(fp, "mmap() call time\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	total += res;

	if (time_ust_notify_perms_start == 0 || time_ust_notify_perms_stop == 0) {
		goto no_data;
	}

	res = get_bench_time(time_ust_notify_perms_start,
			time_ust_notify_perms_stop);
	fprintf(fp, "Setting permissions (chown/chmod)\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	total += res;

	if (time_ust_notify_shm_start == 0 || time_ust_notify_shm_stop == 0) {
		goto no_data;
	}

	res = get_bench_time(time_ust_notify_shm_start,
			time_ust_notify_shm_stop);
	fprintf(fp, "shm_open/ftruncate/fchmod\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	total += res;

	fprintf(fp, "Global UST nonification time\n");
	fprintf(fp, "Time: %.20f sec.\n", total);
	return;

no_data:
	fprintf(fp, "NO DATA\n");
	return;
}

/*
 * This time value is only coherent is an UST application registered.
 */
void bench_print_ust_register(void)
{
	double res, total = 0;

	fprintf(fp, "--- UST registration time ---\n");

	if (time_ust_register_start == 0 || time_ust_register_stop == 0) {
		goto no_data;
	}

	res = get_bench_time(time_ust_register_start, time_ust_register_stop);
	fprintf(fp, "UST registration received and send to dispatch time\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	total += res;

	if (time_ust_dispatch_register_start == 0 ||
			time_ust_dispatch_register_stop == 0) {
		goto no_data;
	}

	res = get_bench_time(time_ust_dispatch_register_start,
			time_ust_dispatch_register_stop);
	fprintf(fp, "Dispatch UST registration request time\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	total += res;

	if (time_ust_manage_register_start == 0 ||
			time_ust_manage_register_stop == 0) {
		goto no_data;
	}

	res = get_bench_time(time_ust_manage_register_start,
			time_ust_manage_register_stop);
	fprintf(fp, "Manage UST registration time\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	total += res;

	fprintf(fp, "Global time of an UST application registration\n");
	fprintf(fp, "Time: %.20f sec.\n", total);
	return;

no_data:
	fprintf(fp, "NO DATA\n");
	return;
}


/*
 * Log results of the sessiond boot process.
 *
 * Uses all time_sessiond_* values (see measures.h)
 */
void bench_print_boot_process(void)
{
	double res;
	double global_boot_time = 0.0;

	fprintf(fp, "--- Session daemon boot process ---\n");

	res = get_bench_time(time_sessiond_boot_start, time_sessiond_boot_end);

	fprintf(fp, "Boot time inside main() from start to first pthread_join (blocking state)\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	global_boot_time += res;

	res = get_bench_time(time_sessiond_th_kern_start, time_sessiond_th_kern_poll);

	fprintf(fp, "Boot time of the kernel thread from start to poll() (ready state)\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	global_boot_time += res;

	res = get_bench_time(time_sessiond_th_apps_start, time_sessiond_th_apps_poll);

	fprintf(fp, "Boot time of the application thread from start to poll() (ready state)\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	global_boot_time += res;

	res = get_bench_time(time_sessiond_th_cli_start, time_sessiond_th_cli_poll);

	fprintf(fp, "Boot time of the client thread from start to poll() (ready state)\n");
	fprintf(fp, "Time: %.20f sec.\n", res);

	global_boot_time += res;

	fprintf(fp, "Global Boot Time of ltt-sessiond: %0.20f sec.\n", global_boot_time);
}
