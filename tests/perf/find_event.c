/*
 * Copyright (C) 2016 Julien Desfossez <jdesfossez@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <errno.h>
#include <linux/perf_event.h>
#include <perfmon/perf_event.h>
#include <perfmon/pfmlib_perf_event.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	int ret, fd;

	/* pfm query objects */
	pfm_perf_encode_arg_t pencoder;
	pfm_event_info_t info;

	/* Perf event object to be populated by libpfm */
	struct perf_event_attr attr;

	if (argc != 2) {
		fprintf(stderr,
			"Usage: %s <pmu counter to find>\n"
			"ex: %s UNHALTED_REFERENCE_CYCLES\n"
			"Returns the event raw number if found and actionable with"
			"return code 0.\n"
			"If not found returns 1,"
			"If not actionable return 2,"
			"on error returns 255\n",
			argv[0],
			argv[0]);
		ret = -1;
		goto end;
	}

	/* Initialize perf_event_attr. */
	memset(&attr, 0, sizeof(struct perf_event_attr));

	/* Initialize libpfm encoder structure. */
	memset(&pencoder, 0, sizeof(pencoder));
	pencoder.size = sizeof(pfm_perf_encode_arg_t);

	/* Initialize libpfm event info structure. */
	memset(&info, 0, sizeof(info));
	info.size = sizeof(info);

	/* Prepare the encoder for query. */
	pencoder.attr = &attr; /* Set the perf_event_attr pointer. */
	pencoder.fstr = NULL; /* Not interested by the fully qualified event string. */

	ret = pfm_initialize();
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "Failed to initialise libpfm: %s", pfm_strerror(ret));
		ret = 255;
		goto end;
	}

	ret = pfm_get_os_event_encoding(
		argv[1], PFM_PLM0 | PFM_PLM1 | PFM_PLM2 | PFM_PLM3, PFM_OS_PERF_EVENT, &pencoder);
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "libpfm: error pfm_get_os_event_encoding: %s\n", pfm_strerror(ret));
		ret = 1;
		goto end;
	}

	/*
	 * Query the raw code for later use. Do it now to simplify error
	 * management.
	 */
	ret = pfm_get_event_info(pencoder.idx, PFM_OS_NONE, &info);
	if (ret != PFM_SUCCESS) {
		fprintf(stderr, "libpfm: error pfm_get_event_info: %s\n", pfm_strerror(ret));
		ret = 1;
		goto end;
	}

	/*
	 * Now that the event is found, try to use it to validate that
	 * the current user has access to it and that it can be used on that
	 * host.
	 */

	/* Set the event to disabled to prevent unnecessary side effects. */
	pencoder.attr->disabled = 1;

	/* perf_event_open is provided by perfmon/perf_event.h. */
	fd = perf_event_open(pencoder.attr, 0, -1, -1, 0);
	if (fd == -1) {
		fprintf(stderr, "perf: error perf_event_open: %d: %s\n", errno, strerror(errno));
		ret = 2;
		goto end;
	}

	/* We close the fd immediately since the event is actionable. */
	close(fd);

	/* Output the raw code for the event */
	fprintf(stdout, "r%" PRIx64 "\n", info.code);
	ret = 0;

end:
	return ret;
}
